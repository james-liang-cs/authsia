import AuthenticatorCore
import AuthenticatorBridge
import Foundation
import MCP

enum MCPBridgeState: String, Sendable {
    case ready
    case unavailable
    case cliAccessDisabled
}

struct MCPWorkspaceInspectionService: @unchecked Sendable {
    typealias BridgeStateProvider = @Sendable () -> MCPBridgeState

    private static let referenceLimit = 1_000
    private static let managedFileLimit = 128
    private static let managedFileByteLimit = 1_048_576
    private static let aggregateManagedFileByteLimit = 4_194_304
    private static let diagnosticLimit = 100

    let runtimeContext: MCPRuntimeContext
    let bridgeStateProvider: BridgeStateProvider
    let selectionStore: WorkspaceEnvironmentSelectionStore
    let fileManager: FileManager

    init(
        runtimeContext: MCPRuntimeContext,
        bridgeStateProvider: @escaping BridgeStateProvider = Self.liveBridgeState,
        selectionStore: WorkspaceEnvironmentSelectionStore = WorkspaceEnvironmentSelectionStore(),
        fileManager: FileManager = .default
    ) {
        self.runtimeContext = runtimeContext
        self.bridgeStateProvider = bridgeStateProvider
        self.selectionStore = selectionStore
        self.fileManager = fileManager
    }

    func status() -> MCPStatusOutput {
        let bridgeState = bridgeStateProvider()
        let workspaceReady = runtimeContext.workspaceRoot != nil && runtimeContext.workspaceName != nil
        var diagnostics: [MCPDiagnostic] = []
        if !workspaceReady {
            diagnostics.append(MCPDiagnostic(
                code: "workspaceUnavailable",
                message: "Open one initialized Authsia workspace in the MCP client or bind it explicitly."
            ))
        }
        if bridgeState != .ready {
            diagnostics.append(MCPDiagnostic(
                code: bridgeState.rawValue,
                message: bridgeState == .cliAccessDisabled
                    ? "CLI access is disabled in Authsia."
                    : "The local Authsia Bridge is unavailable."
            ))
        }
        return MCPStatusOutput(
            serverInstanceID: runtimeContext.instanceID.uuidString,
            protocolRevision: Version.latest,
            workspaceName: runtimeContext.workspaceName ?? "",
            workspaceRoot: runtimeContext.workspaceRoot?.path ?? "",
            bridgeState: bridgeState.rawValue,
            ready: workspaceReady && bridgeState == .ready,
            diagnostics: diagnostics
        )
    }

    func inspect(_ input: MCPWorkspaceInspectInput) throws -> MCPWorkspaceInspectOutput {
        try runtimeContext.requireWorkspace()
        guard let root = runtimeContext.workspaceRoot else {
            throw MCPRuntimeContextError.workspaceUnavailable
        }
        let config = try WorkspaceConfigStore.read(fromWorkspaceRoot: root, fileManager: fileManager)
        let availableEnvironments = availableEnvironmentNames(in: config)
        let selectedEnvironment = try resolveEnvironment(
            input.environment,
            available: availableEnvironments,
            root: root
        )
        var diagnostics: [MCPDiagnostic] = []
        var references = Set<MCPWorkspaceReference>()
        var truncated = false
        var inspectedByteCount = 0
        let managedFiles = Array(config.managedEnvFiles.prefix(Self.managedFileLimit))
        if config.managedEnvFiles.count > managedFiles.count {
            diagnostics.append(MCPDiagnostic(
                code: "managedFileLimitReached",
                message: "Only the first configured managed files were inspected."
            ))
        }

        for binding in config.envBindings {
            appendReference(
                uri: binding.reference,
                environmentVariable: binding.name,
                sourcePath: WorkspaceConfigStore.relativeConfigPath,
                selectedEnvironment: true,
                references: &references,
                truncated: &truncated
            )
            if truncated { break }
        }

        for relativePath in managedFiles where !truncated {
            guard let fileURL = containedManagedFile(relativePath, root: root) else {
                let candidate = root.appendingPathComponent(relativePath)
                let exists = fileManager.fileExists(atPath: candidate.path)
                diagnostics.append(MCPDiagnostic(
                    code: exists ? "managedFileOutsideWorkspace" : "managedFileMissing",
                    message: exists
                        ? "A managed file resolves outside the workspace."
                        : "A configured managed file is missing."
                ))
                continue
            }
            let fileData: Data
            do {
                let handle = try FileHandle(forReadingFrom: fileURL)
                defer { try? handle.close() }
                fileData = try handle.read(upToCount: Self.managedFileByteLimit + 1) ?? Data()
            } catch {
                diagnostics.append(MCPDiagnostic(
                    code: "managedFileUnreadable",
                    message: "A configured managed file could not be inspected."
                ))
                continue
            }
            guard fileData.count <= Self.managedFileByteLimit else {
                diagnostics.append(MCPDiagnostic(
                    code: "managedFileTooLarge",
                    message: "A configured managed file exceeds the inspection size limit."
                ))
                continue
            }
            guard inspectedByteCount <= Self.aggregateManagedFileByteLimit - fileData.count else {
                diagnostics.append(MCPDiagnostic(
                    code: "managedFileByteLimitReached",
                    message: "The aggregate managed-file inspection size limit was reached."
                ))
                break
            }
            inspectedByteCount += fileData.count
            let entries: [(key: String, value: String)]
            do {
                guard let content = String(data: fileData, encoding: .utf8) else {
                    throw CocoaError(.fileReadInapplicableStringEncoding)
                }
                entries = try EnvFileParser.parse(content: content)
            } catch {
                diagnostics.append(MCPDiagnostic(
                    code: "managedFileUnreadable",
                    message: "A configured managed file could not be inspected."
                ))
                continue
            }
            let environment = WorkspaceEnvironmentSuggestion.from(path: relativePath)
            let isSelected = environment == nil || environment == selectedEnvironment
            for entry in entries {
                appendReference(
                    uri: entry.value,
                    environmentVariable: entry.key,
                    sourcePath: relativePath,
                    selectedEnvironment: isSelected,
                    references: &references,
                    truncated: &truncated
                )
                if truncated { break }
            }
        }

        return MCPWorkspaceInspectOutput(
            workspaceName: config.workspace.name,
            workspaceRoot: root.path,
            schemaVersion: config.schemaVersion,
            selectedEnvironment: selectedEnvironment,
            availableEnvironments: availableEnvironments,
            managedFiles: managedFiles,
            references: references.sorted {
                if $0.sourcePath == $1.sourcePath {
                    return ($0.environmentVariable ?? "") < ($1.environmentVariable ?? "")
                }
                return $0.sourcePath < $1.sourcePath
            },
            referencesTruncated: truncated,
            diagnostics: Array(diagnostics.prefix(Self.diagnosticLimit))
        )
    }

    private func resolveEnvironment(
        _ requested: String?,
        available: [String],
        root: URL
    ) throws -> String? {
        if let requested {
            let normalized = requested.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !normalized.isEmpty,
                  normalized.count <= 128,
                  available.contains(normalized) else {
                throw MCPToolInputError.invalidArgument("environment is not available in this workspace.")
            }
            return normalized
        }
        return try? selectionStore.activeEnvironment(for: root)
    }

    private func availableEnvironmentNames(in config: WorkspaceConfig) -> [String] {
        Array(Set(config.managedEnvFiles.compactMap(WorkspaceEnvironmentSuggestion.from(path:))))
            .sorted()
    }

    private func containedManagedFile(_ relativePath: String, root: URL) -> URL? {
        guard WorkspaceConfigStore.isCommitSafeRelativePath(relativePath) else { return nil }
        let candidate = root.appendingPathComponent(relativePath)
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: candidate.path, isDirectory: &isDirectory),
              !isDirectory.boolValue else {
            return nil
        }
        let canonicalRoot = root.resolvingSymlinksInPath().standardizedFileURL.path
        let canonicalFile = candidate.resolvingSymlinksInPath().standardizedFileURL
        guard canonicalFile.path.hasPrefix(canonicalRoot + "/") else { return nil }
        return canonicalFile
    }

    private func appendReference(
        uri: String,
        environmentVariable: String?,
        sourcePath: String,
        selectedEnvironment: Bool,
        references: inout Set<MCPWorkspaceReference>,
        truncated: inout Bool
    ) {
        let normalizedURI = uri.trimmingCharacters(in: .whitespacesAndNewlines)
        guard SecretReference.isSecretReference(normalizedURI),
              let reference = try? SecretReference.parse(normalizedURI),
              (try? reference.validateResolvedField()) != nil else {
            return
        }
        let candidate = MCPWorkspaceReference(
            uri: reference.canonicalURI,
            environmentVariable: environmentVariable,
            sourcePath: sourcePath,
            selectedEnvironment: selectedEnvironment
        )
        guard !references.contains(candidate) else { return }
        guard references.count < Self.referenceLimit else {
            truncated = true
            return
        }
        references.insert(candidate)
    }

    private static func liveBridgeState() -> MCPBridgeState {
        do {
            return bridgeState(for: try AuthsiaBridgeClient.shared.ping())
        } catch {
            return error.localizedDescription.localizedCaseInsensitiveContains("CLI access is disabled")
                ? .cliAccessDisabled
                : .unavailable
        }
    }

    static func bridgeState(for payload: BridgePingPayload) -> MCPBridgeState {
        payload.cliAccessEnabled == false ? .cliAccessDisabled : .ready
    }
}

private extension SecretReference {
    var canonicalURI: String {
        var uri = "authsia://\(type.rawValue)/\(Self.percentEncodePathSegment(item))"
        if let field {
            uri += "/\(Self.percentEncodePathSegment(field))"
        }
        if isFolderScoped {
            uri += "?folder=\(Self.percentEncodeQueryValue(folder ?? ""))"
        }
        return uri
    }

    static func percentEncodePathSegment(_ value: String) -> String {
        var allowed = CharacterSet.urlPathAllowed
        allowed.remove(charactersIn: "/?#")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? ""
    }

    static func percentEncodeQueryValue(_ value: String) -> String {
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "&=+#?/")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? ""
    }
}
