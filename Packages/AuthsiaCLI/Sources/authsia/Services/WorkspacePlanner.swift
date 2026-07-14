import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import Foundation

struct WorkspaceEnvSecretPlan: Equatable {
    let secret: DetectedSecret
    let selectedByDefault: Bool
    let replacementLine: String
    let conflict: WorkspaceSecretConflict?
}

struct WorkspaceSecretConflict: Codable, Equatable, Hashable {
    let itemType: String
    let item: String
    let folderPath: String?
    var environments: [String] = []

    var displayLine: String {
        let folder = folderPath.map { " in folder \($0)" } ?? ""
        return "\(itemType) \(item)\(folder)"
    }
}

struct WorkspaceSecretSelection: Equatable {
    let secret: DetectedSecret
    let action: WorkspaceSecretAction
    var environments: [String]? = nil
}

enum WorkspaceSecretAction: String, Codable, Equatable {
    case create
    case update
    case reuse
}

struct WorkspaceEnvFilePlan: Equatable {
    let relativePath: String
    let absolutePath: String
    let secrets: [WorkspaceEnvSecretPlan]
    let authsiaReferenceCount: Int
}

struct WorkspaceResetEnvFile: Equatable {
    let relativePath: String
    let absolutePath: String
    let isMissing: Bool
    let authsiaReferenceCount: Int
    let restorePreviewDiff: String?
    let restoreError: String?
}

struct WorkspaceResetPlan: Equatable {
    let workspaceRoot: URL
    let config: WorkspaceConfig
    let envFiles: [WorkspaceResetEnvFile]
    let agentRemoval: AgentRuleRemovalResult

    /// Managed env files that hold authsia:// references but have no backup to
    /// restore from. Reset removes the workspace config, so these files would be
    /// left with unusable references and no plaintext values.
    var orphanedEnvFiles: [WorkspaceResetEnvFile] {
        envFiles.filter { !$0.isMissing && $0.authsiaReferenceCount > 0 && $0.restorePreviewDiff == nil }
    }
}

struct WorkspaceResetResult: Equatable {
    var removed: [String] = []
    var restoredEnvFiles: [String] = []
    var updated: [String] = []
    var warnings: [String] = []
    var manualSteps: [AgentRuleManualStep] = []
}

struct WorkspaceInitPlan: Equatable {
    let workspaceRoot: URL
    let config: WorkspaceConfig
    let envFiles: [WorkspaceEnvFilePlan]
    let removedEnvFiles: [String]
    let agents: [AgentTool]
    let missingReferences: [WorkspaceMissingReference]
    let unverifiedReferences: [WorkspaceMissingReference]
}

struct WorkspaceMissingReference: Codable, Equatable, Hashable {
    let relativePath: String
    let itemType: String
    let item: String
    let folderPath: String?
    let envBindingName: String?

    init(
        relativePath: String,
        itemType: String,
        item: String,
        folderPath: String?,
        envBindingName: String? = nil
    ) {
        self.relativePath = relativePath
        self.itemType = itemType
        self.item = item
        self.folderPath = folderPath
        self.envBindingName = envBindingName
    }

    var displayLine: String {
        let folder = folderPath.map { " in folder \($0)" } ?? ""
        if let envBindingName {
            return "\(relativePath): env binding \(envBindingName) -> \(itemType) \(item)\(folder)"
        }
        return "\(relativePath): \(itemType) \(item)\(folder)"
    }
}

enum WorkspacePlannerError: LocalizedError {
    case pathOutsideWorkspace(String)
    case invalidEnvFilePath(String)
    case envFileNotFound(String)

    var errorDescription: String? {
        switch self {
        case .pathOutsideWorkspace(let path):
            return "Env file must be inside the workspace: \(path). Move the file into the workspace, " +
                "or pass a relative path such as --env-file .env."
        case .invalidEnvFilePath(let path):
            return "Invalid env file path: \(path). Use a commit-safe relative path such as --env-file .env."
        case .envFileNotFound(let path):
            return "Env file does not exist: \(path). Create it first, pass the correct relative path, " +
                "preview detected files with `authsia workspace init --dry-run` or " +
                "`authsia workspace update --dry-run`, or open Authsia > Workspace to choose detected files."
        }
    }
}

enum WorkspaceInitPlanner {
    private static let defaultEnvFileDiscoveryDepth = 3
    private static let allowedEnvDiscoverySkippedDirectoryNames: Set<String> = ["packages"]

    static func plan(
        workspaceRoot: URL,
        explicitEnvFiles: [String],
        folderOverride: String?,
        agents: [AgentTool],
        discoverNestedEnvFiles: Bool = false,
        vaultIndex: WorkspaceVaultIndex? = nil,
        fileManager: FileManager = .default
    ) async throws -> WorkspaceInitPlan {
        let root = URL(fileURLWithPath: workspaceRoot.standardizedFileURL.path, isDirectory: true)
        let envFiles = try discoverEnvFiles(
            workspaceRoot: root,
            explicitEnvFiles: explicitEnvFiles,
            discoverNestedEnvFiles: discoverNestedEnvFiles,
            fileManager: fileManager
        )
        let uniqueAgentList = uniqueAgents(agents)
        let folder = WorkspaceFolderPath.normalize(folderOverride, defaultName: root.lastPathComponent)
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: WorkspaceConfig.Workspace(name: root.lastPathComponent, authsiaFolder: folder),
            managedEnvFiles: envFiles.map(\.relativePath),
            agents: uniqueAgentList.isEmpty ? nil : WorkspaceConfig.Agents(rules: uniqueAgentList.map(\.configName))
        )

        let scanner = FileScannerService()
        let secrets = await scanner.scanPaths(
            envFiles.map(\.absolutePath),
            detectionService: SecretDetectionService(),
            recursive: false
        ).filter(isWorkspaceMigratableSecret)

        let diffs = EnvFileRewriteService.generateDiff(for: secrets, folderPath: folder)
        let replacementBySecretID = Dictionary(
            uniqueKeysWithValues: diffs.flatMap { diff in
                diff.changes.map { ($0.secret.id, $0.replacementLine) }
            }
        )
        let secretsByPath = Dictionary(grouping: secrets) { $0.filePath }
        var missingReferences = Set<WorkspaceMissingReference>()
        var unverifiedReferences = Set<WorkspaceMissingReference>()

        var filePlans: [WorkspaceEnvFilePlan] = []
        for envFile in envFiles {
            let refs = await scanner.findURIAuthsiaReferences(in: [envFile.absolutePath])
            if let vaultIndex {
                for reference in refs where !vaultIndex.contains(reference) {
                    missingReferences.insert(workspaceReference(relativePath: envFile.relativePath, reference: reference))
                }
            } else {
                for reference in refs {
                    unverifiedReferences.insert(workspaceReference(relativePath: envFile.relativePath, reference: reference))
                }
            }
            let fileSecrets = (secretsByPath[envFile.absolutePath] ?? [])
                .sorted { $0.lineNumber < $1.lineNumber }
                .map {
                    let suggestedEnvironments = WorkspaceEnvironmentSuggestion.from(path: envFile.relativePath)
                        .map { [$0] } ?? []
                    let conflict = vaultIndex?.existingItem(
                        for: $0,
                        folderPath: config.workspace.authsiaFolder,
                        environments: suggestedEnvironments
                    )
                    return WorkspaceEnvSecretPlan(
                        secret: $0,
                        selectedByDefault: conflict == nil,
                        replacementLine: replacementBySecretID[$0.id] ?? $0.secretReferenceURI(folderPath: folder),
                        conflict: conflict
                    )
                }
            filePlans.append(WorkspaceEnvFilePlan(
                relativePath: envFile.relativePath,
                absolutePath: envFile.absolutePath,
                secrets: fileSecrets,
                authsiaReferenceCount: refs.count
            ))
        }

        return WorkspaceInitPlan(
            workspaceRoot: root,
            config: config,
            envFiles: filePlans,
            removedEnvFiles: [],
            agents: uniqueAgentList,
            missingReferences: sortedReferences(missingReferences),
            unverifiedReferences: sortedReferences(unverifiedReferences)
        )
    }

    fileprivate struct DiscoveredEnvFile {
        let relativePath: String
        let absolutePath: String
    }

    fileprivate struct ExistingEnvFiles {
        let present: [DiscoveredEnvFile]
        let missing: [String]
    }

    fileprivate static func discoverEnvFiles(
        workspaceRoot root: URL,
        explicitEnvFiles: [String],
        discoverNestedEnvFiles: Bool = false,
        fileManager: FileManager
    ) throws -> [DiscoveredEnvFile] {
        let relativeCandidates: [String]
        if explicitEnvFiles.isEmpty {
            relativeCandidates = try boundedEnvFilePaths(workspaceRoot: root, fileManager: fileManager)
        } else {
            var candidates = try explicitEnvFiles.map {
                try relativeEnvFilePath($0, workspaceRoot: root)
            }
            if discoverNestedEnvFiles {
                candidates.append(contentsOf: try boundedEnvFilePaths(
                    workspaceRoot: root,
                    fileManager: fileManager
                ))
            }
            relativeCandidates = candidates
        }

        let relativePaths = try uniqueRelativePaths(relativeCandidates)
        return try relativePaths.map { relativePath in
            let absolutePath = root.appendingPathComponent(relativePath).path
            var isDirectory: ObjCBool = false
            guard fileManager.fileExists(atPath: absolutePath, isDirectory: &isDirectory),
                  !isDirectory.boolValue else {
                throw WorkspacePlannerError.envFileNotFound(relativePath)
            }
            return DiscoveredEnvFile(relativePath: relativePath, absolutePath: absolutePath)
        }
    }

    fileprivate static func discoverExistingEnvFiles(
        workspaceRoot root: URL,
        envFiles: [String],
        fileManager: FileManager
    ) throws -> ExistingEnvFiles {
        let relativePaths = try uniqueRelativePaths(envFiles.map {
            try relativeEnvFilePath($0, workspaceRoot: root)
        })
        var present: [DiscoveredEnvFile] = []
        var missing: [String] = []
        for relativePath in relativePaths {
            let absolutePath = root.appendingPathComponent(relativePath).path
            var isDirectory: ObjCBool = false
            if fileManager.fileExists(atPath: absolutePath, isDirectory: &isDirectory), !isDirectory.boolValue {
                present.append(DiscoveredEnvFile(relativePath: relativePath, absolutePath: absolutePath))
            } else {
                missing.append(relativePath)
            }
        }
        return ExistingEnvFiles(present: present, missing: missing)
    }

    private static func boundedEnvFilePaths(
        workspaceRoot root: URL,
        fileManager: FileManager
    ) throws -> [String] {
        guard let enumerator = fileManager.enumerator(atPath: root.path) else {
            return []
        }

        var paths: [String] = []
        while let relativePath = enumerator.nextObject() as? String {
            let fullPath = (root.path as NSString).appendingPathComponent(relativePath)
            let fileName = (relativePath as NSString).lastPathComponent

            var isDirectory: ObjCBool = false
            guard fileManager.fileExists(atPath: fullPath, isDirectory: &isDirectory) else {
                continue
            }

            if isDirectory.boolValue {
                let directoryDepth = pathDepth(relativePath)
                if shouldSkipEnvDiscoveryDirectory(named: fileName) ||
                    directoryDepth > defaultEnvFileDiscoveryDepth {
                    enumerator.skipDescendants()
                }
                continue
            }

            guard fileManager.isReadableFile(atPath: fullPath),
                  isEnvFileName(fileName),
                  fileDepth(relativePath) <= defaultEnvFileDiscoveryDepth else {
                continue
            }
            paths.append(try relativeEnvFilePath(fullPath, workspaceRoot: root))
        }

        return paths
    }

    private static func shouldSkipEnvDiscoveryDirectory(named name: String) -> Bool {
        FileScannerService.skippedRecursiveDirectoryNames.contains(name) &&
            !allowedEnvDiscoverySkippedDirectoryNames.contains(name)
    }

    private static func fileDepth(_ relativePath: String) -> Int {
        max(0, pathDepth(relativePath) - 1)
    }

    private static func pathDepth(_ relativePath: String) -> Int {
        relativePath.split(separator: "/", omittingEmptySubsequences: true).count
    }

    private static func isEnvFileName(_ name: String) -> Bool {
        name == ".env" || name.hasPrefix(".env.") || name.contains(".env.") || name.hasSuffix(".env")
    }

    private static func uniqueRelativePaths(_ paths: [String]) throws -> [String] {
        var seen = Set<String>()
        return try paths.sorted(by: envFileSort).compactMap { path in
            guard WorkspaceConfigStore.isCommitSafeRelativePath(path) else {
                throw WorkspacePlannerError.invalidEnvFilePath(path)
            }
            return seen.insert(path).inserted ? path : nil
        }
    }

    private static func envFileSort(_ lhs: String, _ rhs: String) -> Bool {
        if lhs == ".env" { return true }
        if rhs == ".env" { return false }
        return lhs < rhs
    }

    private static func relativeEnvFilePath(_ path: String, workspaceRoot root: URL) throws -> String {
        let rootPath = root.standardizedFileURL.path
        let absoluteURL: URL
        if path.hasPrefix("/") {
            absoluteURL = URL(fileURLWithPath: path).standardizedFileURL
        } else {
            absoluteURL = root.appendingPathComponent(path).standardizedFileURL
        }
        let absolutePath = absoluteURL.path
        let rootPrefix = rootPath.hasSuffix("/") ? rootPath : rootPath + "/"
        guard absolutePath.hasPrefix(rootPrefix) else {
            throw WorkspacePlannerError.pathOutsideWorkspace(path)
        }
        let relative = String(absolutePath.dropFirst(rootPrefix.count))
        guard !relative.isEmpty else {
            throw WorkspacePlannerError.invalidEnvFilePath(path)
        }
        return relative
    }

    fileprivate static func normalizeFolderPath(_ folderPath: String?) -> String? {
        guard let folderPath else { return nil }
        let segments = folderPath
            .split(separator: "/")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard !segments.isEmpty else { return nil }
        return segments.joined(separator: "/")
    }

    fileprivate static func uniqueAgents(_ agents: [AgentTool]) -> [AgentTool] {
        var output: [AgentTool] = []
        for agent in agents where !output.contains(agent) {
            output.append(agent)
        }
        return output
    }
}

enum WorkspaceUpdatePlanner {
    static func defaultSecretSelectionsForExplicitEnvFiles(
        plan: WorkspaceInitPlan,
        explicitEnvFiles: [String],
        fileManager: FileManager = .default
    ) throws -> [WorkspaceSecretSelection] {
        let explicitPaths = try Set(WorkspaceInitPlanner.discoverEnvFiles(
            workspaceRoot: plan.workspaceRoot,
            explicitEnvFiles: explicitEnvFiles,
            fileManager: fileManager
        ).map(\.relativePath))
        return plan.envFiles
            .filter { explicitPaths.contains($0.relativePath) }
            .flatMap(\.secrets)
            .filter(\.selectedByDefault)
            .map { WorkspaceSecretSelection(secret: $0.secret, action: .create) }
    }

    static func defaultSelectedSecretsForExplicitEnvFiles(
        plan: WorkspaceInitPlan,
        explicitEnvFiles: [String],
        fileManager: FileManager = .default
    ) throws -> [DetectedSecret] {
        try defaultSecretSelectionsForExplicitEnvFiles(
            plan: plan,
            explicitEnvFiles: explicitEnvFiles,
            fileManager: fileManager
        ).map(\.secret)
    }

    static func plan(
        workspaceRoot: URL,
        explicitEnvFiles: [String],
        agents: [AgentTool],
        discoverNestedEnvFiles: Bool = false,
        mergeExistingAgents: Bool = true,
        vaultIndex: WorkspaceVaultIndex? = nil,
        fileManager: FileManager = .default
    ) async throws -> WorkspaceInitPlan {
        let root = URL(fileURLWithPath: workspaceRoot.standardizedFileURL.path, isDirectory: true)
        let existingConfig = try WorkspaceConfigStore.read(fromWorkspaceRoot: root, fileManager: fileManager)
        let existingEnvFiles = try WorkspaceInitPlanner.discoverExistingEnvFiles(
            workspaceRoot: root,
            envFiles: existingConfig.managedEnvFiles,
            fileManager: fileManager
        )
        let newEnvFiles = try WorkspaceInitPlanner.discoverEnvFiles(
            workspaceRoot: root,
            explicitEnvFiles: explicitEnvFiles,
            discoverNestedEnvFiles: discoverNestedEnvFiles,
            fileManager: fileManager
        )
        let mergedEnvFiles = existingEnvFiles.present.map(\.relativePath) + newEnvFiles.map(\.relativePath)
        let envFiles = try WorkspaceInitPlanner.discoverEnvFiles(
            workspaceRoot: root,
            explicitEnvFiles: mergedEnvFiles,
            fileManager: fileManager
        )
        let existingAgents = (existingConfig.agents?.rules ?? []).compactMap(AgentTool.init(argument:))
        let uniqueAgentList = WorkspaceInitPlanner.uniqueAgents(
            mergeExistingAgents ? existingAgents + agents : agents
        )
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: existingConfig.workspace,
            managedEnvFiles: envFiles.map(\.relativePath),
            agents: uniqueAgentList.isEmpty ? nil : WorkspaceConfig.Agents(rules: uniqueAgentList.map(\.configName)),
            guardSettings: existingConfig.guardSettings,
            envBindings: existingConfig.envBindings
        )

        let scanner = FileScannerService()
        let secrets = await scanner.scanPaths(
            envFiles.map(\.absolutePath),
            detectionService: SecretDetectionService(),
            recursive: false
        ).filter(isWorkspaceMigratableSecret)
        let diffs = EnvFileRewriteService.generateDiff(for: secrets, folderPath: config.workspace.authsiaFolder)
        let replacementBySecretID = Dictionary(
            uniqueKeysWithValues: diffs.flatMap { diff in
                diff.changes.map { ($0.secret.id, $0.replacementLine) }
            }
        )
        let secretsByPath = Dictionary(grouping: secrets) { $0.filePath }
        var missingReferences = Set<WorkspaceMissingReference>()
        var unverifiedReferences = Set<WorkspaceMissingReference>()

        var filePlans: [WorkspaceEnvFilePlan] = []
        for envFile in envFiles {
            let refs = await scanner.findURIAuthsiaReferences(in: [envFile.absolutePath])
            if let vaultIndex {
                for reference in refs where !vaultIndex.contains(reference) {
                    missingReferences.insert(workspaceReference(relativePath: envFile.relativePath, reference: reference))
                }
            } else {
                for reference in refs {
                    unverifiedReferences.insert(workspaceReference(relativePath: envFile.relativePath, reference: reference))
                }
            }
            let fileSecrets = (secretsByPath[envFile.absolutePath] ?? [])
                .sorted { $0.lineNumber < $1.lineNumber }
                .map {
                    let suggestedEnvironments = WorkspaceEnvironmentSuggestion.from(path: envFile.relativePath)
                        .map { [$0] } ?? []
                    let conflict = vaultIndex?.existingItem(
                        for: $0,
                        folderPath: config.workspace.authsiaFolder,
                        environments: suggestedEnvironments
                    )
                    return WorkspaceEnvSecretPlan(
                        secret: $0,
                        selectedByDefault: conflict == nil,
                        replacementLine: replacementBySecretID[$0.id] ?? $0.secretReferenceURI(
                            folderPath: config.workspace.authsiaFolder
                        ),
                        conflict: conflict
                    )
                }
            filePlans.append(WorkspaceEnvFilePlan(
                relativePath: envFile.relativePath,
                absolutePath: envFile.absolutePath,
                secrets: fileSecrets,
                authsiaReferenceCount: refs.count
            ))
        }

        return WorkspaceInitPlan(
            workspaceRoot: root,
            config: config,
            envFiles: filePlans,
            removedEnvFiles: existingEnvFiles.missing,
            agents: uniqueAgentList,
            missingReferences: sortedReferences(missingReferences),
            unverifiedReferences: sortedReferences(unverifiedReferences)
        )
    }
}

enum WorkspaceResetPlanner {
    static func plan(
        workspaceRoot: URL,
        backupService: BackupService? = nil,
        fileManager: FileManager = .default
    ) async throws -> WorkspaceResetPlan {
        let root = URL(fileURLWithPath: workspaceRoot.standardizedFileURL.path, isDirectory: true)
        let config = try WorkspaceConfigStore.read(fromWorkspaceRoot: root, fileManager: fileManager)
        let scanner = FileScannerService()
        var envFiles: [WorkspaceResetEnvFile] = []
        for relativePath in config.managedEnvFiles {
            let absolutePath = root.appendingPathComponent(relativePath).path
            guard fileManager.fileExists(atPath: absolutePath) else {
                envFiles.append(WorkspaceResetEnvFile(
                    relativePath: relativePath,
                    absolutePath: absolutePath,
                    isMissing: true,
                    authsiaReferenceCount: 0,
                    restorePreviewDiff: nil,
                    restoreError: nil
                ))
                continue
            }
            let refs = await scanner.findURIAuthsiaReferences(in: [absolutePath])
            let restorePreview: BackupService.RestorePreview?
            let restoreError: String?
            if refs.isEmpty {
                restorePreview = nil
                restoreError = nil
            } else if let backupService {
                do {
                    restorePreview = try await backupService.previewMostRecentRestore(of: absolutePath)
                    restoreError = nil
                } catch {
                    if BridgeClientError.isApprovalDenied(error) {
                        throw error
                    }
                    restorePreview = nil
                    restoreError = error.localizedDescription
                }
            } else {
                restorePreview = nil
                restoreError = nil
            }
            envFiles.append(WorkspaceResetEnvFile(
                relativePath: relativePath,
                absolutePath: absolutePath,
                isMissing: false,
                authsiaReferenceCount: refs.count,
                restorePreviewDiff: restorePreview?.diff,
                restoreError: restoreError
            ))
        }

        let agents = (config.agents?.rules ?? []).compactMap(AgentTool.init(argument:))
        let agentRemoval = try AgentRuleInstaller.uninstall(
            projectRoot: root,
            agents: agents,
            dryRun: true,
            fileManager: fileManager
        )
        return WorkspaceResetPlan(
            workspaceRoot: root,
            config: config,
            envFiles: envFiles,
            agentRemoval: agentRemoval
        )
    }

    static func renderDryRun(_ plan: WorkspaceResetPlan) -> String {
        var lines: [String] = [
            "Authsia workspace reset: \(plan.config.workspace.name)",
            "Folder: \(plan.config.workspace.authsiaFolder)",
            "",
            "Remove workspace config: \(WorkspaceConfigStore.relativeConfigPath)",
            "",
            "Managed env files:",
        ]
        if plan.envFiles.isEmpty {
            lines.append("- none configured")
        } else {
            for envFile in plan.envFiles {
                if envFile.isMissing {
                    lines.append("- \(envFile.relativePath): missing")
                } else {
                    lines.append("- \(envFile.relativePath): keep file, \(envFile.authsiaReferenceCount) authsia refs")
                }
            }
        }

        lines.append("")
        lines.append("Agent rule artifacts:")
        appendAgentRemoval(plan.agentRemoval, to: &lines)

        lines.append("")
        lines.append("Env file restore:")
        let restoreCandidates = plan.envFiles.filter { !$0.isMissing && $0.authsiaReferenceCount > 0 }
        if restoreCandidates.isEmpty {
            lines.append("- No authsia:// refs found in managed env files.")
        } else {
            for envFile in restoreCandidates {
                if let restoreError = envFile.restoreError {
                    lines.append("- \(envFile.relativePath): restore unavailable (\(restoreError))")
                } else {
                    lines.append("- \(envFile.relativePath): restore from Authsia scrape backup")
                }
                if let diff = envFile.restorePreviewDiff {
                    lines.append(contentsOf: diff.split(separator: "\n", omittingEmptySubsequences: false).map {
                        "  \($0)"
                    })
                }
            }
        }

        let orphaned = plan.orphanedEnvFiles
        if !orphaned.isEmpty {
            lines.append("")
            lines.append("WARNING: reset will leave these env files with unusable authsia:// references")
            lines.append("because no Authsia scrape backup is available to restore plaintext values:")
            for envFile in orphaned {
                lines.append("- \(envFile.relativePath)")
            }
            lines.append("Restore the values manually or re-create them after reset.")
        }
        return lines.joined(separator: "\n")
    }

    static func apply(
        _ plan: WorkspaceResetPlan,
        backupService: BackupService? = nil,
        fileManager: FileManager = .default
    ) async throws -> WorkspaceResetResult {
        var result = WorkspaceResetResult()
        try await restoreManagedEnvFiles(plan.envFiles, backupService: backupService, result: &result)

        let agents = (plan.config.agents?.rules ?? []).compactMap(AgentTool.init(argument:))
        let agentRemoval = try AgentRuleInstaller.uninstall(
            projectRoot: plan.workspaceRoot,
            agents: agents,
            dryRun: false,
            fileManager: fileManager
        )
        result.removed.append(contentsOf: agentRemoval.removed)
        result.updated.append(contentsOf: agentRemoval.updated)
        result.manualSteps.append(contentsOf: agentRemoval.manualSteps)

        if try WorkspaceConfigStore.remove(fromWorkspaceRoot: plan.workspaceRoot, fileManager: fileManager) {
            result.removed.append(WorkspaceConfigStore.relativeConfigPath)
        }
        return result
    }

    static func renderApplyResult(_ result: WorkspaceResetResult) -> String {
        var lines: [String] = []
        appendSection("Restored env files:", values: result.restoredEnvFiles, to: &lines)
        appendSection("Warnings:", values: result.warnings, to: &lines)
        appendSection("Removed:", values: result.removed, to: &lines)
        appendSection("Updated:", values: result.updated, to: &lines)
        if !result.manualSteps.isEmpty {
            if !lines.isEmpty { lines.append("") }
            lines.append("Manual steps:")
            for step in result.manualSteps {
                lines.append("  \(step.path) \(step.reason)")
            }
        }
        if lines.isEmpty {
            lines.append("No workspace metadata artifacts needed removal.")
        }
        return lines.joined(separator: "\n")
    }

    private static func restoreManagedEnvFiles(
        _ envFiles: [WorkspaceResetEnvFile],
        backupService: BackupService?,
        result: inout WorkspaceResetResult
    ) async throws {
        let restoreCandidates = envFiles.filter { !$0.isMissing && $0.authsiaReferenceCount > 0 }
        guard !restoreCandidates.isEmpty else { return }
        guard let backupService else {
            for envFile in restoreCandidates {
                appendRestoreWarning(
                    for: envFile,
                    error: BackupService.BackupError.noBackupFound(envFile.absolutePath),
                    to: &result
                )
            }
            return
        }

        for envFile in restoreCandidates {
            do {
                _ = try await backupService.restoreMostRecentBackup(of: envFile.absolutePath)
                result.restoredEnvFiles.append(envFile.relativePath)
            } catch {
                if BridgeClientError.isApprovalDenied(error) {
                    throw error
                }
                appendRestoreWarning(for: envFile, error: error, to: &result)
            }
        }
    }

    private static func appendRestoreWarning(
        for envFile: WorkspaceResetEnvFile,
        error: Error,
        to result: inout WorkspaceResetResult
    ) {
        result.warnings.append("\(envFile.relativePath): restore unavailable (\(error.localizedDescription))")
    }

    private static func appendAgentRemoval(_ result: AgentRuleRemovalResult, to lines: inout [String]) {
        appendSection(result.dryRun ? "- would remove" : "- removed", values: result.removed, to: &lines)
        appendSection(result.dryRun ? "- would update" : "- updated", values: result.updated, to: &lines)
        appendSection("- unchanged", values: result.unchanged, to: &lines)
        if !result.manualSteps.isEmpty {
            for step in result.manualSteps {
                lines.append("- manual: \(step.path) \(step.reason)")
            }
        }
        if result.removed.isEmpty,
           result.updated.isEmpty,
           result.unchanged.isEmpty,
           result.manualSteps.isEmpty {
            lines.append("- none found")
        }
    }

    private static func appendSection(_ title: String, values: [String], to lines: inout [String]) {
        guard !values.isEmpty else { return }
        lines.append(title)
        lines.append(contentsOf: values.map { "  \($0)" })
    }
}

struct WorkspaceRunPlan: Equatable {
    let workspaceRoot: URL
    let config: WorkspaceConfig
    let envFiles: [String]
    let managedEnvFileCount: Int
    let envBindings: [String: String]
    let activeEnvironment: String?
    let defaultOnly: Bool
    let commandArgs: [String]
    let usesShell: Bool

    static func build(
        startingAt startURL: URL,
        extraEnvFiles: [String],
        commandArgs: [String],
        shellCommandParts: [String] = [],
        fileManager: FileManager = .default
    ) throws -> WorkspaceRunPlan {
        guard let root = WorkspaceRootResolver.findWorkspaceRoot(startingAt: startURL, fileManager: fileManager) else {
            throw WorkspaceConfigError.missingConfig
        }
        let config = try WorkspaceConfigStore.read(fromWorkspaceRoot: root, fileManager: fileManager)
        let startComponents = startURL.standardizedFileURL.pathComponents
        let managedEnvFiles: [(
            relativePath: String,
            absolutePath: String,
            scopeDepth: Int,
            index: Int
        )] = try config.managedEnvFiles.enumerated().compactMap { index, relativePath in
            let fileURL = root.appendingPathComponent(relativePath).standardizedFileURL
            let scopeComponents = fileURL.deletingLastPathComponent().pathComponents
            guard startComponents.starts(with: scopeComponents) else { return nil }
            let absolute = fileURL.path
            guard fileManager.fileExists(atPath: absolute) else {
                throw ValidationError(
                    "Managed env file \"\(relativePath)\" is missing. " +
                        "Restore the file if it should still be managed. " +
                        "Run `authsia workspace update` to remove stale managed env files."
                )
            }
            return (
                relativePath: relativePath,
                absolutePath: absolute,
                scopeDepth: scopeComponents.count,
                index: index
            )
        }.sorted { lhs, rhs in
            (lhs.scopeDepth, lhs.index) < (rhs.scopeDepth, rhs.index)
        }
        try validateEnvBindingsAreNotDuplicatedInManagedEnvFiles(
            config.envBindings,
            managedEnvFiles: managedEnvFiles.map { ($0.relativePath, $0.absolutePath) }
        )
        let normalizedShellCommand = Exec.normalizedShellCommandParts(shellCommandParts)
        let usesShell = !normalizedShellCommand.isEmpty
        return WorkspaceRunPlan(
            workspaceRoot: root,
            config: config,
            envFiles: managedEnvFiles.map { $0.absolutePath } + extraEnvFiles,
            managedEnvFileCount: managedEnvFiles.count,
            envBindings: config.schemaVersion == 1
                ? Dictionary(uniqueKeysWithValues: config.envBindings.map { ($0.name, $0.reference) })
                : [:],
            activeEnvironment: nil,
            defaultOnly: config.schemaVersion >= 2,
            commandArgs: usesShell ? normalizedShellCommand : commandArgs,
            usesShell: usesShell
        )
    }

    private static func validateEnvBindingsAreNotDuplicatedInManagedEnvFiles(
        _ envBindings: [WorkspaceConfig.EnvBinding],
        managedEnvFiles: [(String, String)]
    ) throws {
        let envBindingNames = Set(envBindings.map(\.name))
        guard !envBindingNames.isEmpty else { return }

        for (relativePath, absolutePath) in managedEnvFiles {
            let entries = try EnvFileParser.parse(contentsOf: absolutePath)
            guard let duplicate = entries.first(where: { envBindingNames.contains($0.key) })?.key else {
                continue
            }
            throw ValidationError(
                "Workspace env binding \"\(duplicate)\" is also defined in managed env file \"\(relativePath)\". " +
                    "Remove \(duplicate) from \(relativePath), or run `authsia workspace env remove \(duplicate)` " +
                    "to use the env file value."
            )
        }
    }

    static func renderDryRun(_ plan: WorkspaceRunPlan) -> String {
        var lines = [
            "Workspace: \(plan.config.workspace.name)",
            "Authsia folder: \(plan.config.workspace.authsiaFolder)",
            "Env files:",
        ]
        if plan.envFiles.isEmpty {
            lines.append("- none")
        } else {
            lines.append(contentsOf: plan.envFiles.map { "- \($0)" })
        }
        lines.append("")
        if plan.config.schemaVersion >= 2 {
            lines.append("Environment: \(plan.activeEnvironment ?? "Default environment")")
        }
        lines.append("Env bindings:")
        if plan.envBindings.isEmpty {
            lines.append("- none")
        } else {
            lines.append(contentsOf: plan.envBindings.keys.sorted().map { "- \($0)" })
        }
        if !plan.commandArgs.isEmpty {
            let label = plan.usesShell ? "Shell command" : "Command"
            lines.append("\(label): \(plan.commandArgs.joined(separator: " "))")
        }
        return lines.joined(separator: "\n")
    }
}

struct WorkspaceStatus: Codable, Equatable {
    struct EnvFile: Codable, Equatable {
        let relativePath: String
        let isMissing: Bool
        let authsiaReferenceCount: Int
    }

    struct AgentRule: Codable, Equatable {
        let name: String
        let isInstalled: Bool
    }

    struct EnvBinding: Codable, Equatable {
        let name: String
    }

    struct EnvironmentBinding: Codable, Equatable {
        let variableName: String
        let itemID: UUID?
        let itemType: String?
        let itemName: String?
        let environments: [String]
        let reference: String
        let state: String
    }

    let config: WorkspaceConfig
    let envFiles: [EnvFile]
    let envBindings: [EnvBinding]
    let agentRules: [AgentRule]
    let missingReferences: [WorkspaceMissingReference]
    let unverifiedReferences: [WorkspaceMissingReference]
    var activeEnvironment: String? = nil
    var availableEnvironments: [String] = []
    var effectiveDefaultEnvironmentCount: Int = 0
    var effectiveTaggedCount: Int = 0
    var overrideCount: Int = 0
    var conflictCount: Int = 0
    var selectionHealth: String = "legacy"
    var environmentBindings: [EnvironmentBinding] = []
}

enum WorkspaceStatusReporter {
    static func build(
        workspaceRoot root: URL,
        vaultIndex: WorkspaceVaultIndex? = nil,
        activeEnvironment: String? = nil,
        fileManager: FileManager = .default
    ) async throws -> WorkspaceStatus {
        let config = try WorkspaceConfigStore.read(fromWorkspaceRoot: root, fileManager: fileManager)
        let scanner = FileScannerService()
        var envFiles: [WorkspaceStatus.EnvFile] = []
        var missingReferences = Set<WorkspaceMissingReference>()
        var unverifiedReferences = Set<WorkspaceMissingReference>()
        for relativePath in config.managedEnvFiles {
            let absolutePath = root.appendingPathComponent(relativePath).path
            guard fileManager.fileExists(atPath: absolutePath) else {
                envFiles.append(WorkspaceStatus.EnvFile(
                    relativePath: relativePath,
                    isMissing: true,
                    authsiaReferenceCount: 0
                ))
                continue
            }
            let refs = await scanner.findURIAuthsiaReferences(in: [absolutePath])
            if let vaultIndex {
                for reference in refs where !vaultIndex.contains(reference) {
                    missingReferences.insert(workspaceReference(relativePath: relativePath, reference: reference))
                }
            } else {
                for reference in refs {
                    unverifiedReferences.insert(workspaceReference(relativePath: relativePath, reference: reference))
                }
            }
            envFiles.append(WorkspaceStatus.EnvFile(
                relativePath: relativePath,
                isMissing: false,
                authsiaReferenceCount: refs.count
            ))
        }

        let envBindings = config.envBindings.map { WorkspaceStatus.EnvBinding(name: $0.name) }
        for binding in config.envBindings {
            guard let reference = authsiaReference(for: binding) else { continue }
            let workspaceReference = workspaceReference(envBindingName: binding.name, reference: reference)
            if let vaultIndex {
                if !vaultIndex.contains(reference) {
                    missingReferences.insert(workspaceReference)
                }
            } else {
                unverifiedReferences.insert(workspaceReference)
            }
        }

        let agentRules = (config.agents?.rules ?? []).map { name in
            WorkspaceStatus.AgentRule(
                name: name,
                isInstalled: isAgentRuleInstalled(name: name, workspaceRoot: root, fileManager: fileManager)
            )
        }
        var status = WorkspaceStatus(
            config: config,
            envFiles: envFiles,
            envBindings: envBindings,
            agentRules: agentRules,
            missingReferences: sortedReferences(missingReferences),
            unverifiedReferences: sortedReferences(unverifiedReferences)
        )
        if config.schemaVersion >= 2 {
            status.activeEnvironment = activeEnvironment
        }
        if config.schemaVersion >= 2, let payload = vaultIndex?.payload {
            let selection: WorkspaceEnvironmentSelection = activeEnvironment.map(WorkspaceEnvironmentSelection.named) ?? .defaultOnly
            let evaluation = WorkspaceEnvironmentEvaluation.evaluate(config: config, payload: payload, selection: selection)
            let effectiveIDs = Set(evaluation.resolution.effective.map(\.id))
            let overriddenIDs = Set(evaluation.resolution.overridden.map(\.id))
            let inactiveIDs = Set(evaluation.resolution.inactive.map(\.id))
            status.availableEnvironments = evaluation.resolution.availableEnvironments
            status.effectiveDefaultEnvironmentCount = evaluation.resolution.effective.filter(\.environments.isEmpty).count
            status.effectiveTaggedCount = evaluation.resolution.effective.filter { !$0.environments.isEmpty }.count
            status.overrideCount = evaluation.resolution.overridden.count
            status.conflictCount = evaluation.resolution.issues.filter { $0.kind == .conflict }.count
            status.selectionHealth = evaluation.resolution.issues.isEmpty ? "healthy" : "needsAttention"
            let candidateStates = evaluation.resolution.effective
                .map { ($0, "effective") }
                + evaluation.resolution.overridden.map { ($0, "overridden") }
                + evaluation.resolution.inactive.map { ($0, "inactive") }
            status.environmentBindings = candidateStates.map { candidate, state in
                let bindingID = candidate.id.split(separator: "#", maxSplits: 1).first.map(String.init) ?? candidate.id
                let bindingIndex = Int(bindingID.replacingOccurrences(of: "binding-", with: ""))
                let reference = bindingIndex.flatMap { config.envBindings.indices.contains($0) ? config.envBindings[$0].reference : nil } ?? ""
                return WorkspaceStatus.EnvironmentBinding(
                    variableName: candidate.variableName,
                    itemID: candidate.itemID,
                    itemType: candidate.itemType,
                    itemName: candidate.itemName,
                    environments: candidate.environments,
                    reference: reference,
                    state: effectiveIDs.contains(candidate.id) ? "effective" : overriddenIDs.contains(candidate.id) ? "overridden" : inactiveIDs.contains(candidate.id) ? "inactive" : state
                )
            }
        }
        return status
    }

    static func renderTable(_ status: WorkspaceStatus) -> String {
        let summary = WorkspaceStatusSummaryRenderer.render(
            managedEnvFiles: status.envFiles.map { envFile in
                WorkspaceStatusManagedEnvFile(
                    relativePath: envFile.relativePath,
                    isMissing: envFile.isMissing,
                    authsiaReferenceCount: envFile.authsiaReferenceCount
                )
            },
            envBindings: status.envBindings.map { binding in
                WorkspaceStatusEnvBinding(name: binding.name)
            },
            agentRules: status.agentRules.map { rule in
                WorkspaceStatusAgentRule(
                    title: AgentTool(argument: rule.name)?.title ?? rule.name,
                    isInstalled: rule.isInstalled
                )
            },
            missingReferenceCount: status.missingReferences.count
        )
        var lines: [String] = [
            "Workspace: \(status.config.workspace.name)",
            "Authsia folder: \(status.config.workspace.authsiaFolder)",
            "Status: \(summary.healthSummary)",
            "Health: \(summary.healthDetail)",
            "Managed env files: \(summary.managedEnvFilesText)",
            "Workspace env bindings: \(summary.envBindingsText)",
            "Agent rules: \(summary.agentRulesText)",
            "Active environment: \(status.activeEnvironment ?? "Default environment")",
            "Available environments: \(status.availableEnvironments.isEmpty ? "none" : status.availableEnvironments.joined(separator: ", "))",
            "Effective environment items: \(status.effectiveDefaultEnvironmentCount) default-environment, \(status.effectiveTaggedCount) tagged",
            "Environment overrides: \(status.overrideCount)",
            "Environment conflicts: \(status.conflictCount)",
            "Environment selection: \(status.selectionHealth)",
            "",
            "Managed env files:",
        ]
        if status.envFiles.isEmpty {
            lines.append("- none")
        } else {
            for envFile in status.envFiles {
                let state = envFile.isMissing ? "missing" : "\(envFile.authsiaReferenceCount) authsia refs"
                lines.append("- \(envFile.relativePath): \(state)")
            }
        }

        lines.append("")
        lines.append("Workspace env bindings:")
        if status.envBindings.isEmpty {
            lines.append("- none")
        } else {
            if status.environmentBindings.isEmpty {
                for binding in status.envBindings {
                    lines.append("- \(binding.name): authsia ref")
                }
            } else {
                for binding in status.environmentBindings {
                    let environments = binding.environments.isEmpty ? "Default environment" : binding.environments.joined(separator: ", ")
                    lines.append("- \(binding.variableName): \(environments) · \(binding.state) · \(binding.reference)")
                }
            }
        }

        lines.append("")
        lines.append("Agent rules:")
        if status.agentRules.isEmpty {
            lines.append("- none configured")
        } else {
            for rule in status.agentRules {
                lines.append("- \(rule.name): \(rule.isInstalled ? "installed" : "missing")")
            }
        }

        appendMissingReferenceGuidance(status.missingReferences, to: &lines)
        appendUnverifiedReferenceGuidance(status.unverifiedReferences, to: &lines)

        lines.append("")
        lines.append("Actions:")
        lines.append("- Run securely: authsia workspace run -- <command>")
        lines.append("- End current terminal session: authsia lock")
        lines.append("- Revoke all access: Access Center or menu bar")
        return lines.joined(separator: "\n")
    }

    static func appendMissingReferenceGuidance(
        _ missingReferences: [WorkspaceMissingReference],
        to lines: inout [String]
    ) {
        guard !missingReferences.isEmpty else { return }
        lines.append("")
        lines.append("Missing Authsia references:")
        for reference in missingReferences {
            lines.append("- \(reference.displayLine)")
        }
        lines.append("")
        lines.append("What to do:")
        let fileReferences = missingReferences.filter { $0.envBindingName == nil }
        let files = Set(fileReferences.map(\.relativePath)).sorted()
        for file in files {
            lines.append(
                "- If you still have the original value, replace the URI in \(file) with the raw value, " +
                "then run `authsia workspace update --env-file \(file)`."
            )
        }
        let bindingNames = Set(missingReferences.compactMap(\.envBindingName)).sorted()
        if !bindingNames.isEmpty {
            let updateCommands = bindingNames
                .map { "`authsia workspace env add \($0) <authsia://...>`" }
                .joined(separator: ", ")
            lines.append(
                "- For workspace env bindings, add the missing item in Authsia, update with \(updateCommands), " +
                "or remove with `authsia workspace env remove <NAME>`."
            )
        }
        lines.append("- Or add the missing item in Authsia with the same type, name, and folder.")
        if !fileReferences.isEmpty {
            lines.append("- Or edit the env file to point at an existing Authsia item.")
        }
    }

    static func appendUnverifiedReferenceGuidance(
        _ unverifiedReferences: [WorkspaceMissingReference],
        to lines: inout [String]
    ) {
        guard !unverifiedReferences.isEmpty else { return }
        lines.append("")
        lines.append("Unverified Authsia references:")
        for reference in unverifiedReferences {
            lines.append("- \(reference.displayLine)")
        }
        lines.append("")
        lines.append("What to do:")
        let listCommands = scopedListCommands(for: unverifiedReferences)
        if listCommands.isEmpty {
            lines.append("- Open Authsia, then rerun this command to validate these references.")
        } else if listCommands.count == 1 {
            lines.append(
                "- Open Authsia or run `\(listCommands[0])`, then rerun this command to validate these references."
            )
        } else {
            lines.append(
                "- Open Authsia or run \(listCommands.map { "`\($0)`" }.joined(separator: ", "))," +
                    " then rerun this command to validate these references."
            )
        }
        lines.append(
            "- If Authsia reports it cannot read the Keychain, open Authsia once and grant Keychain access, " +
                "or ask your administrator to allow team identifier 33M8QU65SP under managed keychain access."
        )
        let hasEnvFileReference = unverifiedReferences.contains { $0.envBindingName == nil }
        let hasEnvBindingReference = unverifiedReferences.contains { $0.envBindingName != nil }
        if hasEnvFileReference {
            lines.append(
                "- If an item is missing, restore the raw value and run `authsia workspace update --env-file <path>`, " +
                "add the missing item, or point the env file at an existing item."
            )
        }
        if hasEnvBindingReference {
            lines.append(
                "- If a workspace env binding item is missing, add it in Authsia, update the binding with " +
                "`authsia workspace env add <NAME> <authsia://...>`, or remove it with " +
                "`authsia workspace env remove <NAME>`."
            )
        }
    }

    private static func scopedListCommands(for references: [WorkspaceMissingReference]) -> [String] {
        Set(references.compactMap { reference in
            switch reference.itemType {
            case "api-key":
                return "authsia list api-keys"
            case "password":
                return "authsia list passwords"
            case "note":
                return "authsia list notes"
            case "certificate":
                return "authsia list certs"
            case "ssh":
                return "authsia list ssh"
            default:
                return nil
            }
        }).sorted()
    }

    private static func isAgentRuleInstalled(
        name: String,
        workspaceRoot root: URL,
        fileManager: FileManager
    ) -> Bool {
        guard let tool = AgentTool(argument: name) else { return false }
        return AgentRuleInstaller.isInstalled(projectRoot: root, agent: tool, fileManager: fileManager)
    }
}

private func workspaceReference(relativePath: String, reference: AuthsiaReference) -> WorkspaceMissingReference {
    WorkspaceMissingReference(
        relativePath: relativePath,
        itemType: reference.itemType.rawValue,
        item: reference.query,
        folderPath: reference.folderPath
    )
}

private func workspaceReference(envBindingName: String, reference: AuthsiaReference) -> WorkspaceMissingReference {
    WorkspaceMissingReference(
        relativePath: WorkspaceConfigStore.relativeConfigPath,
        itemType: reference.itemType.rawValue,
        item: reference.query,
        folderPath: reference.folderPath,
        envBindingName: envBindingName
    )
}

private func authsiaReference(for binding: WorkspaceConfig.EnvBinding) -> AuthsiaReference? {
    guard let reference = try? SecretReference.parse(binding.reference) else { return nil }
    let itemType: AuthsiaReference.ItemType
    switch reference.type {
    case .password:
        itemType = .password
    case .apiKey:
        itemType = .apiKey
    case .cert:
        itemType = .certificate
    case .note:
        itemType = .note
    case .ssh:
        itemType = .ssh
    case .otp:
        return nil
    }
    return AuthsiaReference(itemType: itemType, query: reference.item, folderPath: normalizeFolderPath(reference.folder))
}

func isWorkspaceMigratableSecret(_ secret: DetectedSecret) -> Bool {
    secret.type == .password || secret.type.storesAsAPIKey
}

private func sortedReferences(_ references: Set<WorkspaceMissingReference>) -> [WorkspaceMissingReference] {
    references.sorted {
        if $0.relativePath != $1.relativePath { return $0.relativePath < $1.relativePath }
        if $0.itemType != $1.itemType { return $0.itemType < $1.itemType }
        return $0.item < $1.item
    }
}

struct WorkspaceVaultIndex {
    private struct Key: Hashable {
        let itemType: AuthsiaReference.ItemType
        let query: String
        let folderPath: String?
    }

    private let keys: Set<Key>
    private let unscopedKeys: Set<Key>
    private let environmentTiersByKey: [Key: [[String]]]
    let payload: BridgeListPayload

    init(payload: BridgeListPayload) {
        self.payload = payload
        var scoped = Set<Key>()
        var unscoped = Set<Key>()
        var environmentMap: [Key: [[String]]] = [:]

        func insert(itemType: AuthsiaReference.ItemType, id: UUID, name: String, folderPath: String?, environments: [String]) {
            let normalizedFolder = normalizeFolderPath(folderPath)
            for query in [id.uuidString, name] {
                let scopedKey = Key(itemType: itemType, query: query, folderPath: normalizedFolder)
                scoped.insert(scopedKey)
                unscoped.insert(Key(itemType: itemType, query: query, folderPath: nil))
                environmentMap[scopedKey, default: []].append(VaultEnvironmentTags.normalize(environments))
            }
        }

        for item in payload.passwords where item.hasSecret != false {
            insert(itemType: .password, id: item.id, name: item.name, folderPath: item.folderPath, environments: item.environments)
        }
        for item in payload.apiKeys where item.hasSecret != false {
            insert(itemType: .apiKey, id: item.id, name: item.name, folderPath: item.folderPath, environments: item.environments)
        }
        for item in payload.certificates {
            insert(itemType: .certificate, id: item.id, name: item.name, folderPath: item.folderPath, environments: item.environments)
        }
        for item in payload.notes {
            insert(itemType: .note, id: item.id, name: item.title, folderPath: item.folderPath, environments: item.environments)
        }
        for item in payload.sshKeys {
            insert(itemType: .ssh, id: item.id, name: item.name, folderPath: item.folderPath, environments: item.environments)
        }

        self.keys = scoped
        self.unscopedKeys = unscoped
        self.environmentTiersByKey = environmentMap
    }

    func contains(_ reference: AuthsiaReference) -> Bool {
        let folderPath = normalizeFolderPath(reference.folderPath)
        let key = Key(itemType: reference.itemType, query: reference.query, folderPath: folderPath)
        if folderPath != nil {
            return keys.contains(key)
        }
        return unscopedKeys.contains(key)
    }

    func existingItem(
        for secret: DetectedSecret,
        folderPath: String?,
        environments: [String] = []
    ) -> WorkspaceSecretConflict? {
        let itemType = itemType(for: secret)
        let normalizedFolder = normalizeFolderPath(folderPath)
        let key = Key(itemType: itemType, query: secret.authsiaKey, folderPath: normalizedFolder)
        guard keys.contains(key),
              let matchingTier = environmentTiersByKey[key]?.first(where: {
                  WorkspaceSetupExchange.environmentTiersOverlap(environments, $0)
              }) else { return nil }
        return WorkspaceSecretConflict(
            itemType: itemType.rawValue,
            item: secret.authsiaKey,
            folderPath: normalizedFolder,
            environments: matchingTier
        )
    }

    private func itemType(for secret: DetectedSecret) -> AuthsiaReference.ItemType {
        switch secret.type {
        case .apiKey, .token, .secret, .accessKey:
            return .apiKey
        case .certificate:
            if secret.resolvedCertificateContent != nil {
                return .certificate
            }
            if secret.rawContent != nil {
                return .note
            }
            return .password
        default:
            return .password
        }
    }
}

extension AgentTool {
    var configName: String {
        switch self {
        case .claudeCode: return "claude-code"
        case .cursor: return "cursor"
        case .codex: return "codex"
        case .windsurf: return "windsurf"
        case .copilot: return "copilot"
        }
    }
}
