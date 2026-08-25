import Foundation

enum AuthsiaMCPToolName: String, CaseIterable, Codable, Sendable {
    case status = "authsia_status"
    case workspaceInspect = "authsia_workspace_inspect"
    case list = "authsia_list"
    case accessStatus = "authsia_access_status"
    case exec = "authsia_exec"
    case accessRevoke = "authsia_access_revoke"
}

enum MCPToolInputError: LocalizedError, Equatable {
    case invalidJSON
    case unknownFields([String])
    case invalidArgument(String)

    var errorDescription: String? {
        switch self {
        case .invalidJSON:
            return "Tool input must be a JSON object."
        case .unknownFields(let fields):
            return "Unknown tool input fields: \(fields.joined(separator: ", "))."
        case .invalidArgument(let message):
            return message
        }
    }
}

protocol MCPClosedToolInput: Decodable {
    static var allowedKeys: Set<String> { get }
}

enum MCPToolInputDecoder {
    static func decode<T: MCPClosedToolInput>(_ type: T.Type, from data: Data) throws -> T {
        guard let object = try? JSONSerialization.jsonObject(with: data),
              let dictionary = object as? [String: Any] else {
            throw MCPToolInputError.invalidJSON
        }
        let unknown = Set(dictionary.keys).subtracting(T.allowedKeys).sorted()
        guard unknown.isEmpty else {
            throw MCPToolInputError.unknownFields(unknown)
        }
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw MCPToolInputError.invalidArgument("Tool input does not match the required schema.")
        }
    }
}

struct MCPEmptyInput: Codable, Equatable, Sendable, MCPClosedToolInput {
    static let allowedKeys: Set<String> = []
}

struct MCPStatusInput: Codable, Equatable, Sendable, MCPClosedToolInput {
    static let allowedKeys: Set<String> = ["workspaceRoot"]
    let workspaceRoot: String?

    init(workspaceRoot: String? = nil) {
        self.workspaceRoot = workspaceRoot
    }

    func validated() throws -> MCPStatusInput {
        try validateWorkspaceRoot(workspaceRoot)
        return self
    }
}

struct MCPWorkspaceInspectInput: Codable, Equatable, Sendable, MCPClosedToolInput {
    static let allowedKeys: Set<String> = ["environment", "workspaceRoot"]
    let environment: String?
    let workspaceRoot: String?

    init(environment: String? = nil, workspaceRoot: String? = nil) {
        self.environment = environment
        self.workspaceRoot = workspaceRoot
    }

    func validated() throws -> MCPWorkspaceInspectInput {
        try validateWorkspaceRoot(workspaceRoot)
        return self
    }
}

enum MCPListItemType: String, CaseIterable, Codable, Equatable, Sendable {
    case password
    case apiKey = "api-key"
    case certificate
    case note
    case ssh

    var preflightType: String {
        switch self {
        case .certificate: "cert"
        default: rawValue
        }
    }
}

struct MCPListInput: Codable, Equatable, Sendable, MCPClosedToolInput {
    static let allowedKeys: Set<String> = [
        "type", "folder", "environment", "workspaceRoot", "limit", "offset",
    ]

    let type: MCPListItemType
    let folder: String?
    let environment: String?
    let workspaceRoot: String?
    let limit: Int
    let offset: Int

    init(
        type: MCPListItemType,
        folder: String? = nil,
        environment: String? = nil,
        workspaceRoot: String? = nil,
        limit: Int = 50,
        offset: Int = 0
    ) {
        self.type = type
        self.folder = folder
        self.environment = environment
        self.workspaceRoot = workspaceRoot
        self.limit = limit
        self.offset = offset
    }

    private enum CodingKeys: String, CodingKey {
        case type
        case folder
        case environment
        case workspaceRoot
        case limit
        case offset
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            type: try container.decode(MCPListItemType.self, forKey: .type),
            folder: try container.decodeIfPresent(String.self, forKey: .folder),
            environment: try container.decodeIfPresent(String.self, forKey: .environment),
            workspaceRoot: try container.decodeIfPresent(String.self, forKey: .workspaceRoot),
            limit: try container.decodeIfPresent(Int.self, forKey: .limit) ?? 50,
            offset: try container.decodeIfPresent(Int.self, forKey: .offset) ?? 0
        )
    }

    func validated() throws -> MCPListInput {
        try validateWorkspaceRoot(workspaceRoot)
        if let folder {
            let trimmed = folder.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty,
                  trimmed.utf8.count <= 512,
                  folder.unicodeScalars.allSatisfy({
                      !CharacterSet.controlCharacters.contains($0)
                  }) else {
                throw MCPToolInputError.invalidArgument(
                    "folder must be a safe path within the configured Authsia workspace folder."
                )
            }
        }
        if let environment {
            let trimmed = environment.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty,
                  trimmed.utf8.count <= 128,
                  environment.unicodeScalars.allSatisfy({
                      !CharacterSet.controlCharacters.contains($0)
                  }) else {
                throw MCPToolInputError.invalidArgument(
                    "environment must be a safe workspace environment name."
                )
            }
        }
        guard (1...100).contains(limit) else {
            throw MCPToolInputError.invalidArgument("limit must be between 1 and 100.")
        }
        guard (0...100_000).contains(offset) else {
            throw MCPToolInputError.invalidArgument("offset must be between 0 and 100000.")
        }
        return self
    }
}

struct MCPExecInput: Codable, Equatable, Sendable, MCPClosedToolInput {
    static let allowedKeys: Set<String> = [
        "argv", "environment", "defaultOnly", "envFiles", "timeoutSeconds", "workspaceRoot",
    ]

    let argv: [String]
    let environment: String?
    let defaultOnly: Bool
    let envFiles: [String]
    let timeoutSeconds: Int
    let workspaceRoot: String?

    init(
        argv: [String],
        environment: String? = nil,
        defaultOnly: Bool = false,
        envFiles: [String] = [],
        timeoutSeconds: Int = 900,
        workspaceRoot: String? = nil
    ) {
        self.argv = argv
        self.environment = environment
        self.defaultOnly = defaultOnly
        self.envFiles = envFiles
        self.timeoutSeconds = timeoutSeconds
        self.workspaceRoot = workspaceRoot
    }

    private enum CodingKeys: String, CodingKey {
        case argv
        case environment
        case defaultOnly
        case envFiles
        case timeoutSeconds
        case workspaceRoot
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            argv: try container.decode([String].self, forKey: .argv),
            environment: try container.decodeIfPresent(String.self, forKey: .environment),
            defaultOnly: try container.decodeIfPresent(Bool.self, forKey: .defaultOnly) ?? false,
            envFiles: try container.decodeIfPresent([String].self, forKey: .envFiles) ?? [],
            timeoutSeconds: try container.decodeIfPresent(Int.self, forKey: .timeoutSeconds) ?? 900,
            workspaceRoot: try container.decodeIfPresent(String.self, forKey: .workspaceRoot)
        )
    }

    func validated() throws -> MCPExecInput {
        try validateWorkspaceRoot(workspaceRoot)
        guard !argv.isEmpty else {
            throw MCPToolInputError.invalidArgument("argv must contain an executable.")
        }
        guard argv.count <= 64 else {
            throw MCPToolInputError.invalidArgument("argv may contain at most 64 elements.")
        }
        guard argv.first?.isEmpty == false else {
            throw MCPToolInputError.invalidArgument("argv executable must not be empty.")
        }
        guard argv.reduce(0, { $0 + $1.utf8.count }) <= 32 * 1_024 else {
            throw MCPToolInputError.invalidArgument("argv exceeds the 32 KiB limit.")
        }
        guard argv.allSatisfy({ argument in
            argument.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
        }) else {
            throw MCPToolInputError.invalidArgument("argv must not contain control characters.")
        }
        if Self.containsShellCommandString(argv) {
            throw MCPToolInputError.invalidArgument("Shell command strings are not supported; pass argv directly.")
        }
        guard (1...1_800).contains(timeoutSeconds) else {
            throw MCPToolInputError.invalidArgument("timeoutSeconds must be between 1 and 1800.")
        }
        guard !(defaultOnly && environment != nil) else {
            throw MCPToolInputError.invalidArgument("environment and defaultOnly cannot be combined.")
        }
        if let environment {
            let trimmed = environment.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty,
                  trimmed.count <= 128,
                  environment.unicodeScalars.allSatisfy({
                      !CharacterSet.controlCharacters.contains($0)
                  }) else {
                throw MCPToolInputError.invalidArgument("environment must be a safe workspace environment name.")
            }
        }
        guard envFiles.count <= 16 else {
            throw MCPToolInputError.invalidArgument("envFiles may contain at most 16 paths.")
        }
        guard envFiles.allSatisfy(WorkspaceConfigStore.isCommitSafeRelativePath) else {
            throw MCPToolInputError.invalidArgument("envFiles must be commit-safe relative workspace paths.")
        }
        return self
    }

    private static func containsShellCommandString(_ argv: [String]) -> Bool {
        let executable = URL(fileURLWithPath: argv[0]).lastPathComponent.lowercased()
        if shellExecutableNames.contains(executable) {
            return containsCommandStringOption(argv.dropFirst())
        }
        guard executable == "env" else { return false }
        if argv.dropFirst().contains(where: {
            $0 == "-S" || $0 == "--split-string" || $0.hasPrefix("--split-string=")
        }) {
            return true
        }
        guard let shellIndex = argv.indices.dropFirst().first(where: {
            shellExecutableNames.contains(
                URL(fileURLWithPath: argv[$0]).lastPathComponent.lowercased()
            )
        }) else {
            return false
        }
        return containsCommandStringOption(argv[argv.index(after: shellIndex)...])
    }

    private static func containsCommandStringOption<S: Sequence>(_ arguments: S) -> Bool
    where S.Element == String {
        for argument in arguments {
            if argument == "--" { return false }
            if argument == "-c" || argument == "--command" { return true }
            if argument.hasPrefix("-"),
               !argument.hasPrefix("--"),
               argument.dropFirst().contains("c") {
                return true
            }
        }
        return false
    }

    private static let shellExecutableNames: Set<String> = [
        "ash", "bash", "csh", "dash", "fish", "ksh", "mksh", "sh", "tcsh", "zsh",
    ]
}

private func validateWorkspaceRoot(_ workspaceRoot: String?) throws {
    guard let workspaceRoot else { return }
    guard workspaceRoot.hasPrefix("/"),
          !workspaceRoot.isEmpty,
          workspaceRoot.utf8.count <= 4_096,
          workspaceRoot.unicodeScalars.allSatisfy({
              !CharacterSet.controlCharacters.contains($0)
          }) else {
        throw MCPToolInputError.invalidArgument(
            "workspaceRoot must be a safe absolute local filesystem path."
        )
    }
}

struct MCPAccessRevokeInput: Codable, Equatable, Sendable, MCPClosedToolInput {
    static let allowedKeys: Set<String> = ["grantID"]
    let grantID: String
}

struct MCPDiagnostic: Codable, Equatable, Sendable {
    let code: String
    let message: String
}

struct MCPStatusOutput: Codable, Equatable, Sendable {
    let serverInstanceID: String
    let protocolRevision: String
    let workspaceName: String
    let workspaceRoot: String
    let bridgeState: String
    let ready: Bool
    let diagnostics: [MCPDiagnostic]
}

struct MCPWorkspaceReference: Codable, Equatable, Hashable, Sendable {
    let uri: String
    let environmentVariable: String?
    let sourcePath: String
    let selectedEnvironment: Bool
}

struct MCPWorkspaceInspectOutput: Codable, Equatable, Sendable {
    let workspaceName: String
    let workspaceRoot: String
    let schemaVersion: Int
    let selectedEnvironment: String?
    let availableEnvironments: [String]
    let managedFiles: [String]
    let references: [MCPWorkspaceReference]
    let referencesTruncated: Bool
    let diagnostics: [MCPDiagnostic]
}

struct MCPListItem: Codable, Equatable, Sendable {
    let id: String
    let name: String
    let folderPath: String?
    let isFavorite: Bool
    let isCliEnabled: Bool
    let environments: [String]
}

struct MCPListOutput: Codable, Equatable, Sendable {
    let invocationID: String
    let type: MCPListItemType
    let folder: String
    let environment: String?
    let items: [MCPListItem]
    let totalCount: Int
    let count: Int
    let offset: Int
    let hasMore: Bool
    let nextOffset: Int?
}

struct MCPGrantSummary: Codable, Equatable, Sendable {
    let grantID: String
    let status: String
    let sourceLabel: String
    let scopeSummary: String
    let itemCount: Int
    let capabilities: [String]
    let environment: String?
    let createdAt: Date
    let expiresAt: Date
    let lastUsedAt: Date?
    let revokedAt: Date?
    let approvedBy: String
    let serverInstanceID: String
    let invocationID: String?
}

struct MCPAccessStatusOutput: Codable, Equatable, Sendable {
    let grants: [MCPGrantSummary]
}

enum MCPExecutionTermination: String, CaseIterable, Codable, Equatable, Sendable {
    case exited
    case signalled
    case timedOut
    case cancelled
    case launchFailed
}

struct MCPExecOutput: Codable, Equatable, Sendable {
    let invocationID: String
    let termination: MCPExecutionTermination
    let exitCode: Int32?
    let stdout: String
    let stderr: String
    let stdoutTruncated: Bool
    let stderrTruncated: Bool
    let durationMilliseconds: Int
}

struct MCPAccessRevokeOutput: Codable, Equatable, Sendable {
    let grantID: String
    let status: String
    let revokedAt: Date?
}

enum MCPToolErrorCode: String, CaseIterable, Codable, Equatable, Sendable {
    case invalidInput
    case workspaceUnavailable
    case bridgeUnavailable
    case mcpAccessDisabled
    case cliAccessDisabled
    case approvalDenied
    case grantUnavailable
    case grantNotOwned
    case busy
    case timedOut
    case cancelled
    case executionFailed
    case internalError
    case upstreamDenied
    case upstreamUnavailable
    case httpUpstreamUnsupported
}

struct MCPToolErrorOutput: Codable, Equatable, Sendable {
    let code: MCPToolErrorCode
    let message: String
    let invocationID: String?
}
