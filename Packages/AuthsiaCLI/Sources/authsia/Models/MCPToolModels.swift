import Foundation

enum AuthsiaMCPToolName: String, CaseIterable, Codable, Sendable {
    case status = "authsia_status"
    case workspaceInspect = "authsia_workspace_inspect"
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

struct MCPWorkspaceInspectInput: Codable, Equatable, Sendable, MCPClosedToolInput {
    static let allowedKeys: Set<String> = ["environment"]
    let environment: String?

    init(environment: String? = nil) {
        self.environment = environment
    }
}

struct MCPExecInput: Codable, Equatable, Sendable, MCPClosedToolInput {
    static let allowedKeys: Set<String> = [
        "argv", "environment", "defaultOnly", "envFiles", "timeoutSeconds",
    ]

    let argv: [String]
    let environment: String?
    let defaultOnly: Bool
    let envFiles: [String]
    let timeoutSeconds: Int

    init(
        argv: [String],
        environment: String? = nil,
        defaultOnly: Bool = false,
        envFiles: [String] = [],
        timeoutSeconds: Int = 900
    ) {
        self.argv = argv
        self.environment = environment
        self.defaultOnly = defaultOnly
        self.envFiles = envFiles
        self.timeoutSeconds = timeoutSeconds
    }

    private enum CodingKeys: String, CodingKey {
        case argv
        case environment
        case defaultOnly
        case envFiles
        case timeoutSeconds
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            argv: try container.decode([String].self, forKey: .argv),
            environment: try container.decodeIfPresent(String.self, forKey: .environment),
            defaultOnly: try container.decodeIfPresent(Bool.self, forKey: .defaultOnly) ?? false,
            envFiles: try container.decodeIfPresent([String].self, forKey: .envFiles) ?? [],
            timeoutSeconds: try container.decodeIfPresent(Int.self, forKey: .timeoutSeconds) ?? 900
        )
    }

    func validated() throws -> MCPExecInput {
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
        if argv.count >= 2,
           ["sh", "bash", "zsh", "fish", "dash", "/bin/sh", "/bin/bash", "/bin/zsh"]
            .contains(argv[0]),
           ["-c", "--command"].contains(argv[1]) {
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

enum MCPExecutionTermination: String, Codable, Equatable, Sendable {
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

enum MCPToolErrorCode: String, Codable, Sendable {
    case invalidInput
    case workspaceUnavailable
    case bridgeUnavailable
    case cliAccessDisabled
    case approvalDenied
    case grantUnavailable
    case grantNotOwned
    case busy
    case timedOut
    case cancelled
    case executionFailed
    case internalError
}

struct MCPToolErrorOutput: Codable, Equatable, Sendable {
    let code: MCPToolErrorCode
    let message: String
    let invocationID: String?
}
