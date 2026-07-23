import Foundation
import AuthenticatorBridge

struct WorkspaceConfig: Codable, Equatable {
    struct Workspace: Codable, Equatable {
        let name: String
        let authsiaFolder: String
    }

    struct Agents: Codable, Equatable {
        let rules: [String]
    }

    struct EnvBinding: Codable, Equatable {
        let name: String
        let reference: String

        init(name: String, reference: String) {
            self.name = name.trimmingCharacters(in: .whitespacesAndNewlines)
            self.reference = reference.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    struct GuardSettings: Codable, Equatable {
        let autoTabs: Bool
        let tools: [String]
        let responseMode: AgentLeakResponseMode

        init(
            autoTabs: Bool = true,
            tools: [String] = [],
            responseMode: AgentLeakResponseMode = .observe
        ) {
            self.autoTabs = autoTabs
            self.tools = Self.uniqueTools(tools)
            self.responseMode = responseMode
        }

        enum CodingKeys: String, CodingKey {
            case autoTabs
            case tools
            case responseMode
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            let autoTabs = try container.decodeIfPresent(Bool.self, forKey: .autoTabs) ?? true
            let tools = try container.decodeIfPresent([String].self, forKey: .tools) ?? []
            let responseMode = try container.decodeIfPresent(
                AgentLeakResponseMode.self,
                forKey: .responseMode
            ) ?? .observe
            self.init(autoTabs: autoTabs, tools: tools, responseMode: responseMode)
        }

        private static func uniqueTools(_ tools: [String]) -> [String] {
            var seen = Set<String>()
            return tools.compactMap { raw in
                let tool = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !tool.isEmpty, seen.insert(tool).inserted else { return nil }
                return tool
            }
        }
    }

    let schemaVersion: Int
    let workspace: Workspace
    let managedEnvFiles: [String]
    let agents: Agents?
    let guardSettings: GuardSettings
    let envBindings: [EnvBinding]

    init(
        schemaVersion: Int = 1,
        workspace: Workspace,
        managedEnvFiles: [String],
        agents: Agents?,
        guardSettings: GuardSettings = GuardSettings(),
        envBindings: [EnvBinding] = []
    ) {
        self.schemaVersion = schemaVersion
        self.workspace = workspace
        self.managedEnvFiles = managedEnvFiles
        self.agents = agents
        self.guardSettings = guardSettings
        self.envBindings = envBindings.sorted {
            if $0.name.caseInsensitiveCompare($1.name) == .orderedSame {
                return $0.reference < $1.reference
            }
            return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
    }

    enum CodingKeys: String, CodingKey {
        case schemaVersion
        case workspace
        case managedEnvFiles
        case agents
        case guardSettings = "guard"
        case envBindings
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        let workspace = try container.decode(Workspace.self, forKey: .workspace)
        let managedEnvFiles = try container.decode([String].self, forKey: .managedEnvFiles)
        let agents = try container.decodeIfPresent(Agents.self, forKey: .agents)
        let guardSettings = try container.decodeIfPresent(GuardSettings.self, forKey: .guardSettings) ??
            GuardSettings()
        let envBindings = try container.decodeIfPresent([EnvBinding].self, forKey: .envBindings) ?? []
        self.init(
            schemaVersion: schemaVersion,
            workspace: workspace,
            managedEnvFiles: managedEnvFiles,
            agents: agents,
            guardSettings: guardSettings,
            envBindings: envBindings
        )
    }
}

enum WorkspaceConfigError: LocalizedError, Equatable {
    case missingConfig
    case invalidConfigFile
    case unsupportedSchema(Int)
    case invalidRelativePath(String)
    case emptyWorkspaceName
    case emptyAuthsiaFolder
    case invalidEnvBindingName(String)
    case duplicateEnvBindingName(String)
    case invalidEnvBindingReference(String)

    private static let repairConfigGuidance = " Fix .authsia/workspace.json, restore it from version control, " +
        "or remove it and run `authsia workspace init` to recreate it."

    var errorDescription: String? {
        switch self {
        case .missingConfig:
            return "No Authsia workspace found in this folder or its parents. " +
                "Run `authsia workspace init` from the project root, or open Authsia > Workspace and click Setup " +
                "for this project. If you already set it up, cd to the folder that contains " +
                ".authsia/workspace.json and retry."
        case .invalidConfigFile:
            return "Authsia workspace config .authsia/workspace.json is invalid. Fix the JSON and required fields, " +
                "restore it from version control, or remove it and run `authsia workspace init` to recreate it."
        case .unsupportedSchema(let version):
            return """
            Unsupported Authsia workspace schema version \(version). This Authsia build supports schema version \
            \(WorkspaceConfigStore.currentSchemaVersion). Update Authsia to the latest version, then run: \
            authsia workspace update
            """
        case .invalidRelativePath(let path):
            return "Workspace paths must be relative and commit-safe: \(path)." + Self.repairConfigGuidance
        case .emptyWorkspaceName:
            return "Workspace name cannot be empty." + Self.repairConfigGuidance
        case .emptyAuthsiaFolder:
            return "Workspace Authsia folder cannot be empty." + Self.repairConfigGuidance
        case .invalidEnvBindingName(let name):
            return "Workspace env binding name must be a valid environment variable name: \(name)." +
                Self.repairConfigGuidance
        case .duplicateEnvBindingName(let name):
            return "Workspace env binding name is duplicated: \(name)." + Self.repairConfigGuidance
        case .invalidEnvBindingReference(let reference):
            return "Workspace env binding value must be an authsia:// reference: \(reference)." +
                Self.repairConfigGuidance
        }
    }
}

enum WorkspaceConfigStore {
    static let currentSchemaVersion = 2
    static let relativeConfigPath = ".authsia/workspace.json"

    static func read(fromWorkspaceRoot root: URL, fileManager: FileManager = .default) throws -> WorkspaceConfig {
        let url = root.appendingPathComponent(relativeConfigPath)
        guard fileManager.fileExists(atPath: url.path) else {
            throw WorkspaceConfigError.missingConfig
        }
        let data = try Data(contentsOf: url)
        let envelope: WorkspaceConfigSchemaEnvelope
        do {
            envelope = try JSONDecoder().decode(WorkspaceConfigSchemaEnvelope.self, from: data)
        } catch {
            throw WorkspaceConfigError.invalidConfigFile
        }
        guard envelope.schemaVersion <= currentSchemaVersion else {
            throw WorkspaceConfigError.unsupportedSchema(envelope.schemaVersion)
        }
        let config: WorkspaceConfig
        do {
            config = try JSONDecoder().decode(WorkspaceConfig.self, from: data)
        } catch {
            throw WorkspaceConfigError.invalidConfigFile
        }
        let normalized = normalize(config)
        try validate(normalized)
        return normalized
    }

    static func write(
        _ config: WorkspaceConfig,
        toWorkspaceRoot root: URL,
        fileManager: FileManager = .default
    ) throws {
        let normalized = normalize(config)
        try validate(normalized)
        let url = root.appendingPathComponent(relativeConfigPath)
        try fileManager.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(normalized)
        try data.write(to: url, options: .atomic)
    }

    static func migrateToCurrentSchema(_ config: WorkspaceConfig) throws -> WorkspaceConfig {
        switch config.schemaVersion {
        case 1, currentSchemaVersion:
            return config
        default:
            throw WorkspaceConfigError.unsupportedSchema(config.schemaVersion)
        }
    }

    static func migratedToV2(_ config: WorkspaceConfig) -> WorkspaceConfig {
        WorkspaceConfig(
            schemaVersion: 2,
            workspace: config.workspace,
            managedEnvFiles: config.managedEnvFiles,
            agents: config.agents,
            guardSettings: config.guardSettings,
            envBindings: config.envBindings
        )
    }

    static func normalize(_ config: WorkspaceConfig) -> WorkspaceConfig {
        WorkspaceConfig(
            schemaVersion: config.schemaVersion,
            workspace: WorkspaceConfig.Workspace(
                name: config.workspace.name,
                authsiaFolder: WorkspaceFolderPath.normalize(
                    config.workspace.authsiaFolder,
                    defaultName: config.workspace.name
                )
            ),
            managedEnvFiles: config.managedEnvFiles,
            agents: config.agents,
            guardSettings: config.guardSettings,
            envBindings: config.envBindings
        )
    }

    static func remove(fromWorkspaceRoot root: URL, fileManager: FileManager = .default) throws -> Bool {
        let url = root.appendingPathComponent(relativeConfigPath)
        guard fileManager.fileExists(atPath: url.path) else { return false }
        try fileManager.removeItem(at: url)
        return true
    }

    private static func validate(_ config: WorkspaceConfig) throws {
        guard config.schemaVersion == 1 || config.schemaVersion == currentSchemaVersion else {
            throw WorkspaceConfigError.unsupportedSchema(config.schemaVersion)
        }
        guard !config.workspace.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw WorkspaceConfigError.emptyWorkspaceName
        }
        guard !config.workspace.authsiaFolder.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw WorkspaceConfigError.emptyAuthsiaFolder
        }
        for path in config.managedEnvFiles {
            guard isCommitSafeRelativePath(path) else {
                throw WorkspaceConfigError.invalidRelativePath(path)
            }
        }
        var envNames = Set<String>()
        for binding in config.envBindings {
            guard isValidEnvironmentName(binding.name) else {
                throw WorkspaceConfigError.invalidEnvBindingName(binding.name)
            }
            guard config.schemaVersion >= 2 || envNames.insert(binding.name).inserted else {
                throw WorkspaceConfigError.duplicateEnvBindingName(binding.name)
            }
            guard SecretReference.isSecretReference(binding.reference),
                  (try? SecretReference.parse(binding.reference)) != nil else {
                throw WorkspaceConfigError.invalidEnvBindingReference(binding.reference)
            }
        }
    }

    static func isCommitSafeRelativePath(_ path: String) -> Bool {
        guard !path.isEmpty,
              !path.hasPrefix("/"),
              !path.contains("\0") else {
            return false
        }
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !components.contains(where: { $0 == ".." || $0.isEmpty }) else {
            return false
        }
        return true
    }

    static func isValidEnvironmentName(_ name: String) -> Bool {
        guard let first = name.unicodeScalars.first,
              first == "_" || CharacterSet.letters.contains(first) else {
            return false
        }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "_"))
        return name.unicodeScalars.allSatisfy { allowed.contains($0) }
    }
}

private struct WorkspaceConfigSchemaEnvelope: Decodable {
    let schemaVersion: Int
}
