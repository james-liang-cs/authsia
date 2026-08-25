import Foundation
import AuthenticatorBridge

enum MCPUpstreamTransport: String, Codable, Equatable, Sendable {
    case stdio
    case http
    case sse
    case streamableHTTP = "streamable-http"
}

struct MCPUpstreamToolPolicy: Codable, Equatable, Sendable {
    var allow: [String]
    var approve: [String]
    var deny: [String]

    init(allow: [String] = [], approve: [String] = [], deny: [String] = []) {
        self.allow = allow
        self.approve = approve
        self.deny = deny
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        allow = try container.decodeIfPresent([String].self, forKey: .allow) ?? []
        approve = try container.decodeIfPresent([String].self, forKey: .approve) ?? []
        deny = try container.decodeIfPresent([String].self, forKey: .deny) ?? []
    }
}

indirect enum MCPJSONValue: Codable, Equatable, Sendable {
    case object([String: MCPJSONValue])
    case array([MCPJSONValue])
    case string(String)
    case number(Double)
    case bool(Bool)
    case null

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int64.self) {
            self = .number(Double(value))
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([MCPJSONValue].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: MCPJSONValue].self) {
            self = .object(value)
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Unsupported JSON value"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .object(let value):
            try container.encode(value)
        case .array(let value):
            try container.encode(value)
        case .string(let value):
            try container.encode(value)
        case .number(let value):
            if value.rounded() == value,
               let integer = Int64(exactly: value) {
                try container.encode(integer)
            } else {
                try container.encode(value)
            }
        case .bool(let value):
            try container.encode(value)
        case .null:
            try container.encodeNil()
        }
    }
}

struct MCPUpstreamToolDescriptor: Codable, Equatable, Sendable {
    var name: String
    var description: String
    var inputSchema: MCPJSONValue

    init(
        name: String,
        description: String = "",
        inputSchema: MCPJSONValue = .object([
            "additionalProperties": .bool(true),
            "type": .string("object"),
        ])
    ) {
        self.name = name
        self.description = description
        self.inputSchema = inputSchema
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        description = try container.decodeIfPresent(String.self, forKey: .description) ?? ""
        inputSchema = try container.decodeIfPresent(MCPJSONValue.self, forKey: .inputSchema)
            ?? .object([
                "additionalProperties": .bool(true),
                "type": .string("object"),
            ])
    }
}

struct MCPUpstreamConfig: Codable, Equatable, Sendable {
    var name: String
    var transport: MCPUpstreamTransport
    var url: String?
    var command: String?
    var args: [String]
    var env: [String: String]
    var tools: MCPUpstreamToolPolicy
    var catalog: [MCPUpstreamToolDescriptor]

    init(
        name: String,
        transport: MCPUpstreamTransport = .stdio,
        url: String? = nil,
        command: String? = nil,
        args: [String] = [],
        env: [String: String] = [:],
        tools: MCPUpstreamToolPolicy = MCPUpstreamToolPolicy(),
        catalog: [MCPUpstreamToolDescriptor] = []
    ) {
        self.name = name
        self.transport = transport
        self.url = url
        self.command = command
        self.args = args
        self.env = env
        self.tools = tools
        self.catalog = catalog
    }

    var requiresStdioPolicy: Bool {
        transport == .stdio && url == nil
    }

    enum CodingKeys: String, CodingKey {
        case name
        case transport
        case url
        case command
        case args
        case env
        case tools
        case catalog
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        transport = try container.decodeIfPresent(MCPUpstreamTransport.self, forKey: .transport) ?? .stdio
        url = try container.decodeIfPresent(String.self, forKey: .url)
        command = try container.decodeIfPresent(String.self, forKey: .command)
        args = try container.decodeIfPresent([String].self, forKey: .args) ?? []
        env = try container.decodeIfPresent([String: String].self, forKey: .env) ?? [:]
        tools = try container.decodeIfPresent(MCPUpstreamToolPolicy.self, forKey: .tools)
            ?? MCPUpstreamToolPolicy()
        catalog = try container.decodeIfPresent([MCPUpstreamToolDescriptor].self, forKey: .catalog) ?? []
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(name, forKey: .name)
        try container.encode(transport, forKey: .transport)
        try container.encodeIfPresent(url, forKey: .url)
        try container.encodeIfPresent(command, forKey: .command)
        if !args.isEmpty {
            try container.encode(args, forKey: .args)
        }
        if !env.isEmpty {
            try container.encode(env, forKey: .env)
        }
        if !tools.allow.isEmpty || !tools.approve.isEmpty || !tools.deny.isEmpty {
            try container.encode(tools, forKey: .tools)
        }
        if !catalog.isEmpty {
            try container.encode(catalog, forKey: .catalog)
        }
    }
}

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
    let mcpUpstreams: [MCPUpstreamConfig]

    init(
        schemaVersion: Int = 1,
        workspace: Workspace,
        managedEnvFiles: [String],
        agents: Agents?,
        guardSettings: GuardSettings = GuardSettings(),
        envBindings: [EnvBinding] = [],
        mcpUpstreams: [MCPUpstreamConfig] = []
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
        self.mcpUpstreams = mcpUpstreams
    }

    enum CodingKeys: String, CodingKey {
        case schemaVersion
        case workspace
        case managedEnvFiles
        case agents
        case guardSettings = "guard"
        case envBindings
        case mcpUpstreams
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
        let mcpUpstreams = try container.decodeIfPresent([MCPUpstreamConfig].self, forKey: .mcpUpstreams) ?? []
        self.init(
            schemaVersion: schemaVersion,
            workspace: workspace,
            managedEnvFiles: managedEnvFiles,
            agents: agents,
            guardSettings: guardSettings,
            envBindings: envBindings,
            mcpUpstreams: mcpUpstreams
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
    case invalidMCPUpstreamName(String)
    case duplicateMCPUpstreamName(String)
    case missingMCPUpstreamCommand(String)
    case invalidMCPUpstreamCommand(String)
    case invalidMCPUpstreamArgs(String)
    case invalidMCPUpstreamEnv(String)
    case invalidMCPUpstreamTools(String)
    case invalidMCPUpstreamCatalog(String)

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
        case .invalidMCPUpstreamName(let name):
            return "Workspace MCP upstream name must match [A-Za-z][A-Za-z0-9_-]{0,31}: \(name)." +
                Self.repairConfigGuidance
        case .duplicateMCPUpstreamName(let name):
            return "Workspace MCP upstream name is duplicated: \(name)." + Self.repairConfigGuidance
        case .missingMCPUpstreamCommand(let name):
            return "Workspace MCP upstream \(name) requires a PATH basename or workspace-relative command." +
                Self.repairConfigGuidance
        case .invalidMCPUpstreamCommand(let command):
            return "Workspace MCP upstream command must be a PATH basename or commit-safe relative path, " +
                "without a shell: \(command)." + Self.repairConfigGuidance
        case .invalidMCPUpstreamArgs(let detail):
            return "Workspace MCP upstream args are invalid: \(detail)." + Self.repairConfigGuidance
        case .invalidMCPUpstreamEnv(let detail):
            return "Workspace MCP upstream env is invalid: \(detail)." + Self.repairConfigGuidance
        case .invalidMCPUpstreamTools(let detail):
            return "Workspace MCP upstream tools are invalid: \(detail)." + Self.repairConfigGuidance
        case .invalidMCPUpstreamCatalog(let detail):
            return "Workspace MCP upstream catalog is invalid: \(detail)." + Self.repairConfigGuidance
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
        try validateMCPUpstreamCatalogBounds(config.mcpUpstreams)
        let normalized = normalize(config)
        try validate(normalized)
        return normalized
    }

    static func write(
        _ config: WorkspaceConfig,
        toWorkspaceRoot root: URL,
        fileManager: FileManager = .default
    ) throws {
        try validateMCPUpstreamCatalogBounds(config.mcpUpstreams)
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
            envBindings: config.envBindings,
            mcpUpstreams: config.mcpUpstreams
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
            envBindings: config.envBindings,
            mcpUpstreams: config.mcpUpstreams.map(normalizeUpstream)
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
        var upstreamNames = Set<String>()
        for upstream in config.mcpUpstreams {
            guard isValidMCPUpstreamName(upstream.name) else {
                throw WorkspaceConfigError.invalidMCPUpstreamName(upstream.name)
            }
            guard upstreamNames.insert(upstream.name).inserted else {
                throw WorkspaceConfigError.duplicateMCPUpstreamName(upstream.name)
            }
            try validateMCPUpstream(upstream)
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

    private static let mcpUpstreamNamePattern = try! NSRegularExpression(
        pattern: "^[A-Za-z][A-Za-z0-9_-]{0,31}$"
    )
    private static let secretEnvNamePattern = try! NSRegularExpression(
        pattern: #"(?i)(TOKEN|SECRET|PASSWORD|PASSWD|PASS\b|AUTHORIZATION|BEARER|_KEY$)"#
    )
    private static let catalogJSONLimit = 64 * 1_024
    private static let maxArgCount = 64
    private static let maxArgBytes = 32 * 1_024
    private static let maxToolNameLength = 128
    private static let shellExecutableNames: Set<String> = [
        "ash", "bash", "csh", "dash", "fish", "ksh", "mksh", "sh", "tcsh", "zsh",
    ]

    private static func isValidMCPUpstreamName(_ name: String) -> Bool {
        let range = NSRange(name.startIndex..<name.endIndex, in: name)
        return mcpUpstreamNamePattern.firstMatch(in: name, options: [], range: range) != nil
    }

    private static func normalizeUpstream(_ upstream: MCPUpstreamConfig) -> MCPUpstreamConfig {
        let advertised = Set(upstream.tools.allow + upstream.tools.approve)
        return MCPUpstreamConfig(
            name: upstream.name,
            transport: upstream.transport,
            url: upstream.url,
            command: upstream.command,
            args: upstream.args,
            env: upstream.env,
            tools: upstream.tools,
            catalog: upstream.catalog.filter { advertised.contains($0.name) }
        )
    }

    private static func validateMCPUpstream(_ upstream: MCPUpstreamConfig) throws {
        if upstream.requiresStdioPolicy {
            let command = upstream.command?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !command.isEmpty else {
                throw WorkspaceConfigError.missingMCPUpstreamCommand(upstream.name)
            }
            try validateStdioCommand(command, args: upstream.args)
            try validateMCPUpstreamArgs(upstream.args)
            try validateMCPUpstreamTools(upstream.tools)
        }
        try validateMCPUpstreamEnv(upstream.env)
        try validateMCPUpstreamCatalog(upstream.catalog)
    }

    private static func validateStdioCommand(_ command: String, args: [String]) throws {
        if command.hasPrefix("/") {
            throw WorkspaceConfigError.invalidMCPUpstreamCommand(command)
        }
        if command.contains("/") {
            guard isCommitSafeRelativePath(command) else {
                throw WorkspaceConfigError.invalidMCPUpstreamCommand(command)
            }
        } else if command.contains("\0")
            || command == "."
            || command == ".."
            || !command.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) {
            throw WorkspaceConfigError.invalidMCPUpstreamCommand(command)
        }
        if containsShellCommandString([command] + args) {
            throw WorkspaceConfigError.invalidMCPUpstreamCommand(command)
        }
    }

    private static func validateMCPUpstreamArgs(_ args: [String]) throws {
        guard args.count <= maxArgCount else {
            throw WorkspaceConfigError.invalidMCPUpstreamArgs("at most \(maxArgCount) entries")
        }
        for argument in args {
            guard argument.utf8.count <= maxArgBytes else {
                throw WorkspaceConfigError.invalidMCPUpstreamArgs("each entry must be at most 32 KiB")
            }
            guard argument.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
                throw WorkspaceConfigError.invalidMCPUpstreamArgs("must not contain control characters")
            }
            guard !argument.lowercased().contains("authsia://") else {
                throw WorkspaceConfigError.invalidMCPUpstreamArgs("authsia:// references belong in env")
            }
        }
    }

    private static func validateMCPUpstreamEnv(_ env: [String: String]) throws {
        for (name, value) in env {
            guard isValidEnvironmentName(name),
                  value.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
                throw WorkspaceConfigError.invalidMCPUpstreamEnv(name)
            }
            if SecretReference.isSecretReference(value) {
                guard let reference = try? SecretReference.parse(value),
                      reference.type != .otp,
                      reference.type != .ssh else {
                    throw WorkspaceConfigError.invalidMCPUpstreamEnv(name)
                }
                continue
            }
            if envNameRequiresSecretReference(name) {
                throw WorkspaceConfigError.invalidMCPUpstreamEnv(name)
            }
        }
    }

    private static func envNameRequiresSecretReference(_ name: String) -> Bool {
        let range = NSRange(name.startIndex..<name.endIndex, in: name)
        return secretEnvNamePattern.firstMatch(in: name, options: [], range: range) != nil
    }

    private static func validateMCPUpstreamTools(_ tools: MCPUpstreamToolPolicy) throws {
        var seen = Set<String>()
        for name in tools.allow + tools.approve + tools.deny {
            guard !name.isEmpty,
                  name.count <= maxToolNameLength,
                  name.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
                throw WorkspaceConfigError.invalidMCPUpstreamTools(name)
            }
            guard seen.insert(name).inserted else {
                throw WorkspaceConfigError.invalidMCPUpstreamTools(name)
            }
        }
    }

    private static func validateMCPUpstreamCatalogBounds(_ upstreams: [MCPUpstreamConfig]) throws {
        for upstream in upstreams {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let data = try encoder.encode(upstream.catalog)
            guard data.count <= catalogJSONLimit else {
                throw WorkspaceConfigError.invalidMCPUpstreamCatalog("exceeds 64 KiB")
            }
        }
    }

    private static func validateMCPUpstreamCatalog(_ catalog: [MCPUpstreamToolDescriptor]) throws {
        for entry in catalog {
            try validateCatalogSchema(entry.inputSchema)
        }
    }

    private static func validateCatalogSchema(_ schema: MCPJSONValue) throws {
        guard case .object(let object) = schema else {
            throw WorkspaceConfigError.invalidMCPUpstreamCatalog("inputSchema must be a JSON object")
        }
        guard case .string("object") = object["type"] else {
            throw WorkspaceConfigError.invalidMCPUpstreamCatalog("inputSchema type must be object")
        }
        if containsForbiddenSchemaContent(schema) {
            throw WorkspaceConfigError.invalidMCPUpstreamCatalog(
                "inputSchema must not contain $ref, $schema, or URI-shaped values"
            )
        }
    }

    private static func containsForbiddenSchemaContent(_ value: MCPJSONValue) -> Bool {
        switch value {
        case .object(let object):
            if object.keys.contains("$ref") || object.keys.contains("$schema") {
                return true
            }
            return object.values.contains(where: containsForbiddenSchemaContent)
        case .array(let array):
            return array.contains(where: containsForbiddenSchemaContent)
        case .string(let string):
            let lowered = string.lowercased()
            return lowered.hasPrefix("http:") || lowered.hasPrefix("https:") || lowered.hasPrefix("file:")
        case .number, .bool, .null:
            return false
        }
    }

    private static func containsShellCommandString(_ argv: [String]) -> Bool {
        guard let first = argv.first else { return false }
        let executable = URL(fileURLWithPath: first).lastPathComponent.lowercased()
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
}

private struct WorkspaceConfigSchemaEnvelope: Decodable {
    let schemaVersion: Int
}
