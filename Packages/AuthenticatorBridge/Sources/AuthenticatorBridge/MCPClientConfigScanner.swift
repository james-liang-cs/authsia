import Foundation

public enum MCPClientConfigSource: String, Codable, CaseIterable, Equatable, Sendable {
    case codex
    case claude
    case cursor
    case devin
    case vscode

    public var displayName: String {
        switch self {
        case .codex: return "Codex"
        case .claude: return "Claude"
        case .cursor: return "Cursor"
        case .devin: return "Devin"
        case .vscode: return "Visual Studio Code"
        }
    }
}

public struct MCPClientConfigLocation: Equatable, Sendable {
    public let source: MCPClientConfigSource
    public let fileURL: URL
    public let displayPath: String

    public init(source: MCPClientConfigSource, fileURL: URL, displayPath: String) {
        self.source = source
        self.fileURL = fileURL
        self.displayPath = displayPath
    }

    /// Repository-scoped client config files, which take precedence over the
    /// user-global ones for the clients that support them. A wrapped
    /// user-global entry with an unwrapped project entry beside it resolves to
    /// the unwrapped one, so leaving these unscanned reports the opposite of
    /// what runs. Codex and Devin have no project scope.
    public static func projectLocations(
        workspaceRoots: [URL],
        homeDirectory: URL
    ) -> [Self] {
        let relativePaths: [(MCPClientConfigSource, String)] = [
            (.claude, ".mcp.json"),
            (.cursor, ".cursor/mcp.json"),
            (.vscode, ".vscode/mcp.json"),
        ]
        var seen = Set<String>()
        var locations: [Self] = []
        for root in workspaceRoots {
            let standardized = root.standardizedFileURL
            for (source, relativePath) in relativePaths {
                let fileURL = standardized.appendingPathComponent(relativePath)
                guard seen.insert(fileURL.path).inserted else { continue }
                locations.append(Self(
                    source: source,
                    fileURL: fileURL,
                    displayPath: abbreviated(fileURL.path, homeDirectory: homeDirectory)
                ))
            }
        }
        return locations
    }

    /// Project display paths keep the full location so two repositories that
    /// share a basename stay distinct findings.
    private static func abbreviated(_ path: String, homeDirectory: URL) -> String {
        let home = homeDirectory.standardizedFileURL.path
        guard path == home || path.hasPrefix(home + "/") else { return path }
        return "~" + path.dropFirst(home.count)
    }

    public static func knownLocations(homeDirectory: URL) -> [Self] {
        [
            Self(
                source: .codex,
                fileURL: homeDirectory.appendingPathComponent(".codex/config.toml"),
                displayPath: "~/.codex/config.toml"
            ),
            Self(
                source: .claude,
                fileURL: homeDirectory.appendingPathComponent(".claude.json"),
                displayPath: "~/.claude.json"
            ),
            Self(
                source: .cursor,
                fileURL: homeDirectory.appendingPathComponent(".cursor/mcp.json"),
                displayPath: "~/.cursor/mcp.json"
            ),
            Self(
                source: .devin,
                fileURL: homeDirectory.appendingPathComponent(".config/devin/mcp_config.json"),
                displayPath: "~/.config/devin/mcp_config.json"
            ),
            Self(
                source: .vscode,
                fileURL: homeDirectory.appendingPathComponent("Library/Application Support/Code/User/mcp.json"),
                displayPath: "VS Code user mcp.json"
            ),
        ]
    }
}

public struct MCPDeclaredLocalServer: Equatable, Sendable {
    public let name: String
    public let command: String
    public let arguments: [String]

    public init(name: String, command: String, arguments: [String]) {
        self.name = name
        self.command = command
        self.arguments = arguments
    }
}

public enum MCPClientServerAdmissionStatus: String, Codable, Equatable, Sendable {
    case admittedWrapped = "admitted-wrapped"
    case directBypass = "direct-bypass"
    case unadmitted
}

public struct MCPClientServerFinding: Codable, Equatable, Identifiable, Sendable {
    public let source: MCPClientConfigSource
    public let serverName: String
    public let commandLabel: String
    public let status: MCPClientServerAdmissionStatus
    public let declaredUpstreamName: String?
    public let configPathLabel: String
    public let wrapCommand: String?
    public let wrapArguments: [String]
    public let isWrapEligible: Bool

    public var id: String {
        "\(source.rawValue):\(serverName):\(configPathLabel)"
    }

    public var shouldShowInAccessCenter: Bool {
        status == .admittedWrapped || isWrapEligible
    }

    public init(
        source: MCPClientConfigSource,
        serverName: String,
        commandLabel: String,
        status: MCPClientServerAdmissionStatus,
        declaredUpstreamName: String?,
        configPathLabel: String,
        wrapCommand: String? = nil,
        wrapArguments: [String] = [],
        isWrapEligible: Bool = false
    ) {
        self.source = source
        self.serverName = serverName
        self.commandLabel = commandLabel
        self.status = status
        self.declaredUpstreamName = declaredUpstreamName
        self.configPathLabel = configPathLabel
        self.wrapCommand = wrapCommand
        self.wrapArguments = wrapArguments
        self.isWrapEligible = isWrapEligible
    }

    enum CodingKeys: String, CodingKey {
        case source
        case serverName
        case commandLabel
        case status
        case declaredUpstreamName
        case configPathLabel
        case wrapCommand
        case wrapArguments
        case isWrapEligible
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        source = try container.decode(MCPClientConfigSource.self, forKey: .source)
        serverName = try container.decode(String.self, forKey: .serverName)
        commandLabel = try container.decode(String.self, forKey: .commandLabel)
        status = try container.decode(MCPClientServerAdmissionStatus.self, forKey: .status)
        declaredUpstreamName = try container.decodeIfPresent(String.self, forKey: .declaredUpstreamName)
        configPathLabel = try container.decode(String.self, forKey: .configPathLabel)
        wrapCommand = try container.decodeIfPresent(String.self, forKey: .wrapCommand)
        wrapArguments = try container.decodeIfPresent([String].self, forKey: .wrapArguments) ?? []
        isWrapEligible = try container.decodeIfPresent(Bool.self, forKey: .isWrapEligible) ?? false
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(source, forKey: .source)
        try container.encode(serverName, forKey: .serverName)
        try container.encode(commandLabel, forKey: .commandLabel)
        try container.encode(status, forKey: .status)
        try container.encodeIfPresent(declaredUpstreamName, forKey: .declaredUpstreamName)
        try container.encode(configPathLabel, forKey: .configPathLabel)
        try container.encodeIfPresent(wrapCommand, forKey: .wrapCommand)
        if !wrapArguments.isEmpty {
            try container.encode(wrapArguments, forKey: .wrapArguments)
        }
        if isWrapEligible {
            try container.encode(isWrapEligible, forKey: .isWrapEligible)
        }
    }
}

public struct MCPClientConfigScanner {
    private static let maximumConfigBytes: UInt64 = 1_048_576
    private let fileManager: FileManager

    public init(fileManager: FileManager = .default) {
        self.fileManager = fileManager
    }

    public func scan(
        declaredServers: [MCPDeclaredLocalServer],
        locations: [MCPClientConfigLocation]
    ) -> [MCPClientServerFinding] {
        let observedServers = locations.flatMap { entries(at: $0) }
        return observedServers.compactMap { entry in
            finding(for: entry, declaredServers: declaredServers)
        }.sorted { lhs, rhs in
            if lhs.source.rawValue != rhs.source.rawValue {
                return lhs.source.rawValue < rhs.source.rawValue
            }
            if lhs.serverName != rhs.serverName {
                return lhs.serverName < rhs.serverName
            }
            return lhs.configPathLabel < rhs.configPathLabel
        }
    }

    private func entries(at location: MCPClientConfigLocation) -> [ObservedServer] {
        guard let attributes = try? fileManager.attributesOfItem(atPath: location.fileURL.path),
              let size = (attributes[.size] as? NSNumber)?.uint64Value,
              size <= Self.maximumConfigBytes,
              let data = try? Data(contentsOf: location.fileURL, options: .mappedIfSafe) else {
            return []
        }
        if location.source == .codex {
            return Self.codexEntries(data: data, location: location)
        }
        return Self.jsonEntries(data: data, location: location)
    }

    private func finding(
        for entry: ObservedServer,
        declaredServers: [MCPDeclaredLocalServer]
    ) -> MCPClientServerFinding? {
        guard let serverName = Self.safeLabel(entry.name, maximumLength: 128),
              let commandLabel = Self.commandLabel(entry.command),
              let configPathLabel = Self.safeLabel(
                entry.location.displayPath,
                maximumLength: 256
              ) else {
            return nil
        }
        let executableName = URL(fileURLWithPath: entry.command).lastPathComponent
        if executableName == "authsia", entry.arguments == ["mcp", "serve"] {
            return nil
        }

        let wrappedUpstream = executableName == "authsia"
            ? MCPProxyClientLaunch.wrappedUpstreamName(
                arguments: entry.arguments,
                environmentName: entry.upstreamEnvironmentName
            )
            : nil
        let isAuthsiaProxyLaunch = executableName == "authsia"
            && MCPProxyClientLaunch.isProxyLaunch(arguments: entry.arguments)
        let declaredNames = Set(declaredServers.map(\.name))
        let directMatch = declaredServers.first { declared in
            declared.name == entry.name
                && URL(fileURLWithPath: declared.command).lastPathComponent == executableName
                && declared.arguments == entry.arguments
        }
        let status: MCPClientServerAdmissionStatus
        let declaredUpstreamName: String?
        if let wrappedUpstream, declaredNames.contains(wrappedUpstream) {
            status = .admittedWrapped
            declaredUpstreamName = wrappedUpstream
        } else if let directMatch {
            status = .directBypass
            declaredUpstreamName = directMatch.name
        } else {
            status = .unadmitted
            declaredUpstreamName = wrappedUpstream
        }
        let wrap = Self.wrapTarget(
            name: serverName,
            command: entry.command,
            arguments: entry.arguments,
            status: status,
            isAuthsiaProxyLaunch: isAuthsiaProxyLaunch
        )
        return MCPClientServerFinding(
            source: entry.location.source,
            serverName: serverName,
            commandLabel: commandLabel,
            status: status,
            declaredUpstreamName: declaredUpstreamName,
            configPathLabel: configPathLabel,
            wrapCommand: wrap?.command,
            wrapArguments: wrap?.arguments ?? [],
            isWrapEligible: wrap != nil
        )
    }

    private static func wrapTarget(
        name: String,
        command: String,
        arguments: [String],
        status: MCPClientServerAdmissionStatus,
        isAuthsiaProxyLaunch: Bool
    ) -> (command: String, arguments: [String])? {
        guard status != .admittedWrapped,
              !isAuthsiaProxyLaunch,
              validUpstreamName(name) != nil else {
            return nil
        }
        let trimmed = command.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              !trimmed.hasPrefix("/"),
              trimmed != ".",
              trimmed != "..",
              !trimmed.contains("\0"),
              trimmed.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) })
        else {
            return nil
        }
        if trimmed.contains("/") {
            let parts = trimmed.split(separator: "/", omittingEmptySubsequences: false)
            guard !parts.contains(where: { $0 == ".." || $0.isEmpty }) else {
                return nil
            }
        }
        guard arguments.count <= 64 else { return nil }
        for argument in arguments {
            guard argument.utf8.count <= 32 * 1_024,
                  argument.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }),
                  !argument.lowercased().contains("authsia://") else {
                return nil
            }
        }
        // Must match what WorkspaceConfigStore will accept when it reads the
        // declared entry back, or declaring writes a config that no longer
        // loads.
        if MCPUpstreamCommandRules.shellExecutableNames.contains(
            URL(fileURLWithPath: trimmed).lastPathComponent.lowercased()
        ) || MCPUpstreamCommandRules.containsShellCommandString([trimmed] + arguments) {
            return nil
        }
        return (trimmed, arguments)
    }

    private static func jsonEntries(
        data: Data,
        location: MCPClientConfigLocation
    ) -> [ObservedServer] {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let servers = root[location.source == .vscode ? "servers" : "mcpServers"]
                as? [String: Any] else {
            return []
        }
        return servers.compactMap { name, rawValue in
            guard let value = rawValue as? [String: Any],
                  let command = value["command"] as? String else {
                return nil
            }
            let arguments: [String]
            if let rawArguments = value["args"] {
                guard let decodedArguments = rawArguments as? [String] else { return nil }
                arguments = decodedArguments
            } else {
                arguments = []
            }
            let upstreamEnvironmentName = proxyUpstreamEnvironmentName(value["env"])
            return ObservedServer(
                name: name,
                command: command,
                arguments: arguments,
                upstreamEnvironmentName: upstreamEnvironmentName,
                location: location
            )
        }
    }

    private static func codexEntries(
        data: Data,
        location: MCPClientConfigLocation
    ) -> [ObservedServer] {
        guard let text = String(data: data, encoding: .utf8) else { return [] }
        var entries: [ObservedServer] = []
        var name: String?
        var command: String?
        var arguments: [String] = []
        var upstreamEnvironmentName: String?
        var readingEnvTable = false

        func flush() {
            if let name, let command {
                entries.append(ObservedServer(
                    name: name,
                    command: command,
                    arguments: arguments,
                    upstreamEnvironmentName: upstreamEnvironmentName,
                    location: location
                ))
            }
        }

        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("[mcp_servers."), line.hasSuffix("]") {
                let start = line.index(line.startIndex, offsetBy: "[mcp_servers.".count)
                let rawName = String(line[start..<line.index(before: line.endIndex)])
                let heading = parseTOMLString(rawName) ?? rawName
                if heading.hasSuffix(".env"), let current = name {
                    let envOwner = String(heading.dropLast(4))
                    readingEnvTable = envOwner == current
                    continue
                }
                flush()
                name = heading
                command = nil
                arguments = []
                upstreamEnvironmentName = nil
                readingEnvTable = false
            } else if readingEnvTable,
                      let value = assignmentValue(
                        in: line,
                        key: MCPProxyClientLaunch.environmentKey
                      ) {
                upstreamEnvironmentName = parseTOMLString(value)
            } else if !readingEnvTable, name != nil,
                      let value = assignmentValue(in: line, key: "command") {
                command = parseTOMLString(value)
            } else if !readingEnvTable, name != nil,
                      let value = assignmentValue(in: line, key: "args") {
                arguments = parseTOMLStringArray(value) ?? []
            }
        }
        flush()
        return entries
    }

    private static func proxyUpstreamEnvironmentName(_ rawEnv: Any?) -> String? {
        guard let env = rawEnv as? [String: Any],
              let value = env[MCPProxyClientLaunch.environmentKey] as? String else {
            return nil
        }
        return value
    }

    private static func assignmentValue(in line: String, key: String) -> String? {
        guard let equals = line.firstIndex(of: "=") else { return nil }
        let lhs = line[..<equals].trimmingCharacters(in: .whitespaces)
        guard lhs == key else { return nil }
        return line[line.index(after: equals)...].trimmingCharacters(in: .whitespaces)
    }

    private static func parseTOMLString(_ rawValue: String) -> String? {
        let value = rawValue.trimmingCharacters(in: .whitespaces)
        if value.hasPrefix("'"), value.hasSuffix("'"), value.count >= 2 {
            return String(value.dropFirst().dropLast())
        }
        guard let data = "[\(value)]".data(using: .utf8),
              let array = try? JSONSerialization.jsonObject(with: data) as? [String],
              array.count == 1 else {
            return nil
        }
        return array[0]
    }

    private static func parseTOMLStringArray(_ rawValue: String) -> [String]? {
        var value = rawValue.trimmingCharacters(in: .whitespaces)
        value = value.replacingOccurrences(
            of: #",\s*\]$"#,
            with: "]",
            options: .regularExpression
        )
        guard let data = value.data(using: .utf8) else { return nil }
        return try? JSONSerialization.jsonObject(with: data) as? [String]
    }

    private static func commandLabel(_ command: String) -> String? {
        safeLabel(URL(fileURLWithPath: command).lastPathComponent, maximumLength: 128)
    }

    private static func validUpstreamName(_ value: String) -> String? {
        value.range(
            of: #"^[A-Za-z][A-Za-z0-9_-]{0,31}$"#,
            options: .regularExpression
        ) == nil ? nil : value
    }

    private static func safeLabel(_ value: String, maximumLength: Int) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              trimmed.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            return nil
        }
        return String(trimmed.prefix(maximumLength))
    }

    private struct ObservedServer {
        let name: String
        let command: String
        let arguments: [String]
        let upstreamEnvironmentName: String?
        let location: MCPClientConfigLocation
    }
}
