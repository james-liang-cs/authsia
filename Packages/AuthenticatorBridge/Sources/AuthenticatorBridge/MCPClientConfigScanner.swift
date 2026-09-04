import Foundation

public enum MCPClientConfigSource: String, Codable, CaseIterable, Equatable, Sendable {
    case codex
    case claude
    case cursor
    case devin
    case vscode
    case claudeDesktop = "claude-desktop"

    public var displayName: String {
        switch self {
        case .codex: return "Codex"
        case .claude: return "Claude"
        case .cursor: return "Cursor"
        case .devin: return "Devin"
        case .vscode: return "Visual Studio Code"
        case .claudeDesktop: return "Claude Desktop"
        }
    }

    /// A client with no repository of its own. Its launches are real and worth
    /// reporting, but they cannot be closed per pilot repository, so they are
    /// advisory rather than a compliance failure.
    public var hasWorkspaceOfItsOwn: Bool {
        self != .claudeDesktop
    }
}

public enum MCPClientConfigScope: String, Codable, Equatable, Sendable {
    case userGlobal = "user-global"
    case project

    public var displayName: String {
        switch self {
        case .userGlobal: return "User-global"
        case .project: return "Project"
        }
    }
}

public enum MCPClientConfigPrecedence: String, Codable, Equatable, Sendable {
    case effective
    case overridden
    case conditional

    public var displayName: String {
        switch self {
        case .effective: return "Effective"
        case .overridden: return "Overridden"
        case .conditional: return "Conditional"
        }
    }
}

public struct MCPClientConfigLocation: Equatable, Sendable {
    /// Precedence tiers among entries that name the same client and server for
    /// one workspace root. Higher wins; the loser is reported `overridden`.
    enum Rank: Int {
        case userGlobal = 0
        case projectFile = 1
        /// Claude Code's `local` scope, the default for `claude mcp add`. It
        /// lives in `~/.claude.json` under `projects[<root>]` and outranks the
        /// repository's own `.mcp.json`.
        case claudeLocalScope = 2
    }

    public let source: MCPClientConfigSource
    public let fileURL: URL
    public let displayPath: String
    public let scope: MCPClientConfigScope
    public let workspaceRoot: URL?
    public let workspacePathLabel: String?
    /// When set, servers are read from `projects[projectKey].mcpServers`
    /// instead of the file's top-level map.
    let projectKey: String?
    let rank: Rank

    public init(
        source: MCPClientConfigSource,
        fileURL: URL,
        displayPath: String,
        scope: MCPClientConfigScope = .userGlobal,
        workspaceRoot: URL? = nil,
        workspacePathLabel: String? = nil
    ) {
        self.init(
            source: source,
            fileURL: fileURL,
            displayPath: displayPath,
            scope: scope,
            workspaceRoot: workspaceRoot,
            workspacePathLabel: workspacePathLabel,
            projectKey: nil,
            rank: scope == .project ? .projectFile : .userGlobal
        )
    }

    init(
        source: MCPClientConfigSource,
        fileURL: URL,
        displayPath: String,
        scope: MCPClientConfigScope,
        workspaceRoot: URL?,
        workspacePathLabel: String?,
        projectKey: String?,
        rank: Rank
    ) {
        self.source = source
        self.fileURL = fileURL
        self.displayPath = displayPath
        self.scope = scope
        self.workspaceRoot = workspaceRoot?.standardizedFileURL
        self.workspacePathLabel = workspacePathLabel
        self.projectKey = projectKey
        self.rank = rank
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
            let workspacePathLabel = abbreviated(
                standardized.path,
                homeDirectory: homeDirectory
            )
            for (source, relativePath) in relativePaths {
                let fileURL = standardized.appendingPathComponent(relativePath)
                guard seen.insert(fileURL.path).inserted else { continue }
                locations.append(Self(
                    source: source,
                    fileURL: fileURL,
                    displayPath: abbreviated(fileURL.path, homeDirectory: homeDirectory),
                    scope: .project,
                    workspaceRoot: standardized,
                    workspacePathLabel: workspacePathLabel,
                    projectKey: nil,
                    rank: .projectFile
                ))
            }
            // Claude Code's local scope. Reading only the top-level map misses
            // every server added by a plain `claude mcp add`, which defaults
            // there, and those outrank the repository's `.mcp.json`.
            guard seen.insert("claude-local-scope:" + standardized.path).inserted else {
                continue
            }
            locations.append(Self(
                source: .claude,
                fileURL: homeDirectory.appendingPathComponent(".claude.json"),
                displayPath: "~/.claude.json (local scope)",
                scope: .project,
                workspaceRoot: standardized,
                workspacePathLabel: workspacePathLabel,
                projectKey: standardized.path,
                rank: .claudeLocalScope
            ))
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
                displayPath: "~/Library/Application Support/Code/User/mcp.json"
            ),
            Self(
                source: .claudeDesktop,
                fileURL: homeDirectory.appendingPathComponent(
                    "Library/Application Support/Claude/claude_desktop_config.json"
                ),
                displayPath: "~/Library/Application Support/Claude/claude_desktop_config.json"
            ),
        ]
    }
}

public struct MCPDeclaredLocalServer: Equatable, Sendable {
    public let name: String
    public let command: String
    public let arguments: [String]
    public let workspaceRoot: URL?
    /// True when workspace policy already advertises allow ∪ approve names.
    public let hasAdvertisedCatalog: Bool
    /// True when a credential-less stdio probe can record that catalog.
    public let canRecordCatalog: Bool

    public init(
        name: String,
        command: String,
        arguments: [String],
        workspaceRoot: URL? = nil,
        hasAdvertisedCatalog: Bool = false,
        canRecordCatalog: Bool = false
    ) {
        self.name = name
        self.command = command
        self.arguments = arguments
        self.workspaceRoot = workspaceRoot?.standardizedFileURL
        self.hasAdvertisedCatalog = hasAdvertisedCatalog
        self.canRecordCatalog = canRecordCatalog
    }
}

public enum MCPClientServerAdmissionStatus: String, Codable, Equatable, Sendable {
    case admittedWrapped = "admitted-wrapped"
    case directBypass = "direct-bypass"
    case unadmitted
}

public enum MCPClientWrapBlockReason: String, Codable, Equatable, Sendable {
    case packageLauncher = "package-launcher"
    case shell
    /// The scanned entry sets something about the child's execution that
    /// `mcpUpstreams` cannot carry, so wrapping it would silently change how
    /// the child runs.
    case unsupportedLaunchKey = "unsupported-launch-key"
}

public struct MCPClientServerFinding: Codable, Equatable, Identifiable, Sendable {
    public let source: MCPClientConfigSource
    public let serverName: String
    public let commandLabel: String
    public let status: MCPClientServerAdmissionStatus
    public let declaredUpstreamName: String?
    public let configPathLabel: String
    public let configScope: MCPClientConfigScope
    public let precedence: MCPClientConfigPrecedence
    public let workspacePathLabel: String?
    public let isAuthsiaProxyLaunch: Bool
    public let wrapCommand: String?
    public let wrapArguments: [String]
    public let isWrapEligible: Bool
    public let wrapBlockReason: MCPClientWrapBlockReason?
    public let hasAdvertisedCatalog: Bool
    public let canRecordCatalog: Bool
    /// Names the launch keys behind a `.unsupportedLaunchKey` block, so the
    /// reason can be stated instead of the keys being dropped silently.
    public let unsupportedLaunchKeys: [String]
    /// How many environment values the scanned entry sets for the child. A
    /// wrap does not copy them, so the count is what makes that visible before
    /// the write. Never the names, never the values.
    public let childEnvironmentCount: Int
    /// Exact on-disk path of the scanned file. Display labels such as
    /// `~/.claude.json (local scope)` are not paths; wrap and unwrap use this.
    public let configFilePath: String?
    /// Claude Code local-scope key into `projects`. Nil for every other file.
    public let projectKey: String?

    public var id: String {
        "\(workspacePathLabel ?? ""):\(source.rawValue):\(serverName):\(configPathLabel)"
    }

    public var needsCatalogRecording: Bool {
        status == .admittedWrapped
            && !hasAdvertisedCatalog
            && canRecordCatalog
            && childEnvironmentCount == 0
    }

    /// Wrapped, but nothing will ever appear in the client: the upstream
    /// declares environment values, or the scanned client entry did, so listing
    /// may not probe the child, and policy names no tool. Until a human writes
    /// `allow` / `approve`, the proxy advertises an empty catalog and agents
    /// fall through to the unproxied CLI.
    public var needsToolPolicy: Bool {
        status == .admittedWrapped
            && !hasAdvertisedCatalog
            && (!canRecordCatalog || childEnvironmentCount > 0)
    }

    public var shouldShowInAccessCenter: Bool {
        status == .admittedWrapped
            || isAuthsiaProxyLaunch
            || isWrapEligible
            || wrapBlockReason != nil
    }

    public init(
        source: MCPClientConfigSource,
        serverName: String,
        commandLabel: String,
        status: MCPClientServerAdmissionStatus,
        declaredUpstreamName: String?,
        configPathLabel: String,
        configScope: MCPClientConfigScope = .userGlobal,
        precedence: MCPClientConfigPrecedence = .conditional,
        workspacePathLabel: String? = nil,
        isAuthsiaProxyLaunch: Bool = false,
        wrapCommand: String? = nil,
        wrapArguments: [String] = [],
        isWrapEligible: Bool = false,
        wrapBlockReason: MCPClientWrapBlockReason? = nil,
        hasAdvertisedCatalog: Bool = true,
        canRecordCatalog: Bool = false,
        unsupportedLaunchKeys: [String] = [],
        childEnvironmentCount: Int = 0,
        configFilePath: String? = nil,
        projectKey: String? = nil
    ) {
        self.source = source
        self.serverName = serverName
        self.commandLabel = commandLabel
        self.status = status
        self.declaredUpstreamName = declaredUpstreamName
        self.configPathLabel = configPathLabel
        self.configScope = configScope
        self.precedence = precedence
        self.workspacePathLabel = workspacePathLabel
        self.isAuthsiaProxyLaunch = isAuthsiaProxyLaunch
        self.wrapCommand = wrapCommand
        self.wrapArguments = wrapArguments
        self.isWrapEligible = isWrapEligible
        self.wrapBlockReason = wrapBlockReason
        self.hasAdvertisedCatalog = hasAdvertisedCatalog
        self.canRecordCatalog = canRecordCatalog
        self.unsupportedLaunchKeys = unsupportedLaunchKeys
        self.childEnvironmentCount = childEnvironmentCount
        self.configFilePath = configFilePath
        self.projectKey = projectKey
    }

    enum CodingKeys: String, CodingKey {
        case id
        case source
        case serverName
        case commandLabel
        case status
        case declaredUpstreamName
        case configPathLabel
        case configScope
        case precedence
        case workspacePathLabel
        case isAuthsiaProxyLaunch
        case wrapCommand
        case wrapArguments
        case isWrapEligible
        case wrapBlockReason
        case hasAdvertisedCatalog
        case canRecordCatalog
        case unsupportedLaunchKeys
        case childEnvironmentCount
        case configFilePath
        case projectKey
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        source = try container.decode(MCPClientConfigSource.self, forKey: .source)
        serverName = try container.decode(String.self, forKey: .serverName)
        commandLabel = try container.decode(String.self, forKey: .commandLabel)
        status = try container.decode(MCPClientServerAdmissionStatus.self, forKey: .status)
        declaredUpstreamName = try container.decodeIfPresent(String.self, forKey: .declaredUpstreamName)
        configPathLabel = try container.decode(String.self, forKey: .configPathLabel)
        configScope = try container.decodeIfPresent(MCPClientConfigScope.self, forKey: .configScope)
            ?? .userGlobal
        precedence = try container.decodeIfPresent(MCPClientConfigPrecedence.self, forKey: .precedence)
            ?? .conditional
        workspacePathLabel = try container.decodeIfPresent(String.self, forKey: .workspacePathLabel)
        isAuthsiaProxyLaunch = try container.decodeIfPresent(Bool.self, forKey: .isAuthsiaProxyLaunch)
            ?? false
        wrapCommand = try container.decodeIfPresent(String.self, forKey: .wrapCommand)
        wrapArguments = try container.decodeIfPresent([String].self, forKey: .wrapArguments) ?? []
        isWrapEligible = try container.decodeIfPresent(Bool.self, forKey: .isWrapEligible) ?? false
        wrapBlockReason = try container.decodeIfPresent(
            MCPClientWrapBlockReason.self,
            forKey: .wrapBlockReason
        )
        hasAdvertisedCatalog = try container.decodeIfPresent(Bool.self, forKey: .hasAdvertisedCatalog) ?? true
        canRecordCatalog = try container.decodeIfPresent(Bool.self, forKey: .canRecordCatalog) ?? false
        unsupportedLaunchKeys = try container.decodeIfPresent(
            [String].self,
            forKey: .unsupportedLaunchKeys
        ) ?? []
        childEnvironmentCount = try container.decodeIfPresent(
            Int.self,
            forKey: .childEnvironmentCount
        ) ?? 0
        configFilePath = try container.decodeIfPresent(String.self, forKey: .configFilePath)
        projectKey = try container.decodeIfPresent(String.self, forKey: .projectKey)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(source, forKey: .source)
        try container.encode(serverName, forKey: .serverName)
        try container.encode(commandLabel, forKey: .commandLabel)
        try container.encode(status, forKey: .status)
        try container.encodeIfPresent(declaredUpstreamName, forKey: .declaredUpstreamName)
        try container.encode(configPathLabel, forKey: .configPathLabel)
        try container.encode(configScope, forKey: .configScope)
        try container.encode(precedence, forKey: .precedence)
        try container.encodeIfPresent(workspacePathLabel, forKey: .workspacePathLabel)
        if isAuthsiaProxyLaunch {
            try container.encode(isAuthsiaProxyLaunch, forKey: .isAuthsiaProxyLaunch)
        }
        try container.encodeIfPresent(wrapCommand, forKey: .wrapCommand)
        if !wrapArguments.isEmpty {
            try container.encode(wrapArguments, forKey: .wrapArguments)
        }
        if isWrapEligible {
            try container.encode(isWrapEligible, forKey: .isWrapEligible)
        }
        try container.encodeIfPresent(wrapBlockReason, forKey: .wrapBlockReason)
        if !hasAdvertisedCatalog {
            try container.encode(hasAdvertisedCatalog, forKey: .hasAdvertisedCatalog)
        }
        if !unsupportedLaunchKeys.isEmpty {
            try container.encode(unsupportedLaunchKeys, forKey: .unsupportedLaunchKeys)
        }
        if childEnvironmentCount > 0 {
            try container.encode(childEnvironmentCount, forKey: .childEnvironmentCount)
        }
        if canRecordCatalog {
            try container.encode(canRecordCatalog, forKey: .canRecordCatalog)
        }
        try container.encodeIfPresent(configFilePath, forKey: .configFilePath)
        try container.encodeIfPresent(projectKey, forKey: .projectKey)
    }
}

public struct MCPClientConfigScanner {
    private static let maximumConfigBytes: UInt64 = 1_048_576
    /// `mcpUpstreams` has no field for these, and the proxy resolves the
    /// child's working directory itself, so a wrap would quietly change how
    /// the child runs.
    static let unsupportedLaunchKeys: Set<String> = ["cwd"]
    private let fileManager: FileManager

    public init(fileManager: FileManager = .default) {
        self.fileManager = fileManager
    }

    public func scan(
        declaredServers: [MCPDeclaredLocalServer],
        locations: [MCPClientConfigLocation]
    ) -> [MCPClientServerFinding] {
        // A launch the client file marks off cannot run, so it is neither a
        // bypass to report nor protection debt to work off. Claude Code keeps
        // that answer for `.mcp.json` servers in a different file, so the two
        // reads are combined here rather than inside either parser.
        let disabledProjectServers = claudeDisabledProjectServers(in: locations)
        let observedServers = locations.flatMap { entries(at: $0) }
            .filter { entry in
                guard !entry.isDisabled else { return false }
                guard entry.location.source == .claude,
                      entry.location.rank == .projectFile,
                      let root = entry.location.workspaceRoot else {
                    return true
                }
                return disabledProjectServers[root.path]?.contains(entry.name) != true
            }
        var rootsByPath: [String: URL] = [:]
        var labelsByRootPath: [String: String] = [:]
        for location in locations {
            guard let root = location.workspaceRoot else { continue }
            rootsByPath[root.path] = root
            labelsByRootPath[root.path] = location.workspacePathLabel ?? root.path
        }
        for declared in declaredServers {
            guard let root = declared.workspaceRoot else { continue }
            rootsByPath[root.path] = root
            if labelsByRootPath[root.path] == nil {
                labelsByRootPath[root.path] = root.path
            }
        }
        let workspaceRoots = rootsByPath.values.sorted { $0.path < $1.path }
        // Highest workspace-bound tier seen for each client/server/root. A
        // lower tier resolves to nothing for that root and is reported
        // `overridden` rather than as a live bypass.
        var winningRank: [PrecedenceKey: Int] = [:]
        for entry in observedServers {
            guard entry.location.scope == .project,
                  let root = entry.location.workspaceRoot else {
                continue
            }
            let key = PrecedenceKey(
                source: entry.location.source,
                serverName: entry.name,
                workspacePath: root.path
            )
            winningRank[key] = max(winningRank[key] ?? 0, entry.location.rank.rawValue)
        }

        let contextualServers = observedServers.flatMap { entry -> [ContextualObservedServer] in
            if entry.location.scope == .project {
                let root = entry.location.workspaceRoot
                let outranked = root.map { root in
                    (winningRank[PrecedenceKey(
                        source: entry.location.source,
                        serverName: entry.name,
                        workspacePath: root.path
                    )] ?? 0) > entry.location.rank.rawValue
                } ?? false
                return [ContextualObservedServer(
                    entry: entry,
                    workspaceRoot: root,
                    workspacePathLabel: entry.location.workspacePathLabel ?? root?.path,
                    precedence: outranked ? .overridden : .effective
                )]
            }
            guard !workspaceRoots.isEmpty else {
                return [ContextualObservedServer(
                    entry: entry,
                    workspaceRoot: nil,
                    workspacePathLabel: nil,
                    precedence: .conditional
                )]
            }
            return workspaceRoots.map { root in
                let key = PrecedenceKey(
                    source: entry.location.source,
                    serverName: entry.name,
                    workspacePath: root.path
                )
                return ContextualObservedServer(
                    entry: entry,
                    workspaceRoot: root,
                    workspacePathLabel: labelsByRootPath[root.path] ?? root.path,
                    precedence: winningRank[key] != nil ? .overridden : .effective
                )
            }
        }

        return contextualServers.compactMap { contextual in
            finding(
                for: contextual.entry,
                declaredServers: declaredServers,
                workspaceRoot: contextual.workspaceRoot,
                workspacePathLabel: contextual.workspacePathLabel,
                precedence: contextual.precedence
            )
        }.sorted { lhs, rhs in
            if lhs.workspacePathLabel != rhs.workspacePathLabel {
                return (lhs.workspacePathLabel ?? "") < (rhs.workspacePathLabel ?? "")
            }
            if lhs.source.rawValue != rhs.source.rawValue {
                return lhs.source.rawValue < rhs.source.rawValue
            }
            if lhs.serverName != rhs.serverName {
                return lhs.serverName < rhs.serverName
            }
            return lhs.configPathLabel < rhs.configPathLabel
        }
    }

    /// `.mcp.json` servers the human declined, per project, from
    /// `~/.claude.json`. Only the explicit `disabledMcpjsonServers` list counts:
    /// a name in neither list has not been answered yet, and treating that as
    /// off would hide real debt.
    private func claudeDisabledProjectServers(
        in locations: [MCPClientConfigLocation]
    ) -> [String: Set<String>] {
        guard let location = locations.first(where: {
            $0.source == .claude && $0.scope == .userGlobal
        }),
            let attributes = try? fileManager.attributesOfItem(atPath: location.fileURL.path),
            let size = (attributes[.size] as? NSNumber)?.uint64Value,
            size <= Self.maximumConfigBytes,
            let data = try? Data(contentsOf: location.fileURL, options: .mappedIfSafe),
            let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let projects = root["projects"] as? [String: Any] else {
            return [:]
        }
        var disabled: [String: Set<String>] = [:]
        for (projectPath, value) in projects {
            guard let project = value as? [String: Any],
                  let names = project["disabledMcpjsonServers"] as? [String],
                  !names.isEmpty else {
                continue
            }
            disabled[URL(fileURLWithPath: projectPath, isDirectory: true).standardizedFileURL.path]
                = Set(names)
        }
        return disabled
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
        declaredServers: [MCPDeclaredLocalServer],
        workspaceRoot: URL?,
        workspacePathLabel: String?,
        precedence: MCPClientConfigPrecedence
    ) -> MCPClientServerFinding? {
        guard let serverName = Self.safeLabel(entry.name, maximumLength: 128),
              let commandLabel = Self.commandLabel(entry.command),
              let configPathLabel = Self.safeExactPath(entry.location.displayPath) else {
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
            && wrappedUpstream != nil
        let applicableDeclarations = declaredServers.filter { declared in
            declared.workspaceRoot?.path == workspaceRoot?.path
        }
        let declaredNames = Set(applicableDeclarations.map(\.name))
        let directMatch = applicableDeclarations.first { declared in
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
        let declaredMatch = declaredUpstreamName.flatMap { name in
            applicableDeclarations.first { $0.name == name }
        }
        return MCPClientServerFinding(
            source: entry.location.source,
            serverName: serverName,
            commandLabel: commandLabel,
            status: status,
            declaredUpstreamName: declaredUpstreamName,
            configPathLabel: configPathLabel,
            configScope: entry.location.scope,
            precedence: precedence,
            workspacePathLabel: workspacePathLabel.flatMap {
                Self.safeLabel($0, maximumLength: 512)
            },
            isAuthsiaProxyLaunch: isAuthsiaProxyLaunch,
            wrapCommand: wrap?.command,
            wrapArguments: wrap?.arguments ?? [],
            isWrapEligible: wrap != nil && entry.unsupportedKeys.isEmpty,
            wrapBlockReason: entry.unsupportedKeys.isEmpty
                ? (wrap == nil
                    ? MCPUpstreamCommandRules.accessCenterBlockReason(
                        fromScanned: entry.command,
                        arguments: entry.arguments
                    )
                    : nil)
                : .unsupportedLaunchKey,
            hasAdvertisedCatalog: status == .admittedWrapped
                ? (declaredMatch?.hasAdvertisedCatalog ?? true)
                : true,
            canRecordCatalog: status == .admittedWrapped
                && (declaredMatch?.canRecordCatalog ?? false),
            unsupportedLaunchKeys: entry.unsupportedKeys,
            childEnvironmentCount: entry.childEnvironmentCount,
            configFilePath: Self.safeExactPath(entry.location.fileURL.path),
            projectKey: entry.location.projectKey
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
        guard let policyCommand = MCPUpstreamCommandRules.policyCommand(fromScanned: command) else {
            return nil
        }
        guard URL(fileURLWithPath: policyCommand).lastPathComponent.lowercased() != "authsia" else {
            return nil
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
        // loads. Absolute scanned commands store the PATH basename.
        if MCPUpstreamCommandRules.shellExecutableNames.contains(
            URL(fileURLWithPath: policyCommand).lastPathComponent.lowercased()
        ) || MCPUpstreamCommandRules.containsShellCommandString([policyCommand] + arguments) {
            return nil
        }
        return (policyCommand, arguments)
    }

    private static func jsonEntries(
        data: Data,
        location: MCPClientConfigLocation
    ) -> [ObservedServer] {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return []
        }
        let scopeRoot: [String: Any]
        if let projectKey = location.projectKey {
            guard let projects = root["projects"] as? [String: Any],
                  let project = projects[projectKey] as? [String: Any] else {
                return []
            }
            scopeRoot = project
        } else {
            scopeRoot = root
        }
        guard let servers = scopeRoot[location.source == .vscode ? "servers" : "mcpServers"]
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
                location: location,
                isDisabled: value["enabled"] as? Bool == false
                    || value["disabled"] as? Bool == true,
                unsupportedKeys: Self.unsupportedLaunchKeys
                    .filter { value[$0] != nil }
                    .sorted(),
                childEnvironmentCount: (value["env"] as? [String: Any])?
                    .keys
                    .filter { $0 != MCPProxyClientLaunch.environmentKey }
                    .count ?? 0
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
        var isDisabled = false
        var unsupportedKeys: [String] = []
        var childEnvironmentCount = 0
        var readingEnvTable = false

        func flush() {
            if let name, let command {
                entries.append(ObservedServer(
                    name: name,
                    command: command,
                    arguments: arguments,
                    upstreamEnvironmentName: upstreamEnvironmentName,
                    location: location,
                    isDisabled: isDisabled,
                    unsupportedKeys: unsupportedKeys.sorted(),
                    childEnvironmentCount: childEnvironmentCount
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
                isDisabled = false
                unsupportedKeys = []
                childEnvironmentCount = 0
                readingEnvTable = false
            } else if readingEnvTable,
                      let value = assignmentValue(
                        in: line,
                        key: MCPProxyClientLaunch.environmentKey
                      ) {
                upstreamEnvironmentName = parseTOMLString(value)
            } else if readingEnvTable, line.contains("=") {
                childEnvironmentCount += 1
            } else if !readingEnvTable, name != nil,
                      let value = assignmentValue(in: line, key: "command") {
                command = parseTOMLString(value)
            } else if !readingEnvTable, name != nil,
                      let value = assignmentValue(in: line, key: "args") {
                arguments = parseTOMLStringArray(value) ?? []
            } else if !readingEnvTable, name != nil,
                      let value = assignmentValue(in: line, key: "enabled") {
                isDisabled = value == "false"
            } else if !readingEnvTable, name != nil,
                      let key = unsupportedLaunchKey(in: line) {
                unsupportedKeys.append(key)
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

    private static func unsupportedLaunchKey(in line: String) -> String? {
        unsupportedLaunchKeys.first { assignmentValue(in: line, key: $0) != nil }
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

    private static func safeExactPath(_ value: String) -> String? {
        guard !value.isEmpty,
              value.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            return nil
        }
        return value
    }

    private struct ObservedServer {
        let name: String
        let command: String
        let arguments: [String]
        let upstreamEnvironmentName: String?
        let location: MCPClientConfigLocation
        /// The client file marks this launch off. A disabled entry cannot run,
        /// so it is neither a bypass nor protection debt.
        let isDisabled: Bool
        /// Keys on the scanned entry that shape how the child runs and have no
        /// `mcpUpstreams` equivalent. Wrapping would drop them.
        let unsupportedKeys: [String]
        /// How many environment values the client file sets for the child,
        /// ignoring Authsia's own upstream key. The count only: names and
        /// values of a child's environment are never retained or reported.
        let childEnvironmentCount: Int
    }

    private struct ContextualObservedServer {
        let entry: ObservedServer
        let workspaceRoot: URL?
        let workspacePathLabel: String?
        let precedence: MCPClientConfigPrecedence
    }

    private struct PrecedenceKey: Hashable {
        let source: MCPClientConfigSource
        let serverName: String
        let workspacePath: String
    }
}
