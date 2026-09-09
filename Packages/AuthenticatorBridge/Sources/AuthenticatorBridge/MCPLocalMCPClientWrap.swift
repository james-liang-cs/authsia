import CryptoKit
import Foundation

/// Confirmed replacement of a scanned client MCP launch with `authsia mcp proxy`.
///
/// Authsia still never rewrites a client file silently. `plan` is read-only.
/// `apply` writes only when the file checksum still matches the plan.
public enum MCPLocalMCPClientWrap {
    public static let maximumConfigBytes: UInt64 = 1_048_576

    public struct GlobalChange: Equatable, Sendable {
        public let fileURL: URL
        public let checksum: String
        public let replacement: Data
        public let projectReplacement: Data
    }

    public struct Plan: Equatable, Sendable {
        public let finding: MCPClientServerFinding
        public let fileURL: URL
        public let checksum: String
        public let existingSnippet: String
        public let replacementSnippet: String
        /// Optional workspace binding captured in the reviewed plan for clients
        /// without their own launch context.
        public let workspacePath: String?
        public let globalChange: GlobalChange?

        public init(
            finding: MCPClientServerFinding,
            fileURL: URL,
            checksum: String,
            existingSnippet: String,
            replacementSnippet: String,
            workspacePath: String? = nil,
            globalChange: GlobalChange? = nil
        ) {
            self.finding = finding
            self.fileURL = fileURL
            self.checksum = checksum
            self.existingSnippet = existingSnippet
            self.replacementSnippet = replacementSnippet
            self.workspacePath = workspacePath
            self.globalChange = globalChange
        }
    }

    public enum WrapError: Error, Equatable, LocalizedError {
        case notWrapEligible
        case overriddenByProject
        case missingFile
        case configTooLarge
        case malformedConfig
        case checksumMismatch
        case writeFailed
        case missingWorkspaceBinding

        public var errorDescription: String? {
            switch self {
            case .notWrapEligible:
                return "This local MCP server cannot be wrapped as a stdio proxy launch."
            case .overriddenByProject:
                return "This user-global entry is not the launch that wins. Wrap the project file instead."
            case .missingFile:
                return "The scanned client file is no longer present."
            case .configTooLarge:
                return "Client config is larger than 1 MiB."
            case .malformedConfig:
                return "Client config is not valid or does not contain this server."
            case .checksumMismatch:
                return "The client file changed since this wrap was planned. Scan again."
            case .writeFailed:
                return "Could not write the client file."
            case .missingWorkspaceBinding:
                return "Select a managed workspace before protecting this client launch."
            }
        }
    }

    public static func fileURL(
        for finding: MCPClientServerFinding,
        homeDirectory: URL
    ) -> URL {
        if let path = finding.configFilePath, path.hasPrefix("/") {
            return URL(fileURLWithPath: path)
        }
        var label = finding.configPathLabel
        if label.hasSuffix(" (local scope)") {
            label = String(label.dropLast(" (local scope)".count))
        }
        if label == "~" {
            return homeDirectory
        }
        if label.hasPrefix("~/") {
            return homeDirectory.appendingPathComponent(String(label.dropFirst(2)))
        }
        return URL(fileURLWithPath: label)
    }

    public static func checksum(of data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    #if os(macOS)
    /// Repair only the generated Cursor placeholder, preserving all other client
    /// settings. The existing management confirmation applies the checked change.
    public static func workspaceRepair(
        for finding: MCPClientServerFinding,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser
    ) throws -> MCPPreparedFileChange? {
        guard finding.source == .cursor, finding.configScope == .project,
              finding.precedence == .effective, finding.status == .admittedWrapped,
              finding.isAuthsiaProxyLaunch else { return nil }
        let file = fileURL(for: finding, homeDirectory: homeDirectory)
        let before = try readConfig(at: file, fileManager: .default)
        guard var object = try JSONSerialization.jsonObject(with: before) as? [String: Any],
              var servers = object["mcpServers"] as? [String: Any],
              var entry = servers[finding.serverName] as? [String: Any],
              let command = entry["command"] as? String,
              URL(fileURLWithPath: command).lastPathComponent == "authsia",
              let args = entry["args"] as? [String],
              var env = entry["env"] as? [String: Any],
              entry["disabled"] as? Bool != true,
              let upstream = MCPProxyClientLaunch.wrappedUpstreamName(arguments: args,
                  environmentName: env[MCPProxyClientLaunch.environmentKey] as? String),
              upstream.lowercased() == finding.declaredUpstreamName?.lowercased(),
              env[MCPProxyClientLaunch.workspaceEnvironmentKey] as? String == "${workspaceFolder}" else { return nil }
        env.removeValue(forKey: MCPProxyClientLaunch.workspaceEnvironmentKey)
        entry["env"] = env; servers[finding.serverName] = entry; object["mcpServers"] = servers
        let after = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        return MCPPreparedFileChange(fileURL: file, original: before, replacement: after)
    }
    #endif

    public static func plan(
        finding: MCPClientServerFinding,
        authsiaCommand: String,
        fileURL: URL? = nil,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser,
        fileManager: FileManager = .default
    ) throws -> Plan {
        if finding.source == .cursor, finding.configScope == .userGlobal {
            return try planCursorProject(finding: finding, authsiaCommand: authsiaCommand,
                fileURL: fileURL, homeDirectory: homeDirectory, fileManager: fileManager)
        }
        return try plan(
            finding: finding,
            authsiaCommand: authsiaCommand,
            fileURL: fileURL,
            homeDirectory: homeDirectory,
            fileManager: fileManager,
            allowInsert: false
        )
    }

    private static func planCursorProject(
        finding: MCPClientServerFinding,
        authsiaCommand: String,
        fileURL: URL?,
        homeDirectory: URL,
        fileManager: FileManager
    ) throws -> Plan {
        guard finding.precedence != .overridden else { throw WrapError.overriddenByProject }
        guard finding.isWrapEligible || finding.isAuthsiaProxyLaunch,
              finding.status != .disabled else { throw WrapError.notWrapEligible }
        guard let label = finding.workspacePathLabel else { throw WrapError.missingWorkspaceBinding }
        let root = label.hasPrefix("~/")
            ? homeDirectory.appendingPathComponent(String(label.dropFirst(2))).path : label
        guard root.hasPrefix("/") else { throw WrapError.missingWorkspaceBinding }
        let globalURL = fileURL ?? Self.fileURL(for: finding, homeDirectory: homeDirectory)
        let before = try readConfig(at: globalURL, fileManager: fileManager)
        // Keep the global fallback protected but unbound. A project override is
        // the only entry that may carry that project's policy location.
        guard var globalObject = try JSONSerialization.jsonObject(with: before) as? [String: Any],
              var globalServers = globalObject["mcpServers"] as? [String: Any],
              var globalEntry = globalServers[finding.serverName] as? [String: Any] else {
            throw WrapError.malformedConfig
        }
        let inheritedEntry = globalEntry
        globalEntry.removeValue(forKey: "cwd")
        globalServers[finding.serverName] = globalEntry
        globalObject["mcpServers"] = globalServers
        let globalAfter = try rewriteJSON(JSONSerialization.data(withJSONObject: globalObject), source: .cursor,
            serverName: finding.serverName, authsiaCommand: authsiaCommand,
            workspacePath: nil, projectKey: nil, recoveryValue: recoveryValue(for: finding))
        let projectURL = URL(fileURLWithPath: root).appendingPathComponent(".cursor/mcp.json")
        guard projectURL.standardizedFileURL != globalURL.standardizedFileURL else {
            throw WrapError.notWrapEligible
        }
        let projectFinding = MCPClientServerFinding(source: .cursor,
            serverName: finding.serverName, commandLabel: finding.commandLabel,
            status: .unadmitted, declaredUpstreamName: finding.declaredUpstreamName,
            configPathLabel: projectURL.path, configScope: .project, precedence: .effective,
            workspacePathLabel: root, wrapCommand: finding.wrapCommand,
            wrapArguments: finding.wrapArguments, isWrapEligible: true,
            childEnvironmentCount: finding.childEnvironmentCount, configFilePath: projectURL.path)
        let projectPlan = try plan(finding: projectFinding, authsiaCommand: authsiaCommand,
            fileURL: projectURL, homeDirectory: homeDirectory, fileManager: fileManager, allowInsert: true)
        let projectBefore = fileManager.fileExists(atPath: projectURL.path)
            ? try readConfig(at: projectURL, fileManager: fileManager) : Data("{}".utf8)
        guard checksum(of: projectBefore) == projectPlan.checksum else { throw WrapError.checksumMismatch }
        guard var projectObject = try JSONSerialization.jsonObject(with: projectBefore) as? [String: Any] else {
            throw WrapError.malformedConfig
        }
        var projectServers = projectObject["mcpServers"] as? [String: Any] ?? [:]
        projectServers[finding.serverName] = inheritedEntry
        projectObject["mcpServers"] = projectServers
        let inheritedData = try JSONSerialization.data(withJSONObject: projectObject)
        let projectAfter = try rewriteJSON(inheritedData, source: .cursor,
            serverName: finding.serverName, authsiaCommand: authsiaCommand,
            workspacePath: projectPlan.workspacePath, projectKey: nil, recoveryValue: recoveryValue(for: finding))
        return Plan(finding: projectPlan.finding, fileURL: projectPlan.fileURL,
            checksum: projectPlan.checksum,
            existingSnippet: projectPlan.existingSnippet + "\nGlobal entry (\(globalURL.path)):\n"
                + (try existingSnippet(for: finding, data: before)),
            replacementSnippet: (try replacementSnippet(for: projectFinding, authsiaCommand: authsiaCommand,
                data: inheritedData, workspacePath: projectPlan.workspacePath))
                + "\nGlobal entry (\(globalURL.path)):\n"
                + (try existingSnippet(for: finding, data: globalAfter)),
            workspacePath: projectPlan.workspacePath,
            globalChange: GlobalChange(fileURL: globalURL, checksum: checksum(of: before),
                replacement: globalAfter, projectReplacement: projectAfter))
    }

    private static func plan(
        finding: MCPClientServerFinding,
        authsiaCommand: String,
        fileURL: URL?,
        homeDirectory: URL,
        fileManager: FileManager,
        allowInsert: Bool
    ) throws -> Plan {
        try validateFinding(finding, homeDirectory: homeDirectory)
        let url = fileURL ?? Self.fileURL(for: finding, homeDirectory: homeDirectory)
        let data: Data
        if fileManager.fileExists(atPath: url.path) {
            data = try readConfig(at: url, fileManager: fileManager)
        } else if allowInsert {
            data = Data("{}".utf8)
        } else {
            throw WrapError.missingFile
        }
        let workspacePath = wrapWorkspacePath(for: finding, homeDirectory: homeDirectory)
        let replacement = try replacementSnippet(
            for: finding,
            authsiaCommand: authsiaCommand,
            data: data,
            workspacePath: workspacePath
        )
        let existing = try existingSnippet(for: finding, data: data, allowInsert: allowInsert)
        guard !allowInsert || existing == "Not present in this client file." else {
            throw WrapError.notWrapEligible
        }
        return Plan(
            finding: finding,
            fileURL: url,
            checksum: checksum(of: data),
            existingSnippet: existing,
            replacementSnippet: replacement,
            workspacePath: workspacePath
        )
    }

    public static func apply(
        _ plan: Plan,
        authsiaCommand: String,
        fileManager: FileManager = .default
    ) throws {
        try validateFinding(plan.finding, workspacePath: plan.workspacePath)
        let data: Data
        if fileManager.fileExists(atPath: plan.fileURL.path) {
            data = try readConfig(at: plan.fileURL, fileManager: fileManager)
        } else if plan.checksum == checksum(of: Data("{}".utf8)) {
            data = Data("{}".utf8)
        } else {
            throw WrapError.missingFile
        }
        guard checksum(of: data) == plan.checksum else {
            throw WrapError.checksumMismatch
        }
        if let global = plan.globalChange {
            guard checksum(of: try readConfig(at: global.fileURL, fileManager: fileManager)) == global.checksum else {
                throw WrapError.checksumMismatch
            }
        }
        let encoded: Data
        if let global = plan.globalChange {
            encoded = global.projectReplacement
        } else {
            switch plan.finding.source {
            case .codex:
                guard let text = String(data: data, encoding: .utf8),
                      let rewritten = rewriteCodex(
                        text,
                        serverName: plan.finding.serverName,
                        replacement: plan.replacementSnippet
                      ) else {
                    throw WrapError.malformedConfig
                }
                encoded = Data(rewritten.utf8)
            case .claude, .cursor, .devin, .vscode, .claudeDesktop:
                encoded = try rewriteJSON(
                    data,
                    source: plan.finding.source,
                    serverName: plan.finding.serverName,
                    authsiaCommand: authsiaCommand,
                    workspacePath: plan.workspacePath,
                    projectKey: plan.finding.projectKey,
                    recoveryValue: recoveryValue(for: plan.finding)
                )
            case .authsiaCatalog:
                throw WrapError.notWrapEligible
            }
        }
        do {
            // Clear the global pin first: a subsequent project write failure
            // must not leave other projects using the old workspace policy.
            if let global = plan.globalChange {
                try global.replacement.write(to: global.fileURL, options: .atomic)
            }
            try fileManager.createDirectory(
                at: plan.fileURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try encoded.write(to: plan.fileURL, options: .atomic)
        } catch {
            throw WrapError.writeFailed
        }
    }

    /// Prefer the launch that actually runs: effective project over user-global.
    public static func preferredFinding(
        named serverName: String,
        in findings: [MCPClientServerFinding]
    ) -> MCPClientServerFinding? {
        let matches = findings.filter {
            $0.serverName == serverName
                && ($0.isWrapEligible || ($0.source == .cursor && $0.configScope == .userGlobal && $0.isAuthsiaProxyLaunch))
                && $0.precedence != .overridden && $0.status != .disabled
        }
        if let project = matches.first(where: { $0.configScope == .project }) {
            return project
        }
        return matches.first
    }

    /// File a confirmed STDIO enroll writes when the client does not already
    /// name this server. Cursor always uses a project file. Other clients prefer
    /// an existing project file, otherwise their user-global JSON config.
    public static func enrollmentLocation(
        source: MCPClientConfigSource,
        workspacePath: String,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser,
        fileManager: FileManager = .default
    ) throws -> MCPClientConfigLocation {
        guard source.supportsSTDIOEnrollment else { throw WrapError.notWrapEligible }
        let root = URL(fileURLWithPath: workspacePath, isDirectory: true).standardizedFileURL
        let project = MCPClientConfigLocation.projectLocations(
            workspaceRoots: [root],
            homeDirectory: homeDirectory
        ).filter { $0.source == source }
        if source == .cursor, let location = project.first { return location }
        if let existingProject = project.first(where: {
            $0.projectKey == nil && fileManager.fileExists(atPath: $0.fileURL.path)
        }) {
            return existingProject
        }
        if source == .claude, let local = project.first(where: { $0.projectKey != nil }) {
            return local
        }
        let known = MCPClientConfigLocation.knownLocations(homeDirectory: homeDirectory)
            .filter { $0.source == source }
        if let existing = known.first(where: { fileManager.fileExists(atPath: $0.fileURL.path) }) {
            return existing
        }
        guard let fallback = known.first else { throw WrapError.notWrapEligible }
        return fallback
    }

    /// Insert `authsia mcp proxy` for a declared STDIO upstream that this
    /// client file does not yet name. Does not copy workspace env or secrets.
    public static func planInsert(
        source: MCPClientConfigSource,
        serverName: String,
        workspacePath: String,
        authsiaCommand: String,
        upstream: MCPUpstreamConfig? = nil,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser,
        fileManager: FileManager = .default
    ) throws -> Plan {
        guard MCPProxyClientLaunch.validUpstreamName(serverName) != nil else {
            throw WrapError.notWrapEligible
        }
        let location = try enrollmentLocation(
            source: source,
            workspacePath: workspacePath,
            homeDirectory: homeDirectory,
            fileManager: fileManager
        )
        let workspaceLabel = location.workspacePathLabel
            ?? (source.hasWorkspaceOfItsOwn
                ? nil
                : workspacePath)
        let finding = MCPClientServerFinding(
            source: source,
            serverName: serverName,
            commandLabel: "authsia mcp proxy",
            status: .unadmitted,
            declaredUpstreamName: serverName,
            configPathLabel: location.displayPath,
            configScope: location.scope,
            precedence: .effective,
            workspacePathLabel: workspaceLabel,
            wrapCommand: upstream?.command ?? "authsia",
            wrapArguments: upstream?.args ?? MCPProxyClientLaunch.arguments,
            isWrapEligible: true,
            configFilePath: location.fileURL.path,
            projectKey: location.projectKey
        )
        return try plan(
            finding: finding,
            authsiaCommand: authsiaCommand,
            fileURL: location.fileURL,
            homeDirectory: homeDirectory,
            fileManager: fileManager,
            allowInsert: true
        )
    }

    private static func validateFinding(
        _ finding: MCPClientServerFinding,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser,
        workspacePath: String? = nil
    ) throws {
        guard finding.isWrapEligible, finding.precedence != .overridden else {
            throw finding.precedence == .overridden
                ? WrapError.overriddenByProject
                : WrapError.notWrapEligible
        }
        guard MCPProxyClientLaunch.validUpstreamName(finding.serverName) != nil else {
            throw WrapError.notWrapEligible
        }
        let resolvedWorkspace = workspacePath
            ?? wrapWorkspacePath(for: finding, homeDirectory: homeDirectory)
        guard finding.source.hasWorkspaceOfItsOwn || resolvedWorkspace != nil else {
            throw WrapError.missingWorkspaceBinding
        }
    }

    /// The workspace a wrapped launch binds to when the client has no repository
    /// context of its own. Named in the
    /// environment rather than argv, preserving company command allowlists.
    public static func wrapWorkspacePath(
        for finding: MCPClientServerFinding,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> String? {
        // Cursor supplies WORKSPACE_FOLDER_PATHS itself. A configured placeholder
        // overrides that native value without being expanded by its stdio launcher.
        guard !finding.source.hasWorkspaceOfItsOwn,
              let label = finding.workspacePathLabel,
              !label.isEmpty else {
            return nil
        }
        if label.hasPrefix("~/") {
            return homeDirectory.appendingPathComponent(String(label.dropFirst(2))).path
        }
        return label.hasPrefix("/") ? label : nil
    }

    static func readConfig(at url: URL, fileManager: FileManager) throws -> Data {
        guard fileManager.fileExists(atPath: url.path) else {
            throw WrapError.missingFile
        }
        guard let attributes = try? fileManager.attributesOfItem(atPath: url.path),
              let size = (attributes[.size] as? NSNumber)?.uint64Value,
              size <= maximumConfigBytes else {
            throw WrapError.configTooLarge
        }
        guard let data = try? Data(contentsOf: url) else {
            throw WrapError.missingFile
        }
        return data
    }

    private static func recoveryValue(for finding: MCPClientServerFinding) -> String? {
        MCPProxyClientLaunch.recoveryValue(name: finding.serverName, command: finding.wrapCommand,
                                          arguments: finding.wrapArguments)
    }

    private static func recoveryEnvironment(for finding: MCPClientServerFinding) -> [String: String] {
        var environment = MCPProxyClientLaunch.environment(upstreamName: finding.serverName)
        environment[MCPProxyClientLaunch.recoveryEnvironmentKey] = recoveryValue(for: finding)
        return environment
    }

    private static func replacementSnippet(
        for finding: MCPClientServerFinding,
        authsiaCommand: String,
        data: Data,
        workspacePath: String?
    ) throws -> String {
        guard let authsia = MCPLocalMCPWrapRecipe.sanitizedCommand(authsiaCommand) else {
            throw WrapError.notWrapEligible
        }
        switch finding.source {
        case .codex:
            return MCPLocalMCPWrapRecipe.codexTable(
                name: finding.serverName,
                authsiaCommand: authsia,
                environment: recoveryEnvironment(for: finding),
                preservedLines: preservedCodexLines(data: data, serverName: finding.serverName)
            )
        case .claude, .cursor, .devin, .vscode, .claudeDesktop:
            return prettyJSON(jsonObject(
                authsiaCommand: authsia,
                upstreamName: finding.serverName,
                includeType: finding.source == .vscode,
                workspacePath: workspacePath,
                recoveryValue: recoveryValue(for: finding),
                preserving: preservedJSONKeys(
                    data: data,
                    source: finding.source,
                    serverName: finding.serverName,
                    projectKey: finding.projectKey
                )
            ))
        case .authsiaCatalog:
            throw WrapError.notWrapEligible
        }
    }

    /// Keys the human set on the scanned entry that Authsia does not manage.
    /// The wrap replaces the launch, not the rest of the entry.
    static func preservedJSONKeys(
        data: Data,
        source: MCPClientConfigSource,
        serverName: String,
        projectKey: String? = nil
    ) -> [String: Any] {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let servers = jsonServers(in: root, source: source, projectKey: projectKey),
              let existing = servers[serverName] as? [String: Any] else {
            return [:]
        }
        return existing.filter { key, _ in !managedJSONKeys.contains(key) }
    }

    static func preservedCodexLines(data: Data, serverName: String) -> [String] {
        guard let text = String(data: data, encoding: .utf8),
              let table = extractCodexTable(text, serverName: serverName) else {
            return []
        }
        var preserved: [String] = []
        var sawTableHeader = false
        for rawLine in table.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            // Only the entry's own top-level keys are preserved. Everything
            // from the first sub-table on -- `env` above all -- is replaced by
            // the proxy's own environment and must not be carried forward.
            if line.hasPrefix("["), line.hasSuffix("]") {
                if sawTableHeader { break }
                sawTableHeader = true
                continue
            }
            guard !line.hasPrefix("#"), let equals = line.firstIndex(of: "=") else { continue }
            let key = String(line[..<equals]).trimmingCharacters(in: .whitespaces)
            guard !managedCodexKeys.contains(key),
                  !MCPClientConfigScanner.unsupportedLaunchKeys.contains(key) else {
                continue
            }
            preserved.append(line)
        }
        return preserved
    }

    private static let managedJSONKeys: Set<String> = ["command", "args", "env", "type"]
    private static let managedCodexKeys: Set<String> = ["command", "args", "env_vars"]

    static func existingSnippet(
        for finding: MCPClientServerFinding,
        data: Data,
        allowInsert: Bool = false
    ) throws -> String {
        switch finding.source {
        case .codex:
            guard let text = String(data: data, encoding: .utf8),
                  let snippet = extractCodexTable(text, serverName: finding.serverName) else {
                throw WrapError.malformedConfig
            }
            return redactCodexEnvValues(snippet)
        case .claude, .cursor, .devin, .vscode, .claudeDesktop:
            guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw WrapError.malformedConfig
            }
            if let servers = jsonServers(
                in: root,
                source: finding.source,
                projectKey: finding.projectKey
            ), let value = servers[finding.serverName] {
                return prettyJSON(redactingEnvValues(value))
            }
            guard allowInsert else { throw WrapError.malformedConfig }
            return "Not present in this client file."
        case .authsiaCatalog:
            throw WrapError.notWrapEligible
        }
    }

    /// Plan diffs keep env keys so the human sees what Protect will not copy,
    /// and replace every value. The scanner already stores only a count.
    static func redactingEnvValues(_ value: Any) -> Any {
        guard var object = value as? [String: Any],
              let env = object["env"] as? [String: Any] else {
            return value
        }
        object["env"] = Dictionary(uniqueKeysWithValues: env.keys.map { ($0, "•••" as Any) })
        return object
    }

    static func redactCodexEnvValues(_ snippet: String) -> String {
        var inEnvTable = false
        return snippet.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline)
            .map { rawLine -> String in
                let line = String(rawLine)
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("["), trimmed.hasSuffix("]") {
                    inEnvTable = trimmed.hasSuffix(".env]")
                    return line
                }
                guard inEnvTable, let equals = trimmed.firstIndex(of: "=") else {
                    return line
                }
                let key = String(trimmed[..<equals]).trimmingCharacters(in: .whitespaces)
                guard !key.isEmpty else { return line }
                let indent = String(line.prefix { $0.isWhitespace })
                return "\(indent)\(key) = \"•••\""
            }
            .joined(separator: "\n")
    }

    private static func rewriteJSON(
        _ data: Data,
        source: MCPClientConfigSource,
        serverName: String,
        authsiaCommand: String,
        workspacePath: String?,
        projectKey: String?,
        recoveryValue: String?
    ) throws -> Data {
        guard let authsia = MCPLocalMCPWrapRecipe.sanitizedCommand(authsiaCommand) else {
            throw WrapError.notWrapEligible
        }
        guard var root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw WrapError.malformedConfig
        }
        var servers = jsonServers(in: root, source: source, projectKey: projectKey) ?? [:]
        servers[serverName] = jsonObject(
            authsiaCommand: authsia,
            upstreamName: serverName,
            includeType: source == .vscode,
            workspacePath: workspacePath,
            recoveryValue: recoveryValue,
            preserving: preservedJSONKeys(
                data: data,
                source: source,
                serverName: serverName,
                projectKey: projectKey
            )
        )
        root = try replacingJSONServers(
            in: root,
            source: source,
            projectKey: projectKey,
            servers: servers
        )
        guard let encoded = try? JSONSerialization.data(
            withJSONObject: root,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        ) else {
            throw WrapError.writeFailed
        }
        return encoded
    }

    private static func jsonObject(
        authsiaCommand: String,
        upstreamName: String,
        includeType: Bool,
        workspacePath: String? = nil,
        recoveryValue: String? = nil,
        preserving preserved: [String: Any] = [:]
    ) -> [String: Any] {
        var object = preserved
        object["command"] = authsiaCommand
        object["args"] = MCPProxyClientLaunch.arguments
        // The child's credentials never survive the wrap: the proxy resolves
        // them from workspace policy instead of the client file.
        var environment = MCPProxyClientLaunch.environment(
            upstreamName: upstreamName,
            workspacePath: workspacePath
        )
        environment[MCPProxyClientLaunch.recoveryEnvironmentKey] = recoveryValue
        object["env"] = environment
        if includeType {
            object["type"] = "stdio"
        }
        return object
    }

    static func jsonServersKey(for source: MCPClientConfigSource) -> String {
        source == .vscode ? "servers" : "mcpServers"
    }

    static func jsonServers(
        in root: [String: Any],
        source: MCPClientConfigSource,
        projectKey: String?
    ) -> [String: Any]? {
        let container: [String: Any]
        if let projectKey {
            guard let projects = root["projects"] as? [String: Any],
                  let project = projects[projectKey] as? [String: Any] else {
                return nil
            }
            container = project
        } else {
            container = root
        }
        return container[jsonServersKey(for: source)] as? [String: Any]
    }

    static func replacingJSONServers(
        in root: [String: Any],
        source: MCPClientConfigSource,
        projectKey: String?,
        servers: [String: Any]
    ) throws -> [String: Any] {
        var next = root
        if let projectKey {
            var projects = next["projects"] as? [String: Any] ?? [:]
            var project = projects[projectKey] as? [String: Any] ?? [:]
            project[jsonServersKey(for: source)] = servers
            projects[projectKey] = project
            next["projects"] = projects
            return next
        }
        next[jsonServersKey(for: source)] = servers
        return next
    }

    static func prettyJSON(_ value: Any) -> String {
        guard JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(
                withJSONObject: value,
                options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
              ) else {
            return String(describing: value)
        }
        return String(data: data, encoding: .utf8) ?? "{}"
    }

    private static func extractCodexTable(_ text: String, serverName: String) -> String? {
        guard let range = tableRange(in: text, serverName: serverName) else { return nil }
        return String(text[range]).trimmingCharacters(in: .newlines)
    }

    static func rewriteCodex(
        _ text: String,
        serverName: String,
        replacement: String
    ) -> String? {
        guard let range = tableRange(in: text, serverName: serverName) else { return nil }
        var result = text
        result.replaceSubrange(range, with: replacement.trimmingCharacters(in: .newlines) + "\n")
        return result
    }

    private static func tableRange(in text: String, serverName: String) -> Range<String.Index>? {
        var start: String.Index?
        var end = text.endIndex
        var lineStart = text.startIndex
        var index = text.startIndex

        func considerLine(lineEnd: String.Index) {
            let line = text[lineStart..<lineEnd].trimmingCharacters(in: .whitespaces)
            guard line.hasPrefix("["), line.hasSuffix("]") else { return }
            let heading = String(line.dropFirst().dropLast())
            if isCodexHeading(heading, serverName: serverName) {
                if start == nil {
                    start = lineStart
                }
            } else if start != nil {
                end = lineStart
            }
        }

        while index < text.endIndex {
            if text[index] == "\n" {
                considerLine(lineEnd: index)
                if start != nil, end != text.endIndex {
                    break
                }
                index = text.index(after: index)
                lineStart = index
                continue
            }
            index = text.index(after: index)
        }
        if lineStart < text.endIndex {
            considerLine(lineEnd: text.endIndex)
        }
        guard let start else { return nil }
        return start..<end
    }

    private static func isCodexHeading(_ heading: String, serverName: String) -> Bool {
        let unquoted = heading.replacingOccurrences(of: "\"", with: "")
        return unquoted == "mcp_servers.\(serverName)"
            || unquoted.hasPrefix("mcp_servers.\(serverName).")
    }
}
