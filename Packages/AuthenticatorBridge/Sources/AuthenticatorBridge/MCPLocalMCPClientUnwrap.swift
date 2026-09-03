import Foundation

#if os(macOS)
/// Confirmed restore of a wrapped client MCP launch to the child the workspace
/// declares.
///
/// The mirror of `MCPLocalMCPClientWrap`: `plan` is read-only, and `apply`
/// writes only when the file checksum still matches. Workspace policy is left
/// alone. The `mcpUpstreams` entry the restore reads stays declared, so
/// protecting the launch again keeps the catalog already recorded for it.
public enum MCPLocalMCPClientUnwrap {
    public struct Plan: Equatable, Sendable {
        public let finding: MCPClientServerFinding
        public let fileURL: URL
        public let checksum: String
        public let existingSnippet: String
        public let replacementSnippet: String
        /// Which workspace the restored launch was read from, so the diff can
        /// name it rather than leave the reader to guess.
        public let workspaceRoot: URL
        public let command: String
        public let arguments: [String]
        /// Environment values the workspace declares for this upstream. The
        /// restored launch carries none of them.
        public let declaredEnvironmentCount: Int

        public init(
            finding: MCPClientServerFinding,
            fileURL: URL,
            checksum: String,
            existingSnippet: String,
            replacementSnippet: String,
            workspaceRoot: URL,
            command: String,
            arguments: [String],
            declaredEnvironmentCount: Int
        ) {
            self.finding = finding
            self.fileURL = fileURL
            self.checksum = checksum
            self.existingSnippet = existingSnippet
            self.replacementSnippet = replacementSnippet
            self.workspaceRoot = workspaceRoot
            self.command = command
            self.arguments = arguments
            self.declaredEnvironmentCount = declaredEnvironmentCount
        }
    }

    public enum UnwrapError: Error, Equatable, LocalizedError {
        case notProtected
        case overriddenByProject
        case missingDeclaration
        case declarationChanged
        case missingFile
        case configTooLarge
        case malformedConfig
        case checksumMismatch
        case writeFailed

        public var errorDescription: String? {
            switch self {
            case .notProtected:
                return "This launch does not run the Authsia proxy, so it has no protection to remove."
            case .overriddenByProject:
                return "This user-global entry is not the launch that wins. Restore the project file instead."
            case .missingDeclaration:
                return "This launch's workspace does not declare the upstream as a stdio command, "
                    + "so the launch Authsia replaced is not recorded there. Restore the client entry by hand."
            case .declarationChanged:
                return "The workspace declaration changed while you were reviewing this restore. Scan again."
            case .missingFile:
                return "The scanned client file is no longer present."
            case .configTooLarge:
                return "Client config is larger than 1 MiB."
            case .malformedConfig:
                return "Client config is not valid or does not contain this server."
            case .checksumMismatch:
                return "The client file changed since this restore was planned. Scan again."
            case .writeFailed:
                return "Could not write the client file."
            }
        }
    }

    /// Prefer the launch that actually runs: effective project over user-global.
    public static func preferredFinding(
        named serverName: String,
        in findings: [MCPClientServerFinding]
    ) -> MCPClientServerFinding? {
        let matches = findings.filter {
            $0.serverName == serverName
                && $0.isAuthsiaProxyLaunch
                && $0.precedence != .overridden
        }
        if let project = matches.first(where: { $0.configScope == .project }) {
            return project
        }
        return matches.first
    }

    public static func plan(
        finding: MCPClientServerFinding,
        workspaceRoots: [URL],
        fileURL: URL? = nil,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser,
        fileManager: FileManager = .default
    ) throws -> Plan {
        try validateFinding(finding)
        // The client entry names the upstream it proxies; the child argv lives
        // only in workspace policy, so a name no workspace declares cannot be
        // restored to anything.
        guard let workspaceRoot = restorationWorkspaceRoot(
            for: finding,
            workspaceRoots: workspaceRoots,
            homeDirectory: homeDirectory
        ), let launch = MCPLocalMCPWorkspaceDeclaration.declaredLaunch(
            named: finding.declaredUpstreamName ?? finding.serverName,
            workspaceRoot: workspaceRoot,
            fileManager: fileManager
        ) else {
            throw UnwrapError.missingDeclaration
        }
        let url = fileURL ?? MCPLocalMCPClientWrap.fileURL(
            for: finding,
            homeDirectory: homeDirectory
        )
        let data = try configData(at: url, fileManager: fileManager)
        return Plan(
            finding: finding,
            fileURL: url,
            checksum: MCPLocalMCPClientWrap.checksum(of: data),
            existingSnippet: try existingSnippet(for: finding, data: data),
            replacementSnippet: restoredSnippet(for: finding, launch: launch, data: data),
            workspaceRoot: launch.workspaceRoot,
            command: launch.command,
            arguments: launch.arguments,
            declaredEnvironmentCount: launch.environmentCount
        )
    }

    public static func apply(
        _ plan: Plan,
        fileManager: FileManager = .default
    ) throws {
        try validateFinding(plan.finding)
        guard let currentLaunch = MCPLocalMCPWorkspaceDeclaration.declaredLaunch(
            named: plan.finding.declaredUpstreamName ?? plan.finding.serverName,
            workspaceRoot: plan.workspaceRoot,
            fileManager: fileManager
        ) else {
            throw UnwrapError.missingDeclaration
        }
        guard currentLaunch.command == plan.command,
              currentLaunch.arguments == plan.arguments,
              currentLaunch.environmentCount == plan.declaredEnvironmentCount else {
            throw UnwrapError.declarationChanged
        }
        let data = try configData(at: plan.fileURL, fileManager: fileManager)
        guard MCPLocalMCPClientWrap.checksum(of: data) == plan.checksum else {
            throw UnwrapError.checksumMismatch
        }
        let encoded: Data
        switch plan.finding.source {
        case .codex:
            guard let text = String(data: data, encoding: .utf8),
                  let rewritten = MCPLocalMCPClientWrap.rewriteCodex(
                    text,
                    serverName: plan.finding.serverName,
                    replacement: plan.replacementSnippet
                  ) else {
                throw UnwrapError.malformedConfig
            }
            encoded = Data(rewritten.utf8)
        case .claude, .cursor, .devin, .vscode, .claudeDesktop:
            encoded = try rewriteJSON(data, plan: plan)
        }
        do {
            try encoded.write(to: plan.fileURL, options: .atomic)
        } catch {
            throw UnwrapError.writeFailed
        }
    }

    private static func validateFinding(_ finding: MCPClientServerFinding) throws {
        guard finding.isAuthsiaProxyLaunch else {
            throw UnwrapError.notProtected
        }
        guard finding.precedence != .overridden else {
            throw UnwrapError.overriddenByProject
        }
    }

    /// Resolve the exact workspace context the scanner attached to this row.
    /// A missing context may use a sole explicit root, but multiple roots never
    /// fall through by name.
    private static func restorationWorkspaceRoot(
        for finding: MCPClientServerFinding,
        workspaceRoots: [URL],
        homeDirectory: URL
    ) -> URL? {
        let roots = workspaceRoots.map(\.standardizedFileURL)
        guard let label = finding.workspacePathLabel else {
            return roots.count == 1 ? roots[0] : nil
        }
        let path: String
        if label == "~" {
            path = homeDirectory.standardizedFileURL.path
        } else if label.hasPrefix("~/") {
            path = homeDirectory.appendingPathComponent(String(label.dropFirst(2)))
                .standardizedFileURL.path
        } else if label.hasPrefix("/") {
            path = URL(fileURLWithPath: label, isDirectory: true).standardizedFileURL.path
        } else {
            return nil
        }
        return roots.first { $0.path == path }
    }

    private static func configData(at url: URL, fileManager: FileManager) throws -> Data {
        do {
            return try MCPLocalMCPClientWrap.readConfig(at: url, fileManager: fileManager)
        } catch MCPLocalMCPClientWrap.WrapError.missingFile {
            throw UnwrapError.missingFile
        } catch MCPLocalMCPClientWrap.WrapError.configTooLarge {
            throw UnwrapError.configTooLarge
        } catch {
            throw UnwrapError.malformedConfig
        }
    }

    private static func existingSnippet(
        for finding: MCPClientServerFinding,
        data: Data
    ) throws -> String {
        do {
            return try MCPLocalMCPClientWrap.existingSnippet(for: finding, data: data)
        } catch {
            throw UnwrapError.malformedConfig
        }
    }

    private static func restoredSnippet(
        for finding: MCPClientServerFinding,
        launch: MCPLocalMCPWorkspaceDeclaration.DeclaredLaunch,
        data: Data
    ) -> String {
        switch finding.source {
        case .codex:
            return codexTable(
                name: finding.serverName,
                launch: launch,
                preservedLines: MCPLocalMCPClientWrap.preservedCodexLines(
                    data: data,
                    serverName: finding.serverName
                )
            )
        case .claude, .cursor, .devin, .vscode, .claudeDesktop:
            return MCPLocalMCPClientWrap.prettyJSON(jsonObject(
                launch: launch,
                includeType: finding.source == .vscode,
                preserving: MCPLocalMCPClientWrap.preservedJSONKeys(
                    data: data,
                    source: finding.source,
                    serverName: finding.serverName
                )
            ))
        }
    }

    private static func rewriteJSON(_ data: Data, plan: Plan) throws -> Data {
        guard var root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw UnwrapError.malformedConfig
        }
        let key = MCPLocalMCPClientWrap.jsonServersKey(for: plan.finding.source)
        guard var servers = root[key] as? [String: Any],
              servers[plan.finding.serverName] != nil else {
            throw UnwrapError.malformedConfig
        }
        servers[plan.finding.serverName] = jsonObject(
            launch: MCPLocalMCPWorkspaceDeclaration.DeclaredLaunch(
                workspaceRoot: plan.workspaceRoot,
                command: plan.command,
                arguments: plan.arguments,
                environmentCount: plan.declaredEnvironmentCount
            ),
            includeType: plan.finding.source == .vscode,
            preserving: MCPLocalMCPClientWrap.preservedJSONKeys(
                data: data,
                source: plan.finding.source,
                serverName: plan.finding.serverName
            )
        )
        root[key] = servers
        guard let encoded = try? JSONSerialization.data(
            withJSONObject: root,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        ) else {
            throw UnwrapError.writeFailed
        }
        return encoded
    }

    /// The restored entry sets no `env`. Workspace policy may resolve
    /// `authsia://` references for this child, and those only mean something
    /// inside the proxy, so writing them into a client file would leave a
    /// launch that reads them as literal text.
    private static func jsonObject(
        launch: MCPLocalMCPWorkspaceDeclaration.DeclaredLaunch,
        includeType: Bool,
        preserving preserved: [String: Any]
    ) -> [String: Any] {
        var object = preserved
        object["command"] = launch.command
        if !launch.arguments.isEmpty {
            object["args"] = launch.arguments
        }
        if includeType {
            object["type"] = "stdio"
        }
        return object
    }

    private static func codexTable(
        name: String,
        launch: MCPLocalMCPWorkspaceDeclaration.DeclaredLaunch,
        preservedLines: [String]
    ) -> String {
        var table = """
        [mcp_servers.\(name)]
        command = "\(MCPLocalMCPWrapRecipe.tomlEscaped(launch.command))"
        """
        if !launch.arguments.isEmpty {
            table += "\nargs = \(MCPLocalMCPWrapRecipe.tomlStringArray(launch.arguments))"
        }
        // Settings the human put on the protected launch, such as a raised
        // startup timeout, still apply to the child that replaces it.
        for line in preservedLines {
            table += "\n" + line
        }
        return table
    }
}
#endif
