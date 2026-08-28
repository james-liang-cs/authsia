import ArgumentParser
import AuthenticatorBridge
import Foundation

struct MCPCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mcp",
        abstract: "Connect local AI clients to Authsia",
        discussion: """
            Print client configuration or run Authsia's local stdio MCP server.
            Most users should configure a supported client, which launches the server
            automatically and supplies its active workspace when supported.
            Enable MCP Integrations in Authsia Settings > Developer Access first.
            `mcp proxy` wraps one named workspace upstream as a separate stdio
            process; it does not add tools to `mcp serve`. Clients launch a stable
            `mcp proxy` argv and set AUTHSIA_MCP_UPSTREAM; `--upstream` is optional
            for terminal use.

            Examples:
              authsia mcp configure --client codex
              authsia mcp serve --workspace /path/to/repository
              authsia mcp proxy --upstream jira
            """,
        subcommands: [Configure.self, Serve.self, Proxy.self]
    )

    static func startingDirectory(
        workspace: String?,
        environment: [String: String],
        currentDirectoryPath: String
    ) -> URL {
        let clientWorkspacePath: String?
        if let value = environment["WORKSPACE_FOLDER_PATHS"] {
            let paths = value.split(separator: ",", omittingEmptySubsequences: false)
            let path = paths.count == 1 ? String(paths[0]) : ""
            clientWorkspacePath = path.hasPrefix("/") && path.unicodeScalars.allSatisfy {
                !CharacterSet.controlCharacters.contains($0)
            } ? path : nil
        } else {
            clientWorkspacePath = nil
        }
        return URL(
            fileURLWithPath: workspace ?? clientWorkspacePath ?? currentDirectoryPath,
            isDirectory: true
        )
    }

    struct Configure: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Print a user-global MCP fallback and effective config report"
        )

        @Option(help: "Client: codex, claude, cursor, devin, or vscode")
        var client: MCPClient

        mutating func run() throws {
            let upstreams = Self.upstreams(
                environment: ProcessInfo.processInfo.environment,
                currentDirectoryPath: FileManager.default.currentDirectoryPath
            )
            print(try MCPClientConfiguration.render(
                client: client,
                executableURL: Authsia.currentExecutableURL(),
                upstreamNames: upstreams.map(\.name)
            ))
            let workspaceRoot = Self.boundWorkspaceRoot(
                environment: ProcessInfo.processInfo.environment,
                currentDirectoryPath: FileManager.default.currentDirectoryPath
            )
            let declared = upstreams.compactMap { upstream -> MCPDeclaredLocalServer? in
                guard upstream.transport == .stdio, let command = upstream.command else { return nil }
                return MCPDeclaredLocalServer(
                    name: upstream.name,
                    command: command,
                    arguments: upstream.args,
                    workspaceRoot: workspaceRoot
                )
            }
            let homeDirectory = FileManager.default.homeDirectoryForCurrentUser
            // The bound workspace's project config outranks the user-global one
            // this command prints, so report it too.
            let locations = MCPClientConfigLocation.knownLocations(
                homeDirectory: homeDirectory
            ) + MCPClientConfigLocation.projectLocations(
                workspaceRoots: workspaceRoot.map { [$0] } ?? [],
                homeDirectory: homeDirectory
            )
            let findings = MCPClientConfigScanner().scan(
                declaredServers: declared,
                locations: locations
            )
            if let report = MCPClientConfiguration.scanReport(findings) {
                print("\n\(report)")
            }
        }

        static func upstreamNames(
            environment: [String: String],
            currentDirectoryPath: String
        ) -> [String] {
            upstreams(
                environment: environment,
                currentDirectoryPath: currentDirectoryPath
            ).map(\.name)
        }

        static func boundWorkspaceRoot(
            environment: [String: String],
            currentDirectoryPath: String
        ) -> URL? {
            MCPRuntimeContext(
                startingDirectory: Serve.startingDirectory(
                    workspace: nil,
                    environment: environment,
                    currentDirectoryPath: currentDirectoryPath
                )
            ).workspaceRoot
        }

        private static func upstreams(
            environment: [String: String],
            currentDirectoryPath: String
        ) -> [MCPUpstreamConfig] {
            guard let root = boundWorkspaceRoot(
                environment: environment,
                currentDirectoryPath: currentDirectoryPath
            ),
                  let config = try? WorkspaceConfigStore.read(fromWorkspaceRoot: root) else {
                return []
            }
            return config.mcpUpstreams
        }
    }

    struct Serve: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Serve Authsia tools over local stdio"
        )

        @Option(help: "Explicit workspace binding (otherwise uses tool input or launch context)")
        var workspace: String?

        mutating func run() async throws {
            let startingDirectory = MCPCommand.startingDirectory(
                workspace: workspace,
                environment: ProcessInfo.processInfo.environment,
                currentDirectoryPath: FileManager.default.currentDirectoryPath
            )
            let server = AuthsiaMCPServer(
                version: Authsia.version(),
                runtimeContext: MCPRuntimeContext(startingDirectory: startingDirectory),
                acceptsToolWorkspace: workspace == nil,
                mcpAccessEnabled: { MCPAccessSettings.isEnabled() }
            )
            try await server.runStdio()
        }

        static func startingDirectory(
            workspace: String?,
            environment: [String: String],
            currentDirectoryPath: String
        ) -> URL {
            MCPCommand.startingDirectory(
                workspace: workspace,
                environment: environment,
                currentDirectoryPath: currentDirectoryPath
            )
        }
    }

    struct Proxy: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Proxy a named workspace upstream over local stdio"
        )

        @Option(help: "Named workspace MCP upstream (or AUTHSIA_MCP_UPSTREAM)")
        var upstream: String?

        @Option(help: "Explicit workspace binding (otherwise uses tool input or launch context)")
        var workspace: String?

        mutating func validate() throws {
            _ = try Self.resolveUpstreamName(
                flag: upstream,
                environment: ProcessInfo.processInfo.environment
            )
        }

        mutating func run() async throws {
            let environment = ProcessInfo.processInfo.environment
            let upstreamName = try Self.resolveUpstreamName(
                flag: upstream,
                environment: environment
            )
            let startingDirectory = MCPCommand.startingDirectory(
                workspace: workspace,
                environment: environment,
                currentDirectoryPath: FileManager.default.currentDirectoryPath
            )
            let proxy = AuthsiaMCPProxy(
                version: Authsia.version(),
                upstreamName: upstreamName,
                runtimeContext: MCPRuntimeContext(startingDirectory: startingDirectory),
                mcpAccessEnabled: { MCPAccessSettings.isEnabled() }
            )
            try await proxy.runStdio()
        }

        static func resolveUpstreamName(
            flag: String?,
            environment: [String: String]
        ) throws -> String {
            let fromFlag = trimmed(flag)
            let fromEnv = trimmed(environment[MCPProxyClientLaunch.environmentKey])
            if let fromFlag, let fromEnv, fromFlag != fromEnv {
                throw ValidationError(
                    "--upstream and AUTHSIA_MCP_UPSTREAM must name the same upstream."
                )
            }
            let name = fromFlag ?? fromEnv
            guard let name else {
                throw ValidationError(
                    "Pass --upstream or set AUTHSIA_MCP_UPSTREAM to a workspace mcpUpstreams name."
                )
            }
            guard WorkspaceConfigStore.isValidMCPUpstreamName(name) else {
                throw ValidationError(
                    "Upstream name must match [A-Za-z][A-Za-z0-9_-]{0,31}."
                )
            }
            return name
        }

        private static func trimmed(_ value: String?) -> String? {
            guard let value else { return nil }
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }
    }
}
