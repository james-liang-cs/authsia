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

            Examples:
              authsia mcp configure --client codex
              authsia mcp serve --workspace /path/to/repository
            """,
        subcommands: [Configure.self, Serve.self]
    )

    struct Configure: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Print user-global MCP client configuration"
        )

        @Option(help: "Client: codex, claude, cursor, devin, or vscode")
        var client: MCPClient

        mutating func run() throws {
            print(try MCPClientConfiguration.render(
                client: client,
                executableURL: Authsia.currentExecutableURL()
            ))
        }
    }

    struct Serve: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Serve Authsia tools over local stdio"
        )

        @Option(help: "Explicit workspace binding (otherwise uses tool input or launch context)")
        var workspace: String?

        mutating func run() async throws {
            let startingDirectory = Self.startingDirectory(
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
    }
}
