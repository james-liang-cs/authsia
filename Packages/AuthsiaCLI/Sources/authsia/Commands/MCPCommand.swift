import ArgumentParser
import Foundation

struct MCPCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mcp",
        abstract: "Connect local AI clients to Authsia",
        discussion: """
            Print client configuration or run Authsia's local stdio MCP server.
            Most users should configure a supported client, which launches the server
            automatically from the client's active working directory.

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

        @Option(help: "Client: codex, claude, cursor, windsurf, or vscode")
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

        @Option(help: "Workspace directory used for binding (defaults to current directory)")
        var workspace: String?

        mutating func run() async throws {
            let startingDirectory = URL(
                fileURLWithPath: workspace ?? FileManager.default.currentDirectoryPath,
                isDirectory: true
            )
            let server = AuthsiaMCPServer(
                version: Authsia.version(),
                runtimeContext: MCPRuntimeContext(startingDirectory: startingDirectory)
            )
            try await server.runStdio()
        }
    }
}
