import ArgumentParser
import Foundation

struct MCPCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mcp",
        abstract: "Connect local AI clients to Authsia",
        subcommands: [Configure.self, Serve.self]
    )

    struct Configure: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Print workspace-bound MCP client configuration"
        )

        @Option(help: "Client: codex, claude, cursor, or vscode")
        var client: MCPClient

        mutating func run() throws {
            print(try MCPClientConfiguration.render(
                client: client,
                executableURL: Authsia.currentExecutableURL(),
                startingDirectory: URL(
                    fileURLWithPath: FileManager.default.currentDirectoryPath,
                    isDirectory: true
                )
            ))
        }
    }

    struct Serve: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Serve Authsia tools over local stdio",
            shouldDisplay: false
        )

        mutating func run() async throws {
            let server = AuthsiaMCPServer(version: Authsia.version())
            try await server.runStdio()
        }
    }
}
