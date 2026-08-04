import ArgumentParser

struct MCPCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mcp",
        abstract: "Connect local AI clients to Authsia",
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
            abstract: "Serve Authsia tools over local stdio",
            shouldDisplay: false
        )

        mutating func run() async throws {
            let server = AuthsiaMCPServer(version: Authsia.version())
            try await server.runStdio()
        }
    }
}
