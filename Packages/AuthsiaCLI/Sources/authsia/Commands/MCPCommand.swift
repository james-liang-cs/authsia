import ArgumentParser

struct MCPCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mcp",
        abstract: "Connect local AI clients to Authsia",
        subcommands: [Serve.self]
    )

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
