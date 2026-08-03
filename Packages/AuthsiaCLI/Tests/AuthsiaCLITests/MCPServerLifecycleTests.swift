import ArgumentParser
import Foundation
import MCP
import Testing
@testable import authsia

@Suite("Local MCP server lifecycle")
struct MCPServerLifecycleTests {
    @Test("hidden serve command is registered at the root")
    func commandRegistration() throws {
        #expect(MCPCommand.Serve.configuration.shouldDisplay == false)
        #expect(Authsia.configuration.subcommands.contains { $0 == MCPCommand.self })
        _ = try Authsia.parseAsRoot(["mcp", "serve"])
    }

    @Test("initialize advertises tools only and supports ping")
    func initializationAndDiscovery() async throws {
        let fixture = try makeServer()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let server = fixture.server
        let client = Client(name: "MCP lifecycle test", version: "1")

        try await server.start(transport: transports.server)
        let initialized = try await client.connect(transport: transports.client)

        #expect(initialized.capabilities.tools != nil)
        #expect(initialized.capabilities.resources == nil)
        #expect(initialized.capabilities.prompts == nil)
        #expect(initialized.capabilities.logging == nil)

        let listed = try await client.listTools()
        #expect(listed.tools.map(\.name) == AuthsiaMCPToolName.allCases.map(\.rawValue))
        try await client.ping()

        await client.disconnect()
        await server.waitUntilCompleted()
    }

    @Test("unknown calls return a structured tool error")
    func unknownToolCall() async throws {
        let fixture = try makeServer()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let server = fixture.server
        let client = Client(name: "MCP lifecycle test", version: "1")

        try await server.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)
        let result = try await client.callTool(name: "not_an_authsia_tool")

        #expect(result.isError == true)

        await client.disconnect()
        await server.waitUntilCompleted()
    }

    @Test("diagnostics use the injected sink, never protocol output")
    func diagnosticsAreSeparated() async throws {
        let recorder = DiagnosticRecorder()
        let fixture = try makeServer { recorder.append($0) }
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let server = fixture.server
        let client = Client(name: "MCP lifecycle test", version: "1")

        try await server.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)
        await client.disconnect()
        await server.waitUntilCompleted()

        #expect(recorder.messages.contains("Authsia MCP server started"))
        #expect(recorder.messages.contains("Authsia MCP server stopped"))
    }

    private func makeServer(
        diagnostics: @escaping AuthsiaMCPServer.Diagnostics = { _ in }
    ) throws -> (server: AuthsiaMCPServer, root: URL) {
        let root = try makeWorkspaceRoot()
        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                workspace: .init(name: "lifecycle", authsiaFolder: "Workspaces/lifecycle"),
                managedEnvFiles: [],
                agents: nil
            ),
            toWorkspaceRoot: root
        )
        let runtime = MCPRuntimeContext(startingDirectory: root)
        return (
            AuthsiaMCPServer(
                version: "test",
                runtimeContext: runtime,
                diagnostics: diagnostics
            ),
            root
        )
    }
}

private final class DiagnosticRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String] = []

    var messages: [String] {
        lock.withLock { storage }
    }

    func append(_ message: String) {
        lock.withLock { storage.append(message) }
    }
}
