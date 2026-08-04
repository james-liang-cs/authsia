import Foundation
import Testing
@testable import authsia

@Suite("MCP client configuration")
struct MCPClientConfigurationTests {
    @Test("all supported clients receive deterministic exact binary and workspace configuration")
    func supportedClients() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        for client in MCPClient.allCases {
            let first = try MCPClientConfiguration.render(
                client: client,
                executableURL: fixture.binary,
                startingDirectory: fixture.nested
            )
            let second = try MCPClientConfiguration.render(
                client: client,
                executableURL: fixture.binary,
                startingDirectory: fixture.nested
            )

            #expect(first == second)
            #expect(first.contains(fixture.binary.path))
            #expect(first.contains(fixture.root.path))
            #expect(first.contains("mcp"))
            #expect(first.contains("serve"))
            #expect(first.contains("Machine-specific absolute path"))
            #expect(!first.contains("AUTHSIA_ACCESS_CREDENTIAL"))
            #expect(!first.lowercased().contains("bearer"))
            #expect(!first.contains("sh -c"))
            #expect(!first.contains("bash -c"))
        }
    }

    @Test("client shapes match their documented configuration surfaces")
    func clientShapes() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        let codex = try render(.codex, fixture: fixture)
        #expect(codex.contains("[mcp_servers.authsia]"))
        #expect(codex.contains("args = [\"mcp\", \"serve\"]"))
        #expect(codex.contains("cwd = \"" + fixture.root.path + "\""))

        let claude = try render(.claude, fixture: fixture)
        #expect(claude.contains("Place in \(fixture.root.path)/.mcp.json"))
        #expect(claude.contains("\"mcpServers\""))

        let cursor = try render(.cursor, fixture: fixture)
        #expect(cursor.contains("Place in \(fixture.root.path)/.cursor/mcp.json"))
        #expect(cursor.contains("\"mcpServers\""))

        let vscode = try render(.vscode, fixture: fixture)
        #expect(vscode.contains("Place in \(fixture.root.path)/.vscode/mcp.json"))
        #expect(vscode.contains("\"servers\""))
        #expect(vscode.contains("\"type" + "\" : \"stdio\""))
        #expect(vscode.contains("\"cwd\" : \"" + fixture.root.path + "\""))
    }

    @Test("missing workspaces and unsafe paths fail closed")
    func invalidInputs() throws {
        let unmanaged = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: unmanaged) }
        let safeBinary = URL(fileURLWithPath: "/Applications/Authsia.app/Contents/Helpers/authsia")

        #expect(throws: MCPClientConfigurationError.self) {
            try MCPClientConfiguration.render(
                client: .codex,
                executableURL: safeBinary,
                startingDirectory: unmanaged
            )
        }
        #expect(throws: MCPClientConfigurationError.self) {
            try MCPClientConfiguration.render(
                clientName: "codex\nmalicious",
                executableURL: safeBinary,
                startingDirectory: unmanaged
            )
        }
        #expect(throws: MCPClientConfigurationError.self) {
            try MCPClientConfiguration.render(
                clientName: "unsupported",
                executableURL: safeBinary,
                startingDirectory: unmanaged
            )
        }
    }

    @Test("configure command is visible and serve remains hidden")
    func commandRegistration() throws {
        #expect(MCPCommand.Configure.configuration.shouldDisplay)
        #expect(!MCPCommand.Serve.configuration.shouldDisplay)
        _ = try Authsia.parseAsRoot(["mcp", "configure", "--client", "codex"])
    }

    private func render(
        _ client: MCPClient,
        fixture: (root: URL, nested: URL, binary: URL)
    ) throws -> String {
        try MCPClientConfiguration.render(
            client: client,
            executableURL: fixture.binary,
            startingDirectory: fixture.nested
        )
    }

    private func makeFixture() throws -> (root: URL, nested: URL, binary: URL) {
        let root = try makeWorkspaceRoot()
        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                workspace: .init(name: "mcp-config", authsiaFolder: "Workspaces/mcp-config"),
                managedEnvFiles: [],
                agents: nil
            ),
            toWorkspaceRoot: root
        )
        let nested = root.appendingPathComponent("Sources/App", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        let binary = root.appendingPathComponent("bin/authsia")
        try FileManager.default.createDirectory(
            at: binary.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        return (root, nested, binary)
    }
}
