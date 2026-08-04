import Foundation
import Testing
@testable import authsia

@Suite("MCP client configuration")
struct MCPClientConfigurationTests {
    @Test("all supported clients receive deterministic global configuration")
    func supportedClients() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }

        for client in MCPClient.allCases {
            let first = try MCPClientConfiguration.render(
                client: client,
                executableURL: fixture.binary
            )
            let second = try MCPClientConfiguration.render(
                client: client,
                executableURL: fixture.binary
            )

            #expect(first == second)
            #expect(first.contains(fixture.binary.path))
            #expect(!first.contains("cwd"))
            #expect(first.contains("mcp"))
            #expect(first.contains("serve"))
            #expect(first.contains("Machine-specific absolute path"))
            #expect(first.contains("user-global"))
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
        #expect(codex.contains("~/.codex/config.toml"))
        #expect(codex.contains("[mcp_servers.authsia]"))
        #expect(codex.contains("args = [\"mcp\", \"serve\"]"))
        #expect(!codex.contains("cwd ="))

        let claude = try render(.claude, fixture: fixture)
        #expect(claude.contains("~/.claude.json"))
        #expect(claude.contains("\"mcpServers\""))

        let cursor = try render(.cursor, fixture: fixture)
        #expect(cursor.contains("~/.cursor/mcp.json"))
        #expect(cursor.contains("\"mcpServers\""))

        let windsurf = try render(.windsurf, fixture: fixture)
        #expect(windsurf.contains("~/.codeium/windsurf/mcp_config.json"))
        #expect(windsurf.contains("\"mcpServers\""))

        let vscode = try render(.vscode, fixture: fixture)
        #expect(vscode.contains("MCP: Open User Configuration"))
        #expect(vscode.contains("\"servers\""))
        #expect(vscode.contains("\"type" + "\" : \"stdio\""))
        #expect(!vscode.contains("\"cwd\""))
    }

    @Test("global configuration needs no workspace and unsafe values fail closed")
    func invalidInputs() throws {
        let safeBinary = URL(fileURLWithPath: "/Applications/Authsia.app/Contents/Helpers/authsia")

        let global = try MCPClientConfiguration.render(
            client: .codex,
            executableURL: safeBinary
        )
        #expect(global.contains("~/.codex/config.toml"))
        #expect(throws: MCPClientConfigurationError.self) {
            try MCPClientConfiguration.render(
                clientName: "codex\nmalicious",
                executableURL: safeBinary
            )
        }
        #expect(throws: MCPClientConfigurationError.self) {
            try MCPClientConfiguration.render(
                clientName: "unsupported",
                executableURL: safeBinary
            )
        }
    }

    @Test("configure command is visible and serve remains hidden")
    func commandRegistration() throws {
        #expect(MCPCommand.Configure.configuration.shouldDisplay)
        #expect(!MCPCommand.Serve.configuration.shouldDisplay)
        _ = try Authsia.parseAsRoot(["mcp", "configure", "--client", "codex"])
        _ = try Authsia.parseAsRoot(["mcp", "configure", "--client", "windsurf"])
    }

    private func render(
        _ client: MCPClient,
        fixture: (root: URL, binary: URL)
    ) throws -> String {
        try MCPClientConfiguration.render(
            client: client,
            executableURL: fixture.binary
        )
    }

    private func makeFixture() throws -> (root: URL, binary: URL) {
        let root = try makeWorkspaceRoot()
        let binary = root.appendingPathComponent("bin/authsia")
        try FileManager.default.createDirectory(
            at: binary.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        return (root, binary)
    }
}
