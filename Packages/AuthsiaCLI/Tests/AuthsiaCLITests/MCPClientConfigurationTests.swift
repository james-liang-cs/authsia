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
            #expect(first.contains("The server can start from any directory"))
            #expect(first.contains("uses MCP Roots or safe launch context"))
            #expect(first.contains("workspace tools remain unavailable"))
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
        #expect(codex.contains("codex mcp add authsia --"))
        #expect(codex.contains("~/.codex/config.toml"))
        #expect(codex.contains("[mcp_servers.authsia]"))
        #expect(codex.contains("args = [\"mcp\", \"serve\"]"))
        #expect(!codex.contains("cwd ="))

        let claude = try render(.claude, fixture: fixture)
        #expect(claude.contains("claude mcp add --scope user authsia --"))
        #expect(claude.contains("~/.claude.json"))
        #expect(claude.contains("\"mcpServers\""))

        let cursor = try render(.cursor, fixture: fixture)
        #expect(!cursor.contains("Configure directly:"))
        #expect(cursor.contains("~/.cursor/mcp.json"))
        #expect(cursor.contains("\"mcpServers\""))
        #expect(!cursor.contains("\"--workspace\""))
        #expect(!cursor.contains("${workspaceFolder}"))

        let windsurf = try render(.windsurf, fixture: fixture)
        #expect(!windsurf.contains("Configure directly:"))
        #expect(windsurf.contains("~/.codeium/windsurf/mcp_config.json"))
        #expect(windsurf.contains("\"mcpServers\""))

        let vscode = try render(.vscode, fixture: fixture)
        #expect(vscode.contains("code --add-mcp"))
        #expect(vscode.contains("MCP: Open User Configuration"))
        #expect(vscode.contains("\"servers\""))
        #expect(vscode.contains("\"type" + "\" : \"stdio\""))
        #expect(!vscode.contains("\"cwd\""))
    }

    @Test("serve discovers one client workspace without fixed configuration")
    func serveWorkspaceDiscovery() throws {
        let fallback = "/tmp/fallback"

        #expect(MCPCommand.Serve.startingDirectory(
            workspace: "/tmp/explicit",
            environment: ["WORKSPACE_FOLDER_PATHS": "/tmp/client"],
            currentDirectoryPath: fallback
        ).path == "/tmp/explicit")
        #expect(MCPCommand.Serve.startingDirectory(
            workspace: nil,
            environment: ["WORKSPACE_FOLDER_PATHS": "/tmp/client"],
            currentDirectoryPath: fallback
        ).path == "/tmp/client")
        #expect(MCPCommand.Serve.startingDirectory(
            workspace: nil,
            environment: ["WORKSPACE_FOLDER_PATHS": "/tmp/one,/tmp/two"],
            currentDirectoryPath: fallback
        ).path == fallback)
        #expect(MCPCommand.Serve.startingDirectory(
            workspace: nil,
            environment: [:],
            currentDirectoryPath: fallback
        ).path == fallback)

        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                workspace: .init(name: "cursor", authsiaFolder: "Workspaces/cursor"),
                managedEnvFiles: [],
                agents: nil
            ),
            toWorkspaceRoot: root
        )
        let selected = MCPCommand.Serve.startingDirectory(
            workspace: nil,
            environment: ["WORKSPACE_FOLDER_PATHS": root.path],
            currentDirectoryPath: fallback
        )
        let runtime = MCPRuntimeContext(startingDirectory: selected)
        #expect(runtime.workspaceName == "cursor")
        #expect(runtime.workspaceRoot?.path == root.resolvingSymlinksInPath().path)
    }

    @Test("direct commands shell-quote machine-specific paths")
    func directCommandEscaping() throws {
        let binary = URL(fileURLWithPath: "/Applications/Authsia's App/authsia")

        let codex = try MCPClientConfiguration.render(client: .codex, executableURL: binary)
        #expect(codex.contains("'/Applications/Authsia'\\''s App/authsia'"))

        let vscode = try MCPClientConfiguration.render(client: .vscode, executableURL: binary)
        #expect(vscode.contains("Authsia'\\''s App"))
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

    @Test("configure and serve commands are visible")
    func commandRegistration() throws {
        #expect(MCPCommand.Configure.configuration.shouldDisplay)
        #expect(MCPCommand.Serve.configuration.shouldDisplay)
        _ = try Authsia.parseAsRoot(["mcp", "configure", "--client", "codex"])
        _ = try Authsia.parseAsRoot(["mcp", "configure", "--client", "windsurf"])
        _ = try Authsia.parseAsRoot(["mcp", "serve", "--workspace", "/tmp/project"])
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
