import XCTest
@testable import AuthenticatorBridge

final class MCPLocalMCPClientUnwrapTests: XCTestCase {
    func testJSONRestoreDropsProxyLaunchAndRefusesStaleChecksum() throws {
        let root = try makeWorkspace(upstreams: [
            ["name": "filesystem", "command": "node", "args": ["server.js"], "env": [:]],
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let cursor = root.appendingPathComponent("mcp.json")
        try writeJSON([
            "mcpServers": [
                "filesystem": [
                    "command": "/Applications/Authsia.app/Contents/Helpers/authsia",
                    "args": ["mcp", "proxy"],
                    "env": ["AUTHSIA_MCP_UPSTREAM": "filesystem"],
                ],
                "keep": ["command": "npx", "args": ["other"]],
            ],
        ], to: cursor)

        let plan = try MCPLocalMCPClientUnwrap.plan(
            finding: protectedFinding(source: .cursor, configPathLabel: cursor.path),
            workspaceRoots: [root],
            fileURL: cursor
        )
        XCTAssertEqual(plan.workspaceRoot.standardizedFileURL, root.standardizedFileURL)
        XCTAssertTrue(plan.existingSnippet.contains("AUTHSIA_MCP_UPSTREAM"))
        XCTAssertTrue(plan.replacementSnippet.contains("node"))
        XCTAssertFalse(plan.replacementSnippet.contains("AUTHSIA_MCP_UPSTREAM"))

        try MCPLocalMCPClientUnwrap.apply(plan)
        let servers = try servers(in: cursor, key: "mcpServers")
        let filesystem = try XCTUnwrap(servers["filesystem"] as? [String: Any])
        XCTAssertEqual(filesystem["command"] as? String, "node")
        XCTAssertEqual(filesystem["args"] as? [String], ["server.js"])
        XCTAssertNil(filesystem["env"])
        XCTAssertEqual((servers["keep"] as? [String: Any])?["command"] as? String, "npx")

        XCTAssertThrowsError(try MCPLocalMCPClientUnwrap.apply(plan)) { error in
            XCTAssertEqual(error as? MCPLocalMCPClientUnwrap.UnwrapError, .checksumMismatch)
        }
    }

    func testVSCodeRestoreKeepsStdioTypeAndUnmanagedKeys() throws {
        let root = try makeWorkspace(upstreams: [
            ["name": "filesystem", "command": "node", "args": ["server.js"], "env": [:]],
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let config = root.appendingPathComponent("mcp.json")
        try writeJSON([
            "servers": [
                "filesystem": [
                    "command": "/Applications/Authsia.app/Contents/Helpers/authsia",
                    "args": ["mcp", "proxy"],
                    "env": ["AUTHSIA_MCP_UPSTREAM": "filesystem"],
                    "type": "stdio",
                    "gallery": true,
                ],
            ],
        ], to: config)

        let plan = try MCPLocalMCPClientUnwrap.plan(
            finding: protectedFinding(source: .vscode, configPathLabel: config.path),
            workspaceRoots: [root],
            fileURL: config
        )
        try MCPLocalMCPClientUnwrap.apply(plan)
        let filesystem = try XCTUnwrap(
            servers(in: config, key: "servers")["filesystem"] as? [String: Any]
        )
        XCTAssertEqual(filesystem["command"] as? String, "node")
        XCTAssertEqual(filesystem["type"] as? String, "stdio")
        XCTAssertEqual(filesystem["gallery"] as? Bool, true)
        XCTAssertNil(filesystem["env"])
    }

    func testCodexRestoreKeepsNeighborTablesAndUnmanagedKeys() throws {
        let root = try makeWorkspace(upstreams: [
            ["name": "playwright", "command": "node", "args": ["server.js"], "env": [:]],
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        let codex = root.appendingPathComponent("config.toml")
        try """
        model = "gpt-5"
        [mcp_servers.keep]
        command = "npx"
        args = ["other"]

        [mcp_servers.playwright]
        command = "/Applications/Authsia.app/Contents/Helpers/authsia"
        args = ["mcp", "proxy"]
        env_vars = ["SSL_CERT_FILE"]
        startup_timeout_sec = 45.0

        [mcp_servers.playwright.env]
        AUTHSIA_MCP_UPSTREAM = "playwright"

        [projects."/tmp"]
        trust_level = "trusted"
        """.write(to: codex, atomically: true, encoding: .utf8)

        let plan = try MCPLocalMCPClientUnwrap.plan(
            finding: protectedFinding(
                source: .codex,
                serverName: "playwright",
                configPathLabel: codex.path
            ),
            workspaceRoots: [root],
            fileURL: codex
        )
        try MCPLocalMCPClientUnwrap.apply(plan)
        let text = try String(contentsOf: codex, encoding: .utf8)
        XCTAssertTrue(text.contains("model = \"gpt-5\""))
        XCTAssertTrue(text.contains("[mcp_servers.keep]"))
        XCTAssertTrue(text.contains("[projects.\"/tmp\"]"))
        XCTAssertTrue(text.contains("command = \"node\""))
        XCTAssertTrue(text.contains("args = [\"server.js\"]"))
        // A raised timeout applies to whatever runs behind this name, so the
        // restore keeps it for the same reason the wrap did.
        XCTAssertTrue(text.contains("startup_timeout_sec = 45.0"))
        XCTAssertFalse(text.contains("AUTHSIA_MCP_UPSTREAM"))
        XCTAssertFalse(text.contains("[mcp_servers.playwright.env]"))
        XCTAssertFalse(text.contains("env_vars"))
    }

    func testRestoreRefusesWhenNoWorkspaceDeclaresTheUpstream() throws {
        let root = try makeWorkspace(upstreams: [])
        defer { try? FileManager.default.removeItem(at: root) }
        let cursor = root.appendingPathComponent("mcp.json")
        try writeJSON([
            "mcpServers": [
                "filesystem": [
                    "command": "/Applications/Authsia.app/Contents/Helpers/authsia",
                    "args": ["mcp", "proxy"],
                ],
            ],
        ], to: cursor)

        XCTAssertThrowsError(
            try MCPLocalMCPClientUnwrap.plan(
                finding: protectedFinding(source: .cursor, configPathLabel: cursor.path),
                workspaceRoots: [root],
                fileURL: cursor
            )
        ) { error in
            XCTAssertEqual(error as? MCPLocalMCPClientUnwrap.UnwrapError, .missingDeclaration)
        }
    }

    func testPrefersProjectFindingAndRefusesOverriddenRestore() throws {
        let user = protectedFinding(
            source: .cursor,
            configPathLabel: "~/.cursor/mcp.json",
            configScope: .userGlobal,
            precedence: .overridden
        )
        let project = protectedFinding(
            source: .cursor,
            configPathLabel: "~/repo/.cursor/mcp.json",
            configScope: .project,
            precedence: .effective
        )
        XCTAssertEqual(
            MCPLocalMCPClientUnwrap.preferredFinding(named: "filesystem", in: [user, project])?
                .configScope,
            .project
        )
        XCTAssertThrowsError(
            try MCPLocalMCPClientUnwrap.plan(
                finding: user,
                workspaceRoots: [],
                fileURL: URL(fileURLWithPath: "/tmp/unused.json")
            )
        ) { error in
            XCTAssertEqual(error as? MCPLocalMCPClientUnwrap.UnwrapError, .overriddenByProject)
        }
    }

    func testDeclaredLaunchIgnoresRemoteUpstreamsAndReportsEnvironmentCount() throws {
        let root = try makeWorkspace(upstreams: [
            ["name": "jira", "transport": "http", "url": "https://example.invalid/mcp"],
            ["name": "filesystem", "command": "node", "env": ["TOKEN": "authsia://password/jira"]],
        ])
        defer { try? FileManager.default.removeItem(at: root) }

        XCTAssertNil(
            MCPLocalMCPWorkspaceDeclaration.declaredLaunch(named: "jira", workspaceRoots: [root])
        )
        let launch = try XCTUnwrap(
            MCPLocalMCPWorkspaceDeclaration.declaredLaunch(
                named: "filesystem",
                workspaceRoots: [root]
            )
        )
        XCTAssertEqual(launch.command, "node")
        XCTAssertTrue(launch.arguments.isEmpty)
        XCTAssertEqual(launch.environmentCount, 1)
    }

    private func protectedFinding(
        source: MCPClientConfigSource,
        serverName: String = "filesystem",
        configPathLabel: String,
        configScope: MCPClientConfigScope = .project,
        precedence: MCPClientConfigPrecedence = .effective
    ) -> MCPClientServerFinding {
        MCPClientServerFinding(
            source: source,
            serverName: serverName,
            commandLabel: "authsia",
            status: .admittedWrapped,
            declaredUpstreamName: serverName,
            configPathLabel: configPathLabel,
            configScope: configScope,
            precedence: precedence,
            isAuthsiaProxyLaunch: true
        )
    }

    private func makeWorkspace(upstreams: [[String: Any]]) throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        try writeJSON(
            ["mcpUpstreams": upstreams],
            to: root.appendingPathComponent(".authsia/workspace.json")
        )
        return root
    }

    private func servers(in url: URL, key: String) throws -> [String: Any] {
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        )
        return try XCTUnwrap(root[key] as? [String: Any])
    }

    private func writeJSON(_ object: [String: Any], to url: URL) throws {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted])
        try data.write(to: url)
    }
}
