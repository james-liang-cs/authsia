import XCTest
@testable import AuthenticatorBridge

final class MCPLocalMCPClientWrapTests: XCTestCase {
    func testJSONWriteReplacesOnlyTheNamedServerAndRefusesStaleChecksum() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let cursor = root.appendingPathComponent("mcp.json")
        try writeJSON([
            "mcpServers": [
                "filesystem": ["command": "/opt/homebrew/bin/node", "args": ["server.js"]],
                "keep": ["command": "npx", "args": ["other"]],
            ],
        ], to: cursor)

        let finding = MCPClientServerFinding(
            source: .cursor,
            serverName: "filesystem",
            commandLabel: "node",
            status: .unadmitted,
            declaredUpstreamName: nil,
            configPathLabel: cursor.path,
            wrapCommand: "node",
            wrapArguments: ["server.js"],
            isWrapEligible: true
        )
        let authsia = "/Applications/Authsia.app/Contents/Helpers/authsia"
        let plan = try MCPLocalMCPClientWrap.plan(
            finding: finding,
            authsiaCommand: authsia,
            fileURL: cursor
        )
        XCTAssertTrue(plan.existingSnippet.contains("node") || plan.existingSnippet.contains("/opt/homebrew/bin/node"))
        XCTAssertTrue(plan.replacementSnippet.contains("mcp"))
        XCTAssertTrue(plan.replacementSnippet.contains("proxy"))
        XCTAssertTrue(plan.replacementSnippet.contains("AUTHSIA_MCP_UPSTREAM"))

        try MCPLocalMCPClientWrap.apply(plan, authsiaCommand: authsia)
        let rootObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: cursor)) as? [String: Any]
        )
        let servers = try XCTUnwrap(rootObject["mcpServers"] as? [String: Any])
        let filesystem = try XCTUnwrap(servers["filesystem"] as? [String: Any])
        XCTAssertEqual(filesystem["command"] as? String, authsia)
        XCTAssertEqual(filesystem["args"] as? [String], ["mcp", "proxy"])
        XCTAssertEqual(
            (filesystem["env"] as? [String: String])?[MCPProxyClientLaunch.environmentKey],
            "filesystem"
        )
        XCTAssertEqual((servers["keep"] as? [String: Any])?["command"] as? String, "npx")

        XCTAssertThrowsError(
            try MCPLocalMCPClientWrap.apply(plan, authsiaCommand: authsia)
        ) { error in
            XCTAssertEqual(error as? MCPLocalMCPClientWrap.WrapError, .checksumMismatch)
        }
    }

    func testCodexWriteKeepsNeighborTables() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let codex = root.appendingPathComponent("config.toml")
        try """
        model = "gpt-5"
        [mcp_servers.keep]
        command = "npx"
        args = ["other"]

        [mcp_servers.playwright]
        command = "/opt/homebrew/bin/node"
        args = ["server.js"]

        [mcp_servers.playwright.env]
        TOKEN = "must-not-survive"

        [projects."/tmp"]
        trust_level = "trusted"
        """.write(to: codex, atomically: true, encoding: .utf8)

        let finding = MCPClientServerFinding(
            source: .codex,
            serverName: "playwright",
            commandLabel: "node",
            status: .directBypass,
            declaredUpstreamName: "playwright",
            configPathLabel: "~/.codex/config.toml",
            wrapCommand: "node",
            wrapArguments: ["server.js"],
            isWrapEligible: true
        )
        let authsia = "/Applications/Authsia.app/Contents/Helpers/authsia"
        let plan = try MCPLocalMCPClientWrap.plan(
            finding: finding,
            authsiaCommand: authsia,
            fileURL: codex
        )
        try MCPLocalMCPClientWrap.apply(plan, authsiaCommand: authsia)
        let text = try String(contentsOf: codex, encoding: .utf8)
        XCTAssertTrue(text.contains("model = \"gpt-5\""))
        XCTAssertTrue(text.contains("[mcp_servers.keep]"))
        XCTAssertTrue(text.contains("command = \"npx\""))
        XCTAssertTrue(text.contains("[projects.\"/tmp\"]"))
        XCTAssertTrue(text.contains("[mcp_servers.playwright]"))
        XCTAssertTrue(text.contains("args = [\"mcp\", \"proxy\"]"))
        XCTAssertTrue(text.contains("AUTHSIA_MCP_UPSTREAM = \"playwright\""))
        XCTAssertFalse(text.contains("must-not-survive"))
    }

    func testPrefersProjectFindingAndRefusesOverriddenWrite() throws {
        let user = MCPClientServerFinding(
            source: .cursor,
            serverName: "filesystem",
            commandLabel: "node",
            status: .unadmitted,
            declaredUpstreamName: nil,
            configPathLabel: "~/.cursor/mcp.json",
            configScope: .userGlobal,
            precedence: .overridden,
            wrapCommand: "node",
            wrapArguments: ["server.js"],
            isWrapEligible: true
        )
        let project = MCPClientServerFinding(
            source: .cursor,
            serverName: "filesystem",
            commandLabel: "node",
            status: .unadmitted,
            declaredUpstreamName: nil,
            configPathLabel: "~/repo/.cursor/mcp.json",
            configScope: .project,
            precedence: .effective,
            workspacePathLabel: "~/repo",
            wrapCommand: "node",
            wrapArguments: ["server.js"],
            isWrapEligible: true
        )
        XCTAssertEqual(
            MCPLocalMCPClientWrap.preferredFinding(named: "filesystem", in: [user, project])?.configScope,
            .project
        )
        XCTAssertThrowsError(
            try MCPLocalMCPClientWrap.plan(
                finding: user,
                authsiaCommand: "/Applications/Authsia.app/Contents/Helpers/authsia",
                fileURL: URL(fileURLWithPath: "/tmp/unused.json")
            )
        ) { error in
            XCTAssertEqual(error as? MCPLocalMCPClientWrap.WrapError, .overriddenByProject)
        }
    }

    func testAbsoluteHomebrewCommandBecomesPATHBasename() throws {
        XCTAssertEqual(
            MCPUpstreamCommandRules.policyCommand(fromScanned: "/opt/homebrew/bin/node"),
            "node"
        )
        XCTAssertEqual(
            MCPUpstreamCommandRules.policyCommand(fromScanned: "/opt/homebrew/bin/npx"),
            nil
        )
        XCTAssertEqual(
            MCPUpstreamCommandRules.policyCommand(fromScanned: "npx"),
            "npx"
        )
        XCTAssertEqual(
            MCPUpstreamCommandRules.policyCommand(fromScanned: "/bin/bash"),
            nil
        )
        XCTAssertEqual(
            MCPProxyPathOverlay.searchPath(
                path: "/custom/bin",
                homeDirectory: URL(fileURLWithPath: "/Users/tester", isDirectory: true)
            ),
            "/custom/bin:/Users/tester/.local/bin:/opt/homebrew/bin:/usr/local/bin"
        )
    }

    private func writeJSON(_ object: [String: Any], to url: URL) throws {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted])
        try data.write(to: url)
    }

    func testWrapKeepsLaunchSettingsAuthsiaDoesNotManage() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let codex = root.appendingPathComponent("config.toml")
        try """
        [mcp_servers.playwright]
        command = "node"
        args = ["server.js"]
        startup_timeout_sec = 45.0

        [mcp_servers.playwright.env]
        TOKEN = "must-not-survive"
        """.write(to: codex, atomically: true, encoding: .utf8)
        let finding = MCPClientServerFinding(
            source: .codex,
            serverName: "playwright",
            commandLabel: "node",
            status: .directBypass,
            declaredUpstreamName: "playwright",
            configPathLabel: "~/.codex/config.toml",
            wrapCommand: "node",
            wrapArguments: ["server.js"],
            isWrapEligible: true
        )
        let authsia = "/Applications/Authsia.app/Contents/Helpers/authsia"

        let plan = try MCPLocalMCPClientWrap.plan(
            finding: finding,
            authsiaCommand: authsia,
            fileURL: codex
        )
        try MCPLocalMCPClientWrap.apply(plan, authsiaCommand: authsia)

        // A raised timeout still applies to the proxy process; dropping it
        // would change the launch without saying so.
        XCTAssertTrue(plan.replacementSnippet.contains("startup_timeout_sec = 45.0"))
        let text = try String(contentsOf: codex, encoding: .utf8)
        XCTAssertTrue(text.contains("startup_timeout_sec = 45.0"))
        XCTAssertFalse(text.contains("must-not-survive"))
    }

    func testJSONWrapKeepsUnmanagedKeysAndDropsChildEnvironment() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let cursor = root.appendingPathComponent("mcp.json")
        try JSONSerialization.data(withJSONObject: [
            "mcpServers": [
                "filesystem": [
                    "command": "node",
                    "args": ["server.js"],
                    "env": ["TOKEN": "must-not-survive"],
                    "timeout": 60,
                ],
            ],
        ]).write(to: cursor)
        let finding = MCPClientServerFinding(
            source: .cursor,
            serverName: "filesystem",
            commandLabel: "node",
            status: .directBypass,
            declaredUpstreamName: "filesystem",
            configPathLabel: "~/.cursor/mcp.json",
            wrapCommand: "node",
            wrapArguments: ["server.js"],
            isWrapEligible: true
        )
        let authsia = "/Applications/Authsia.app/Contents/Helpers/authsia"

        let plan = try MCPLocalMCPClientWrap.plan(
            finding: finding,
            authsiaCommand: authsia,
            fileURL: cursor
        )
        try MCPLocalMCPClientWrap.apply(plan, authsiaCommand: authsia)

        XCTAssertTrue(plan.replacementSnippet.contains("\"timeout\""))
        let text = try String(contentsOf: cursor, encoding: .utf8)
        XCTAssertTrue(text.contains("\"timeout\""))
        XCTAssertTrue(text.contains("AUTHSIA_MCP_UPSTREAM"))
        XCTAssertFalse(text.contains("must-not-survive"))
    }

}
