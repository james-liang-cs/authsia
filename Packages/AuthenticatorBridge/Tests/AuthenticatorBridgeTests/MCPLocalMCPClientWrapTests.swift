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


    func testClaudeDesktopWrapPinsTheWorkspaceInEnvironmentNotArgv() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let config = root.appendingPathComponent("claude_desktop_config.json")
        try JSONSerialization.data(withJSONObject: [
            "mcpServers": [
                "filesystem": ["command": "server", "args": ["mcp"]],
            ],
        ]).write(to: config)
        func finding(workspace: String?) -> MCPClientServerFinding {
            MCPClientServerFinding(
                source: .claudeDesktop,
                serverName: "filesystem",
                commandLabel: "server",
                status: .unadmitted,
                declaredUpstreamName: nil,
                configPathLabel: "~/Library/Application Support/Claude/claude_desktop_config.json",
                configScope: .userGlobal,
                precedence: .effective,
                workspacePathLabel: workspace,
                wrapCommand: "server",
                wrapArguments: ["mcp"],
                isWrapEligible: true
            )
        }
        let authsia = "/Applications/Authsia.app/Contents/Helpers/authsia"

        let plan = try MCPLocalMCPClientWrap.plan(
            finding: finding(workspace: "~/repo"),
            authsiaCommand: authsia,
            fileURL: config,
            homeDirectory: URL(fileURLWithPath: "/Users/example", isDirectory: true)
        )
        try MCPLocalMCPClientWrap.apply(plan, authsiaCommand: authsia)

        // Argv stays the stable two-entry shape a company allowlist matches;
        // the workspace binding rides in the environment instead.
        let object = try JSONSerialization.jsonObject(with: Data(contentsOf: config)) as? [String: Any]
        let servers = object?["mcpServers"] as? [String: Any]
        let entry = servers?["filesystem"] as? [String: Any]
        XCTAssertEqual(entry?["args"] as? [String], ["mcp", "proxy"])
        let environment = entry?["env"] as? [String: String]
        XCTAssertEqual(environment?["AUTHSIA_MCP_UPSTREAM"], "filesystem")
        XCTAssertEqual(environment?["WORKSPACE_FOLDER_PATHS"], "/Users/example/repo")

        // Claude Desktop has no cwd to fall back on, so an unbound finding
        // cannot be wrapped at all.
        XCTAssertThrowsError(
            try MCPLocalMCPClientWrap.plan(
                finding: finding(workspace: nil),
                authsiaCommand: authsia,
                fileURL: config
            )
        ) { error in
            XCTAssertEqual(error as? MCPLocalMCPClientWrap.WrapError, .missingWorkspaceBinding)
        }
    }

    func testClaudeLocalScopeWrapUsesTheProjectsMapNotTopLevelMcpServers() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let home = root.appendingPathComponent("home")
        let workspace = root.appendingPathComponent("repo")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)
        let claude = home.appendingPathComponent(".claude.json")
        try writeJSON([
            "mcpServers": [
                "keep-global": ["command": "npx", "args": ["other"]],
            ],
            "projects": [
                workspace.path: [
                    "mcpServers": [
                        "filesystem": [
                            "command": "/opt/homebrew/bin/node",
                            "args": ["server.js"],
                            "startup_timeout_sec": 15,
                        ],
                    ],
                ],
            ],
        ], to: claude)

        let finding = MCPClientServerFinding(
            source: .claude,
            serverName: "filesystem",
            commandLabel: "node",
            status: .unadmitted,
            declaredUpstreamName: nil,
            configPathLabel: "~/.claude.json (local scope)",
            configScope: .project,
            precedence: .effective,
            workspacePathLabel: workspace.path,
            wrapCommand: "node",
            wrapArguments: ["server.js"],
            isWrapEligible: true,
            configFilePath: claude.path,
            projectKey: workspace.path
        )
        let authsia = "/Applications/Authsia.app/Contents/Helpers/authsia"
        let plan = try MCPLocalMCPClientWrap.plan(
            finding: finding,
            authsiaCommand: authsia,
            homeDirectory: home
        )
        XCTAssertEqual(plan.fileURL.path, claude.path)
        XCTAssertTrue(plan.existingSnippet.contains("node") || plan.existingSnippet.contains("/opt/homebrew/bin/node"))
        try MCPLocalMCPClientWrap.apply(plan, authsiaCommand: authsia)

        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: claude)) as? [String: Any]
        )
        let global = try XCTUnwrap(object["mcpServers"] as? [String: Any])
        XCTAssertEqual((global["keep-global"] as? [String: Any])?["command"] as? String, "npx")
        XCTAssertNil(global["filesystem"])
        let projects = try XCTUnwrap(object["projects"] as? [String: Any])
        let project = try XCTUnwrap(projects[workspace.path] as? [String: Any])
        let servers = try XCTUnwrap(project["mcpServers"] as? [String: Any])
        let filesystem = try XCTUnwrap(servers["filesystem"] as? [String: Any])
        XCTAssertEqual(filesystem["command"] as? String, authsia)
        XCTAssertEqual(filesystem["args"] as? [String], ["mcp", "proxy"])
        XCTAssertEqual((filesystem["startup_timeout_sec"] as? NSNumber)?.intValue, 15)
    }

    func testClaudeLocalScopeWrapResolvesTheFileFromTheDisplayLabel() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let home = root.appendingPathComponent("home")
        let workspace = root.appendingPathComponent("repo")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: workspace, withIntermediateDirectories: true)
        let claude = home.appendingPathComponent(".claude.json")
        try writeJSON([
            "mcpServers": [
                "keep-global": ["command": "npx"],
            ],
            "projects": [
                workspace.path: [
                    "mcpServers": [
                        "filesystem": ["command": "node", "args": ["server.js"]],
                    ],
                ],
            ],
        ], to: claude)

        let finding = MCPClientServerFinding(
            source: .claude,
            serverName: "filesystem",
            commandLabel: "node",
            status: .unadmitted,
            declaredUpstreamName: nil,
            configPathLabel: "~/.claude.json (local scope)",
            configScope: .project,
            precedence: .effective,
            workspacePathLabel: workspace.path,
            wrapCommand: "node",
            wrapArguments: ["server.js"],
            isWrapEligible: true,
            projectKey: workspace.path
        )
        let authsia = "/Applications/Authsia.app/Contents/Helpers/authsia"
        let plan = try MCPLocalMCPClientWrap.plan(
            finding: finding,
            authsiaCommand: authsia,
            homeDirectory: home
        )
        XCTAssertEqual(plan.fileURL.path, claude.path)
        try MCPLocalMCPClientWrap.apply(plan, authsiaCommand: authsia)

        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: claude)) as? [String: Any]
        )
        XCTAssertNil((object["mcpServers"] as? [String: Any])?["filesystem"])
        let projects = try XCTUnwrap(object["projects"] as? [String: Any])
        let project = try XCTUnwrap(projects[workspace.path] as? [String: Any])
        let servers = try XCTUnwrap(project["mcpServers"] as? [String: Any])
        let filesystem = try XCTUnwrap(servers["filesystem"] as? [String: Any])
        XCTAssertEqual(filesystem["command"] as? String, authsia)
        XCTAssertEqual(filesystem["args"] as? [String], ["mcp", "proxy"])
    }

    func testExistingJSONSnippetRedactsChildEnvValuesAndKeepsKeys() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let cursor = root.appendingPathComponent("mcp.json")
        try writeJSON([
            "mcpServers": [
                "jira": [
                    "command": "/opt/homebrew/bin/node",
                    "args": ["server.js"],
                    "env": ["JIRA_API_TOKEN": "synthetic-token-must-not-appear"],
                ],
            ],
        ], to: cursor)

        let finding = MCPClientServerFinding(
            source: .cursor,
            serverName: "jira",
            commandLabel: "node",
            status: .unadmitted,
            declaredUpstreamName: nil,
            configPathLabel: cursor.path,
            wrapCommand: "node",
            wrapArguments: ["server.js"],
            isWrapEligible: true,
            childEnvironmentCount: 1
        )
        let plan = try MCPLocalMCPClientWrap.plan(
            finding: finding,
            authsiaCommand: "/Applications/Authsia.app/Contents/Helpers/authsia",
            fileURL: cursor
        )
        XCTAssertTrue(plan.existingSnippet.contains("JIRA_API_TOKEN"))
        XCTAssertTrue(plan.existingSnippet.contains("•••"))
        XCTAssertFalse(plan.existingSnippet.contains("synthetic-token-must-not-appear"))
        XCTAssertTrue(plan.existingSnippet.contains("node") || plan.existingSnippet.contains("/opt/homebrew/bin/node"))
    }

    func testExistingCodexSnippetRedactsEnvTableValues() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let codex = root.appendingPathComponent("config.toml")
        try """
        [mcp_servers.playwright]
        command = "/opt/homebrew/bin/node"
        args = ["server.js"]

        [mcp_servers.playwright.env]
        TOKEN = "synthetic-token-must-not-appear"
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
            isWrapEligible: true,
            childEnvironmentCount: 1
        )
        let plan = try MCPLocalMCPClientWrap.plan(
            finding: finding,
            authsiaCommand: "/Applications/Authsia.app/Contents/Helpers/authsia",
            fileURL: codex
        )
        XCTAssertTrue(plan.existingSnippet.contains("TOKEN"))
        XCTAssertTrue(plan.existingSnippet.contains("•••"))
        XCTAssertFalse(plan.existingSnippet.contains("synthetic-token-must-not-appear"))
        XCTAssertTrue(plan.existingSnippet.contains("command = \"/opt/homebrew/bin/node\""))
    }

}
