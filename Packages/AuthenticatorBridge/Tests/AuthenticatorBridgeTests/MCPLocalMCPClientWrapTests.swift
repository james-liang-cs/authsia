import XCTest
@testable import AuthenticatorBridge

final class MCPLocalMCPClientWrapTests: XCTestCase {
    func testCursorWorkspaceRepairPreservesOtherSettingsAndChecksForStaleChanges() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent(".cursor/mcp.json")
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        let original: [String: Any] = ["mcpServers": ["example": [
            "command": "authsia", "args": ["mcp", "proxy"], "disabledTools": ["write"],
            "env": ["AUTHSIA_MCP_UPSTREAM": "example", "WORKSPACE_FOLDER_PATHS": "${workspaceFolder}", "FIXTURE_OPTION": "fixture-value"]
        ], "neighbor": ["command": "fixture-server"]], "futureSetting": true]
        try writeJSON(original, to: file)
        let before = try Data(contentsOf: file)
        let findings = MCPClientConfigScanner().scan(declaredServers: [
            .init(name: "example", command: "fixture-server", arguments: [], workspaceRoot: root)
        ], locations: [.init(source: .cursor, fileURL: file, displayPath: file.path, scope: .project, workspaceRoot: root)])
        let finding = try XCTUnwrap(findings.first { $0.serverName == "example" })
        let repair = try XCTUnwrap(MCPLocalMCPClientWrap.workspaceRepair(for: finding))
        XCTAssertEqual(try Data(contentsOf: file), before, "Detection and preparation must not write")
        try repair.apply()
        let after = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
        var expected = original
        var servers = expected["mcpServers"] as! [String: Any]
        var entry = servers["example"] as! [String: Any]
        var env = entry["env"] as! [String: String]
        env.removeValue(forKey: "WORKSPACE_FOLDER_PATHS")
        entry["env"] = env; servers["example"] = entry; expected["mcpServers"] = servers
        XCTAssertTrue(NSDictionary(dictionary: after).isEqual(NSDictionary(dictionary: expected)))
        XCTAssertNil(try MCPLocalMCPClientWrap.workspaceRepair(for: finding))
        try repair.rollback()
        XCTAssertEqual(try Data(contentsOf: file), before)
        try writeJSON(["mcpServers": ["example": ["command": "changed-server"]]], to: file)
        XCTAssertThrowsError(try repair.apply()) { XCTAssertEqual($0 as? MCPManagementError, .stale) }
        XCTAssertNil(try MCPLocalMCPClientWrap.workspaceRepair(for: finding))
    }

    func testCursorGlobalPinMovesToProjectOverridesWithoutLeakingAcrossProjects() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let global = home.appendingPathComponent(".cursor/mcp.json")
        try FileManager.default.createDirectory(at: global.deletingLastPathComponent(), withIntermediateDirectories: true)
        let projects = [home.appendingPathComponent("project-a"), home.appendingPathComponent("project-b")]
        try writeJSON(["mcpServers": [
            "example": ["command": "authsia", "args": ["mcp", "proxy", "--workspace", projects[0].path],
                "cwd": projects[0].path, "disabledTools": ["restricted_tool"], "env": [
                "AUTHSIA_MCP_UPSTREAM": "example", "WORKSPACE_FOLDER_PATHS": projects[0].path]],
            "keep": ["command": "fixture-server"],
        ]], to: global)
        for project in projects {
            let findings = MCPClientConfigScanner().scan(declaredServers: [], locations: [
                .init(source: .cursor, fileURL: global, displayPath: global.path,
                    scope: .userGlobal, workspaceRoot: project),
            ])
            let finding = try XCTUnwrap(MCPLocalMCPClientWrap.preferredFinding(named: "example", in: findings))
            XCTAssertTrue(finding.isAuthsiaProxyLaunch)
            let plan = try MCPLocalMCPClientWrap.plan(finding: finding, authsiaCommand: "authsia", homeDirectory: home)
            XCTAssertEqual(plan.fileURL.path, project.appendingPathComponent(".cursor/mcp.json").path)
            XCTAssertNotNil(plan.globalChange)
            XCTAssertTrue(plan.replacementSnippet.contains(global.path))
            try MCPLocalMCPClientWrap.apply(plan, authsiaCommand: "authsia")
            let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: plan.fileURL)) as? [String: Any])
            let servers = try XCTUnwrap(object["mcpServers"] as? [String: Any])
            let entry = try XCTUnwrap(servers["example"] as? [String: Any])
            XCTAssertNil((entry["env"] as? [String: String])?["WORKSPACE_FOLDER_PATHS"])
            XCTAssertEqual(entry["args"] as? [String], ["mcp", "proxy"])
            XCTAssertEqual(entry["disabledTools"] as? [String], ["restricted_tool"])
        }
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: global)) as? [String: Any])
        let servers = try XCTUnwrap(object["mcpServers"] as? [String: Any])
        let entry = try XCTUnwrap(servers["example"] as? [String: Any])
        XCTAssertNil((entry["env"] as? [String: String])?["WORKSPACE_FOLDER_PATHS"])
        XCTAssertNil(entry["cwd"])
        XCTAssertEqual(entry["args"] as? [String], ["mcp", "proxy"])
        XCTAssertEqual((servers["keep"] as? [String: String])?["command"], "fixture-server")
        XCTAssertFalse(FileManager.default.fileExists(atPath: home.appendingPathComponent("project-c/.cursor/mcp.json").path))
    }

    func testCursorMigrationRefusesStaleGlobalBeforeWritingProject() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let global = home.appendingPathComponent("mcp.json")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try writeJSON(["mcpServers": ["example": ["command": "fixture-server"]]], to: global)
        let finding = MCPClientServerFinding(source: .cursor, serverName: "example",
            commandLabel: "fixture-server", status: .unadmitted, declaredUpstreamName: nil,
            configPathLabel: global.path, workspacePathLabel: home.appendingPathComponent("project").path,
            wrapCommand: "fixture-server", isWrapEligible: true)
        let plan = try MCPLocalMCPClientWrap.plan(finding: finding, authsiaCommand: "authsia", homeDirectory: home)
        try writeJSON(["mcpServers": ["example": ["command": "changed-server"]]], to: global)
        XCTAssertThrowsError(try MCPLocalMCPClientWrap.apply(plan, authsiaCommand: "authsia")) {
            XCTAssertEqual($0 as? MCPLocalMCPClientWrap.WrapError, .checksumMismatch)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: plan.fileURL.path))
    }

    func testDevinAndVSCodeEnrollmentDoNotPinGlobalWorkspace() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let home = root.appendingPathComponent("home")
        let project = root.appendingPathComponent("project")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
        for source in [MCPClientConfigSource.devin, .vscode] {
            let plan = try MCPLocalMCPClientWrap.planInsert(source: source,
                serverName: "example", workspacePath: project.path,
                authsiaCommand: "authsia", homeDirectory: home)
            try MCPLocalMCPClientWrap.apply(plan, authsiaCommand: "authsia")
            let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: plan.fileURL)) as? [String: Any])
            let servers = try XCTUnwrap(object[source == .vscode ? "servers" : "mcpServers"] as? [String: Any])
            let entry = try XCTUnwrap(servers["example"] as? [String: Any])
            XCTAssertEqual(entry["args"] as? [String], ["mcp", "proxy"])
            let env = try XCTUnwrap(entry["env"] as? [String: String])
            XCTAssertEqual(env[MCPProxyClientLaunch.environmentKey], "example")
            XCTAssertNil(env[MCPProxyClientLaunch.workspaceEnvironmentKey])
            if source == .vscode { XCTAssertEqual(entry["type"] as? String, "stdio") }
        }
    }

    func testDevinAndVSCodeWrapDoNotPinSelectedWorkspace() {
        for source in [MCPClientConfigSource.devin, .vscode] {
            let finding = MCPClientServerFinding(source: source, serverName: "example",
                commandLabel: "fixture-server", status: .unadmitted,
                declaredUpstreamName: nil, configPathLabel: "mcp.json",
                workspacePathLabel: "~/project")
            XCTAssertEqual(MCPLocalMCPClientWrap.wrapWorkspacePath(for: finding,
                homeDirectory: URL(fileURLWithPath: "/Users/example")),
                nil)
        }
    }

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
            configScope: .project,
            workspacePathLabel: root.path,
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
        XCTAssertNil((filesystem["env"] as? [String: String])?[MCPProxyClientLaunch.workspaceEnvironmentKey])
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
            configScope: .project,
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
            configScope: .project,
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

    func testJSONInsertAddsNamedServerWithoutTouchingNeighbors() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let home = root.appendingPathComponent("home")
        let project = root.appendingPathComponent("project")
        try FileManager.default.createDirectory(at: home.appendingPathComponent(".cursor"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: project.appendingPathComponent(".cursor"), withIntermediateDirectories: true)
        let projectFile = project.appendingPathComponent(".cursor/mcp.json")
        try writeJSON(["mcpServers": ["keep": ["command": "npx", "args": ["other"]]]], to: projectFile)
        let authsia = "/Applications/Authsia.app/Contents/Helpers/authsia"
        let plan = try MCPLocalMCPClientWrap.planInsert(
            source: .cursor,
            serverName: "playwright",
            workspacePath: project.path,
            authsiaCommand: authsia,
            homeDirectory: home
        )
        XCTAssertEqual(plan.existingSnippet, "Not present in this client file.")
        XCTAssertTrue(plan.replacementSnippet.contains("AUTHSIA_MCP_UPSTREAM"))
        XCTAssertEqual(plan.fileURL.path, projectFile.path)
        try MCPLocalMCPClientWrap.apply(plan, authsiaCommand: authsia)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: projectFile)) as? [String: Any])
        let servers = try XCTUnwrap(object["mcpServers"] as? [String: Any])
        XCTAssertEqual((servers["keep"] as? [String: Any])?["command"] as? String, "npx")
        let playwright = try XCTUnwrap(servers["playwright"] as? [String: Any])
        XCTAssertEqual(playwright["command"] as? String, authsia)
        XCTAssertEqual(playwright["args"] as? [String], ["mcp", "proxy"])
        XCTAssertEqual((playwright["env"] as? [String: String])?[MCPProxyClientLaunch.environmentKey], "playwright")
        XCTAssertNil((playwright["env"] as? [String: String])?[MCPProxyClientLaunch.workspaceEnvironmentKey])
    }

    func testCursorInsertCreatesProjectFileWithoutGlobalFallback() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let home = root.appendingPathComponent("home")
        let project = root.appendingPathComponent("project")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
        let authsia = "/Applications/Authsia.app/Contents/Helpers/authsia"
        let plan = try MCPLocalMCPClientWrap.planInsert(
            source: .cursor,
            serverName: "playwright",
            workspacePath: project.path,
            authsiaCommand: authsia,
            homeDirectory: home
        )
        XCTAssertEqual(plan.fileURL.path, project.appendingPathComponent(".cursor/mcp.json").path)
        try MCPLocalMCPClientWrap.apply(plan, authsiaCommand: authsia)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: plan.fileURL)) as? [String: Any]
        )
        let servers = try XCTUnwrap(object["mcpServers"] as? [String: Any])
        let playwright = try XCTUnwrap(servers["playwright"] as? [String: Any])
        XCTAssertEqual(playwright["args"] as? [String], ["mcp", "proxy"])
        XCTAssertNil((playwright["env"] as? [String: String])?[MCPProxyClientLaunch.workspaceEnvironmentKey])
        XCTAssertFalse(FileManager.default.fileExists(atPath: home.appendingPathComponent(".cursor/mcp.json").path))
    }

    func testClaudeInsertCreatesProjectLocalScope() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let home = root.appendingPathComponent("home")
        let project = root.appendingPathComponent("project")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
        try Data("{}".utf8).write(to: home.appendingPathComponent(".claude.json"))
        let authsia = "/Applications/Authsia.app/Contents/Helpers/authsia"
        let plan = try MCPLocalMCPClientWrap.planInsert(
            source: .claude,
            serverName: "playwright",
            workspacePath: project.path,
            authsiaCommand: authsia,
            homeDirectory: home
        )
        try MCPLocalMCPClientWrap.apply(plan, authsiaCommand: authsia)
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: home.appendingPathComponent(".claude.json"))) as? [String: Any]
        )
        let projects = try XCTUnwrap(object["projects"] as? [String: Any])
        let servers = try XCTUnwrap(
            (projects[project.path] as? [String: Any])?["mcpServers"] as? [String: Any]
        )
        XCTAssertEqual((servers["playwright"] as? [String: Any])?["args"] as? [String], ["mcp", "proxy"])
    }

    func testJSONInsertRefusesExistingUnsupportedLaunch() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let home = root.appendingPathComponent("home")
        let project = root.appendingPathComponent("project")
        try FileManager.default.createDirectory(at: home.appendingPathComponent(".cursor"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: project.appendingPathComponent(".cursor"), withIntermediateDirectories: true)
        let projectFile = project.appendingPathComponent(".cursor/mcp.json")
        let before: [String: Any] = [
            "mcpServers": [
                "playwright": ["command": "npx", "args": ["@playwright/mcp"], "cwd": project.path],
            ],
        ]
        try writeJSON(before, to: projectFile)
        XCTAssertThrowsError(
            try MCPLocalMCPClientWrap.planInsert(
                source: .cursor,
                serverName: "playwright",
                workspacePath: project.path,
                authsiaCommand: "/Applications/Authsia.app/Contents/Helpers/authsia",
                homeDirectory: home
            )
        ) { error in
            XCTAssertEqual(error as? MCPLocalMCPClientWrap.WrapError, .notWrapEligible)
        }
        let after = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: projectFile)) as? [String: Any])
        let playwright = try XCTUnwrap((after["mcpServers"] as? [String: Any])?["playwright"] as? [String: Any])
        XCTAssertEqual(playwright["command"] as? String, "npx")
        XCTAssertEqual(playwright["cwd"] as? String, project.path)
    }

    func testCodexInsertIsNotSupported() {
        XCTAssertThrowsError(
            try MCPLocalMCPClientWrap.planInsert(
                source: .codex,
                serverName: "playwright",
                workspacePath: "/tmp/project",
                authsiaCommand: "/Applications/Authsia.app/Contents/Helpers/authsia"
            )
        ) { error in
            XCTAssertEqual(error as? MCPLocalMCPClientWrap.WrapError, .notWrapEligible)
        }
    }

}
