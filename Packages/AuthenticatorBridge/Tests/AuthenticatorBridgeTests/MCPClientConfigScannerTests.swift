import XCTest
@testable import AuthenticatorBridge

final class MCPClientConfigScannerTests: XCTestCase {
    func testScansKnownJSONAndCodexConfigurationsAgainstDeclaredAllowlist() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let codex = root.appendingPathComponent("codex.toml")
        let cursor = root.appendingPathComponent("cursor.json")
        let vscode = root.appendingPathComponent("vscode.json")
        try """
        [mcp_servers.jira]
        command = "/Applications/Authsia.app/Contents/Helpers/authsia"
        args = ["mcp", "proxy", "--upstream", "jira"]

        [mcp_servers.filesystem]
        command = "npx"
        args = ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
        """.write(to: codex, atomically: true, encoding: .utf8)
        try writeJSON([
            "mcpServers": [
                "filesystem": [
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    "env": ["TOKEN": "must-not-appear"],
                ],
                "rogue": ["command": "uvx", "args": ["rogue-server"]],
            ],
        ], to: cursor)
        try writeJSON([
            "servers": [
                "authsia": ["command": "/usr/local/bin/authsia", "args": ["mcp", "serve"]],
                "invalid-wrapper": [
                    "command": "/usr/local/bin/authsia",
                    "args": ["mcp", "proxy", "--upstream", "bad\nname"],
                ],
                "stale": [
                    "type": "stdio",
                    "command": "/usr/local/bin/authsia",
                    "args": ["mcp", "proxy", "--upstream", "stale"],
                ],
            ],
        ], to: vscode)
        let locations = [
            MCPClientConfigLocation(source: .codex, fileURL: codex, displayPath: "~/.codex/config.toml"),
            MCPClientConfigLocation(source: .cursor, fileURL: cursor, displayPath: "~/.cursor/mcp.json"),
            MCPClientConfigLocation(source: .vscode, fileURL: vscode, displayPath: "VS Code user mcp.json"),
        ]
        let declared = [
            MCPDeclaredLocalServer(
                name: "jira",
                command: "mcp-atlassian",
                arguments: []
            ),
            MCPDeclaredLocalServer(
                name: "filesystem",
                command: "npx",
                arguments: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
            ),
        ]

        let findings = MCPClientConfigScanner().scan(
            declaredServers: declared,
            locations: locations
        )

        XCTAssertEqual(findings.map { "\($0.source.rawValue):\($0.serverName):\($0.status.rawValue)" }, [
            "codex:filesystem:direct-bypass",
            "codex:jira:admitted-wrapped",
            "cursor:filesystem:direct-bypass",
            "cursor:rogue:unadmitted",
            "vscode:invalid-wrapper:unadmitted",
            "vscode:stale:unadmitted",
        ])
        XCTAssertEqual(findings.first { $0.serverName == "filesystem" && $0.source == .cursor }?.isWrapEligible, true)
        XCTAssertEqual(findings.first { $0.serverName == "filesystem" && $0.source == .cursor }?.wrapCommand, "npx")
        XCTAssertEqual(
            findings.first { $0.serverName == "rogue" }?.wrapArguments,
            ["rogue-server"]
        )
        XCTAssertEqual(findings.first { $0.serverName == "jira" }?.isWrapEligible, false)
        XCTAssertEqual(findings.first { $0.serverName == "stale" }?.isWrapEligible, false)
        XCTAssertEqual(findings.first { $0.serverName == "invalid-wrapper" }?.shouldShowInAccessCenter, false)
        XCTAssertEqual(findings.first { $0.serverName == "rogue" }?.commandLabel, "uvx")
        XCTAssertNil(findings.first { $0.serverName == "invalid-wrapper" }?.declaredUpstreamName)
        let encoded = String(decoding: try JSONEncoder().encode(findings), as: UTF8.self)
        XCTAssertFalse(encoded.contains("must-not-appear"))
        XCTAssertFalse(encoded.contains("TOKEN"))
        XCTAssertFalse(findings.contains { $0.serverName == "authsia" })
    }

    func testScanIsReadOnlyAndFailsOpenForMissingMalformedAndEmptyAllowlist() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let cursor = root.appendingPathComponent("cursor.json")
        let malformed = root.appendingPathComponent("claude.json")
        let missing = root.appendingPathComponent("missing.json")
        try writeJSON([
            "mcpServers": ["filesystem": ["command": "node", "args": ["server.js"]]],
        ], to: cursor)
        try Data("{not-json".utf8).write(to: malformed)
        let original = try Data(contentsOf: cursor)

        let findings = MCPClientConfigScanner().scan(
            declaredServers: [],
            locations: [
                MCPClientConfigLocation(source: .cursor, fileURL: cursor, displayPath: "cursor"),
                MCPClientConfigLocation(source: .claude, fileURL: malformed, displayPath: "claude"),
                MCPClientConfigLocation(source: .devin, fileURL: missing, displayPath: "devin"),
            ]
        )

        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.status, .unadmitted)
        XCTAssertEqual(findings.first?.isWrapEligible, true)
        XCTAssertEqual(findings.first?.wrapCommand, "node")
        XCTAssertTrue(findings.first?.shouldShowInAccessCenter == true)
        XCTAssertEqual(try Data(contentsOf: cursor), original)
        XCTAssertEqual(try Data(contentsOf: malformed), Data("{not-json".utf8))
        XCTAssertFalse(FileManager.default.fileExists(atPath: missing.path))
    }

    func testKnownLocationsCoverSupportedUserGlobalClients() {
        let home = URL(fileURLWithPath: "/Users/example", isDirectory: true)
        let locations = MCPClientConfigLocation.knownLocations(homeDirectory: home)

        XCTAssertEqual(locations.map(\.source), [.codex, .claude, .cursor, .devin, .vscode])
        XCTAssertEqual(locations.map(\.fileURL.path), [
            "/Users/example/.codex/config.toml",
            "/Users/example/.claude.json",
            "/Users/example/.cursor/mcp.json",
            "/Users/example/.config/devin/mcp_config.json",
            "/Users/example/Library/Application Support/Code/User/mcp.json",
        ])
    }

    func testAbsoluteAndShellCommandsAreNotWrapEligible() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let cursor = root.appendingPathComponent("cursor.json")
        try writeJSON([
            "mcpServers": [
                "abs": ["command": "/usr/bin/node", "args": ["server.js"]],
                "shell": ["command": "bash", "args": ["-c", "node server.js"]],
            ],
        ], to: cursor)

        let findings = MCPClientConfigScanner().scan(
            declaredServers: [],
            locations: [
                MCPClientConfigLocation(source: .cursor, fileURL: cursor, displayPath: "cursor"),
            ]
        )

        XCTAssertEqual(Set(findings.map(\.serverName)), ["abs", "shell"])
        XCTAssertTrue(findings.allSatisfy { !$0.isWrapEligible && !$0.shouldShowInAccessCenter })
    }

    func testWrapRecipeOmitsSecretsAndUsesProxyArgv() {
        let finding = MCPClientServerFinding(
            source: .codex,
            serverName: "playwright",
            commandLabel: "npx",
            status: .unadmitted,
            declaredUpstreamName: nil,
            configPathLabel: "~/.codex/config.toml",
            wrapCommand: "npx",
            wrapArguments: ["-y", "@playwright/mcp"],
            isWrapEligible: true
        )

        let text = MCPLocalMCPWrapRecipe.clipboardText(
            for: finding,
            authsiaCommand: "/Applications/Authsia.app/Contents/Helpers/authsia"
        )

        XCTAssertTrue(text?.contains("Replace the Codex playwright entry in ~/.codex/config.toml.") == true)
        XCTAssertTrue(text?.contains("Open ~/.codex/config.toml") == true)
        XCTAssertTrue(text?.contains("codex mcp add playwright --env AUTHSIA_MCP_UPSTREAM=playwright --") == true)
        XCTAssertTrue(text?.contains("[mcp_servers.playwright]") == true)
        XCTAssertTrue(text?.contains("args = [\"mcp\", \"proxy\"]") == true)
        XCTAssertTrue(text?.contains("AUTHSIA_MCP_UPSTREAM = \"playwright\"") == true)
        XCTAssertTrue(text?.contains("\"name\" : \"playwright\"") == true || text?.contains("\"name\": \"playwright\"") == true)
        XCTAssertTrue(text?.contains("mcpUpstreams") == true)
        XCTAssertTrue(text?.contains("\"command\" : \"npx\"") == true || text?.contains("\"command\": \"npx\"") == true)
        XCTAssertFalse(text?.contains("--upstream") == true)
        XCTAssertTrue(text?.contains("does not edit the client file") == true)
        XCTAssertFalse(text?.contains("TOKEN") == true)

        let afterDeclare = MCPLocalMCPWrapRecipe.clipboardText(
            for: finding,
            authsiaCommand: "/Applications/Authsia.app/Contents/Helpers/authsia",
            includeWorkspacePolicy: false
        )
        XCTAssertTrue(afterDeclare?.contains("Open ~/.codex/config.toml") == true)
        XCTAssertFalse(afterDeclare?.contains("mcpUpstreams") == true)
        XCTAssertFalse(afterDeclare?.contains("\"command\": \"npx\"") == true)
        XCTAssertFalse(afterDeclare?.contains("\"command\" : \"npx\"") == true)

        let cursor = MCPLocalMCPWrapRecipe.clipboardText(
            for: MCPClientServerFinding(
                source: .cursor,
                serverName: "codegraph",
                commandLabel: "codegraph",
                status: .directBypass,
                declaredUpstreamName: "codegraph",
                configPathLabel: "~/.cursor/mcp.json",
                wrapCommand: "codegraph",
                wrapArguments: ["serve", "--mcp"],
                isWrapEligible: true
            ),
            authsiaCommand: "/Applications/Authsia.app/Contents/Helpers/authsia"
        )
        XCTAssertTrue(cursor?.contains("Open ~/.cursor/mcp.json") == true)
        XCTAssertTrue(cursor?.contains("\"mcpServers\"") == true || cursor?.contains("under \"mcpServers\"") == true)
        XCTAssertFalse(cursor?.contains("mcpUpstreams") == true)
        XCTAssertNil(MCPLocalMCPWrapRecipe.clipboardText(
            for: MCPClientServerFinding(
                source: .codex,
                serverName: "jira",
                commandLabel: "authsia",
                status: .admittedWrapped,
                declaredUpstreamName: "jira",
                configPathLabel: "~/.codex/config.toml"
            ),
            authsiaCommand: "/Applications/Authsia.app/Contents/Helpers/authsia"
        ))
    }

    func testStableProxyArgvWithUpstreamEnvironmentIsWrapped() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let claude = root.appendingPathComponent("claude.json")
        let codex = root.appendingPathComponent("codex.toml")
        try writeJSON([
            "mcpServers": [
                "playwright": [
                    "command": "/Applications/Authsia.app/Contents/Helpers/authsia",
                    "args": ["mcp", "proxy"],
                    "env": [
                        "AUTHSIA_MCP_UPSTREAM": "playwright",
                        "TOKEN": "must-not-appear",
                    ],
                ],
                "bare-proxy": [
                    "command": "/Applications/Authsia.app/Contents/Helpers/authsia",
                    "args": ["mcp", "proxy"],
                ],
            ],
        ], to: claude)
        try """
        [mcp_servers.codegraph]
        command = "/Applications/Authsia.app/Contents/Helpers/authsia"
        args = ["mcp", "proxy"]

        [mcp_servers.codegraph.env]
        AUTHSIA_MCP_UPSTREAM = "codegraph"
        TOKEN = "must-not-appear"
        """.write(to: codex, atomically: true, encoding: .utf8)

        let findings = MCPClientConfigScanner().scan(
            declaredServers: [
                MCPDeclaredLocalServer(name: "playwright", command: "npx", arguments: ["-y", "@playwright/mcp"]),
                MCPDeclaredLocalServer(name: "codegraph", command: "codegraph", arguments: ["mcp"]),
            ],
            locations: [
                MCPClientConfigLocation(source: .claude, fileURL: claude, displayPath: "~/.claude.json"),
                MCPClientConfigLocation(source: .codex, fileURL: codex, displayPath: "~/.codex/config.toml"),
            ]
        )

        XCTAssertEqual(findings.map { "\($0.source.rawValue):\($0.serverName):\($0.status.rawValue)" }, [
            "claude:bare-proxy:unadmitted",
            "claude:playwright:admitted-wrapped",
            "codex:codegraph:admitted-wrapped",
        ])
        XCTAssertEqual(findings.first { $0.serverName == "playwright" }?.isWrapEligible, false)
        XCTAssertEqual(findings.first { $0.serverName == "bare-proxy" }?.isWrapEligible, false)
        XCTAssertEqual(findings.first { $0.serverName == "bare-proxy" }?.shouldShowInAccessCenter, false)
        let encoded = String(decoding: try JSONEncoder().encode(findings), as: UTF8.self)
        XCTAssertFalse(encoded.contains("must-not-appear"))
        XCTAssertFalse(encoded.contains("TOKEN"))
    }

    private func writeJSON(_ object: [String: Any], to url: URL) throws {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: url)
    }
}
