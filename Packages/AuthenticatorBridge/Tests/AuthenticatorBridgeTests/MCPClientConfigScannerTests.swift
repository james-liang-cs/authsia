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

        XCTAssertTrue(text?.contains("\"name\": \"playwright\"") == true)
        XCTAssertTrue(text?.contains("\"command\": \"npx\"") == true)
        XCTAssertTrue(text?.contains("\"--upstream\"") == true)
        XCTAssertTrue(text?.contains("does not edit the client file") == true)
        XCTAssertFalse(text?.contains("TOKEN") == true)
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

    private func writeJSON(_ object: [String: Any], to url: URL) throws {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: url)
    }
}
