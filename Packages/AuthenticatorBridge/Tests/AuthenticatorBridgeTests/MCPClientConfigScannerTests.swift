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
        XCTAssertEqual(findings.first { $0.serverName == "jira" }?.declaredUpstreamName, "jira")
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

    private func writeJSON(_ object: [String: Any], to url: URL) throws {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: url)
    }
}
