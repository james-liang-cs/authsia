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
        XCTAssertEqual(findings.first { $0.serverName == "jira" }?.hasAdvertisedCatalog, false)
        XCTAssertEqual(findings.first { $0.serverName == "jira" }?.canRecordCatalog, false)
        XCTAssertEqual(findings.first { $0.serverName == "stale" }?.isWrapEligible, false)
        XCTAssertEqual(findings.first { $0.serverName == "stale" }?.shouldShowInAccessCenter, true)
        XCTAssertEqual(findings.first { $0.serverName == "invalid-wrapper" }?.shouldShowInAccessCenter, false)
        XCTAssertEqual(findings.first { $0.serverName == "rogue" }?.commandLabel, "uvx")
        XCTAssertNil(findings.first { $0.serverName == "invalid-wrapper" }?.declaredUpstreamName)
        let encoded = String(decoding: try JSONEncoder().encode(findings), as: UTF8.self)
        XCTAssertFalse(encoded.contains("must-not-appear"))
        XCTAssertFalse(encoded.contains("TOKEN"))
        XCTAssertFalse(findings.contains { $0.serverName == "authsia" })
    }

    func testWrappedLaunchWithoutCatalogIsRecordable() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let codex = root.appendingPathComponent("codex.toml")
        try """
        [mcp_servers.codegraph]
        command = "/Applications/Authsia.app/Contents/Helpers/authsia"
        args = ["mcp", "proxy"]

        [mcp_servers.codegraph.env]
        AUTHSIA_MCP_UPSTREAM = "codegraph"
        """.write(to: codex, atomically: true, encoding: .utf8)
        let findings = MCPClientConfigScanner().scan(
            declaredServers: [
                MCPDeclaredLocalServer(
                    name: "codegraph",
                    command: "codegraph",
                    arguments: ["serve", "--mcp"],
                    workspaceRoot: root,
                    hasAdvertisedCatalog: false,
                    canRecordCatalog: true
                ),
            ],
            locations: [
                MCPClientConfigLocation(
                    source: .codex,
                    fileURL: codex,
                    displayPath: "~/.codex/config.toml"
                ),
            ]
        )
        let finding = findings.first { $0.serverName == "codegraph" }
        XCTAssertEqual(finding?.status, .admittedWrapped)
        XCTAssertEqual(finding?.hasAdvertisedCatalog, false)
        XCTAssertEqual(finding?.canRecordCatalog, true)
        XCTAssertEqual(finding?.needsCatalogRecording, true)
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
        XCTAssertEqual(locations.map(\.displayPath), [
            "~/.codex/config.toml",
            "~/.claude.json",
            "~/.cursor/mcp.json",
            "~/.config/devin/mcp_config.json",
            "~/Library/Application Support/Code/User/mcp.json",
        ])
        XCTAssertTrue(locations.allSatisfy { $0.scope == .userGlobal })
        XCTAssertTrue(locations.allSatisfy { $0.workspaceRoot == nil })
    }

    func testAbsoluteHomebrewCommandsAreWrapEligibleAsPATHBasenames() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let cursor = root.appendingPathComponent("cursor.json")
        try writeJSON([
            "mcpServers": [
                "abs": ["command": "/opt/homebrew/bin/node", "args": ["server.js"]],
                "npxabs": ["command": "/opt/homebrew/bin/npx", "args": ["-y", "pkg"]],
                "shell": ["command": "bash", "args": ["-c", "node server.js"]],
            ],
        ], to: cursor)

        let findings = MCPClientConfigScanner().scan(
            declaredServers: [],
            locations: [
                MCPClientConfigLocation(source: .cursor, fileURL: cursor, displayPath: "cursor"),
            ]
        )

        XCTAssertEqual(Set(findings.map(\.serverName)), ["abs", "npxabs", "shell"])
        XCTAssertEqual(findings.first { $0.serverName == "abs" }?.isWrapEligible, true)
        XCTAssertEqual(findings.first { $0.serverName == "abs" }?.wrapCommand, "node")
        XCTAssertEqual(findings.first { $0.serverName == "abs" }?.shouldShowInAccessCenter, true)
        XCTAssertEqual(findings.first { $0.serverName == "npxabs" }?.isWrapEligible, false)
        XCTAssertEqual(findings.first { $0.serverName == "npxabs" }?.wrapBlockReason, .packageLauncher)
        XCTAssertEqual(findings.first { $0.serverName == "npxabs" }?.shouldShowInAccessCenter, true)
        XCTAssertEqual(findings.first { $0.serverName == "shell" }?.isWrapEligible, false)
        XCTAssertEqual(findings.first { $0.serverName == "shell" }?.wrapBlockReason, .shell)
        XCTAssertEqual(findings.first { $0.serverName == "shell" }?.shouldShowInAccessCenter, true)
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
        // `-e, --env <env...>` is variadic in both CLIs, so a recipe that puts
        // the server name after the env flags makes the client read the name as
        // another KEY=value and reject the command.
        XCTAssertFalse(text?.contains("--env AUTHSIA_MCP_UPSTREAM=playwright playwright") == true)
        XCTAssertTrue(text?.contains("[mcp_servers.playwright]") == true)
        XCTAssertTrue(text?.contains("args = [\"mcp\", \"proxy\"]") == true)
        XCTAssertTrue(
            text?.contains(
                "env_vars = [\"NODE_EXTRA_CA_CERTS\", \"REQUESTS_CA_BUNDLE\", \"SSL_CERT_FILE\"]"
            ) == true
        )
        XCTAssertTrue(text?.contains("AUTHSIA_MCP_UPSTREAM = \"playwright\"") == true)
        XCTAssertTrue(text?.contains("\"name\" : \"playwright\"") == true || text?.contains("\"name\": \"playwright\"") == true)
        XCTAssertTrue(text?.contains("mcpUpstreams") == true)
        XCTAssertTrue(text?.contains("\"command\" : \"npx\"") == true || text?.contains("\"command\": \"npx\"") == true)
        XCTAssertFalse(text?.contains("--upstream") == true)
        XCTAssertTrue(text?.contains("writes the scanned client file only after you confirm Write wrap") == true)
        XCTAssertTrue(text?.contains("authsia mcp catalog --server playwright --write") == true)
        XCTAssertFalse(text?.contains("TOKEN") == true)

        let claudeFinding = MCPClientServerFinding(
            source: .claude,
            serverName: "codegraph",
            commandLabel: "codegraph",
            status: .unadmitted,
            declaredUpstreamName: nil,
            configPathLabel: "~/.claude.json",
            wrapCommand: "codegraph",
            wrapArguments: ["serve", "--mcp"],
            isWrapEligible: true
        )
        let claudeText = MCPLocalMCPWrapRecipe.clipboardText(
            for: claudeFinding,
            authsiaCommand: "/Applications/Authsia.app/Contents/Helpers/authsia"
        )
        // The recipe replaces an entry the scan found, and `claude mcp add`
        // refuses an existing name, so the remove has to lead.
        XCTAssertTrue(
            claudeText?.contains(
                "claude mcp remove --scope user codegraph\n"
                    + "claude mcp add --scope user codegraph --env AUTHSIA_MCP_UPSTREAM=codegraph -- "
            ) == true
        )

        let afterDeclare = MCPLocalMCPWrapRecipe.clipboardText(
            for: finding,
            authsiaCommand: "/Applications/Authsia.app/Contents/Helpers/authsia",
            includeWorkspacePolicy: false
        )
        XCTAssertTrue(afterDeclare?.contains("Open ~/.codex/config.toml") == true)
        XCTAssertFalse(afterDeclare?.contains("mcpUpstreams") == true)
        XCTAssertFalse(afterDeclare?.contains("\"command\": \"npx\"") == true)
        XCTAssertFalse(afterDeclare?.contains("\"command\" : \"npx\"") == true)

        let projectClaude = MCPLocalMCPWrapRecipe.clipboardText(
            for: MCPClientServerFinding(
                source: .claude,
                serverName: "codegraph",
                commandLabel: "codegraph",
                status: .directBypass,
                declaredUpstreamName: "codegraph",
                configPathLabel: "~/repo/.mcp.json",
                configScope: .project,
                precedence: .effective,
                workspacePathLabel: "~/repo",
                wrapCommand: "codegraph",
                wrapArguments: ["serve", "--mcp"],
                isWrapEligible: true
            ),
            authsiaCommand: "/Applications/Authsia.app/Contents/Helpers/authsia"
        )
        XCTAssertTrue(projectClaude?.contains("Open ~/repo/.mcp.json") == true)
        XCTAssertFalse(projectClaude?.contains("--scope user") == true)

        let projectVSCode = MCPLocalMCPWrapRecipe.clipboardText(
            for: MCPClientServerFinding(
                source: .vscode,
                serverName: "codegraph",
                commandLabel: "codegraph",
                status: .directBypass,
                declaredUpstreamName: "codegraph",
                configPathLabel: "~/repo/.vscode/mcp.json",
                configScope: .project,
                precedence: .effective,
                workspacePathLabel: "~/repo",
                wrapCommand: "codegraph",
                wrapArguments: ["serve", "--mcp"],
                isWrapEligible: true
            ),
            authsiaCommand: "/Applications/Authsia.app/Contents/Helpers/authsia"
        )
        XCTAssertTrue(projectVSCode?.contains("Open ~/repo/.vscode/mcp.json") == true)
        XCTAssertFalse(projectVSCode?.contains("Open User Configuration") == true)
        XCTAssertFalse(projectVSCode?.contains("code --add-mcp") == true)

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
        XCTAssertTrue(cursor?.contains("authsia mcp wrap --write --server codegraph") == true)
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

    func testFindingJSONIncludesStableID() throws {
        let finding = MCPClientServerFinding(
            source: .cursor,
            serverName: "filesystem",
            commandLabel: "npx",
            status: .unadmitted,
            declaredUpstreamName: nil,
            configPathLabel: "~/.cursor/mcp.json",
            workspacePathLabel: "~/repo"
        )
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(finding)) as? [String: Any]
        )

        XCTAssertEqual(object["id"] as? String, finding.id)
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
    func testProjectLocationsCoverClientsThatOutrankUserGlobalConfig() {
        let home = URL(fileURLWithPath: "/Users/dev", isDirectory: true)
        let locations = MCPClientConfigLocation.projectLocations(
            workspaceRoots: [URL(fileURLWithPath: "/Users/dev/repo", isDirectory: true)],
            homeDirectory: home
        )

        XCTAssertEqual(locations.map(\.source), [.claude, .cursor, .vscode, .claude])
        XCTAssertEqual(locations.map(\.displayPath), [
            "~/repo/.mcp.json",
            "~/repo/.cursor/mcp.json",
            "~/repo/.vscode/mcp.json",
            "~/.claude.json (local scope)",
        ])
        XCTAssertTrue(locations.allSatisfy { $0.scope == .project })
        XCTAssertTrue(locations.allSatisfy { $0.workspaceRoot == URL(fileURLWithPath: "/Users/dev/repo", isDirectory: true).standardizedFileURL })
        // Codex and Devin have no project scope; inventing paths for them would
        // report findings from files those clients never read.
        XCTAssertFalse(locations.contains { $0.source == .codex || $0.source == .devin })
    }

    func testProjectLocationsKeepFullPathOutsideHomeAndDeduplicate() {
        let home = URL(fileURLWithPath: "/Users/dev", isDirectory: true)
        let root = URL(fileURLWithPath: "/srv/repo", isDirectory: true)
        let locations = MCPClientConfigLocation.projectLocations(
            workspaceRoots: [root, root],
            homeDirectory: home
        )

        XCTAssertEqual(locations.count, 4)
        XCTAssertEqual(locations.first?.displayPath, "/srv/repo/.mcp.json")
    }

    func testFindingPreservesExactLongConfigPath() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let config = root.appendingPathComponent("mcp.json")
        try writeJSON([
            "mcpServers": ["filesystem": ["command": "npx"]],
        ], to: config)
        let exactPath = "/" + String(repeating: "long-path/", count: 40) + "mcp.json"

        let findings = MCPClientConfigScanner().scan(
            declaredServers: [],
            locations: [MCPClientConfigLocation(
                source: .cursor,
                fileURL: config,
                displayPath: exactPath
            )]
        )

        XCTAssertEqual(findings.first?.configPathLabel, exactPath)
    }

    func testProjectScopedDirectLaunchIsReportedBesideWrappedUserGlobalEntry() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let root = home.appendingPathComponent("repo", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

        // User-global holds the wrapped proxy entry.
        try JSONSerialization.data(withJSONObject: [
            "mcpServers": [
                "codegraph": [
                    "command": "/Applications/Authsia.app/Contents/Helpers/authsia",
                    "args": ["mcp", "proxy"],
                    "env": ["AUTHSIA_MCP_UPSTREAM": "codegraph"],
                ],
            ],
        ]).write(to: home.appendingPathComponent(".claude.json"))

        // The repository holds an unwrapped entry, and it wins at runtime.
        try JSONSerialization.data(withJSONObject: [
            "mcpServers": [
                "codegraph": ["command": "codegraph", "args": ["serve", "--mcp"]],
            ],
        ]).write(to: root.appendingPathComponent(".mcp.json"))

        let declared = [
            MCPDeclaredLocalServer(
                name: "codegraph",
                command: "codegraph",
                arguments: ["serve", "--mcp"],
                workspaceRoot: root
            ),
        ]
        let findings = MCPClientConfigScanner().scan(
            declaredServers: declared,
            locations: MCPClientConfigLocation.knownLocations(homeDirectory: home)
                + MCPClientConfigLocation.projectLocations(workspaceRoots: [root], homeDirectory: home)
        )

        let byPath = Dictionary(uniqueKeysWithValues: findings.map { ($0.configPathLabel, $0) })
        XCTAssertEqual(byPath["~/.claude.json"]?.status, .admittedWrapped)
        XCTAssertEqual(byPath["~/.claude.json"]?.configScope, .userGlobal)
        XCTAssertEqual(byPath["~/.claude.json"]?.precedence, .overridden)
        XCTAssertEqual(byPath["~/.claude.json"]?.workspacePathLabel, "~/repo")
        // Without the project scan this row is missing and Access Center shows
        // only "wrapped", which is the opposite of what actually runs.
        XCTAssertEqual(byPath["~/repo/.mcp.json"]?.status, .directBypass)
        XCTAssertEqual(byPath["~/repo/.mcp.json"]?.configScope, .project)
        XCTAssertEqual(byPath["~/repo/.mcp.json"]?.precedence, .effective)
    }

    func testDeclarationsDoNotCrossWorkspaceBoundaries() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let rootA = home.appendingPathComponent("repo-a", isDirectory: true)
        let rootB = home.appendingPathComponent("repo-b", isDirectory: true)
        try FileManager.default.createDirectory(at: rootA, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: rootB, withIntermediateDirectories: true)

        try JSONSerialization.data(withJSONObject: [
            "mcpServers": [
                "codegraph": [
                    "command": "/Applications/Authsia.app/Contents/Helpers/authsia",
                    "args": ["mcp", "proxy"],
                    "env": ["AUTHSIA_MCP_UPSTREAM": "codegraph"],
                ],
            ],
        ]).write(to: home.appendingPathComponent(".claude.json"))
        try JSONSerialization.data(withJSONObject: [
            "mcpServers": [
                "codegraph": [
                    "command": "/Applications/Authsia.app/Contents/Helpers/authsia",
                    "args": ["mcp", "proxy"],
                    "env": ["AUTHSIA_MCP_UPSTREAM": "codegraph"],
                ],
            ],
        ]).write(to: rootB.appendingPathComponent(".mcp.json"))

        let findings = MCPClientConfigScanner().scan(
            declaredServers: [
                MCPDeclaredLocalServer(
                    name: "codegraph",
                    command: "codegraph",
                    arguments: ["serve", "--mcp"],
                    workspaceRoot: rootA
                ),
            ],
            locations: MCPClientConfigLocation.knownLocations(homeDirectory: home)
                + MCPClientConfigLocation.projectLocations(
                    workspaceRoots: [rootA, rootB],
                    homeDirectory: home
                )
        )

        let rootBFinding = try XCTUnwrap(findings.first {
            $0.configPathLabel == "~/repo-b/.mcp.json"
        })
        XCTAssertEqual(rootBFinding.workspacePathLabel, "~/repo-b")
        XCTAssertEqual(rootBFinding.status, .unadmitted)
        XCTAssertEqual(rootBFinding.precedence, .effective)
        XCTAssertTrue(rootBFinding.shouldShowInAccessCenter)
    }


    func testDisabledLaunchesAreNotReportedAsProtectionDebt() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let codex = root.appendingPathComponent("codex.toml")
        let cursor = root.appendingPathComponent("cursor.json")
        try """
        [mcp_servers.off]
        command = "off-server"
        args = ["mcp"]
        enabled = false

        [mcp_servers.on]
        command = "on-server"
        args = ["mcp"]
        """.write(to: codex, atomically: true, encoding: .utf8)
        try writeJSON([
            "mcpServers": [
                "cursor-off": ["command": "off-server", "enabled": false],
                "cursor-also-off": ["command": "off-server", "disabled": true],
                "cursor-on": ["command": "on-server"],
            ],
        ], to: cursor)

        let findings = MCPClientConfigScanner().scan(
            declaredServers: [],
            locations: [
                MCPClientConfigLocation(source: .codex, fileURL: codex, displayPath: "~/.codex/config.toml"),
                MCPClientConfigLocation(source: .cursor, fileURL: cursor, displayPath: "~/.cursor/mcp.json"),
            ]
        )

        XCTAssertEqual(findings.map(\.serverName), ["on", "cursor-on"])
    }

    func testClaudeLocalScopeIsDiscoveredAndOutranksProjectFile() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        let repo = home.appendingPathComponent("repo", isDirectory: true)
        try FileManager.default.createDirectory(at: repo, withIntermediateDirectories: true)
        try writeJSON([
            "mcpServers": ["shared": ["command": "user-global-server"]],
            "projects": [
                repo.standardizedFileURL.path: [
                    "mcpServers": [
                        "shared": ["command": "local-scope-server"],
                        "local-only": ["command": "local-only-server"],
                    ],
                ],
            ],
        ], to: home.appendingPathComponent(".claude.json"))
        try writeJSON([
            "mcpServers": ["shared": ["command": "project-file-server"]],
        ], to: repo.appendingPathComponent(".mcp.json"))

        let findings = MCPClientConfigScanner().scan(
            declaredServers: [],
            locations: MCPClientConfigLocation.knownLocations(homeDirectory: home)
                + MCPClientConfigLocation.projectLocations(
                    workspaceRoots: [repo],
                    homeDirectory: home
                )
        )

        // `claude mcp add` defaults to local scope, so a server that exists
        // only there must still be discovered.
        XCTAssertEqual(
            findings.first { $0.serverName == "local-only" }?.commandLabel,
            "local-only-server"
        )
        let shared = findings.filter { $0.serverName == "shared" }
        XCTAssertEqual(
            shared.filter { $0.precedence == .effective }.map(\.commandLabel),
            ["local-scope-server"]
        )
        XCTAssertEqual(
            Set(shared.filter { $0.precedence == .overridden }.map(\.commandLabel)),
            ["project-file-server", "user-global-server"]
        )
    }


    func testLaunchKeysWorkspacePolicyCannotCarryBlockTheWrap() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let codex = root.appendingPathComponent("codex.toml")
        let cursor = root.appendingPathComponent("cursor.json")
        try """
        [mcp_servers.relative]
        command = "./tool/server"
        args = ["mcp"]
        cwd = "."
        """.write(to: codex, atomically: true, encoding: .utf8)
        try writeJSON([
            "mcpServers": [
                "pinned": ["command": "server", "cwd": "/srv/tool"],
            ],
        ], to: cursor)

        let findings = MCPClientConfigScanner().scan(
            declaredServers: [],
            locations: [
                MCPClientConfigLocation(source: .codex, fileURL: codex, displayPath: "~/.codex/config.toml"),
                MCPClientConfigLocation(source: .cursor, fileURL: cursor, displayPath: "~/.cursor/mcp.json"),
            ]
        )

        XCTAssertEqual(findings.count, 2)
        for finding in findings {
            // Wrapping would drop the working directory and quietly change how
            // the child runs, so Coverage must not offer Protect here.
            XCTAssertFalse(finding.isWrapEligible, finding.serverName)
            XCTAssertEqual(finding.wrapBlockReason, .unsupportedLaunchKey, finding.serverName)
            XCTAssertEqual(finding.unsupportedLaunchKeys, ["cwd"], finding.serverName)
            XCTAssertTrue(finding.shouldShowInAccessCenter, finding.serverName)
        }
    }


    func testChildEnvironmentIsCountedButNeverRetained() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let codex = root.appendingPathComponent("codex.toml")
        let cursor = root.appendingPathComponent("cursor.json")
        try """
        [mcp_servers.node_repl]
        command = "node_repl"
        args = []

        [mcp_servers.node_repl.env]
        NODE_PATH = "must-not-appear"
        NODE_MODULE_DIRS = "must-not-appear"
        """.write(to: codex, atomically: true, encoding: .utf8)
        try writeJSON([
            "mcpServers": [
                "jira": [
                    "command": "mcp-atlassian",
                    "env": ["TOKEN": "must-not-appear"],
                ],
            ],
        ], to: cursor)

        let findings = MCPClientConfigScanner().scan(
            declaredServers: [],
            locations: [
                MCPClientConfigLocation(source: .codex, fileURL: codex, displayPath: "~/.codex/config.toml"),
                MCPClientConfigLocation(source: .cursor, fileURL: cursor, displayPath: "~/.cursor/mcp.json"),
            ]
        )

        XCTAssertEqual(findings.first { $0.serverName == "node_repl" }?.childEnvironmentCount, 2)
        XCTAssertEqual(findings.first { $0.serverName == "jira" }?.childEnvironmentCount, 1)
        let encoded = String(decoding: try JSONEncoder().encode(findings), as: UTF8.self)
        XCTAssertFalse(encoded.contains("must-not-appear"))
        XCTAssertFalse(encoded.contains("TOKEN"))
        XCTAssertFalse(encoded.contains("NODE_PATH"))
    }

}
