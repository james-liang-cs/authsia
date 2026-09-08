import XCTest
@testable import AuthenticatorBridge

final class MCPDiscoveryProjectionTests: XCTestCase {
    func testDirectServerWorkspaceEnvironmentStillCountsAsChildEnvironment() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("mcp.json")
        try JSONSerialization.data(withJSONObject: ["mcpServers": ["example": [
            "command": "fixture-server", "args": ["--stdio"],
            "env": [MCPProxyClientLaunch.workspaceEnvironmentKey: root.path],
        ]]]).write(to: file)
        let location = MCPClientConfigLocation(source: .cursor, fileURL: file,
            displayPath: file.path, scope: .project, workspaceRoot: root)
        let finding = try XCTUnwrap(MCPClientConfigScanner().scan(declaredServers: [], locations: [location]).first)
        XCTAssertEqual(finding.childEnvironmentCount, 1)
    }

    func testWrappedLaunchRetainsRecoveryWithoutAnyWorkspaceDeclaration() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        for client in [MCPClientConfigSource.codex, .cursor] {
            let file = root.appendingPathComponent(client == .codex ? "config.toml" : "mcp.json")
            let text = client == .codex
                ? "[mcp_servers.example]\ncommand = \"fixture-server\"\nargs = [\"--stdio\"]\n"
                : #"{"mcpServers":{"example":{"command":"fixture-server","args":["--stdio"]}}}"#
            try Data(text.utf8).write(to: file)
            let location = MCPClientConfigLocation(source: client, fileURL: file, displayPath: file.path,
                scope: .project, workspaceRoot: root)
            let scanner = MCPClientConfigScanner()
            let direct = try XCTUnwrap(scanner.scan(declaredServers: [], locations: [location]).first)
            let plan = try MCPLocalMCPClientWrap.plan(finding: direct, authsiaCommand: "authsia", homeDirectory: root)
            try MCPLocalMCPClientWrap.apply(plan, authsiaCommand: "authsia")
            let findings = scanner.scan(declaredServers: [], locations: [location])
            let wrapped = try XCTUnwrap(findings.first)
            XCTAssertTrue(wrapped.isAuthsiaProxyLaunch)
            XCTAssertFalse(wrapped.isWrapEligible)
            XCTAssertEqual(wrapped.wrapCommand, "fixture-server")
            XCTAssertEqual(wrapped.wrapArguments, ["--stdio"])
            XCTAssertEqual(wrapped.childEnvironmentCount, 0)
            let row = try XCTUnwrap(MCPDiscoveryProjection.servers(findings: findings, declared: [],
                workspaceRoots: [root], homeDirectory: root).first)
            XCTAssertTrue(row.canConfigure)
        }
    }

    func testLegacyContext7OffersPresetWithoutManualExecutableEntry() throws {
        let finding = MCPClientServerFinding(source: .codex, serverName: "context7", commandLabel: "authsia",
            status: .unadmitted, declaredUpstreamName: "context7", configPathLabel: "~/.codex/config.toml",
            precedence: .effective, workspacePathLabel: reuseTarget.path, isAuthsiaProxyLaunch: true)
        let row = try XCTUnwrap(MCPDiscoveryProjection.servers(findings: [finding], declared: [],
            workspaceRoots: [reuseTarget], homeDirectory: reuseHome).first)
        XCTAssertTrue(row.canConfigure)
        XCTAssertTrue(row.configurationHint.contains("Context7 preset"))
    }

    func testNewClientEnrollmentRetainsDeclaredLaunchOnly() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let upstream = MCPUpstreamConfig(name: "example", command: "fixture-server", args: ["--stdio"],
            env: ["EXAMPLE_KEY": "authsia://api-key/fixture-reference/key"], tools: .init(allow: ["read"]))
        let plan = try MCPLocalMCPClientWrap.planInsert(source: .cursor, serverName: "example",
            workspacePath: home.path, authsiaCommand: "authsia", upstream: upstream, homeDirectory: home)
        try MCPLocalMCPClientWrap.apply(plan, authsiaCommand: "authsia")
        let finding = try XCTUnwrap(MCPClientConfigScanner().scan(declaredServers: [], locations: [
            .init(source: .cursor, fileURL: plan.fileURL, displayPath: plan.fileURL.path, scope: .project, workspaceRoot: home)
        ]).first)
        let recovered = try XCTUnwrap(MCPDiscoveryProjection.recoveredDeclaration(for: finding))
        XCTAssertEqual(recovered.command, "fixture-server")
        XCTAssertEqual(recovered.args, ["--stdio"])
        XCTAssertTrue(recovered.env.isEmpty)
        XCTAssertTrue(recovered.tools.allow.isEmpty)
        XCTAssertFalse(try String(contentsOf: plan.fileURL, encoding: .utf8).contains("authsia://"))
    }

    func testRecoveryRejectsUnsafeMismatchedAndInactiveLaunches() throws {
        XCTAssertNil(MCPProxyClientLaunch.recoveryValue(name: "example", command: "authsia", arguments: ["mcp", "proxy"]))
        XCTAssertNil(MCPProxyClientLaunch.recoveryValue(name: "example", command: "sh", arguments: ["-c", "fixture"]))
        XCTAssertNil(MCPProxyClientLaunch.recoveryValue(name: "example", command: "fixture", arguments: ["--password", "REDACTED_FIXTURE"]))
        let value = try XCTUnwrap(MCPProxyClientLaunch.recoveryValue(name: "example", command: "fixture", arguments: []))
        XCTAssertNil(MCPProxyClientLaunch.recoveredLaunch(value, name: "unrelated"))
        XCTAssertNil(MCPProxyClientLaunch.recoveredLaunch("invalid", name: "example"))
        for finding in [wrappedFinding(status: .disabled), wrappedFinding(precedence: .overridden)] {
            XCTAssertNil(MCPDiscoveryProjection.recoveredDeclaration(for: finding))
        }
    }

    func testMalformedSavedLaunchDoesNotFallBackToContext7Preset() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("mcp.json")
        for invalidValue: Any in ["invalid", 42] {
            let data = try JSONSerialization.data(withJSONObject: ["mcpServers": ["context7": [
                "command": "authsia", "args": ["mcp", "proxy"],
                "env": ["AUTHSIA_MCP_UPSTREAM": "context7", "AUTHSIA_MCP_LAUNCH": invalidValue]
            ]]])
            try data.write(to: file)
            let finding = try XCTUnwrap(MCPClientConfigScanner().scan(declaredServers: [], locations: [
                .init(source: .cursor, fileURL: file, displayPath: file.path, scope: .project, workspaceRoot: root)
            ]).first)
            XCTAssertNil(MCPDiscoveryProjection.recoveredDeclaration(for: finding))
            XCTAssertNotNil(MCPDiscoveryProjection.configurationHint(for: finding))
        }
    }

    func testRecoveryUsesUpstreamNameRatherThanClientAliasAndCopiesNoAuthority() throws {
        let finding = MCPClientServerFinding(source: .codex, serverName: "client-alias", commandLabel: "authsia",
            status: .unadmitted, declaredUpstreamName: "example", configPathLabel: "fixture",
            precedence: .effective, isAuthsiaProxyLaunch: true, wrapCommand: "fixture-server", wrapArguments: ["--stdio"])
        let upstream = try XCTUnwrap(MCPDiscoveryProjection.recoveredDeclaration(for: finding))
        XCTAssertEqual(upstream.name, "example")
        XCTAssertEqual(upstream.command, "fixture-server")
        XCTAssertTrue(upstream.env.isEmpty)
        XCTAssertTrue(upstream.tools.allow.isEmpty)
        XCTAssertTrue(upstream.tools.approve.isEmpty)
        XCTAssertTrue(upstream.catalog.isEmpty)
    }

    private let reuseTarget = URL(fileURLWithPath: "/tmp/authsia-reuse-target")
    private let reuseHome = URL(fileURLWithPath: "/tmp/authsia-reuse-home")

    private func wrappedFinding(status: MCPClientServerAdmissionStatus = .unadmitted,
                                precedence: MCPClientConfigPrecedence = .effective) -> MCPClientServerFinding {
        .init(source: .codex, serverName: "client-alias", commandLabel: "authsia", status: status,
              declaredUpstreamName: "example", configPathLabel: "~/.codex/config.toml",
              precedence: precedence, workspacePathLabel: reuseTarget.path, isAuthsiaProxyLaunch: true)
    }

    private func reuseSource(name: String = "example", command: String = "fixture-server",
                             args: [String] = []) -> MCPServerDefinition {
        .init(identity: .init(workspacePath: "/tmp/authsia-reuse-source", upstreamName: name),
              upstream: .init(name: name, command: command, args: args,
                              env: ["EXAMPLE_KEY": "authsia://api-key/fixture-reference/key"],
                              tools: .init(allow: ["read"], deny: ["delete"]),
                              catalog: [.init(name: "read")]), revision: "fixture")
    }

    func testWrappedLaunchOffersMatchingSetupInAnotherWorkspace() throws {
        let source = reuseSource()
        let rows = MCPDiscoveryProjection.servers(findings: [wrappedFinding()], declared: [source.identity],
            workspaceRoots: [reuseTarget], homeDirectory: reuseHome, definitions: [source, reuseSource(name: "unrelated")])
        let row = try XCTUnwrap(rows.first)
        XCTAssertFalse(row.canConfigure)
        XCTAssertEqual(row.reusableSourceServerIDs, [source.serverID])
        XCTAssertTrue(row.configurationHint.contains("Choose an existing setup"))
        XCTAssertFalse(row.configurationHint.contains("manual setup"))
    }

    func testReuseCopiesLaunchAndPolicyWithoutCredentialsOrCatalog() throws {
        let source = reuseSource(args: ["--stdio"])
        let copy = try MCPDiscoveryProjection.reusableDeclaration(from: source, for: wrappedFinding(), targetRoot: reuseTarget, homeDirectory: reuseHome)
        XCTAssertEqual(copy.name, "example")
        XCTAssertEqual(copy.command, source.upstream.command)
        XCTAssertEqual(copy.args, source.upstream.args)
        XCTAssertEqual(copy.tools, source.upstream.tools)
        XCTAssertTrue(copy.env.isEmpty)
        XCTAssertTrue(copy.credentialHeaders.isEmpty)
        XCTAssertTrue(copy.catalog.isEmpty)
        XCTAssertNil(copy.catalogCapturedAt)
    }

    func testReuseRejectsDisabledOverriddenUnrelatedAndRecursiveLaunches() throws {
        for finding in [wrappedFinding(status: .disabled), wrappedFinding(precedence: .overridden)] {
            XCTAssertThrowsError(try MCPDiscoveryProjection.reusableDeclaration(from: reuseSource(), for: finding, targetRoot: reuseTarget, homeDirectory: reuseHome))
        }
        for source in [reuseSource(name: "unrelated"), reuseSource(command: "authsia", args: ["mcp", "proxy"])] {
            XCTAssertThrowsError(try MCPDiscoveryProjection.reusableDeclaration(from: source, for: wrappedFinding(), targetRoot: reuseTarget, homeDirectory: reuseHome))
        }
        XCTAssertThrowsError(try MCPDiscoveryProjection.reusableDeclaration(from: reuseSource(), for: wrappedFinding(), targetRoot: URL(fileURLWithPath: "/tmp/other-target"), homeDirectory: reuseHome))
    }

    func testReuseRejectsArgumentsFlaggedByRedaction() {
        // The synthetic argument is deliberately recognizable to the redactor.
        let source = reuseSource(args: ["--password", "REDACTED_FIXTURE"])
        XCTAssertThrowsError(try MCPDiscoveryProjection.reusableDeclaration(from: source, for: wrappedFinding(), targetRoot: reuseTarget, homeDirectory: reuseHome))
    }

    func testDeclarationInAnotherWorkspaceDoesNotHideDiscovery() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let a = root.appendingPathComponent("a"), b = root.appendingPathComponent("b"), global = root.appendingPathComponent("client.json")
        try Data(#"{"mcpServers":{"shared":{"command":"fixture"}}}"#.utf8).write(to: global)
        let findings = MCPClientConfigScanner().scan(declaredServers: [.init(name: "shared", command: "fixture", arguments: [], workspaceRoot: a)], locations: [
            .init(source: .cursor, fileURL: global, displayPath: global.path),
            .init(source: .cursor, fileURL: b.appendingPathComponent("absent.json"), displayPath: "project", scope: .project, workspaceRoot: b)
        ])
        let discovered = MCPDiscoveryProjection.servers(findings: findings, declared: [.init(workspaceRoot: a, upstreamName: "shared")],
                                                        workspaceRoots: [a, b], homeDirectory: root)
        XCTAssertEqual(discovered.count, 1)
        XCTAssertEqual(discovered.first?.workspacePath, b.path)
        XCTAssertEqual(discovered.first?.canConfigure, true)
    }

    func testUnconfiguredWorkspaceStillDiscoversUserGlobalAndProjectServers() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let workspace = root.appendingPathComponent("project")
        let global = root.appendingPathComponent("global.json"), project = root.appendingPathComponent("project.json")
        try Data(#"{"mcpServers":{"global":{"command":"fixture-global","args":["--stdio"]}}}"#.utf8).write(to: global)
        try Data(#"{"mcpServers":{"local":{"command":"fixture-local"}}}"#.utf8).write(to: project)
        let findings = MCPClientConfigScanner().scan(declaredServers: [], locations: [
            .init(source: .cursor, fileURL: global, displayPath: global.path),
            .init(source: .cursor, fileURL: project, displayPath: project.path, scope: .project, workspaceRoot: workspace)
        ])
        let discovered = MCPDiscoveryProjection.servers(findings: findings, declared: [], workspaceRoots: [workspace], homeDirectory: root)
        XCTAssertEqual(Set(discovered.map(\.displayName)), ["global", "local"])
        XCTAssertTrue(discovered.allSatisfy(\.canConfigure))
        XCTAssertTrue(discovered.allSatisfy { $0.workspaceID == MCPWorkspaceStore.digest(Data(workspace.path.utf8)) })
        let data = try JSONEncoder().encode(discovered)
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("--stdio"))
        let configured = MCPDiscoveryProjection.servers(findings: findings,
            declared: [.init(workspaceRoot: workspace, upstreamName: "local")], workspaceRoots: [workspace], homeDirectory: root)
        XCTAssertEqual(configured.map(\.displayName), ["global"])
    }

    func testProjectOverrideIsNotOfferedAsAnEffectiveImport() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let global = root.appendingPathComponent("global.json"), project = root.appendingPathComponent("project.json")
        let data = Data(#"{"mcpServers":{"shared":{"command":"fixture"}}}"#.utf8)
        try data.write(to: global); try data.write(to: project)
        let findings = MCPClientConfigScanner().scan(declaredServers: [], locations: [
            .init(source: .cursor, fileURL: global, displayPath: global.path),
            .init(source: .cursor, fileURL: project, displayPath: project.path, scope: .project, workspaceRoot: root)
        ])
        let discovered = MCPDiscoveryProjection.servers(findings: findings, declared: [], workspaceRoots: [root], homeDirectory: root)
        XCTAssertEqual(discovered.filter(\.canConfigure).count, 1)
        XCTAssertEqual(discovered.first(where: { !$0.canConfigure })?.precedence, .overridden)
    }

    func testLocalHTTPDiscoveryDoesNotExposeQueryCredentials() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("client.json")
        try Data(#"{"mcpServers":{"good":{"url":"http://localhost:9000/mcp"},"bad":{"url":"http://127.0.0.1:9000/mcp?key=synthetic-value"}}}"#.utf8).write(to: file)
        let findings = MCPClientConfigScanner().scan(declaredServers: [], locations: [
            .init(source: .cursor, fileURL: file, displayPath: file.path, scope: .project, workspaceRoot: root)
        ])
        XCTAssertEqual(findings.first(where: { $0.serverName == "good" })?.localHTTPEndpoint, "http://localhost:9000/mcp")
        XCTAssertNil(findings.first(where: { $0.serverName == "bad" })?.localHTTPEndpoint)
        let discovered = MCPDiscoveryProjection.servers(findings: findings, declared: [], workspaceRoots: [root], homeDirectory: root)
        XCTAssertFalse(discovered.first(where: { $0.displayName == "bad" })!.canConfigure)
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(discovered), as: UTF8.self).contains("synthetic-value"))
    }

    func testCodexProjectHTTPConflictIsNotOfferedAsEnrollment() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let workspace = root.appendingPathComponent("repo")
        try FileManager.default.createDirectory(at: workspace.appendingPathComponent(".codex"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: root.appendingPathComponent(".codex"), withIntermediateDirectories: true)
        try Data("[mcp_servers.internal]\nurl = \"http://127.0.0.1:9000/mcp\"\n".utf8)
            .write(to: workspace.appendingPathComponent(".codex/config.toml"))
        try Data("[mcp_servers.internal]\nurl = \"http://127.0.0.1:8788/mcp/placeholder\"\n".utf8)
            .write(to: root.appendingPathComponent(".codex/config.toml"))
        let findings = MCPClientConfigScanner().scan(
            declaredServers: [],
            locations: MCPClientConfigLocation.knownLocations(homeDirectory: root)
                + MCPClientConfigLocation.projectLocations(workspaceRoots: [workspace], homeDirectory: root)
        )
        let discovered = MCPDiscoveryProjection.servers(
            findings: findings,
            declared: [],
            workspaceRoots: [workspace],
            homeDirectory: root
        )
        XCTAssertTrue(discovered.contains { $0.client == .codex && $0.canEnrollHTTP == false })
        XCTAssertTrue(discovered.contains {
            $0.client == .codex && ($0.unsupportedActionReason?.contains("project") == true)
        })
        XCTAssertFalse(discovered.contains { $0.client == .codex && $0.canEnrollHTTP })
    }
}
