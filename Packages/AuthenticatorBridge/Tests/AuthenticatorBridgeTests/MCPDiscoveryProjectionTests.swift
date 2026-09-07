import XCTest
@testable import AuthenticatorBridge

final class MCPDiscoveryProjectionTests: XCTestCase {
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
