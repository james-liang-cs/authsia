import XCTest
@testable import AuthenticatorBridge

final class MCPHTTPClientConfigurationTests: XCTestCase {
    func testProtectingDirectEntryPreservesClientOptions() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root.appendingPathComponent(".cursor"), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent(".cursor/mcp.json")
        try Data(#"{"mcpServers":{"internal":{"url":"http://127.0.0.1:9000/mcp","disabled":true}}}"#.utf8).write(to: file)
        let identity = MCPServerIdentity(workspacePath: root.appendingPathComponent("project").path, upstreamName: "internal")
        let binding = MCPHTTPAssociationBinding(serverID: MCPWorkspaceStore.serverID(identity), identity: identity, client: .cursor)
        let plan = try MCPHTTPClientConfiguration.prepare(binding: binding, token: "synthetic-association", home: root,
            replacingEndpoint: "http://127.0.0.1:9000/mcp")
        try plan.apply()
        let object = try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as! [String: Any]
        let server = (object["mcpServers"] as! [String: Any])["internal"] as! [String: Any]
        XCTAssertEqual(server["disabled"] as? Bool, true)
        XCTAssertEqual(server["url"] as? String, "http://127.0.0.1:8788/mcp/" + binding.serverID)
    }
    func testPreparationDoesNotWriteAndApplyPreservesUnrelatedEntries() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root.appendingPathComponent(".cursor"), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent(".cursor/mcp.json")
        let before = Data(#"{"mcpServers":{"unrelated":{"command":"fixture"}},"other":true}"#.utf8)
        try before.write(to: file)
        let identity = MCPServerIdentity(workspacePath: root.appendingPathComponent("project").path, upstreamName: "internal")
        let binding = MCPHTTPAssociationBinding(serverID: MCPWorkspaceStore.serverID(identity), identity: identity, client: .cursor)
        let plan = try MCPHTTPClientConfiguration.prepare(binding: binding, token: "synthetic-association", home: root)
        XCTAssertEqual(try Data(contentsOf: file), before)
        try plan.apply()
        let object = try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as! [String: Any]
        XCTAssertEqual(object["other"] as? Bool, true)
        XCTAssertNotNil((object["mcpServers"] as? [String: Any])?["unrelated"])
        XCTAssertThrowsError(try MCPHTTPClientConfiguration.prepare(binding: binding, token: "replacement", home: root))
        XCTAssertTrue(String(decoding: try Data(contentsOf: file), as: UTF8.self).contains("synthetic-association"))
    }
    func testQuotedCodexConflictIsRejectedBeforeAnyWrite() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root.appendingPathComponent(".codex"), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent(".codex/config.toml")
        let before = Data("[mcp_servers.\"internal\"]\nurl = \"http://127.0.0.1:9000/mcp\"\n".utf8)
        try before.write(to: file)
        let identity = MCPServerIdentity(workspacePath: root.appendingPathComponent("project").path, upstreamName: "internal")
        let binding = MCPHTTPAssociationBinding(serverID: MCPWorkspaceStore.serverID(identity), identity: identity, client: .codex)
        XCTAssertThrowsError(try MCPHTTPClientConfiguration.prepare(binding: binding, token: "replacement", home: root))
        XCTAssertEqual(try Data(contentsOf: file), before)
    }
}
