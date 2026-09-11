import XCTest
@testable import AuthenticatorBridge

final class MCPHTTPClientConfigurationTests: XCTestCase {
    func testRemovalPreservesArraysCommentsAndIndentedNeighbors() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root.appendingPathComponent(".codex"), withIntermediateDirectories: true)
        let file = root.appendingPathComponent(".codex/config.toml")
        let identity = MCPServerIdentity(workspacePath: root.path, upstreamName: "internal")
        let binding = MCPHTTPAssociationBinding(serverID: MCPWorkspaceStore.serverID(identity), identity: identity, client: .codex)
        let prefix = "# comment containing ''' and \"\"\"\nexamples = [\n  '[mcp_servers.internal]',\n  '''\n[mcp_servers.internal.http_headers]\n'''\n]\n"
        let neighbor = "  [mcp_servers.keep]\ncommand = 'fixture'\n"
        let target = "  [\"mcp_servers\" . 'internal'] # selected\nurl = 'http://127.0.0.1:8788/mcp/\(binding.serverID)'\n[[mcp_servers.internal.tools]]\nname = 'read'\n"
        for newline in ["\n", "\r\n"] {
            let before = Data((prefix + target + neighbor).replacingOccurrences(of: "\n", with: newline).utf8)
            try before.write(to: file)
            let plan = try MCPHTTPClientConfiguration.prepareRemoval(binding: binding, home: root)
            XCTAssertEqual(plan.replacement, Data((prefix + neighbor).replacingOccurrences(of: "\n", with: newline).utf8))
        }
        for text in [prefix + "notes = '''unterminated\n" + target,
                     "notes = '''\n" + target + "'''\n"] {
            let before = Data(text.utf8)
            try before.write(to: file)
            XCTAssertThrowsError(try MCPHTTPClientConfiguration.prepareRemoval(binding: binding, home: root))
            XCTAssertEqual(try Data(contentsOf: file), before)
        }
    }

    func testRemovalPreservesTableExamplesInsideMultilineStrings() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root.appendingPathComponent(".codex"), withIntermediateDirectories: true)
        let file = root.appendingPathComponent(".codex/config.toml")
        let identity = MCPServerIdentity(workspacePath: root.path, upstreamName: "internal")
        let binding = MCPHTTPAssociationBinding(serverID: MCPWorkspaceStore.serverID(identity), identity: identity, client: .codex)
        for delimiter in ["'''", "\"\"\""] {
            let instructions = "developer_instructions = \(delimiter)\n[mcp_servers.internal]\nurl = 'example only'\n[mcp_servers.internal.http_headers]\nExample = 'fixture'\n\(delimiter)\n"
            let neighbor = "[mcp_servers.keep]\ncommand = 'fixture-server'\nnotes = \(delimiter)\n[mcp_servers.internal.tools.read]\n\(delimiter)\n"
            let before = Data((instructions + "[mcp_servers.internal]\nurl = 'http://127.0.0.1:8788/mcp/\(binding.serverID)'\n[mcp_servers.internal.http_headers]\nAuthorization = 'Bearer synthetic-association'\n" + neighbor).utf8)
            try before.write(to: file)
            let plan = try MCPHTTPClientConfiguration.prepareRemoval(binding: binding, home: root)
            XCTAssertEqual(String(decoding: plan.replacement, as: UTF8.self), instructions + neighbor)
            XCTAssertEqual(try Data(contentsOf: file), before)
        }
    }

    func testCodexRemovalDeletesNestedTablesAndPreservesOtherServers() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root.appendingPathComponent(".codex"), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent(".codex/config.toml")
        let identity = MCPServerIdentity(workspacePath: root.appendingPathComponent("project").path, upstreamName: "internal")
        let binding = MCPHTTPAssociationBinding(serverID: MCPWorkspaceStore.serverID(identity), identity: identity, client: .codex)
        let unrelated = "[mcp_servers.internal_other]\ncommand = \"fixture\"\n"
        for name in ["internal", "\"internal\"", "'internal'"] {
            let before = Data(("""
            [mcp_servers.\(name)]
            url = "http://127.0.0.1:8788/mcp/\(binding.serverID)"
            [mcp_servers.\(name).http_headers]
            Authorization = "Bearer synthetic-association"
            \(unrelated)
            [mcp_servers.\(name).tools.read]
            approval_mode = "prompt"
            """ + "\n").utf8)
            try before.write(to: file)
            let plan = try MCPHTTPClientConfiguration.prepareRemoval(binding: binding, home: root)
            XCTAssertEqual(try Data(contentsOf: file), before)
            XCTAssertEqual(String(decoding: plan.replacement, as: UTF8.self), unrelated + "\n")
            try plan.apply()
            XCTAssertEqual(try Data(contentsOf: file), plan.replacement)
        }
    }

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

    func testProjectCodexQuotedConflictIsRejectedBeforeAnyWrite() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root.appendingPathComponent(".codex"), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let home = root.appendingPathComponent("home")
        try FileManager.default.createDirectory(at: home.appendingPathComponent(".codex"), withIntermediateDirectories: true)
        let project = root.appendingPathComponent("project")
        try FileManager.default.createDirectory(at: project.appendingPathComponent(".codex"), withIntermediateDirectories: true)
        let userFile = home.appendingPathComponent(".codex/config.toml")
        let projectFile = project.appendingPathComponent(".codex/config.toml")
        let before = Data("# commented [mcp_servers.other]\n".utf8)
        try before.write(to: userFile)
        try Data("[mcp_servers.\"internal\"]\nurl = \"http://127.0.0.1:9000/mcp\"\n".utf8).write(to: projectFile)
        let identity = MCPServerIdentity(workspacePath: project.path, upstreamName: "internal")
        let binding = MCPHTTPAssociationBinding(serverID: MCPWorkspaceStore.serverID(identity), identity: identity, client: .codex)
        XCTAssertThrowsError(try MCPHTTPClientConfiguration.prepare(binding: binding, token: "replacement", home: home))
        XCTAssertEqual(try Data(contentsOf: userFile), before)
    }

    func testCodexHTTPHeadersSubtableIsRejectedBeforeAnyWrite() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root.appendingPathComponent(".codex"), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent(".codex/config.toml")
        let before = Data("""
        [mcp_servers.internal]
        url = "http://127.0.0.1:9000/mcp"

        [mcp_servers.internal.http_headers]
        Authorization = "Bearer already-present"
        """.utf8)
        try before.write(to: file)
        let identity = MCPServerIdentity(workspacePath: root.appendingPathComponent("project").path, upstreamName: "internal")
        let binding = MCPHTTPAssociationBinding(serverID: MCPWorkspaceStore.serverID(identity), identity: identity, client: .codex)
        XCTAssertThrowsError(
            try MCPHTTPClientConfiguration.prepare(
                binding: binding, token: "replacement", home: root,
                replacingEndpoint: "http://127.0.0.1:9000/mcp"
            )
        )
        XCTAssertEqual(try Data(contentsOf: file), before)
        XCTAssertFalse(String(decoding: try Data(contentsOf: file), as: UTF8.self).contains("http_headers = {"))
    }

    func testQuotedCodexHTTPHeadersSubtableIsRejectedBeforeAnyWrite() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root.appendingPathComponent(".codex"), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent(".codex/config.toml")
        let before = Data("""
        [mcp_servers."internal"]
        url = "http://127.0.0.1:9000/mcp"

        [mcp_servers."internal".http_headers]
        Authorization = "Bearer already-present"
        """.utf8)
        try before.write(to: file)
        let identity = MCPServerIdentity(workspacePath: root.appendingPathComponent("project").path, upstreamName: "internal")
        let binding = MCPHTTPAssociationBinding(serverID: MCPWorkspaceStore.serverID(identity), identity: identity, client: .codex)
        XCTAssertThrowsError(
            try MCPHTTPClientConfiguration.prepare(
                binding: binding, token: "replacement", home: root,
                replacingEndpoint: "http://127.0.0.1:9000/mcp"
            )
        )
        XCTAssertEqual(try Data(contentsOf: file), before)
    }

    func testCommentedCodexHeadingIsNotAUserGlobalConflict() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root.appendingPathComponent(".codex"), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent(".codex/config.toml")
        try Data("# [mcp_servers.internal]\nurl = \"http://127.0.0.1:9000/mcp\"\n".utf8).write(to: file)
        let identity = MCPServerIdentity(workspacePath: root.appendingPathComponent("project").path, upstreamName: "internal")
        let binding = MCPHTTPAssociationBinding(serverID: MCPWorkspaceStore.serverID(identity), identity: identity, client: .codex)
        let plan = try MCPHTTPClientConfiguration.prepare(binding: binding, token: "synthetic-association", home: root)
        XCTAssertTrue(String(decoding: plan.replacement, as: UTF8.self).contains("synthetic-association"))
    }
}
