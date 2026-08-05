import Foundation
import Testing
@testable import authsia

@Suite("MCP runtime context")
struct MCPRuntimeContextTests {
    @Test("server identity and initial canonical workspace are resolved")
    func serverIdentityAndInitialWorkspace() throws {
        let root = try makeManagedWorkspace()
        defer { try? FileManager.default.removeItem(at: root) }
        let nested = root.appendingPathComponent("Sources/App", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        let id = UUID(uuidString: "7E05890F-5C3A-44EF-9208-83A12F17D6CE")!

        let context = MCPRuntimeContext(startingDirectory: nested, instanceID: id)

        #expect(context.instanceID == id)
        #expect(context.workspaceRoot?.path == root.resolvingSymlinksInPath().path)
        #expect(context.workspaceName == "api")
    }

    @Test("each invocation has fresh agent projection")
    func freshInvocationProjection() async throws {
        let root = try makeManagedWorkspace()
        defer { try? FileManager.default.removeItem(at: root) }
        let serverID = UUID(uuidString: "7E05890F-5C3A-44EF-9208-83A12F17D6CE")!
        let firstID = UUID(uuidString: "2624F49A-65EE-433C-B816-03631A44D1C7")!
        let context = MCPRuntimeContext(startingDirectory: root, instanceID: serverID)

        await context.updateClientInfo(name: "Codex", version: "999-untrusted")
        let first = await context.makeInvocation(id: firstID)
        let second = await context.makeInvocation()

        #expect(first.id == firstID)
        #expect(first.id != second.id)
        #expect(first.environment == [
            "AUTHSIA_AGENT_INVOKES_AUTHSIA": "1",
            "AUTHSIA_AGENT_PLATFORM": "Codex",
            "AUTHSIA_AGENT_SESSION_ID": "mcp:\(serverID.uuidString)",
            "AUTHSIA_AGENT_TURN_ID": "mcp-call:\(firstID.uuidString)",
            "AUTHSIA_AGENT_TYPE": "authsia-mcp",
            "AUTHSIA_AGENT_TOOL_USE_ID": "mcp-call:\(firstID.uuidString)",
        ])
        #expect(!first.environment.values.contains("999-untrusted"))
    }

    @Test("untrusted client labels are sanitized and never change authority")
    func clientLabelsAreDisplayOnly() async throws {
        let root = try makeManagedWorkspace()
        defer { try? FileManager.default.removeItem(at: root) }
        let context = MCPRuntimeContext(startingDirectory: root)
        let authority = context.workspaceRoot

        await context.updateClientInfo(name: "bad\nclient", version: root.path)
        let invalid = await context.makeInvocation()
        #expect(invalid.environment["AUTHSIA_AGENT_PLATFORM"] == "mcp-client")
        #expect(context.workspaceRoot == authority)

        await context.updateClientInfo(name: String(repeating: "x", count: 200), version: "1")
        let long = await context.makeInvocation()
        #expect(long.environment["AUTHSIA_AGENT_PLATFORM"]?.count == 128)
        #expect(context.workspaceRoot == authority)
    }

    @Test("missing or invalid workspaces cannot become authority")
    func missingWorkspaceIsRejected() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let context = MCPRuntimeContext(startingDirectory: root)

        #expect(context.workspaceRoot == nil)
        #expect(throws: MCPRuntimeContextError.self) {
            try context.requireWorkspace()
        }
    }

    @Test("an explicit tool workspace path binds a managed workspace")
    func toolWorkspacePathBindsManagedWorkspace() throws {
        let launchDirectory = try makeWorkspaceRoot()
        let managedRoot = try makeManagedWorkspace(name: "ide")
        defer {
            try? FileManager.default.removeItem(at: launchDirectory)
            try? FileManager.default.removeItem(at: managedRoot)
        }
        let nested = managedRoot.appendingPathComponent("Sources/App", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        let context = MCPRuntimeContext(startingDirectory: launchDirectory)

        try context.bindToWorkspaceRoot(nested)

        #expect(context.workspaceName == "ide")
        #expect(context.workspaceRoot?.path == managedRoot.resolvingSymlinksInPath().path)
    }

    @Test("an invalid tool workspace path clears stale authority")
    func invalidToolWorkspacePathFailsClosed() throws {
        let launchDirectory = try makeWorkspaceRoot()
        let managedRoot = try makeManagedWorkspace(name: "frontend")
        let invalidRoot = try makeWorkspaceRoot()
        defer {
            try? FileManager.default.removeItem(at: launchDirectory)
            try? FileManager.default.removeItem(at: managedRoot)
            try? FileManager.default.removeItem(at: invalidRoot)
        }
        let context = MCPRuntimeContext(startingDirectory: launchDirectory)

        try context.bindToWorkspaceRoot(managedRoot)
        #expect(context.workspaceName == "frontend")
        #expect(throws: MCPRuntimeContextError.self) {
            try context.bindToWorkspaceRoot(invalidRoot)
        }

        #expect(context.workspaceRoot == nil)
        #expect(context.workspaceName == nil)
    }

    private func makeManagedWorkspace(name: String = "api") throws -> URL {
        let root = try makeWorkspaceRoot()
        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                workspace: .init(name: name, authsiaFolder: "Workspaces/\(name)"),
                managedEnvFiles: [],
                agents: nil
            ),
            toWorkspaceRoot: root
        )
        return root
    }
}
