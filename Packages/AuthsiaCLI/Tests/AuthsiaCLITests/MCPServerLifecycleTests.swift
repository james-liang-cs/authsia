import ArgumentParser
import AuthenticatorBridge
import Foundation
import MCP
import Testing
@testable import authsia

@Suite("Local MCP server lifecycle")
struct MCPServerLifecycleTests {
    @Test("hidden serve command is registered at the root")
    func commandRegistration() throws {
        #expect(MCPCommand.Serve.configuration.shouldDisplay == false)
        #expect(Authsia.configuration.subcommands.contains { $0 == MCPCommand.self })
        _ = try Authsia.parseAsRoot(["mcp", "serve"])
    }

    @Test("initialize advertises tools only and supports ping")
    func initializationAndDiscovery() async throws {
        let fixture = try makeServer()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let server = fixture.server
        let client = Client(name: "MCP lifecycle test", version: "1")

        try await server.start(transport: transports.server)
        let initialized = try await client.connect(transport: transports.client)

        #expect(initialized.capabilities.tools != nil)
        #expect(initialized.capabilities.resources == nil)
        #expect(initialized.capabilities.prompts == nil)
        #expect(initialized.capabilities.logging == nil)

        let listed = try await client.listTools()
        #expect(listed.tools.map(\.name) == AuthsiaMCPToolName.allCases.map(\.rawValue))
        try await client.ping()

        let statusContext: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.status.rawValue
        )
        let status = try await statusContext.value
        #expect(status.isError != true)
        #expect(status.structuredContent?.objectValue?["workspaceName"]?.stringValue == "lifecycle")

        let inspectionContext: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.workspaceInspect.rawValue
        )
        let inspection = try await inspectionContext.value
        #expect(inspection.isError != true)
        #expect(inspection.structuredContent?.objectValue?["references"]?.arrayValue?.isEmpty == true)

        await client.disconnect()
        await server.waitUntilCompleted()
    }

    @Test("unknown calls return a structured tool error")
    func unknownToolCall() async throws {
        let fixture = try makeServer()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let server = fixture.server
        let client = Client(name: "MCP lifecycle test", version: "1")

        try await server.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)
        let result = try await client.callTool(name: "not_an_authsia_tool")

        #expect(result.isError == true)

        await client.disconnect()
        await server.waitUntilCompleted()
    }

    @Test("status rejects fields outside its closed input schema")
    func statusRejectsUnknownInput() async throws {
        let fixture = try makeServer()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(name: "MCP lifecycle test", version: "1")

        try await fixture.server.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)
        let context: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.status.rawValue,
            arguments: ["unexpected": true]
        )
        let result = try await context.value

        #expect(result.isError == true)
        #expect(result.structuredContent?.objectValue?["code"]?.stringValue == "invalidInput")

        await client.disconnect()
        await fixture.server.waitUntilCompleted()
    }

    @Test("access tools expose and revoke only the current MCP instance grant")
    func accessTools() async throws {
        let serverID = UUID(uuidString: "7E05890F-5C3A-44EF-9208-83A12F17D6CE")!
        let owned = mcpGrant(sessionID: "mcp:\(serverID.uuidString)")
        let foreign = mcpGrant(
            id: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
            sessionID: "mcp:foreign"
        )
        let grantClient = LifecycleGrantClient(
            snapshot: .init(active: [owned, foreign], history: [])
        )
        let fixture = try makeServer(
            instanceID: serverID,
            grantClient: grantClient
        )
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(name: "MCP lifecycle test", version: "1")

        try await fixture.server.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)

        let statusContext: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.accessStatus.rawValue
        )
        let status = try await statusContext.value
        #expect(status.isError != true)
        #expect(status.structuredContent?.objectValue?["grants"]?.arrayValue?.count == 1)

        let foreignRevokeContext: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.accessRevoke.rawValue,
            arguments: ["grantID": .string(foreign.id.uuidString)]
        )
        let foreignRevoke = try await foreignRevokeContext.value
        #expect(foreignRevoke.isError == true)
        #expect(
            foreignRevoke.structuredContent?.objectValue?["code"]?.stringValue
                == MCPToolErrorCode.grantNotOwned.rawValue
        )
        #expect(
            foreignRevoke.structuredContent?.objectValue?["invocationID"]?.stringValue?.isEmpty
                == false
        )

        let ownedRevokeContext: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.accessRevoke.rawValue,
            arguments: ["grantID": .string(owned.id.uuidString)]
        )
        let ownedRevoke = try await ownedRevokeContext.value
        #expect(ownedRevoke.isError != true)
        #expect(grantClient.revokedIDs == [owned.id])

        await client.disconnect()
        await fixture.server.waitUntilCompleted()
    }

    @Test("diagnostics use the injected sink, never protocol output")
    func diagnosticsAreSeparated() async throws {
        let recorder = DiagnosticRecorder()
        let fixture = try makeServer { recorder.append($0) }
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let server = fixture.server
        let client = Client(name: "MCP lifecycle test", version: "1")

        try await server.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)
        await client.disconnect()
        await server.waitUntilCompleted()

        #expect(recorder.messages.contains("Authsia MCP server started"))
        #expect(recorder.messages.contains("Authsia MCP server stopped"))
    }

    @Test("graceful shutdown revokes active grants owned by this MCP instance")
    func gracefulShutdownRevokesOwnedGrants() async throws {
        let serverID = UUID(uuidString: "7E05890F-5C3A-44EF-9208-83A12F17D6CE")!
        let owned = mcpGrant(sessionID: "mcp:\(serverID.uuidString)")
        let foreign = mcpGrant(
            id: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
            sessionID: "mcp:foreign"
        )
        let grantClient = LifecycleGrantClient(
            snapshot: .init(active: [owned, foreign], history: [])
        )
        let fixture = try makeServer(
            instanceID: serverID,
            grantClient: grantClient,
            childRunner: LifecycleRunner()
        )
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(name: "MCP lifecycle test", version: "1")

        try await fixture.server.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)
        let execution: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.exec.rawValue,
            arguments: ["argv": ["true"]]
        )
        _ = try await execution.value
        await client.disconnect()
        await fixture.server.waitUntilCompleted()

        #expect(grantClient.revokedIDs == [owned.id])
    }

    @Test("shutdown cancels and awaits the active execution")
    func shutdownCancelsActiveExecution() async throws {
        let runner = CancellableLifecycleRunner()
        let fixture = try makeServer(
            grantClient: LifecycleGrantClient(snapshot: .init(active: [], history: [])),
            childRunner: runner
        )
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(name: "MCP lifecycle test", version: "1")

        try await fixture.server.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)
        let _: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.exec.rawValue,
            arguments: ["argv": ["synthetic-long-running-command"]]
        )
        await runner.waitUntilStarted()

        await fixture.server.stop()
        let observedCancellation = await runner.cancelled
        if !observedCancellation {
            await runner.finish()
        }
        await runner.waitUntilFinished()

        #expect(observedCancellation)
        #expect(await runner.finished)
    }

    private func makeServer(
        instanceID: UUID = UUID(),
        grantClient: (any MCPGrantClient)? = nil,
        childRunner: (any MCPChildRunning)? = nil,
        diagnostics: @escaping AuthsiaMCPServer.Diagnostics = { _ in }
    ) throws -> (server: AuthsiaMCPServer, root: URL) {
        let root = try makeWorkspaceRoot()
        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                workspace: .init(name: "lifecycle", authsiaFolder: "Workspaces/lifecycle"),
                managedEnvFiles: [],
                agents: nil
            ),
            toWorkspaceRoot: root
        )
        let runtime = MCPRuntimeContext(startingDirectory: root, instanceID: instanceID)
        let inspection = MCPWorkspaceInspectionService(
            runtimeContext: runtime,
            bridgeStateProvider: { .ready },
            selectionStore: WorkspaceEnvironmentSelectionStore(
                fileURL: root.appendingPathComponent("selection.json")
            )
        )
        return (
            AuthsiaMCPServer(
                version: "test",
                runtimeContext: runtime,
                workspaceInspection: inspection,
                grantService: grantClient.map {
                    MCPGrantService(serverInstanceID: instanceID, client: $0)
                },
                childRunner: childRunner,
                diagnostics: diagnostics
            ),
            root
        )
    }

    private func mcpGrant(id: UUID = UUID(
        uuidString: "11111111-1111-1111-1111-111111111111"
    )!, sessionID: String) -> AgentJITGrant {
        AgentJITGrant(
            id: id,
            agentName: "Codex",
            callerFingerprint: .init(
                processName: "authsia",
                bundleIdentifier: "com.authsia.cli",
                signingTeamId: "TEAM",
                signingIdentity: "Developer ID",
                parentProcessName: "Codex",
                parentBundleIdentifier: nil,
                sessionScope: nil,
                workingDirectory: "/tmp/project"
            ),
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            createdAt: Date().addingTimeInterval(-10),
            expiresAt: Date().addingTimeInterval(3_600),
            revokedAt: nil,
            lastUsedAt: nil,
            requestedItems: [],
            agentRuntimeContext: .init(
                sessionID: sessionID,
                agentType: "authsia-mcp"
            ),
            approvedBy: "local"
        )
    }
}

private struct LifecycleRunner: MCPChildRunning {
    func run(
        arguments: [String],
        invocation: MCPInvocationContext,
        timeoutSeconds: Int
    ) async -> MCPChildResult {
        MCPChildResult(
            invocationID: invocation.id,
            exitCode: 0,
            stdout: "",
            stderr: "",
            stdoutTruncated: false,
            stderrTruncated: false,
            cancelled: false,
            timedOut: false,
            durationMilliseconds: 1
        )
    }
}

private actor CancellableLifecycleRunner: MCPChildRunning {
    private var started = false
    private(set) var cancelled = false
    private(set) var finished = false
    private var startWaiters: [CheckedContinuation<Void, Never>] = []
    private var finishWaiters: [CheckedContinuation<Void, Never>] = []
    private var completion: CheckedContinuation<Void, Never>?

    func run(
        arguments: [String],
        invocation: MCPInvocationContext,
        timeoutSeconds: Int
    ) async -> MCPChildResult {
        started = true
        startWaiters.forEach { $0.resume() }
        startWaiters.removeAll()
        await withTaskCancellationHandler {
            await withCheckedContinuation { completion = $0 }
        } onCancel: {
            Task { await self.cancelExecution() }
        }
        finished = true
        finishWaiters.forEach { $0.resume() }
        finishWaiters.removeAll()
        return MCPChildResult(
            invocationID: invocation.id,
            exitCode: nil,
            stdout: "",
            stderr: "",
            stdoutTruncated: false,
            stderrTruncated: false,
            cancelled: cancelled,
            timedOut: false,
            durationMilliseconds: 1
        )
    }

    func waitUntilStarted() async {
        guard !started else { return }
        await withCheckedContinuation { startWaiters.append($0) }
    }

    func finish() {
        completion?.resume()
        completion = nil
    }

    func waitUntilFinished() async {
        guard !finished else { return }
        await withCheckedContinuation { finishWaiters.append($0) }
    }

    private func cancelExecution() {
        cancelled = true
        finish()
    }
}

private final class LifecycleGrantClient: MCPGrantClient, @unchecked Sendable {
    var snapshot: AgentJITGrantSnapshotPayload
    private(set) var revokedIDs: [UUID] = []

    init(snapshot: AgentJITGrantSnapshotPayload) {
        self.snapshot = snapshot
    }

    func agentJITSnapshot(
        agentRuntimeContext: AgentRuntimeContext
    ) throws -> AgentJITGrantSnapshotPayload {
        snapshot
    }

    func revokeAgentJITGrant(
        id: UUID,
        agentRuntimeContext: AgentRuntimeContext
    ) throws -> AgentJITGrantMutationPayload {
        revokedIDs.append(id)
        return AgentJITGrantMutationPayload(revokedGrantIDs: [id])
    }
}

private final class DiagnosticRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String] = []

    var messages: [String] {
        lock.withLock { storage }
    }

    func append(_ message: String) {
        lock.withLock { storage.append(message) }
    }
}
