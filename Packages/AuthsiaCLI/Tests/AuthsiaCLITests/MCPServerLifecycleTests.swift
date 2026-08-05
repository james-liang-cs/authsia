import ArgumentParser
import AuthenticatorBridge
import Foundation
import MCP
import Testing
@testable import authsia

@Suite("Local MCP server lifecycle")
struct MCPServerLifecycleTests {
    @Test("serve command is visible and registered at the root")
    func commandRegistration() throws {
        #expect(MCPCommand.Serve.configuration.shouldDisplay)
        #expect(Authsia.configuration.subcommands.contains { $0 == MCPCommand.self })
        _ = try Authsia.parseAsRoot(["mcp", "serve"])
    }

    @Test("command help describes setup and direct server usage")
    func commandHelpDescribesMCPWorkflow() {
        let help = MCPCommand.helpMessage(columns: 160)

        #expect(help.contains("configure"))
        #expect(help.contains("serve"))
        #expect(help.contains("authsia mcp configure --client codex"))
        #expect(help.contains("authsia mcp serve"))
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

    @Test("server starts outside a managed workspace and keeps workspace tools closed")
    func initializationWithoutWorkspace() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let serverID = UUID()
        let runtime = MCPRuntimeContext(startingDirectory: root, instanceID: serverID)
        let server = AuthsiaMCPServer(
            version: "test",
            runtimeContext: runtime,
            workspaceInspection: MCPWorkspaceInspectionService(
                runtimeContext: runtime,
                bridgeStateProvider: { .ready },
                selectionStore: WorkspaceEnvironmentSelectionStore(
                    fileURL: root.appendingPathComponent("selection.json")
                )
            ),
            grantService: MCPGrantService(
                serverInstanceID: serverID,
                client: LifecycleGrantClient(snapshot: .init(active: [], history: []))
            ),
            diagnostics: { _ in }
        )
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(name: "MCP lifecycle test", version: "1")

        try await server.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)

        let statusContext: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.status.rawValue
        )
        let status = try await statusContext.value
        #expect(status.isError != true)
        #expect(status.structuredContent?.objectValue?["ready"]?.boolValue == false)
        #expect(status.structuredContent?.objectValue?["workspaceRoot"]?.stringValue == "")
        #expect(
            status.structuredContent?.objectValue?["diagnostics"]?.arrayValue?.first?
                .objectValue?["code"]?.stringValue == "workspaceUnavailable"
        )

        for (name, arguments) in [
            (AuthsiaMCPToolName.workspaceInspect.rawValue, nil),
            (AuthsiaMCPToolName.list.rawValue, ["type": Value.string("password")]),
            (AuthsiaMCPToolName.exec.rawValue, ["argv": Value.array([.string("true")])]),
        ] {
            let context: RequestContext<CallTool.Result> = try await client.callTool(
                name: name,
                arguments: arguments
            )
            let result = try await context.value
            #expect(result.isError == true)
            #expect(
                result.structuredContent?.objectValue?["code"]?.stringValue
                    == MCPToolErrorCode.workspaceUnavailable.rawValue
            )
        }

        await client.disconnect()
        await server.waitUntilCompleted()
    }

    @Test("IDE client roots bind a server launched outside the workspace")
    func clientRootsBindWorkspace() async throws {
        let launchDirectory = try makeWorkspaceRoot()
        let workspace = try makeWorkspaceRoot()
        defer {
            try? FileManager.default.removeItem(at: launchDirectory)
            try? FileManager.default.removeItem(at: workspace)
        }
        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                workspace: .init(name: "ide-hosted", authsiaFolder: "Workspaces/ide-hosted"),
                managedEnvFiles: [],
                agents: nil
            ),
            toWorkspaceRoot: workspace
        )
        let runtime = MCPRuntimeContext(startingDirectory: launchDirectory)
        let server = AuthsiaMCPServer(
            version: "test",
            runtimeContext: runtime,
            workspaceInspection: MCPWorkspaceInspectionService(
                runtimeContext: runtime,
                bridgeStateProvider: { .ready }
            ),
            diagnostics: { _ in }
        )
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(
            name: "IDE MCP lifecycle test",
            version: "1",
            capabilities: .init(roots: .init(listChanged: true))
        )
        await client.withRootsHandler {
            [
                Root(uri: "https://example.invalid/workspace", name: "Not a file root"),
                Root(uri: "file://remote.invalid/workspace", name: "Non-local file root"),
                Root(uri: workspace.absoluteString, name: "Active workspace"),
            ]
        }

        try await server.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)
        let statusContext: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.status.rawValue
        )
        let status = try await statusContext.value

        #expect(status.isError != true)
        #expect(status.structuredContent?.objectValue?["ready"]?.boolValue == true)
        #expect(status.structuredContent?.objectValue?["workspaceName"]?.stringValue == "ide-hosted")
        #expect(
            status.structuredContent?.objectValue?["workspaceRoot"]?.stringValue
                == workspace.resolvingSymlinksInPath().path
        )

        await client.disconnect()
        await server.waitUntilCompleted()
    }

    @Test("explicit workspace binding takes precedence over client roots")
    func explicitWorkspacePrecedesClientRoots() async throws {
        let explicitWorkspace = try makeWorkspaceRoot()
        let clientWorkspace = try makeWorkspaceRoot()
        defer {
            try? FileManager.default.removeItem(at: explicitWorkspace)
            try? FileManager.default.removeItem(at: clientWorkspace)
        }
        for (root, name) in [(explicitWorkspace, "explicit"), (clientWorkspace, "client")] {
            try WorkspaceConfigStore.write(
                WorkspaceConfig(
                    workspace: .init(name: name, authsiaFolder: "Workspaces/\(name)"),
                    managedEnvFiles: [],
                    agents: nil
                ),
                toWorkspaceRoot: root
            )
        }
        let runtime = MCPRuntimeContext(startingDirectory: explicitWorkspace)
        let server = AuthsiaMCPServer(
            version: "test",
            runtimeContext: runtime,
            acceptsClientRoots: false,
            workspaceInspection: MCPWorkspaceInspectionService(
                runtimeContext: runtime,
                bridgeStateProvider: { .ready }
            ),
            diagnostics: { _ in }
        )
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(
            name: "IDE MCP lifecycle test",
            version: "1",
            capabilities: .init(roots: .init())
        )
        await client.withRootsHandler {
            [Root(uri: clientWorkspace.absoluteString, name: "Client workspace")]
        }

        try await server.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)
        let statusContext: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.status.rawValue
        )
        let status = try await statusContext.value

        #expect(status.structuredContent?.objectValue?["workspaceName"]?.stringValue == "explicit")

        await client.disconnect()
        await server.waitUntilCompleted()
    }

    @Test("client root changes rebind the same IDE server instance")
    func clientRootChangesRebindWorkspace() async throws {
        let launchDirectory = try makeWorkspaceRoot()
        let firstWorkspace = try makeWorkspaceRoot()
        let secondWorkspace = try makeWorkspaceRoot()
        defer {
            try? FileManager.default.removeItem(at: launchDirectory)
            try? FileManager.default.removeItem(at: firstWorkspace)
            try? FileManager.default.removeItem(at: secondWorkspace)
        }
        for (root, name) in [(firstWorkspace, "first"), (secondWorkspace, "second")] {
            try WorkspaceConfigStore.write(
                WorkspaceConfig(
                    workspace: .init(name: name, authsiaFolder: "Workspaces/\(name)"),
                    managedEnvFiles: [],
                    agents: nil
                ),
                toWorkspaceRoot: root
            )
        }
        let serverID = UUID()
        let ownedGrant = mcpGrant(sessionID: "mcp:\(serverID.uuidString)")
        let grantClient = LifecycleGrantClient(
            snapshot: .init(active: [ownedGrant], history: [])
        )
        let runtime = MCPRuntimeContext(
            startingDirectory: launchDirectory,
            instanceID: serverID
        )
        let server = AuthsiaMCPServer(
            version: "test",
            runtimeContext: runtime,
            workspaceInspection: MCPWorkspaceInspectionService(
                runtimeContext: runtime,
                bridgeStateProvider: { .ready }
            ),
            grantService: MCPGrantService(
                serverInstanceID: serverID,
                client: grantClient
            ),
            childRunner: LifecycleRunner(),
            diagnostics: { _ in }
        )
        let roots = LifecycleRootsProvider([
            Root(uri: firstWorkspace.absoluteString, name: "First workspace")
        ])
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(
            name: "IDE MCP lifecycle test",
            version: "1",
            capabilities: .init(roots: .init(listChanged: true))
        )
        await client.withRootsHandler { await roots.current() }

        try await server.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)
        let firstStatusContext: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.status.rawValue
        )
        let firstStatus = try await firstStatusContext.value
        #expect(firstStatus.structuredContent?.objectValue?["workspaceName"]?.stringValue == "first")
        let executionContext: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.exec.rawValue,
            arguments: ["argv": ["true"]]
        )
        #expect(try await executionContext.value.isError != true)

        await roots.replace(with: [
            Root(uri: secondWorkspace.absoluteString, name: "Second workspace")
        ])
        try await client.notifyRootsChanged()
        let secondStatusContext: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.status.rawValue
        )
        let secondStatus = try await secondStatusContext.value
        #expect(secondStatus.structuredContent?.objectValue?["workspaceName"]?.stringValue == "second")
        #expect(grantClient.revokedIDs == [ownedGrant.id])

        await client.disconnect()
        await server.waitUntilCompleted()
    }

    @Test("unknown tools return a protocol error")
    func unknownToolCall() async throws {
        let fixture = try makeServer()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let server = fixture.server
        let client = Client(name: "MCP lifecycle test", version: "1")

        try await server.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)
        let context: RequestContext<CallTool.Result> = try await client.callTool(
            name: "not_an_authsia_tool"
        )
        do {
            _ = try await context.value
            Issue.record("Expected invalidParams protocol error")
        } catch MCPError.invalidParams {
            // Expected.
        } catch {
            Issue.record("Expected invalidParams protocol error, got \(error)")
        }

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

    @Test("shutdown cancels and awaits an active JIT list")
    func shutdownCancelsActiveList() async throws {
        let serverID = UUID()
        let owned = mcpGrant(sessionID: "mcp:\(serverID.uuidString)")
        let grantClient = LifecycleGrantClient(
            snapshot: .init(active: [owned], history: [])
        )
        let provider = CancellableLifecycleListProvider()
        let fixture = try makeServer(
            instanceID: serverID,
            grantClient: grantClient,
            listService: provider
        )
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(name: "MCP lifecycle test", version: "1")

        try await fixture.server.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)
        let _: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.list.rawValue,
            arguments: ["type": "password"]
        )
        await provider.waitUntilStarted()

        await fixture.server.stop()
        #expect(await provider.cancelled)
        #expect(await provider.finished)
        #expect(grantClient.revokedIDs == [owned.id])
    }

    private func makeServer(
        instanceID: UUID = UUID(),
        grantClient: (any MCPGrantClient)? = nil,
        listService: (any MCPListProviding)? = nil,
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
                listService: listService,
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

private actor CancellableLifecycleListProvider: MCPListProviding {
    private var started = false
    private(set) var cancelled = false
    private(set) var finished = false
    private var startWaiters: [CheckedContinuation<Void, Never>] = []
    private var completion: CheckedContinuation<Void, Never>?

    func list(
        _ input: MCPListInput,
        invocation: MCPInvocationContext
    ) async throws -> MCPListOutput {
        started = true
        startWaiters.forEach { $0.resume() }
        startWaiters.removeAll()
        await withTaskCancellationHandler {
            await withCheckedContinuation { completion = $0 }
        } onCancel: {
            Task { await self.cancelList() }
        }
        finished = true
        return MCPListOutput(
            invocationID: invocation.id.uuidString,
            type: input.type,
            folder: "Workspaces/lifecycle",
            environment: input.environment,
            items: [],
            totalCount: 0,
            count: 0,
            offset: input.offset,
            hasMore: false,
            nextOffset: nil
        )
    }

    func waitUntilStarted() async {
        guard !started else { return }
        await withCheckedContinuation { startWaiters.append($0) }
    }

    private func cancelList() {
        cancelled = true
        completion?.resume()
        completion = nil
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

private actor LifecycleRootsProvider {
    private var roots: [Root]

    init(_ roots: [Root]) {
        self.roots = roots
    }

    func current() -> [Root] {
        roots
    }

    func replace(with roots: [Root]) {
        self.roots = roots
    }
}
