import Foundation
import AuthenticatorBridge
import MCP
import Testing
@testable import authsia

@Suite("MCP scoped list tool")
struct MCPListToolTests {
    @Test("list uses list-only JIT context and returns bounded common metadata")
    func listUsesJITAndPaginatesMetadata() async throws {
        let root = try makeManagedWorkspace()
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = MCPRuntimeContext(startingDirectory: root)
        let client = RecordingMCPListBridgeClient(payload: BridgeListPayload(
            accounts: [],
            passwords: [
                password(name: "First", folder: "Workspaces/api/Production"),
                password(name: "Second", folder: "Workspaces/api/Production/Nested"),
                password(name: "Outside", folder: "Workspaces/other"),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        ))
        let service = MCPListService(runtimeContext: runtime, client: client)
        let invocation = await runtime.makeInvocation()

        let output = try await service.list(
            MCPListInput(
                type: .password,
                folder: "Workspaces/api/Production",
                environment: "Production",
                limit: 1
            ),
            invocation: invocation
        )

        #expect(output.type == .password)
        #expect(output.folder == "Workspaces/api/Production")
        #expect(output.totalCount == 2)
        #expect(output.count == 1)
        #expect(output.hasMore)
        #expect(output.nextOffset == 1)
        #expect(output.items.map(\.name) == ["First"])
        #expect(output.items[0].folderPath == "Workspaces/api/Production")

        let request = try #require(client.requests.first)
        #expect(request.preflight == AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [AgentJITPreflightReference(
                type: "password",
                query: "",
                folderPath: "Workspaces/api/Production",
                isFolderScoped: true
            )],
            environmentScope: .named("Production")
        ))
        #expect(request.context.agentType == "authsia-mcp")
        #expect(request.context.sessionID?.hasPrefix("mcp:") == true)
        #expect(request.context.toolUseID?.hasPrefix("mcp-call:") == true)
    }

    @Test("list defaults to workspace folder and rejects broader folders")
    func workspaceScopeCannotBeBroadened() async throws {
        let root = try makeManagedWorkspace()
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = MCPRuntimeContext(startingDirectory: root)
        let client = RecordingMCPListBridgeClient(payload: emptyPayload)
        let service = MCPListService(runtimeContext: runtime, client: client)
        let invocation = await runtime.makeInvocation()

        let output = try await service.list(
            MCPListInput(type: .apiKey),
            invocation: invocation
        )
        #expect(output.folder == "Workspaces/api")
        #expect(client.requests.first?.preflight.references.first?.folderPath == "Workspaces/api")

        await #expect(throws: MCPToolInputError.self) {
            try await service.list(
                MCPListInput(type: .apiKey, folder: "Workspaces"),
                invocation: invocation
            )
        }
        #expect(client.requests.count == 1)
    }

    @Test("server dispatches authsia_list as structured metadata output")
    func serverDispatchesList() async throws {
        let root = try makeManagedWorkspace()
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = MCPRuntimeContext(startingDirectory: root)
        let provider = StubMCPListProvider()
        let server = AuthsiaMCPServer(
            version: "test",
            runtimeContext: runtime,
            workspaceInspection: MCPWorkspaceInspectionService(
                runtimeContext: runtime,
                bridgeStateProvider: { .ready }
            ),
            grantService: MCPGrantService(
                serverInstanceID: runtime.instanceID,
                client: ListToolGrantClient()
            ),
            listService: provider,
            diagnostics: { _ in }
        )
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(name: "Codex", version: "1")
        try await server.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)

        let context: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.list.rawValue,
            arguments: ["type": "password", "limit": 10]
        )
        let response = try await context.value

        #expect(response.isError != true)
        #expect(response.structuredContent?.objectValue?["type"]?.stringValue == "password")
        #expect(response.structuredContent?.objectValue?["items"]?.arrayValue?.isEmpty == true)
        #expect(provider.contexts.first?.agentType == "authsia-mcp")

        await client.disconnect()
        await server.waitUntilCompleted()
    }

    @Test("list failures retain the allocated invocation ID")
    func listFailureRetainsInvocationID() async throws {
        let root = try makeManagedWorkspace()
        defer { try? FileManager.default.removeItem(at: root) }
        let runtime = MCPRuntimeContext(startingDirectory: root)
        let server = AuthsiaMCPServer(
            version: "test",
            runtimeContext: runtime,
            workspaceInspection: MCPWorkspaceInspectionService(
                runtimeContext: runtime,
                bridgeStateProvider: { .ready }
            ),
            grantService: MCPGrantService(
                serverInstanceID: runtime.instanceID,
                client: ListToolGrantClient()
            ),
            listService: FailingMCPListProvider(),
            diagnostics: { _ in }
        )
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(name: "Codex", version: "1")
        try await server.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)

        let context: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.list.rawValue,
            arguments: ["type": "password"]
        )
        let response = try await context.value

        #expect(response.isError == true)
        #expect(response.structuredContent?.objectValue?["code"]?.stringValue == "bridgeUnavailable")
        #expect(response.structuredContent?.objectValue?["invocationID"]?.stringValue?.isEmpty == false)

        await client.disconnect()
        await server.waitUntilCompleted()
    }

    private func makeManagedWorkspace() throws -> URL {
        let root = try makeWorkspaceRoot()
        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                workspace: .init(name: "api", authsiaFolder: "Workspaces/api"),
                managedEnvFiles: [],
                agents: nil
            ),
            toWorkspaceRoot: root
        )
        return root
    }

    private func password(name: String, folder: String) -> BridgePassword {
        BridgePassword(
            id: UUID(),
            name: name,
            username: "not-returned",
            website: "https://not-returned.invalid",
            folderPath: folder,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            createdAt: Date(timeIntervalSince1970: 1),
            updatedAt: Date(timeIntervalSince1970: 2),
            environments: ["Production"]
        )
    }

    private var emptyPayload: BridgeListPayload {
        BridgeListPayload(
            accounts: [],
            passwords: [],
            certificates: [],
            notes: [],
            sshKeys: []
        )
    }
}

private final class RecordingMCPListBridgeClient: MCPListBridgeClient, @unchecked Sendable {
    struct Request {
        let preflight: AgentJITPreflightPayload
        let context: AgentRuntimeContext
    }

    let payload: BridgeListPayload
    private(set) var requests: [Request] = []

    init(payload: BridgeListPayload) {
        self.payload = payload
    }

    func list(
        preflight: AgentJITPreflightPayload,
        agentRuntimeContext: AgentRuntimeContext
    ) throws -> BridgeListPayload {
        requests.append(Request(preflight: preflight, context: agentRuntimeContext))
        return payload
    }
}

private final class StubMCPListProvider: MCPListProviding, @unchecked Sendable {
    private(set) var contexts: [AgentRuntimeContext] = []

    func list(
        _ input: MCPListInput,
        invocation: MCPInvocationContext
    ) async throws -> MCPListOutput {
        if let context = invocation.agentRuntimeContext {
            contexts.append(context)
        }
        return MCPListOutput(
            invocationID: invocation.id.uuidString,
            type: input.type,
            folder: "Workspaces/api",
            environment: input.environment,
            items: [],
            totalCount: 0,
            count: 0,
            offset: input.offset,
            hasMore: false,
            nextOffset: nil
        )
    }
}

private struct FailingMCPListProvider: MCPListProviding {
    func list(
        _ input: MCPListInput,
        invocation: MCPInvocationContext
    ) async throws -> MCPListOutput {
        throw BridgeClientError.connectionFailed
    }
}

private final class ListToolGrantClient: MCPGrantClient, @unchecked Sendable {
    func agentJITSnapshot(
        agentRuntimeContext: AgentRuntimeContext
    ) throws -> AgentJITGrantSnapshotPayload {
        .init(active: [], history: [])
    }

    func revokeAgentJITGrant(
        id: UUID,
        agentRuntimeContext: AgentRuntimeContext
    ) throws -> AgentJITGrantMutationPayload {
        .init(revokedGrantIDs: [id])
    }
}
