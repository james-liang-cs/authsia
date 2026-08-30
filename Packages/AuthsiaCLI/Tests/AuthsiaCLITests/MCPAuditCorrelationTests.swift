import AuthenticatorBridge
import Foundation
import MCP
import Testing
@testable import authsia

@Suite("MCP audit correlation")
struct MCPAuditCorrelationTests {
    @Test("one MCP session projects distinct calls into existing audit and activity models")
    func correlatedInvocations() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                workspace: .init(name: "audit", authsiaFolder: "Workspaces/audit"),
                managedEnvFiles: [],
                agents: nil
            ),
            toWorkspaceRoot: root
        )
        let serverID = UUID(uuidString: "7E05890F-5C3A-44EF-9208-83A12F17D6CE")!
        let firstID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
        let secondID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        let runtime = MCPRuntimeContext(startingDirectory: root, instanceID: serverID)
        await runtime.updateClientInfo(name: "Codex", version: "1")

        let first = await runtime.makeInvocation(id: firstID)
        let second = await runtime.makeInvocation(id: secondID)
        let firstContext = try #require(AgentRuntimeContextResolver.resolve(environment: first.environment))
        let secondContext = try #require(AgentRuntimeContextResolver.resolve(environment: second.environment))

        #expect(firstContext.sessionID == secondContext.sessionID)
        #expect(firstContext.sessionID == "mcp:\(serverID.uuidString)")
        #expect(firstContext.agentType == "authsia-mcp")
        #expect(firstContext.toolUseID == "mcp-call:\(firstID.uuidString)")
        #expect(secondContext.toolUseID == "mcp-call:\(secondID.uuidString)")

        let grantID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
        let grant = AgentJITGrant(
            id: grantID,
            agentName: "Codex",
            callerFingerprint: .init(
                processName: "authsia",
                bundleIdentifier: "com.authsia.cli",
                signingTeamId: "TEAM",
                signingIdentity: "Developer ID",
                parentProcessName: "Codex",
                parentBundleIdentifier: nil,
                sessionScope: nil,
                workingDirectory: root.path
            ),
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresAt: Date(timeIntervalSince1970: 1_700_000_300),
            revokedAt: nil,
            lastUsedAt: nil,
            requestedItems: [],
            agentRuntimeContext: firstContext,
            approvedBy: "mac-panel",
            environmentScope: .named("Development")
        )
        let events = [firstContext, secondContext].enumerated().map { index, context in
            AgentCommandEvent(
                recordedAt: Date(timeIntervalSince1970: 1_700_000_010 + Double(index)),
                agentPlatform: context.platform,
                sessionID: context.sessionID,
                turnID: context.turnID,
                agentType: context.agentType,
                toolUseID: context.toolUseID,
                agentJITGrantID: grantID,
                captureSource: .injectedTree,
                workingDirectory: root.path,
                executable: "/usr/bin/true",
                arguments: []
            )
        }

        #expect(AgentCommandHistoryQuery.events(for: grant, from: events).map(\.id) == events.map(\.id))
    }

    @Test("correlation fixtures contain no secret or raw JSON-RPC envelope")
    func correlationRedaction() throws {
        let secret = "mcp-correlation-secret-DO-NOT-LOG"
        let grantID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
        let context = AgentRuntimeContext(
            platform: "Codex",
            sessionID: "mcp:7E05890F-5C3A-44EF-9208-83A12F17D6CE",
            turnID: "mcp-call:11111111-1111-1111-1111-111111111111",
            agentType: "authsia-mcp",
            toolUseID: "mcp-call:11111111-1111-1111-1111-111111111111"
        )
        let audit = BridgeAuditRecord(
            command: .getPassword,
            itemId: "item-id",
            itemName: "API credential",
            approvedBy: "jit",
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            requestedCommand: "exec",
            agentJITGrantID: grantID,
            agentRuntimeContext: context,
            workspaceContext: .init(
                name: "audit",
                rootLabel: "repo",
                authsiaFolder: "Workspaces/audit"
            ),
            environmentScope: .named("Development")
        )
        let activity = AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 1_700_000_001),
            agentPlatform: context.platform,
            sessionID: context.sessionID,
            turnID: context.turnID,
            agentType: context.agentType,
            toolUseID: context.toolUseID,
            agentJITGrantID: grantID,
            captureSource: .injectedTree,
            executable: "/usr/bin/example",
            arguments: ["--token", secret]
        )

        let encoded = try JSONEncoder().encode(CorrelationFixture(audit: audit, activity: activity))
        let text = String(decoding: encoded, as: UTF8.self)

        #expect(!text.contains(secret))
        #expect(!text.contains("\"jsonrpc\""))
        #expect(!text.contains("\"method\""))
        #expect(!text.contains("\"params\""))
    }

    @Test("post-audit timeout envelope matches the recorded audit turnID")
    func postAuditTimeoutCarriesInvocationID() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-atlassian"))
        let recorder = RecordingMCPProxyToolCallRecorder()
        let sessionClient = RecordingMCPProxySessionClient(
            environment: ["AUTHSIA_TEST_TOOLS": "slow,fast"]
        )
        let root = try makeMCPProxyWorkspace(
            upstreams: [
                stdioJiraUpstream(
                    env: [:],
                    allow: ["slow", "fast"],
                    approve: [],
                    deny: []
                )
            ]
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "jira",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15,
            callTimeoutSeconds: 0.1,
            killGraceSeconds: 0.05,
            toolCallRecorder: recorder
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP audit timeout")
        let slow: RequestContext<CallTool.Result> = try await connection.client.callTool(name: "slow")
        let slowResult = try await slow.value
        #expect(slowResult.isError == true)
        #expect(toolErrorCode(slowResult) == MCPToolErrorCode.timedOut.rawValue)

        let envelopeID = try #require(toolErrorInvocationID(slowResult))
        #expect(UUID(uuidString: envelopeID) != nil)
        let recorded = try #require(recorder.calls.first)
        #expect(recorded.agentRuntimeContext.turnID == "mcp-call:\(envelopeID)")
        #expect(recorder.outcomes.first?.outcome == .timedOut)
        #expect(recorder.outcomes.first?.grantID == recorded.grantID)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("an audit persistence failure omits the invocationID")
    func auditPersistenceFailureOmitsInvocationID() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-atlassian"))
        let recorder = RecordingMCPProxyToolCallRecorder()
        recorder.error = CorrelationTestError.recordingFailed
        let sessionClient = RecordingMCPProxySessionClient(
            environment: ["AUTHSIA_TEST_TOOLS": "fast"]
        )
        let root = try makeMCPProxyWorkspace(
            upstreams: [
                stdioJiraUpstream(
                    env: [:],
                    allow: ["fast"],
                    approve: [],
                    deny: []
                )
            ]
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "jira",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15,
            toolCallRecorder: recorder
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP failed audit")
        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(name: "fast")
        let result = try await call.value

        #expect(result.isError == true)
        #expect(toolErrorCode(result) == MCPToolErrorCode.upstreamUnavailable.rawValue)
        #expect(toolErrorInvocationID(result) == nil)
        #expect(recorder.calls.isEmpty)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("pre-invocation workspace failure records a denied invocation")
    func preInvocationFailureRecordsInvocationOutcome() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let recorder = RecordingMCPProxyToolCallRecorder()
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "jira",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            mcpAccessEnabled: { true },
            toolCallRecorder: recorder
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP unbound audit")
        let context: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        let result = try await context.value
        #expect(result.isError == true)
        #expect(toolErrorCode(result) == MCPToolErrorCode.workspaceUnavailable.rawValue)
        #expect(toolErrorInvocationID(result) != nil)
        #expect(recorder.outcomes.first?.outcome == .upstreamUnavailable)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }
}

private struct CorrelationFixture: Codable {
    let audit: BridgeAuditRecord
    let activity: AgentCommandEvent
}

private enum CorrelationTestError: Error {
    case recordingFailed
}
