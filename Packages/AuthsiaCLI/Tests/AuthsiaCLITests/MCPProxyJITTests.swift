import AuthenticatorBridge
import Foundation
import MCP
import Testing
@testable import authsia

@Suite("MCP proxy JIT", .serialized)
struct MCPProxyJITTests {
    @Test("matching MCP exec grant is required for inject and a get without that sessionID cannot use it")
    func matchingMCPExecGrantIsRequired() {
        let sessionID = "mcp:\(UUID().uuidString)"
        let grant = AgentJITGrant(
            id: UUID(),
            agentName: "Cursor",
            callerFingerprint: AgentJITCallerFingerprint(
                processName: "Cursor",
                bundleIdentifier: "app.cursor",
                signingTeamId: "TEAM",
                signingIdentity: "Developer ID",
                parentProcessName: nil,
                parentBundleIdentifier: nil,
                sessionScope: nil,
                workingDirectory: "/tmp/project"
            ),
            folderScope: .folder("Workspaces/proxy"),
            capabilities: [.exec],
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresAt: Date(timeIntervalSince1970: 1_700_003_600),
            revokedAt: nil,
            lastUsedAt: nil,
            requestedItems: [],
            agentRuntimeContext: AgentRuntimeContext(
                platform: "Cursor",
                sessionID: sessionID,
                turnID: "mcp-call:1",
                agentID: "proxy:jira",
                agentType: "authsia-mcp",
                toolUseID: "mcp-call:1"
            ),
            approvedBy: "local"
        )
        let matching = AgentRuntimeContext(
            platform: "Cursor",
            sessionID: sessionID,
            turnID: "mcp-call:2",
            agentID: "proxy:jira",
            agentType: "authsia-mcp",
            toolUseID: "mcp-call:2"
        )
        let missingSessionID = AgentRuntimeContext(
            platform: "Cursor",
            agentType: "authsia-mcp"
        )
        let otherSession = AgentRuntimeContext(
            sessionID: "mcp:\(UUID().uuidString)",
            agentType: "authsia-mcp"
        )
        let humanGet = AgentRuntimeContext()

        #expect(grant.matchesAgentRuntimeContext(matching))
        #expect(!grant.matchesAgentRuntimeContext(missingSessionID))
        #expect(!grant.matchesAgentRuntimeContext(otherSession))
        #expect(!grant.matchesAgentRuntimeContext(humanGet))
        #expect(!grant.matchesAgentRuntimeContext(nil))
    }

    @Test("LiveMCPProxySessionClient exec get requires the matching MCP sessionID")
    func livePrepareRejectsGetWithoutMatchingSessionID() throws {
        let sessionID = "mcp:\(UUID().uuidString)"
        let matching = AgentRuntimeContext(
            sessionID: sessionID,
            agentID: "proxy:jira",
            agentType: "authsia-mcp"
        )
        let missingSession = AgentRuntimeContext(agentType: "authsia-mcp")
        let bridge = RecordingMCPProxyBridgeSession()
        bridge.allowedSessionID = sessionID
        let client = LiveMCPProxySessionClient(bridge: bridge)
        let declared = [
            "JIRA_API_TOKEN": "authsia://api-key/Atlassian/key",
            "JIRA_URL": "https://example.atlassian.net",
        ]
        let root = URL(fileURLWithPath: "/tmp")

        let resolved = try client.prepareChildEnvironment(
            declared: declared,
            agentRuntimeContext: matching,
            workspaceRoot: root
        )
        #expect(bridge.requestedCommands == ["exec"])
        #expect(resolved.environment["JIRA_API_TOKEN"] == "synthetic-token")
        #expect(bridge.resolveContexts.first?.sessionID == sessionID)

        #expect(throws: BridgeClientError.self) {
            _ = try client.prepareChildEnvironment(
                declared: declared,
                agentRuntimeContext: missingSession,
                workspaceRoot: root
            )
        }
    }

    @Test("LiveMCPProxySessionClient copies MCP tool and upstream onto the exec preflight payload")
    func livePrepareCopiesMCPDisplayFieldsOntoPreflightPayload() throws {
        let bridge = RecordingMCPProxyBridgeSession()
        let client = LiveMCPProxySessionClient(bridge: bridge)
        _ = try client.prepareChildEnvironment(
            declared: [
                "JIRA_API_TOKEN": "authsia://api-key/Atlassian/key",
                "JIRA_URL": "https://example.atlassian.net",
            ],
            agentRuntimeContext: AgentRuntimeContext(
                sessionID: "mcp:\(UUID().uuidString)",
                agentType: "authsia-mcp"
            ),
            workspaceRoot: URL(fileURLWithPath: "/tmp"),
            mcpUpstreamName: "jira",
            mcpToolName: "jira_create_issue",
            mcpToolPolicy: .approve
        )

        let payload = try #require(bridge.payloads.first)
        #expect(payload.requestedCommand == "exec")
        #expect(payload.mcpUpstreamName == "jira")
        #expect(payload.mcpToolName == "jira_create_issue")
        #expect(payload.mcpToolPolicy == .approve)
        #expect(!payload.mcpAdmissionRequested)
    }

    @Test("credential-less upstream requests a watched admission grant before spawn")
    func credentiallessUpstreamRequestsAdmissionGrant() throws {
        let bridge = RecordingMCPProxyBridgeSession()
        let client = LiveMCPProxySessionClient(bridge: bridge)

        let resolved = try client.prepareChildEnvironment(
            declared: ["JIRA_URL": "https://example.atlassian.net"],
            agentRuntimeContext: AgentRuntimeContext(
                sessionID: "mcp:\(UUID().uuidString)",
                agentID: "proxy:jira",
                agentType: "authsia-mcp"
            ),
            workspaceRoot: URL(fileURLWithPath: "/tmp/project"),
            mcpUpstreamName: "jira",
            mcpToolName: "jira_get_issue",
            mcpToolPolicy: .allow
        )

        let payload = try #require(bridge.payloads.first)
        #expect(bridge.requestedCommands == ["exec"])
        #expect(payload.references.isEmpty)
        #expect(payload.mcpAdmissionRequested)
        #expect(payload.mcpUpstreamName == "jira")
        #expect(resolved.environment == ["JIRA_URL": "https://example.atlassian.net"])
        #expect(resolved.secrets.isEmpty)
        #expect(resolved.grantIDs.count == 1)
    }

    @Test("credential-less upstream fails closed when admission has no grant")
    func credentiallessUpstreamRejectsMissingAdmissionGrant() {
        let bridge = RecordingMCPProxyBridgeSession()
        bridge.preflightGrantIDs = []
        let client = LiveMCPProxySessionClient(bridge: bridge)

        #expect(throws: MCPProxySpawnError.self) {
            _ = try client.prepareChildEnvironment(
                declared: ["JIRA_URL": "https://example.atlassian.net"],
                agentRuntimeContext: AgentRuntimeContext(
                    sessionID: "mcp:\(UUID().uuidString)",
                    agentID: "proxy:jira",
                    agentType: "authsia-mcp"
                ),
                workspaceRoot: URL(fileURLWithPath: "/tmp/project"),
                mcpUpstreamName: "jira",
                mcpToolName: "jira_get_issue",
                mcpToolPolicy: .allow
            )
        }
    }

    @Test("tools/list stays responsive while JIT preflight is in flight")
    func toolsListDoesNotWaitForJIT() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-atlassian"))
        let sessionClient = RecordingMCPProxySessionClient(
            environment: [
                "JIRA_API_TOKEN": "synthetic-token",
                "JIRA_URL": "https://example.atlassian.net",
            ],
            delayNanoseconds: 400_000_000
        )
        let root = try makeMCPProxyWorkspace(upstreams: [stdioJiraUpstream()])
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "jira",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15,
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "Cursor")
        let call = Task {
            let context: RequestContext<CallTool.Result> = try await connection.client.callTool(
                name: "jira_get_issue"
            )
            return try await context.value
        }
        try await Task.sleep(nanoseconds: 50_000_000)
        let listed = try await connection.client.listTools()
        #expect(listed.tools.map(\.name).contains("jira_get_issue"))
        let result = try await call.value
        #expect(result.isError != true)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("OTP and SSH refs are rejected before inject")
    func otpAndSSHRefsAreRejected() throws {
        let resolver = MCPProxySecretResolver(
            client: .shared,
            agentRuntimeContext: AgentRuntimeContext(
                sessionID: "mcp:\(UUID().uuidString)",
                agentType: "authsia-mcp"
            ),
            workspaceRoot: URL(fileURLWithPath: "/tmp")
        )
        #expect(throws: MCPToolInputError.self) {
            try resolver.resolveSecret(
                type: .otp,
                query: "GitHub",
                field: "code",
                folder: nil,
                isFolderScoped: false
            )
        }
        #expect(throws: MCPToolInputError.self) {
            try resolver.resolveSecret(
                type: .ssh,
                query: "deploy",
                field: "privateKey",
                folder: nil,
                isFolderScoped: false
            )
        }
        #expect(throws: MCPToolInputError.self) {
            _ = try LiveMCPProxySessionClient().prepareChildEnvironment(
                declared: [
                    "OTP": "authsia://otp/GitHub/code",
                    "JIRA_URL": "https://example.atlassian.net",
                ],
                agentRuntimeContext: AgentRuntimeContext(
                    sessionID: "mcp:\(UUID().uuidString)",
                    agentType: "authsia-mcp"
                ),
                workspaceRoot: URL(fileURLWithPath: "/tmp")
            )
        }
    }

    @Test("first secret-needing call JITs; second reuses the child; tools/list does not JIT")
    func firstSecretCallJITsAndSecondReuses() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        let script = bin.appendingPathComponent("mcp-atlassian")
        try writeExecutableMCPProxyScript(at: script)

        let serverID = UUID()
        let grantID = UUID()
        let grantClient = MutableMCPProxyGrantClient(
            snapshot: .init(
                active: [mcpProxyGrant(id: grantID, serverID: serverID)],
                history: []
            )
        )
        let sessionClient = RecordingMCPProxySessionClient(
            environment: [
                "JIRA_API_TOKEN": "synthetic-token",
                "JIRA_URL": "https://example.atlassian.net",
            ],
            secrets: ["synthetic-token"],
            grantIDs: [grantID]
        )
        let launcher = RecordingMCPProxyChildLauncher()
        let recorder = RecordingMCPProxyToolCallRecorder()
        let root = try makeMCPProxyWorkspace(upstreams: [stdioJiraUpstream()])
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "jira",
            runtimeContext: MCPRuntimeContext(startingDirectory: root, instanceID: serverID),
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            childLauncher: launcher,
            parentEnvironment: [
                "PATH": "\(bin.path):/usr/bin:/bin",
                "HOME": "/synthetic/home",
            ],
            initializeTimeoutSeconds: 15,
            grantService: MCPGrantService(serverInstanceID: serverID, client: grantClient),
            toolCallRecorder: recorder
        )
        let connection = try await connectMCPProxy(proxy, clientName: "Cursor")

        #expect(sessionClient.prepareCount == 0)
        let listed = try await connection.client.listTools()
        #expect(listed.tools.map(\.name).contains("jira_get_issue"))
        #expect(sessionClient.prepareCount == 0)
        #expect(launcher.spawnCount == 0)

        let first: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        let firstResult = try await first.value
        #expect(firstResult.isError != true)
        #expect(sessionClient.prepareCount == 1)
        #expect(launcher.spawnCount == 1)
        let context = try #require(sessionClient.contexts.first)
        #expect(context.agentType == "authsia-mcp")
        #expect(context.sessionID?.hasPrefix("mcp:") == true)
        #expect(context.agentID == "proxy:jira")
        #expect(context.toolUseID?.hasPrefix("mcp-call:") == true)
        #expect(context.platform == "Cursor")
        #expect(sessionClient.mcpUpstreamNames == ["jira"])
        #expect(sessionClient.mcpToolNames == ["jira_get_issue"])
        #expect(sessionClient.mcpToolPolicies == [.allow])
        #expect(recorder.calls.count == 1)
        #expect(recorder.calls.first?.upstreamName == "jira")
        #expect(recorder.calls.first?.toolName == "jira_get_issue")
        #expect(recorder.calls.first?.grantID == grantID)
        #expect(recorder.outcomes.first?.outcome == .succeeded)
        #expect(recorder.outcomes.first?.grantID == grantID)

        let second: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_search"
        )
        let secondResult = try await second.value
        #expect(secondResult.isError != true)
        #expect(sessionClient.prepareCount == 1)
        #expect(launcher.spawnCount == 1)
        #expect(recorder.calls.map(\.toolName) == ["jira_get_issue", "jira_search"])

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("deny does not spawn or JIT")
    func denyDoesNotSpawn() async throws {
        let sessionClient = RecordingMCPProxySessionClient()
        let launcher = RecordingMCPProxyChildLauncher()
        let root = try makeMCPProxyWorkspace(upstreams: [stdioJiraUpstream()])
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "jira",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            childLauncher: launcher,
            parentEnvironment: ["PATH": "/usr/bin"],
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP deny test")
        let denied: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_delete_issue"
        )
        let result = try await denied.value
        #expect(result.isError == true)
        #expect(toolErrorCode(result) == MCPToolErrorCode.upstreamDenied.rawValue)
        #expect(toolErrorInvocationID(result) != nil)
        #expect(sessionClient.prepareCount == 0)
        #expect(launcher.spawnCount == 0)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("an advertised tool missing on the child is upstreamUnavailable")
    func missingChildToolIsUnavailable() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-atlassian"))
        let sessionClient = RecordingMCPProxySessionClient(
            environment: ["AUTHSIA_TEST_TOOLS": "jira_search"]
        )
        let root = try makeMCPProxyWorkspace(upstreams: [stdioJiraUpstream()])
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "jira",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15,
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP drift test")
        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        let result = try await call.value
        #expect(result.isError == true)
        #expect(toolErrorCode(result) == MCPToolErrorCode.upstreamUnavailable.rawValue)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }
}
