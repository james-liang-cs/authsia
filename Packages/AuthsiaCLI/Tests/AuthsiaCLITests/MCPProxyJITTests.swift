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

        let sessionClient = RecordingMCPProxySessionClient(
            environment: [
                "JIRA_API_TOKEN": "synthetic-token",
                "JIRA_URL": "https://example.atlassian.net",
            ],
            secrets: ["synthetic-token"]
        )
        let launcher = RecordingMCPProxyChildLauncher()
        let root = try makeMCPProxyWorkspace(upstreams: [stdioJiraUpstream()])
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "jira",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            acceptsToolWorkspace: true,
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            childLauncher: launcher,
            parentEnvironment: [
                "PATH": "\(bin.path):/usr/bin:/bin",
                "HOME": "/synthetic/home",
            ],
            initializeTimeoutSeconds: 15
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

        let second: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_search"
        )
        let secondResult = try await second.value
        #expect(secondResult.isError != true)
        #expect(sessionClient.prepareCount == 1)
        #expect(launcher.spawnCount == 1)

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
            acceptsToolWorkspace: true,
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            childLauncher: launcher,
            parentEnvironment: ["PATH": "/usr/bin"]
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP deny test")
        let denied: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_delete_issue"
        )
        let result = try await denied.value
        #expect(result.isError == true)
        #expect(toolErrorCode(result) == MCPToolErrorCode.upstreamDenied.rawValue)
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
            acceptsToolWorkspace: true,
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15
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
