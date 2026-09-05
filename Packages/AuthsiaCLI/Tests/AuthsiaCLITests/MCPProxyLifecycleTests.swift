import AuthenticatorBridge
import Darwin
import Foundation
import MCP
import Testing
@testable import authsia

@Suite("MCP proxy lifecycle")
struct MCPProxyLifecycleTests {
    @Test("initialize advertises filtered tools only and supports ping")
    func initializationAndDiscovery() async throws {
        let fixture = try makeProxy()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(name: "MCP proxy lifecycle test", version: "1")

        try await fixture.proxy.start(transport: transports.server)
        let initialized = try await client.connect(transport: transports.client)

        #expect(initialized.serverInfo.name == "authsia-mcp-proxy")
        #expect(initialized.capabilities.tools != nil)
        #expect(initialized.capabilities.tools?.listChanged == false)
        #expect(initialized.capabilities.resources == nil)
        #expect(initialized.capabilities.prompts == nil)
        #expect(initialized.capabilities.logging == nil)
        #expect(initialized.capabilities.completions == nil)
        #expect(initialized.instructions?.contains("jira") == true)
        #expect(
            initialized.instructions?.localizedCaseInsensitiveContains(
                "tools are filtered by workspace policy"
            ) == true
        )

        let listed = try await client.listTools()
        #expect(listed.tools.map(\.name) == ["jira_get_issue", "jira_search", "jira_create_issue"])
        #expect(!listed.tools.map(\.name).contains("jira_delete_issue"))
        #expect(!listed.tools.map(\.name).contains("authsia_status"))
        #expect(!listed.tools.map(\.name).contains("authsia_workspace_inspect"))
        #expect(listed.tools[0].description == "Get one Jira issue by key")
        #expect(
            listed.tools[0].inputSchema.objectValue?["properties"]?.objectValue?["issueKey"] != nil
        )
        #expect(listed.tools[1].description == "")
        #expect(listed.tools[1].inputSchema == MCPProxyCatalog.defaultInputSchema)
        try await client.ping()

        await client.disconnect()
        await fixture.proxy.waitUntilCompleted()
    }

    @Test("tools/list reads policy only and does not require MCP access")
    func toolsListDoesNotJIT() async throws {
        let fixture = try makeProxy(mcpAccessEnabled: { false })
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(name: "MCP proxy lifecycle test", version: "1")

        try await fixture.proxy.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)

        let listed = try await client.listTools()
        #expect(listed.tools.map(\.name) == ["jira_get_issue", "jira_search", "jira_create_issue"])

        let denied: RequestContext<CallTool.Result> = try await client.callTool(
            name: "jira_get_issue"
        )
        let result = try await denied.value
        #expect(result.isError == true)
        #expect(
            result.structuredContent?.objectValue?["code"]?.stringValue
                == MCPToolErrorCode.mcpAccessDisabled.rawValue
        )

        await client.disconnect()
        await fixture.proxy.waitUntilCompleted()
    }

    @Test("disabled MCP access still lists policy tools when bound")
    func disabledAccessKeepsPolicyCatalog() async throws {
        let fixture = try makeProxy(mcpAccessEnabled: { false })
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(name: "MCP proxy disabled test", version: "1")

        try await fixture.proxy.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)
        let listed = try await client.listTools()
        #expect(!listed.tools.isEmpty)

        for name in ["jira_get_issue", "jira_delete_issue", "not_a_tool"] {
            let context: RequestContext<CallTool.Result> = try await client.callTool(name: name)
            let result = try await context.value
            #expect(result.isError == true)
            #expect(
                result.structuredContent?.objectValue?["code"]?.stringValue
                    == MCPToolErrorCode.mcpAccessDisabled.rawValue
            )
        }

        await client.disconnect()
        await fixture.proxy.waitUntilCompleted()
    }

    @Test("unbound proxy lists nothing and rejects calls as workspaceUnavailable")
    func unboundListsNothing() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "jira",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            mcpAccessEnabled: { true },
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(name: "MCP proxy unbound test", version: "1")

        try await proxy.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)
        let listed = try await client.listTools()
        #expect(listed.tools.isEmpty)

        let context: RequestContext<CallTool.Result> = try await client.callTool(
            name: "jira_get_issue"
        )
        let result = try await context.value
        #expect(result.isError == true)
        #expect(
            result.structuredContent?.objectValue?["code"]?.stringValue
                == MCPToolErrorCode.workspaceUnavailable.rawValue
        )

        await client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("missing named upstream lists nothing and rejects calls as upstreamUnavailable")
    func missingUpstreamListsNothing() async throws {
        let fixture = try makeProxy(upstreamName: "missing")
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(name: "MCP proxy missing test", version: "1")

        try await fixture.proxy.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)
        let listed = try await client.listTools()
        #expect(listed.tools.isEmpty)

        let context: RequestContext<CallTool.Result> = try await client.callTool(
            name: "jira_get_issue"
        )
        let result = try await context.value
        #expect(result.isError == true)
        #expect(
            result.structuredContent?.objectValue?["code"]?.stringValue
                == MCPToolErrorCode.upstreamUnavailable.rawValue
        )

        await client.disconnect()
        await fixture.proxy.waitUntilCompleted()
    }

    @Test("HTTP upstreams list nothing and reject calls as httpUpstreamUnsupported")
    func httpUpstreamListsNothing() async throws {
        for upstream in [
            MCPUpstreamConfig(name: "jira", transport: .http, url: "https://example.atlassian.net/mcp"),
            MCPUpstreamConfig(name: "jira", transport: .sse, url: "https://example.atlassian.net/mcp"),
            MCPUpstreamConfig(
                name: "jira",
                transport: .streamableHTTP,
                url: "https://example.atlassian.net/mcp"
            ),
            MCPUpstreamConfig(name: "jira", url: "https://example.atlassian.net/mcp"),
        ] {
            let fixture = try makeProxy(upstreams: [upstream])
            defer { try? FileManager.default.removeItem(at: fixture.root) }
            let transports = await InMemoryTransport.createConnectedPair()
            let client = Client(name: "MCP proxy http test", version: "1")

            try await fixture.proxy.start(transport: transports.server)
            _ = try await client.connect(transport: transports.client)
            let listed = try await client.listTools()
            #expect(listed.tools.isEmpty, "transport: \(upstream.transport.rawValue)")

            let context: RequestContext<CallTool.Result> = try await client.callTool(
                name: "jira_get_issue"
            )
            let result = try await context.value
            #expect(result.isError == true)
            #expect(
                result.structuredContent?.objectValue?["code"]?.stringValue
                    == MCPToolErrorCode.httpUpstreamUnsupported.rawValue
            )

            await client.disconnect()
            await fixture.proxy.waitUntilCompleted()
        }
    }

    @Test("deny and unknown tools are omitted from the list and rejected on call")
    func denyAndUnknownAreRejected() async throws {
        let fixture = try makeProxy()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(name: "MCP proxy deny test", version: "1")

        try await fixture.proxy.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)
        let listed = try await client.listTools()
        #expect(!listed.tools.map(\.name).contains("jira_delete_issue"))

        for name in ["jira_delete_issue", "not_a_tool"] {
            let context: RequestContext<CallTool.Result> = try await client.callTool(name: name)
            let result = try await context.value
            #expect(result.isError == true)
            #expect(
                result.structuredContent?.objectValue?["code"]?.stringValue
                    == MCPToolErrorCode.upstreamDenied.rawValue
            )
        }

        await client.disconnect()
        await fixture.proxy.waitUntilCompleted()
    }

    @Test("resources and prompts are method-not-found")
    func unsupportedMethodsAreRejected() async throws {
        let fixture = try makeProxy()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(name: "MCP proxy methods test", version: "1")

        try await fixture.proxy.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)

        do {
            _ = try await client.listResources()
            Issue.record("Expected resources/list to fail")
        } catch MCPError.methodNotFound {
            // Expected.
        } catch {
            Issue.record("Expected methodNotFound, got \(error)")
        }

        do {
            _ = try await client.listPrompts()
            Issue.record("Expected prompts/list to fail")
        } catch MCPError.methodNotFound {
            // Expected.
        } catch {
            Issue.record("Expected methodNotFound, got \(error)")
        }

        await client.disconnect()
        await fixture.proxy.waitUntilCompleted()
    }

    @Test("empty credential-less policy lists nothing and discovers on the first call")
    func emptyPolicyDiscoversChildCatalogOnFirstCall() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("codegraph"))
        let sessionClient = RecordingMCPProxySessionClient(
            environment: [:],
            grantIDs: [UUID()]
        )
        let launcher = RecordingMCPProxyChildLauncher()
        let root = try makeMCPProxyWorkspace(
            upstreams: [
                MCPUpstreamConfig(
                    name: "codegraph",
                    command: "codegraph",
                    args: ["serve", "--mcp"],
                    tools: MCPUpstreamToolPolicy(deny: ["jira_search"])
                ),
            ]
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "codegraph",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            childLauncher: launcher,
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15,
            killGraceSeconds: 0.05,
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "Codex")

        // A client lists on connect. Nothing about opening a workspace may
        // start the declared child or ask the human for admission.
        let listed = try await connection.client.listTools()
        #expect(listed.tools.isEmpty)
        #expect(sessionClient.prepareCount == 0)
        #expect(launcher.spawnCount == 0)

        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        let result = try await call.value
        #expect(result.isError != true)
        // Invoking a tool is what pays for discovery and then for the
        // long-lived child, each named by the declared argv.
        #expect(sessionClient.prepareCount == 2)
        #expect(sessionClient.mcpToolNames == [nil, "jira_get_issue"])
        #expect(sessionClient.mcpUpstreamNames == ["codegraph", "codegraph"])
        #expect(sessionClient.mcpUpstreamCommands == ["codegraph serve --mcp", "codegraph serve --mcp"])
        #expect(launcher.spawnCount == 2)

        let denied: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_search"
        )
        let deniedResult = try await denied.value
        #expect(deniedResult.isError == true)
        #expect(
            deniedResult.structuredContent?.objectValue?["code"]?.stringValue
                == MCPToolErrorCode.upstreamDenied.rawValue
        )

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("declined admission blocks catalog discovery before spawn")
    func declinedAdmissionBlocksCatalogDiscoveryBeforeSpawn() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("codegraph"))
        let sessionClient = RecordingMCPProxySessionClient(
            environment: [:],
            error: BridgeClientError.bridgeError(
                code: "notAuthorized",
                message: "Access denied",
                query: nil
            )
        )
        let launcher = RecordingMCPProxyChildLauncher()
        let root = try makeMCPProxyWorkspace(
            upstreams: [
                MCPUpstreamConfig(
                    name: "codegraph",
                    command: "codegraph"
                ),
            ]
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "codegraph",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            childLauncher: launcher,
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15,
            killGraceSeconds: 0.05,
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "Codex")

        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        let result = try await call.value
        #expect(result.isError == true)
        #expect(launcher.spawnCount == 0)
        #expect(sessionClient.prepareCount == 1)

        // The declined result is cached for this proxy session, avoiding an
        // approval loop when an agent retries.
        let retry: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        #expect(try await retry.value.isError == true)
        #expect(sessionClient.prepareCount == 1)
        #expect(launcher.spawnCount == 0)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("concurrent calls join one in-flight catalog discovery")
    func concurrentCallsJoinOneCatalogDiscovery() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("codegraph"))
        let serverID = UUID()
        let grantID = UUID()
        let grantClient = MutableMCPProxyGrantClient(
            snapshot: .init(active: [mcpProxyGrant(id: grantID, serverID: serverID)], history: [])
        )
        let sessionClient = RecordingMCPProxySessionClient(
            environment: [:],
            grantIDs: [grantID],
            delayNanoseconds: 200_000_000
        )
        let launcher = RecordingMCPProxyChildLauncher()
        let root = try makeMCPProxyWorkspace(
            upstreams: [
                MCPUpstreamConfig(
                    name: "codegraph",
                    command: "codegraph"
                ),
            ]
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "codegraph",
            runtimeContext: MCPRuntimeContext(startingDirectory: root, instanceID: serverID),
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            childLauncher: launcher,
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15,
            killGraceSeconds: 0.05,
            grantService: MCPGrantService(serverInstanceID: serverID, client: grantClient),
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "Codex")

        async let first: RequestContext<CallTool.Result> = connection.client.callTool(
            name: "jira_get_issue"
        )
        async let second: RequestContext<CallTool.Result> = connection.client.callTool(
            name: "jira_search"
        )
        let requests = try await [first, second]
        var results: [CallTool.Result] = []
        for request in requests {
            results.append(try await request.value)
        }

        // The second call must wait for the in-flight probe instead of reading
        // a cache that was published before the probe finished, which would
        // reject it as an unadvertised tool.
        for result in results {
            #expect(result.isError != true)
        }
        // One probe, then one long-lived child shared by both calls.
        #expect(launcher.spawnCount == 2)
        #expect(sessionClient.prepareCount == 2)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("disabled MCP access starts no child on list or call")
    func emptyPolicySkipsDiscoveryWhenAccessDisabled() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("codegraph"))
        let launcher = RecordingMCPProxyChildLauncher()
        let root = try makeMCPProxyWorkspace(
            upstreams: [
                MCPUpstreamConfig(
                    name: "codegraph",
                    command: "codegraph",
                    env: ["PYTHONUNBUFFERED": "1"]
                ),
            ]
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "codegraph",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            mcpAccessEnabled: { false },
            childLauncher: launcher,
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15,
            killGraceSeconds: 0.05,
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "Codex")
        let listed = try await connection.client.listTools()
        #expect(listed.tools.isEmpty)
        #expect(launcher.spawnCount == 0)

        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        let result = try await call.value
        #expect(result.isError == true)
        #expect(toolErrorCode(result) == MCPToolErrorCode.mcpAccessDisabled.rawValue)
        #expect(launcher.spawnCount == 0)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("disabled MCP persists mcpAccessDisabled at settings and does not borrow another grant")
    func disabledMCPPersistsErrorCodeWithoutGrantFallback() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-atlassian"))
        let serverID = UUID()
        let foreignGrantID = UUID()
        let grantClient = MutableMCPProxyGrantClient(
            snapshot: .init(
                active: [mcpProxyGrant(id: foreignGrantID, serverID: serverID)],
                history: []
            )
        )
        let recorder = RecordingMCPProxyToolCallRecorder()
        let launcher = RecordingMCPProxyChildLauncher()
        let root = try makeMCPProxyWorkspace(upstreams: [Self.stdioJiraUpstream])
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "jira",
            runtimeContext: MCPRuntimeContext(startingDirectory: root, instanceID: serverID),
            mcpAccessEnabled: { false },
            childLauncher: launcher,
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15,
            killGraceSeconds: 0.05,
            grantService: MCPGrantService(serverInstanceID: serverID, client: grantClient),
            toolCallRecorder: recorder
        )
        let connection = try await connectMCPProxy(proxy, clientName: "Codex")
        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        let result = try await call.value
        #expect(result.isError == true)
        #expect(toolErrorCode(result) == MCPToolErrorCode.mcpAccessDisabled.rawValue)
        #expect(launcher.spawnCount == 0)
        #expect(recorder.outcomes.count == 1)
        #expect(recorder.outcomes[0].outcome == .denied)
        #expect(recorder.outcomes[0].errorCode == MCPToolErrorCode.mcpAccessDisabled.rawValue)
        #expect(recorder.outcomes[0].stage == .settings)
        #expect(recorder.outcomes[0].grantID == nil)
        #expect(recorder.outcomes[0].grantIDs.isEmpty)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("an undeclared upstream persists upstreamUnavailable at policy")
    func missingUpstreamPersistsPolicyStage() async throws {
        let recorder = RecordingMCPProxyToolCallRecorder()
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                schemaVersion: 2,
                workspace: .init(name: "proxy", authsiaFolder: "Workspaces/proxy"),
                managedEnvFiles: [],
                agents: nil,
                mcpUpstreams: [Self.stdioJiraUpstream]
            ),
            toWorkspaceRoot: root
        )
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "missing",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            mcpAccessEnabled: { true },
            toolCallRecorder: recorder
        )
        let connection = try await connectMCPProxy(proxy, clientName: "Codex")
        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        let result = try await call.value
        #expect(result.isError == true)
        #expect(toolErrorCode(result) == MCPToolErrorCode.upstreamUnavailable.rawValue)
        #expect(recorder.outcomes.count == 1)
        #expect(recorder.outcomes[0].outcome == .upstreamUnavailable)
        #expect(recorder.outcomes[0].errorCode == MCPToolErrorCode.upstreamUnavailable.rawValue)
        #expect(recorder.outcomes[0].stage == .policy)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("a multi-grant session records every grant ID")
    func multiGrantSessionRecordsEveryGrantID() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-atlassian"))
        let serverID = UUID()
        let firstGrant = UUID(uuidString: "BBBBBBBB-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!
        let secondGrant = UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!
        let grantClient = MutableMCPProxyGrantClient(
            snapshot: .init(
                active: [
                    mcpProxyGrant(id: firstGrant, serverID: serverID),
                    mcpProxyGrant(id: secondGrant, serverID: serverID),
                ],
                history: []
            )
        )
        let sessionClient = RecordingMCPProxySessionClient(
            environment: [:],
            grantIDs: [firstGrant, secondGrant]
        )
        let recorder = RecordingMCPProxyToolCallRecorder()
        let root = try makeMCPProxyWorkspace(
            upstreams: [
                MCPUpstreamConfig(
                    name: "jira",
                    command: "mcp-atlassian",
                    tools: MCPUpstreamToolPolicy(
                        allow: ["jira_get_issue"],
                        approve: [],
                        deny: []
                    )
                ),
            ]
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "jira",
            runtimeContext: MCPRuntimeContext(startingDirectory: root, instanceID: serverID),
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15,
            grantService: MCPGrantService(serverInstanceID: serverID, client: grantClient),
            toolCallRecorder: recorder
        )
        let connection = try await connectMCPProxy(proxy, clientName: "Codex")
        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        let result = try await call.value
        #expect(result.isError != true)
        let expected = [secondGrant, firstGrant]
        #expect(recorder.calls.count == 1)
        #expect(recorder.calls[0].grantID == secondGrant)
        #expect(recorder.calls[0].grantIDs == expected)
        #expect(recorder.outcomes.contains { outcome in
            outcome.outcome == .succeeded
                && outcome.grantID == secondGrant
                && outcome.grantIDs == expected
                && outcome.errorCode == nil
                && outcome.stage == .forward
        })

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("empty policy does not discover when env contains authsia references")
    func emptyPolicySkipsDiscoveryWhenEnvHasSecretRefs() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-atlassian"))
        let launcher = RecordingMCPProxyChildLauncher()
        let sessionClient = RecordingMCPProxySessionClient()
        let root = try makeMCPProxyWorkspace(
            upstreams: [
                MCPUpstreamConfig(
                    name: "jira",
                    command: "mcp-atlassian",
                    env: [
                        "JIRA_API_TOKEN": "authsia://api-key/Atlassian/key?folder=Workspaces%2Fproxy",
                    ]
                ),
            ]
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "jira",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            childLauncher: launcher,
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15,
            killGraceSeconds: 0.05,
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "Codex")
        let listed = try await connection.client.listTools()
        #expect(listed.tools.isEmpty)
        #expect(launcher.spawnCount == 0)
        #expect(sessionClient.prepareCount == 0)

        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        let result = try await call.value
        #expect(result.isError == true)
        #expect(
            result.structuredContent?.objectValue?["code"]?.stringValue
                == MCPToolErrorCode.upstreamDenied.rawValue
        )
        #expect(sessionClient.prepareCount == 0)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("catalog discovery reaps the probe child instead of leaving a zombie")
    func catalogDiscoveryReapsProbeChild() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("codegraph"))
        let sessionClient = RecordingMCPProxySessionClient(environment: [:], grantIDs: [UUID()])
        let launcher = RecordingMCPProxyChildLauncher()
        let root = try makeMCPProxyWorkspace(
            upstreams: [MCPUpstreamConfig(name: "codegraph", command: "codegraph")]
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "codegraph",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            childLauncher: launcher,
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15,
            killGraceSeconds: 0.05,
            grantService: MCPGrantService(
                serverInstanceID: UUID(),
                client: MutableMCPProxyGrantClient(
                    snapshot: AgentJITGrantSnapshotPayload(active: [], history: [])
                )
            ),
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )

        // `authsia mcp catalog` runs the probe and nothing else, so the only
        // child the launcher saw is the one being reaped.
        let captured = try await proxy.captureCatalog().get()
        #expect(captured.isEmpty == false)
        let probeProcessID = try #require(launcher.lastSpawned?.processID)

        // An unreaped probe child stays a zombie whose process group still
        // answers kill(-pgid, 0) with EPERM, so the terminator would never see
        // it die and would burn the whole grace and force window. Nothing left
        // to wait for means the proxy reaped it.
        var status: Int32 = 0
        let reaped = waitpid(probeProcessID, &status, WNOHANG)
        let reapErrno = errno
        #expect(reaped == -1)
        #expect(reapErrno == ECHILD)
    }

    @Test("a deny added after discovery applies without a second probe")
    func denyAddedAfterDiscoveryApplies() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("codegraph"))
        let sessionClient = RecordingMCPProxySessionClient(environment: [:], grantIDs: [UUID()])
        let launcher = RecordingMCPProxyChildLauncher()
        let root = try makeMCPProxyWorkspace(
            upstreams: [MCPUpstreamConfig(name: "codegraph", command: "codegraph")]
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "codegraph",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            childLauncher: launcher,
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15,
            killGraceSeconds: 0.05,
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "Codex")

        let first: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        #expect(try await first.value.isError != true)
        // One probe child, then the long-lived one.
        #expect(launcher.spawnCount == 2)

        // Policy is committed repository content and can change while the
        // client is still connected. The discovered catalog is cached for the
        // proxy session, so deny has to be re-read, not baked into the cache.
        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                schemaVersion: 2,
                workspace: .init(name: "proxy", authsiaFolder: "Workspaces/proxy"),
                managedEnvFiles: [],
                agents: nil,
                mcpUpstreams: [
                    MCPUpstreamConfig(
                        name: "codegraph",
                        command: "codegraph",
                        tools: MCPUpstreamToolPolicy(deny: ["jira_search"])
                    ),
                ]
            ),
            toWorkspaceRoot: root
        )

        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_search"
        )
        let result = try await call.value
        #expect(result.isError == true)
        #expect(toolErrorCode(result) == MCPToolErrorCode.upstreamDenied.rawValue)
        #expect(launcher.spawnCount == 2)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("child start and exit persist lifecycle rows")
    func childStartAndNaturalExitPersistLifecycleRows() async throws {
        let fixture = try await makeLiveChildFixture()
        defer { fixture.tearDown() }
        let call: RequestContext<CallTool.Result> = try await fixture.connection.client.callTool(
            name: "jira_get_issue"
        )
        #expect(try await call.value.isError != true)
        #expect(waitForMCPProxyLifecycle(fixture.recorder, outcome: .childStarted))
        let spawned = try #require(fixture.launcher.lastSpawned)
        Darwin.kill(spawned.processID, SIGKILL)
        #expect(waitForMCPProxyLifecycle(fixture.recorder, outcome: .childExited, exitReason: .exit))
        await fixture.connection.client.disconnect()
        await fixture.proxy.waitUntilCompleted()
    }

    @Test("revoking the grant records childExited revoked")
    func revokePersistsRevokedChildExit() async throws {
        let fixture = try await makeLiveChildFixture()
        defer { fixture.tearDown() }
        let call: RequestContext<CallTool.Result> = try await fixture.connection.client.callTool(
            name: "jira_get_issue"
        )
        #expect(try await call.value.isError != true)
        #expect(waitForMCPProxyLifecycle(fixture.recorder, outcome: .childStarted))
        fixture.grantClient.setSnapshot(.init(
            active: [],
            history: [mcpProxyGrant(
                id: fixture.grantID,
                serverID: fixture.serverID,
                revokedAt: Date()
            )]
        ))
        #expect(waitForMCPProxyLifecycle(fixture.recorder, outcome: .childExited, exitReason: .revoked))
        await fixture.connection.client.disconnect()
        await fixture.proxy.waitUntilCompleted()
    }

    @Test("an expired grant records childExited expired")
    func expiryPersistsExpiredChildExit() async throws {
        let fixture = try await makeLiveChildFixture()
        defer { fixture.tearDown() }
        let call: RequestContext<CallTool.Result> = try await fixture.connection.client.callTool(
            name: "jira_get_issue"
        )
        #expect(try await call.value.isError != true)
        fixture.grantClient.setSnapshot(.init(
            active: [],
            history: [mcpProxyGrant(
                id: fixture.grantID,
                serverID: fixture.serverID,
                expiresAt: Date().addingTimeInterval(-1)
            )]
        ))
        #expect(waitForMCPProxyLifecycle(fixture.recorder, outcome: .childExited, exitReason: .expired))
        await fixture.connection.client.disconnect()
        await fixture.proxy.waitUntilCompleted()
    }

    @Test("graceful stop records childExited stdinClosed")
    func stopPersistsStdinClosedChildExit() async throws {
        let fixture = try await makeLiveChildFixture()
        defer { fixture.tearDown() }
        let call: RequestContext<CallTool.Result> = try await fixture.connection.client.callTool(
            name: "jira_get_issue"
        )
        #expect(try await call.value.isError != true)
        await fixture.proxy.stop()
        #expect(waitForMCPProxyLifecycle(fixture.recorder, outcome: .childExited, exitReason: .stdinClosed))
        await fixture.connection.client.disconnect()
    }

    @Test("a stuck Bridge watcher records childExited timeout")
    func unreachableBridgePersistsTimeoutChildExit() async throws {
        let fixture = try await makeLiveChildFixture()
        defer { fixture.tearDown() }
        let call: RequestContext<CallTool.Result> = try await fixture.connection.client.callTool(
            name: "jira_get_issue"
        )
        #expect(try await call.value.isError != true)
        fixture.grantClient.failSnapshotsPermanently()
        #expect(waitForMCPProxyLifecycle(
            fixture.recorder,
            outcome: .childExited,
            exitReason: .timeout,
            timeoutSeconds: 2
        ))
        await fixture.connection.client.disconnect()
        await fixture.proxy.waitUntilCompleted()
    }

    private struct LiveChildFixture {
        let proxy: AuthsiaMCPProxy
        let connection: (client: Client, serverTransport: any Transport)
        let recorder: RecordingMCPProxyToolCallRecorder
        let launcher: RecordingMCPProxyChildLauncher
        let grantClient: MutableMCPProxyGrantClient
        let grantID: UUID
        let serverID: UUID
        let roots: [URL]

        func tearDown() {
            for root in roots {
                try? FileManager.default.removeItem(at: root)
            }
        }
    }

    private func makeLiveChildFixture() async throws -> LiveChildFixture {
        let bin = try makeWorkspaceRoot()
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-atlassian"))
        let serverID = UUID(uuidString: "7E05890F-5C3A-44EF-9208-83A12F17D6CE")!
        let grantID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
        let grantClient = MutableMCPProxyGrantClient(
            snapshot: .init(
                active: [mcpProxyGrant(id: grantID, serverID: serverID)],
                history: []
            )
        )
        let sessionClient = RecordingMCPProxySessionClient(
            environment: ["JIRA_API_TOKEN": "synthetic-token"],
            secrets: ["synthetic-token"],
            grantIDs: [grantID]
        )
        let launcher = RecordingMCPProxyChildLauncher()
        let recorder = RecordingMCPProxyToolCallRecorder()
        let root = try makeMCPProxyWorkspace(upstreams: [Self.stdioJiraUpstream])
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "jira",
            runtimeContext: MCPRuntimeContext(startingDirectory: root, instanceID: serverID),
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            childLauncher: launcher,
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15,
            killGraceSeconds: 0.05,
            grantPollIntervalSeconds: 0.05,
            grantService: MCPGrantService(serverInstanceID: serverID, client: grantClient),
            toolCallRecorder: recorder
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP lifecycle child")
        return LiveChildFixture(
            proxy: proxy,
            connection: connection,
            recorder: recorder,
            launcher: launcher,
            grantClient: grantClient,
            grantID: grantID,
            serverID: serverID,
            roots: [bin, root]
        )
    }

    private func makeProxy(
        upstreamName: String = "jira",
        mcpAccessEnabled: @escaping @Sendable () -> Bool = { true },
        upstreams: [MCPUpstreamConfig]? = nil
    ) throws -> (proxy: AuthsiaMCPProxy, root: URL) {
        let root = try makeWorkspaceRoot()
        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                schemaVersion: 2,
                workspace: .init(name: "proxy", authsiaFolder: "Workspaces/proxy"),
                managedEnvFiles: [],
                agents: nil,
                mcpUpstreams: upstreams ?? [Self.stdioJiraUpstream]
            ),
            toWorkspaceRoot: root
        )
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: upstreamName,
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            mcpAccessEnabled: mcpAccessEnabled,
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        return (proxy, root)
    }

    private static let stdioJiraUpstream = MCPUpstreamConfig(
        name: "jira",
        command: "mcp-atlassian",
        env: [
            "JIRA_API_TOKEN": "authsia://api-key/Atlassian/key?folder=Workspaces%2Fproxy",
            "JIRA_URL": "https://example.atlassian.net",
        ],
        tools: MCPUpstreamToolPolicy(
            allow: ["jira_get_issue", "jira_search"],
            approve: ["jira_create_issue"],
            deny: ["jira_delete_issue"]
        ),
        catalog: [
            MCPUpstreamToolDescriptor(
                name: "jira_get_issue",
                description: "Get one Jira issue by key",
                inputSchema: .object([
                    "additionalProperties": .bool(false),
                    "properties": .object([
                        "issueKey": .object(["type": .string("string")]),
                    ]),
                    "required": .array([.string("issueKey")]),
                    "type": .string("object"),
                ])
            ),
            MCPUpstreamToolDescriptor(name: "jira_delete_issue"),
            MCPUpstreamToolDescriptor(name: "other_tool"),
        ]
    )
}
