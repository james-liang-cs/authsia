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
            mcpAccessEnabled: { true }
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

    @Test("empty credential-less policy discovers child tools on list after admission")
    func emptyPolicyDiscoversChildCatalogAfterAdmission() async throws {
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
                    env: [
                        "AUTHSIA_TEST_TOOLS": "codegraph_explore,hidden_tool,extra_tool",
                        "PYTHONUNBUFFERED": "1",
                    ],
                    tools: MCPUpstreamToolPolicy(deny: ["hidden_tool"])
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

        let listed = try await connection.client.listTools()
        #expect(listed.tools.map(\.name) == ["codegraph_explore", "extra_tool"])
        #expect(!listed.tools.map(\.name).contains("hidden_tool"))
        // Discovery starts the child, so it takes admission first, with no tool
        // name because no tool has been called yet.
        #expect(sessionClient.prepareCount == 1)
        #expect(sessionClient.mcpToolNames == [nil])
        #expect(sessionClient.mcpUpstreamNames == ["codegraph"])
        // The approval has to name the binary, not just the policy label.
        #expect(sessionClient.mcpUpstreamCommands == ["codegraph serve --mcp"])
        #expect(launcher.spawnCount == 1)

        let listedAgain = try await connection.client.listTools()
        #expect(listedAgain.tools.map(\.name) == ["codegraph_explore", "extra_tool"])
        #expect(sessionClient.prepareCount == 1)
        #expect(launcher.spawnCount == 1)

        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "codegraph_explore"
        )
        let result = try await call.value
        #expect(result.isError != true)
        // The Bridge reuses the admission grant for this caller, workspace,
        // upstream, and instance, so this preflight does not prompt again.
        #expect(sessionClient.prepareCount == 2)
        #expect(sessionClient.mcpToolNames == [nil, "codegraph_explore"])
        #expect(launcher.spawnCount == 2)

        let denied: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "hidden_tool"
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

    @Test("declined admission blocks catalog discovery and does not re-prompt")
    func declinedAdmissionBlocksCatalogDiscovery() async throws {
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
                    command: "codegraph",
                    env: ["AUTHSIA_TEST_TOOLS": "codegraph_explore"]
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

        let listed = try await connection.client.listTools()
        #expect(listed.tools.isEmpty)
        #expect(launcher.spawnCount == 0)
        #expect(sessionClient.prepareCount == 1)

        // A decline is cached, so a client that lists on every turn cannot turn
        // discovery into an approval-prompt loop.
        let listedAgain = try await connection.client.listTools()
        #expect(listedAgain.tools.isEmpty)
        #expect(sessionClient.prepareCount == 1)
        #expect(launcher.spawnCount == 0)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("concurrent lists join one in-flight catalog discovery")
    func concurrentListsJoinOneCatalogDiscovery() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("codegraph"))
        let sessionClient = RecordingMCPProxySessionClient(
            environment: [:],
            grantIDs: [UUID()],
            delayNanoseconds: 200_000_000
        )
        let launcher = RecordingMCPProxyChildLauncher()
        let root = try makeMCPProxyWorkspace(
            upstreams: [
                MCPUpstreamConfig(
                    name: "codegraph",
                    command: "codegraph",
                    env: ["AUTHSIA_TEST_TOOLS": "codegraph_explore"]
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

        async let first = connection.client.listTools()
        async let second = connection.client.listTools()
        let results = try await [first, second]

        // The second list must wait for the in-flight probe instead of reading a
        // cache that was published before the probe finished.
        for result in results {
            #expect(result.tools.map(\.name) == ["codegraph_explore"])
        }
        #expect(launcher.spawnCount == 1)
        #expect(sessionClient.prepareCount == 1)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("empty policy does not discover a child catalog when MCP access is disabled")
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
            mcpAccessEnabled: mcpAccessEnabled
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
