import Darwin
import Foundation
import AuthenticatorBridge
import MCP
import Testing
@testable import authsia

@Suite("MCP proxy spawn", .serialized)
struct MCPProxySpawnTests {
    @Test("child environment strips ambient secrets including AUTHSIA_AGENT_INVOKES_AUTHSIA")
    func ambientEnvironmentIsStripped() {
        let child = MCPProxyChildEnvironment.make(
            parent: [
                "HOME": "/synthetic/home",
                "PATH": "/usr/bin",
                "LANG": "en_US.UTF-8",
                "LC_CTYPE": "UTF-8",
                "NODE_EXTRA_CA_CERTS": "/synthetic/trust/node.pem",
                "HTTPS_PROXY": "http://127.0.0.1:9",
                "HTTP_PROXY": "http://127.0.0.1:9",
                "NO_PROXY": "localhost,127.0.0.1",
                "http_proxy": "http://127.0.0.1:9",
                "GITHUB_TOKEN": "synthetic-token-must-not-survive",
                "AWS_SECRET_ACCESS_KEY": "synthetic-key-must-not-survive",
                "AUTHSIA_AGENT_ID": "stale-agent-must-not-survive",
                "AUTHSIA_AGENT_INVOKES_AUTHSIA": "1",
                "AUTHSIA_AGENT_SESSION_ID": "mcp:stale",
                "AUTHSIA_AGENT_TYPE": "authsia-mcp",
                "AUTHSIA_ACCESS_CREDENTIAL": "must-not-survive",
                "AUTHSIA_MCP_PROCESS_GROUP": "1",
                "AUTHSIA_MCP_FAILURE_FILE": "/tmp/failure",
                "AUTHSIA_MCP_UPSTREAM": "jira",
            ],
            declared: [
                "JIRA_URL": "https://example.atlassian.net",
                "JIRA_API_TOKEN": "synthetic-token",
            ]
        )
        #expect(child["HOME"] == "/synthetic/home")
        #expect(child["PATH"] == "/usr/bin")
        #expect(child["LANG"] == "en_US.UTF-8")
        #expect(child["LC_CTYPE"] == "UTF-8")
        #expect(child["NODE_EXTRA_CA_CERTS"] == "/synthetic/trust/node.pem")
        #expect(child["HTTPS_PROXY"] == "http://127.0.0.1:9")
        #expect(child["HTTP_PROXY"] == "http://127.0.0.1:9")
        #expect(child["NO_PROXY"] == "localhost,127.0.0.1")
        #expect(child["http_proxy"] == "http://127.0.0.1:9")
        #expect(child["JIRA_URL"] == "https://example.atlassian.net")
        #expect(child["JIRA_API_TOKEN"] == "synthetic-token")
        #expect(child["GITHUB_TOKEN"] == nil)
        #expect(child["AWS_SECRET_ACCESS_KEY"] == nil)
        #expect(child["AUTHSIA_AGENT_ID"] == nil)
        #expect(child["AUTHSIA_AGENT_INVOKES_AUTHSIA"] == nil)
        #expect(child["AUTHSIA_AGENT_SESSION_ID"] == nil)
        #expect(child["AUTHSIA_AGENT_TYPE"] == nil)
        #expect(child["AUTHSIA_ACCESS_CREDENTIAL"] == nil)
        #expect(child["AUTHSIA_MCP_PROCESS_GROUP"] == nil)
        #expect(child["AUTHSIA_MCP_FAILURE_FILE"] == nil)
        #expect(child["AUTHSIA_MCP_UPSTREAM"] == nil)
        #expect(child[AutomationAccessResolver.environmentKey] == nil)
    }

    @Test("PATH basename and relative commands spawn, and the parent trampoline sets the process group")
    func pathRelativeAndProcessGroup() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let bin = root.appendingPathComponent("bin", isDirectory: true)
        let relative = root.appendingPathComponent("tools/upstream-mcp")
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-atlassian"))
        try writeExecutableMCPProxyScript(at: relative)

        let pathResolved = try MCPProxyCommandResolver.resolve(
            command: "mcp-atlassian",
            workspaceRoot: root,
            path: bin.path
        )
        #expect(pathResolved.lastPathComponent == "mcp-atlassian")

        let overlayHome = root.appendingPathComponent("overlay-home", isDirectory: true)
        try FileManager.default.createDirectory(
            at: overlayHome.appendingPathComponent(".local/bin", isDirectory: true),
            withIntermediateDirectories: true
        )
        try writeExecutableMCPProxyScript(
            at: overlayHome.appendingPathComponent(".local/bin/overlay-mcp")
        )
        let overlayResolved = try MCPProxyCommandResolver.resolve(
            command: "overlay-mcp",
            workspaceRoot: root,
            path: "/usr/bin",
            homeDirectory: overlayHome
        )
        #expect(overlayResolved.lastPathComponent == "overlay-mcp")

        let relativeResolved = try MCPProxyCommandResolver.resolve(
            command: "tools/upstream-mcp",
            workspaceRoot: root,
            path: bin.path
        )
        #expect(relativeResolved.lastPathComponent == "upstream-mcp")

        #expect(throws: MCPProxySpawnError.commandNotFound) {
            _ = try MCPProxyCommandResolver.resolve(
                command: "missing-binary",
                workspaceRoot: root,
                path: bin.path
            )
        }

        let pgidFile = root.appendingPathComponent("child.pgid")
        let spawned = try MCPProxyPosixLauncher().spawn(
            executable: relativeResolved,
            arguments: [],
            environment: [
                "PATH": "\(bin.path):/usr/bin:/bin",
                "AUTHSIA_TEST_PGID": pgidFile.path,
            ],
            currentDirectory: root
        )
        defer {
            let terminator = MCPProcessTerminator(
                processID: spawned.processID,
                processGroupID: spawned.processGroupID,
                killGraceSeconds: 0.05
            )
            terminator.start()
        }
        let observed = waitForMCPProxyTestFile(pgidFile)
        let parts = observed.split(separator: " ")
        let pid = try #require(pid_t(parts.first.map(String.init) ?? ""))
        let pgid = try #require(pid_t(parts.dropFirst().first.map(String.init) ?? ""))
        #expect(pid == spawned.processID)
        #expect(pgid == spawned.processID)
        #expect(pgid == pid)
        #expect(Darwin.getpgid(pid) == pid)

        Darwin.close(spawned.stdinWrite)
        Darwin.close(spawned.stdoutRead)
        Darwin.close(spawned.stderrRead)
    }

    @Test("proxy spawn injects resolved refs only and keeps ambient agent env off the child")
    func proxySpawnStripsAmbientEnv() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-atlassian"))
        let dump = bin.appendingPathComponent("env.json")
        let sessionClient = RecordingMCPProxySessionClient(
            environment: [
                "JIRA_URL": "https://example.atlassian.net",
                "JIRA_API_TOKEN": "synthetic-token",
                "AUTHSIA_TEST_DUMP": dump.path,
            ]
        )
        let root = try makeMCPProxyWorkspace(upstreams: [stdioJiraUpstream()])
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "jira",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            parentEnvironment: [
                "PATH": "\(bin.path):/usr/bin:/bin",
                "HOME": "/synthetic/home",
                "GITHUB_TOKEN": "synthetic-token-must-not-survive",
                "AWS_SECRET_ACCESS_KEY": "synthetic-key-must-not-survive",
                "AUTHSIA_AGENT_ID": "stale-agent-must-not-survive",
                "AUTHSIA_AGENT_INVOKES_AUTHSIA": "1",
                "AUTHSIA_AGENT_SESSION_ID": "mcp:stale",
                "AUTHSIA_AGENT_TYPE": "authsia-mcp",
                "AUTHSIA_ACCESS_CREDENTIAL": "must-not-survive",
                "AUTHSIA_MCP_PROCESS_GROUP": "1",
                "AUTHSIA_MCP_FAILURE_FILE": "/tmp/failure",
            ],
            initializeTimeoutSeconds: 15,
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP spawn env test")
        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        let result = try await call.value
        #expect(result.isError != true)
        let env = try JSONSerialization.jsonObject(with: Data(contentsOf: dump)) as? [String: String]
        let observed = try #require(env)
        #expect(observed["JIRA_API_TOKEN"] == "synthetic-token")
        #expect(observed["JIRA_URL"] == "https://example.atlassian.net")
        #expect(observed["GITHUB_TOKEN"] == nil)
        #expect(observed["AWS_SECRET_ACCESS_KEY"] == nil)
        #expect(observed["AUTHSIA_AGENT_ID"] == nil)
        #expect(observed["AUTHSIA_AGENT_INVOKES_AUTHSIA"] == nil)
        #expect(observed["AUTHSIA_AGENT_SESSION_ID"] == nil)
        #expect(observed["AUTHSIA_AGENT_TYPE"] == nil)
        #expect(observed["AUTHSIA_ACCESS_CREDENTIAL"] == nil)
        #expect(observed["AUTHSIA_MCP_PROCESS_GROUP"] == nil)
        #expect(observed["AUTHSIA_MCP_FAILURE_FILE"] == nil)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("revoking the associated grant kills the live upstream process group")
    func revokedGrantKillsLiveProcessGroup() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
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
        let root = try makeMCPProxyWorkspace(upstreams: [stdioJiraUpstream()])
        defer { try? FileManager.default.removeItem(at: root) }
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
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP revoke test")
        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        #expect(try await call.value.isError != true)
        let spawned = try #require(launcher.lastSpawned)
        #expect(mcpProxyProcessGroupIsAlive(spawned.processGroupID))

        grantClient.setSnapshot(.init(
            active: [],
            history: [mcpProxyGrant(
                id: grantID,
                serverID: serverID,
                revokedAt: Date()
            )]
        ))

        #expect(waitForMCPProxyProcessGroupExit(spawned.processGroupID))

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("graceful stop kills the child and revokes active owned grants")
    func gracefulStopKillsChildAndRevokesGrant() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
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
        let root = try makeMCPProxyWorkspace(upstreams: [stdioJiraUpstream()])
        defer { try? FileManager.default.removeItem(at: root) }
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
            grantPollIntervalSeconds: 5,
            grantService: MCPGrantService(serverInstanceID: serverID, client: grantClient),
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP shutdown test")
        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        #expect(try await call.value.isError != true)
        let spawned = try #require(launcher.lastSpawned)

        await proxy.stop()

        #expect(waitForMCPProxyProcessGroupExit(spawned.processGroupID))
        #expect(grantClient.revokedIDs == [grantID])
        await connection.client.disconnect()
    }

    @Test("a call after revocation starts a fresh JIT session and child")
    func callAfterRevocationStartsFreshSession() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-atlassian"))
        let serverID = UUID(uuidString: "7E05890F-5C3A-44EF-9208-83A12F17D6CE")!
        let oldGrantID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
        let newGrantID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        let grantClient = MutableMCPProxyGrantClient(
            snapshot: .init(
                active: [mcpProxyGrant(id: oldGrantID, serverID: serverID)],
                history: []
            )
        )
        let sessionClient = RecordingMCPProxySessionClient(
            environment: ["JIRA_API_TOKEN": "synthetic-token"],
            secrets: ["synthetic-token"],
            grantIDs: [oldGrantID]
        )
        let launcher = RecordingMCPProxyChildLauncher()
        let root = try makeMCPProxyWorkspace(upstreams: [stdioJiraUpstream()])
        defer { try? FileManager.default.removeItem(at: root) }
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
            grantPollIntervalSeconds: 5,
            grantService: MCPGrantService(serverInstanceID: serverID, client: grantClient),
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP on-call revoke test")
        let firstCall: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        #expect(try await firstCall.value.isError != true)
        let firstChild = try #require(launcher.lastSpawned)

        sessionClient.grantIDs = [newGrantID]
        grantClient.setSnapshot(.init(
            active: [mcpProxyGrant(id: newGrantID, serverID: serverID)],
            history: [mcpProxyGrant(
                id: oldGrantID,
                serverID: serverID,
                revokedAt: Date()
            )]
        ))

        let secondCall: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        #expect(try await secondCall.value.isError != true)
        #expect(sessionClient.prepareCount == 2)
        #expect(launcher.spawnCount == 2)
        #expect(waitForMCPProxyProcessGroupExit(firstChild.processGroupID))

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("a workspace command change drops the live child and re-admits")
    func workspaceCommandChangeDropsLiveChild() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-atlassian"))
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-other"))
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
        let root = try makeMCPProxyWorkspace(upstreams: [stdioJiraUpstream()])
        defer { try? FileManager.default.removeItem(at: root) }
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
            grantPollIntervalSeconds: 5,
            grantService: MCPGrantService(serverInstanceID: serverID, client: grantClient),
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP argv change")
        let firstCall: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        #expect(try await firstCall.value.isError != true)
        let firstChild = try #require(launcher.lastSpawned)
        #expect(sessionClient.mcpUpstreamCommands == ["mcp-atlassian"])

        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                schemaVersion: 2,
                workspace: .init(name: "proxy", authsiaFolder: "Workspaces/proxy"),
                managedEnvFiles: [],
                agents: nil,
                mcpUpstreams: [stdioJiraUpstream(command: "mcp-other")]
            ),
            toWorkspaceRoot: root
        )

        let secondCall: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        #expect(try await secondCall.value.isError != true)
        #expect(sessionClient.prepareCount == 2)
        #expect(sessionClient.mcpUpstreamCommands == ["mcp-atlassian", "mcp-other"])
        #expect(launcher.spawnCount == 2)
        #expect(launcher.lastSpawned?.processID != firstChild.processID)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("relative workspace command is spawned from the workspace root")
    func relativeCommandSpawns() async throws {
        let root = try makeMCPProxyWorkspace(
            upstreams: [
                stdioJiraUpstream(
                    command: "tools/upstream-mcp",
                    env: ["JIRA_URL": "https://example.atlassian.net"]
                )
            ]
        )
        defer { try? FileManager.default.removeItem(at: root) }
        try writeExecutableMCPProxyScript(at: root.appendingPathComponent("tools/upstream-mcp"))
        let sessionClient = RecordingMCPProxySessionClient(
            environment: ["JIRA_URL": "https://example.atlassian.net"]
        )
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "jira",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            parentEnvironment: ["PATH": "/usr/bin:/bin"],
            initializeTimeoutSeconds: 15,
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP relative spawn")
        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        let result = try await call.value
        #expect(result.isError != true)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("the default cap admits eight overlapping calls, rejects the ninth, and drains")
    func defaultConcurrentCallCeiling() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-atlassian"))
        let arrival = bin.appendingPathComponent("arrival.log")
        let sessionClient = RecordingMCPProxySessionClient(
            environment: [
                "AUTHSIA_TEST_TOOLS": "slow,fast",
                "AUTHSIA_TEST_ARRIVAL": arrival.path,
            ]
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
        let recorder = RecordingMCPProxyToolCallRecorder()
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
        let connection = try await connectMCPProxy(proxy, clientName: "MCP sdk spike")
        var admitted: [RequestContext<CallTool.Result>] = []
        for _ in 0..<8 {
            admitted.append(try await connection.client.callTool(name: "slow"))
        }
        let arrivals = waitForMCPProxyTestFile(arrival, minimumLineCount: 8)
        #expect(arrivals.split(whereSeparator: \.isNewline).count == 8)

        let ninth: RequestContext<CallTool.Result> = try await connection.client.callTool(name: "fast")
        let ninthResult = try await ninth.value
        #expect(ninthResult.isError == true)
        #expect(toolErrorCode(ninthResult) == MCPToolErrorCode.busy.rawValue)
        #expect(toolErrorInvocationID(ninthResult) != nil)
        #expect(recorder.outcomes.contains { $0.outcome == .busy && $0.toolName == "fast" })

        for call in admitted {
            #expect((try await call.value).isError != true)
        }

        let later: RequestContext<CallTool.Result> = try await connection.client.callTool(name: "fast")
        #expect((try await later.value).isError != true)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("a call the child does not answer in time is timedOut")
    func unansweredCallTimesOut() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-atlassian"))
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
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP call timeout")

        // The fixture sleeps 0.4s on "slow". Without a deadline of its own the
        // proxy would hold the caller for as long as the child stays wedged.
        let slow: RequestContext<CallTool.Result> = try await connection.client.callTool(name: "slow")
        let slowResult = try await slow.value
        #expect(slowResult.isError == true)
        #expect(toolErrorCode(slowResult) == MCPToolErrorCode.timedOut.rawValue)

        // One slow tool does not take the child down with it.
        let fast: RequestContext<CallTool.Result> = try await connection.client.callTool(name: "fast")
        let fastResult = try await fast.value
        #expect(fastResult.isError != true)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("a second overlapping call is busy when the concurrency cap is 1")
    func overlappingCallIsBusyAtCap() async throws {
        let fixture = try await makeConcurrentCallFixture(maximumConcurrentCalls: 1)
        defer { fixture.tearDown() }
        let slow: RequestContext<CallTool.Result> = try await fixture.connection.client.callTool(
            name: "slow"
        )
        #expect(!waitForMCPProxyTestFile(fixture.arrival).isEmpty)
        let overlapping: RequestContext<CallTool.Result> = try await fixture.connection.client.callTool(
            name: "fast"
        )
        let overlappingResult = try await overlapping.value
        #expect(overlappingResult.isError == true)
        #expect(toolErrorCode(overlappingResult) == MCPToolErrorCode.busy.rawValue)
        #expect(toolErrorInvocationID(overlappingResult) != nil)

        let slowResult = try await slow.value
        #expect(slowResult.isError != true)

        await fixture.connection.client.disconnect()
        await fixture.proxy.waitUntilCompleted()
    }

    @Test("the concurrent-call counter drains after a busy rejection")
    func concurrentCallCounterDrains() async throws {
        let fixture = try await makeConcurrentCallFixture(maximumConcurrentCalls: 1)
        defer { fixture.tearDown() }
        let slow: RequestContext<CallTool.Result> = try await fixture.connection.client.callTool(
            name: "slow"
        )
        #expect(!waitForMCPProxyTestFile(fixture.arrival).isEmpty)
        let overlapping: RequestContext<CallTool.Result> = try await fixture.connection.client.callTool(
            name: "fast"
        )
        #expect(toolErrorCode(try await overlapping.value) == MCPToolErrorCode.busy.rawValue)
        #expect((try await slow.value).isError != true)

        let later: RequestContext<CallTool.Result> = try await fixture.connection.client.callTool(
            name: "fast"
        )
        let laterResult = try await later.value
        #expect(laterResult.isError != true)

        await fixture.connection.client.disconnect()
        await fixture.proxy.waitUntilCompleted()
    }

    @Test("relative non-executable command is commandNotFound")
    func relativeNonExecutableIsCommandNotFound() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let relative = root.appendingPathComponent("tools/upstream-mcp")
        try FileManager.default.createDirectory(
            at: relative.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try "#!/usr/bin/python3\n".write(to: relative, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644],
            ofItemAtPath: relative.path
        )
        #expect(throws: MCPProxySpawnError.commandNotFound) {
            _ = try MCPProxyCommandResolver.resolve(
                command: "tools/upstream-mcp",
                workspaceRoot: root,
                path: "/usr/bin"
            )
        }
    }

    @Test("hung initialize kills the child process group")
    func hungInitializeKillsProcessGroup() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let script = root.appendingPathComponent("tools/upstream-mcp")
        try writeExecutableMCPProxyScript(at: script)
        let pgidFile = root.appendingPathComponent("child.pgid")
        let spawned = try MCPProxyPosixLauncher().spawn(
            executable: script,
            arguments: [],
            environment: [
                "PATH": "/usr/bin:/bin",
                "AUTHSIA_TEST_HANG": "1",
                "AUTHSIA_TEST_PGID": pgidFile.path,
            ],
            currentDirectory: root
        )
        _ = waitForMCPProxyTestFile(pgidFile)
        #expect(Darwin.kill(-spawned.processGroupID, 0) == 0 || errno == EPERM)
        let terminator = MCPProcessTerminator(
            processID: spawned.processID,
            processGroupID: spawned.processGroupID,
            killGraceSeconds: 0.05
        )
        Darwin.kill(-spawned.processGroupID, SIGKILL)
        terminator.start()
        Darwin.close(spawned.stdinWrite)
        Darwin.close(spawned.stdoutRead)
        Darwin.close(spawned.stderrRead)
        let deadline = Date().addingTimeInterval(2)
        while Date() < deadline {
            let alive = Darwin.kill(-spawned.processGroupID, 0) == 0 || errno == EPERM
            if !alive { break }
            Thread.sleep(forTimeInterval: 0.02)
        }
        #expect(Darwin.kill(-spawned.processGroupID, 0) != 0)
    }

    @Test("trampoline restores SIGTERM and does not inherit extra parent FDs")
    func trampolineRestoresSignalsAndCloexec() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let script = root.appendingPathComponent("tools/upstream-mcp")
        try writeExecutableMCPProxyScript(at: script)
        var extraPipe = [Int32](repeating: 0, count: 2)
        guard Darwin.pipe(&extraPipe) == 0 else {
            Issue.record("pipe failed")
            return
        }
        defer {
            Darwin.close(extraPipe[0])
            Darwin.close(extraPipe[1])
        }
        let sigtermFile = root.appendingPathComponent("sigterm")
        let inheritedFile = root.appendingPathComponent("inherited")
        let spawned = try MCPProxyPosixLauncher().spawn(
            executable: script,
            arguments: [],
            environment: [
                "PATH": "/usr/bin:/bin",
                "AUTHSIA_TEST_SIGTERM": sigtermFile.path,
                "AUTHSIA_TEST_PARENT_FD": String(extraPipe[0]),
                "AUTHSIA_TEST_PARENT_FD_RESULT": inheritedFile.path,
            ],
            currentDirectory: root
        )
        defer {
            let terminator = MCPProcessTerminator(
                processID: spawned.processID,
                processGroupID: spawned.processGroupID,
                killGraceSeconds: 0.05
            )
            terminator.start()
            Darwin.close(spawned.stdinWrite)
            Darwin.close(spawned.stdoutRead)
            Darwin.close(spawned.stderrRead)
        }
        #expect(waitForMCPProxyTestFile(sigtermFile) == "DEFAULT")
        #expect(waitForMCPProxyTestFile(inheritedFile) == "closed")
    }

    @Test("teardown sends SIGTERM to the group before escalating to SIGKILL")
    func teardownTerminatesGroupGracefully() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-atlassian"))
        let caught = bin.appendingPathComponent("sigterm-caught")
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
                "AUTHSIA_TEST_SIGTERM_CAUGHT": caught.path,
            ],
            secrets: ["synthetic-token"],
            grantIDs: [grantID]
        )
        let launcher = RecordingMCPProxyChildLauncher()
        let root = try makeMCPProxyWorkspace(upstreams: [stdioJiraUpstream()])
        defer { try? FileManager.default.removeItem(at: root) }
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "jira",
            runtimeContext: MCPRuntimeContext(startingDirectory: root, instanceID: serverID),
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            childLauncher: launcher,
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15,
            grantPollIntervalSeconds: 5,
            grantService: MCPGrantService(serverInstanceID: serverID, client: grantClient),
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP graceful stop test")
        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        #expect(try await call.value.isError != true)
        let spawned = try #require(launcher.lastSpawned)

        await proxy.stop()

        // The child only writes this file from its own SIGTERM handler, so an
        // unconditional SIGKILL would leave it absent.
        #expect(waitForMCPProxyTestFile(caught) == "SIGTERM")
        #expect(waitForMCPProxyProcessGroupExit(spawned.processGroupID))
        await connection.client.disconnect()
    }

    @Test("resolved refs with no owned grant are refused before the child starts")
    func secretsWithoutOwnedGrantRefuseToSpawn() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-atlassian"))
        let sessionClient = RecordingMCPProxySessionClient(
            environment: ["JIRA_API_TOKEN": "synthetic-token"],
            secrets: ["synthetic-token"],
            grantIDs: []
        )
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
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15,
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP ungranted test")
        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        let result = try await call.value

        #expect(result.isError == true)
        #expect(toolErrorCode(result) == "grantUnavailable")
        // Nothing to revoke means nothing may hold the secrets.
        #expect(launcher.spawnCount == 0)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("two Bridge snapshot throws do not kill the child")
    func transientGrantSnapshotThrowLeavesChildRunning() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
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
        let root = try makeMCPProxyWorkspace(upstreams: [stdioJiraUpstream()])
        defer { try? FileManager.default.removeItem(at: root) }
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
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP grant blip")
        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        #expect(try await call.value.isError != true)
        let spawned = try #require(launcher.lastSpawned)
        #expect(mcpProxyProcessGroupIsAlive(spawned.processGroupID))

        grantClient.failNextSnapshots(2)
        try await Task.sleep(for: .milliseconds(250))
        #expect(mcpProxyProcessGroupIsAlive(spawned.processGroupID))

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("a child that exits during initialize fails fast with childExited")
    func childExitDuringInitializeFailsFast() async throws {
        let bin = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: bin) }
        let script = bin.appendingPathComponent("mcp-atlassian")
        try """
        #!/usr/bin/python3
        import sys
        sys.exit(7)
        """.write(to: script, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: script.path)

        let root = try makeMCPProxyWorkspace(
            upstreams: [
                stdioJiraUpstream(env: [:], allow: ["jira_get_issue"], approve: [], deny: [])
            ]
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let started = ContinuousClock.now
        let sessionClient = RecordingMCPProxySessionClient(environment: [:])
        let launcher = RecordingMCPProxyChildLauncher()
        let serverID = UUID(uuidString: "7E05890F-5C3A-44EF-9208-83A12F17D6CE")!
        let grantClient = MutableMCPProxyGrantClient(
            snapshot: .init(active: [], history: [])
        )
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
            grantService: MCPGrantService(serverInstanceID: serverID, client: grantClient),
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP instant exit")
        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        let result = try await call.value
        let elapsed = started.duration(to: .now)
        #expect(result.isError == true)
        #expect(toolErrorCode(result) == "upstreamUnavailable")
        #expect(toolErrorMessage(result)?.contains("exited during startup") == true)
        #expect(elapsed < .seconds(3))
        #expect(launcher.spawnCount == 1)

        let cached: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        let cachedResult = try await cached.value
        #expect(cachedResult.isError == true)
        #expect(toolErrorMessage(cachedResult)?.contains("exited during startup") == true)
        #expect(launcher.spawnCount == 1)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }

    @Test("invalid workspace.json is named instead of unbound")
    func invalidWorkspaceJSONIsNamed() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = root.appendingPathComponent(".authsia/workspace.json")
        try FileManager.default.createDirectory(
            at: config.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try "{ not json".write(to: config, atomically: true, encoding: .utf8)
        let proxy = AuthsiaMCPProxy(
            version: "test",
            upstreamName: "jira",
            runtimeContext: MCPRuntimeContext(startingDirectory: root),
            mcpAccessEnabled: { true },
            toolCallRecorder: NoopMCPProxyToolCallRecorder()
        )
        let connection = try await connectMCPProxy(proxy, clientName: "MCP invalid workspace")
        let call: RequestContext<CallTool.Result> = try await connection.client.callTool(
            name: "jira_get_issue"
        )
        let result = try await call.value
        #expect(result.isError == true)
        #expect(toolErrorCode(result) == MCPToolErrorCode.workspaceUnavailable.rawValue)
        #expect(toolErrorMessage(result)?.contains("failed validation") == true)
        #expect(toolErrorMessage(result)?.contains("could not be read") == true)
        #expect(toolErrorMessage(result)?.contains("workspace.json") == true)

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
    }
}

private struct ConcurrentCallFixture {
    let bin: URL
    let root: URL
    let arrival: URL
    let proxy: AuthsiaMCPProxy
    let connection: (client: Client, serverTransport: InMemoryTransport)

    func tearDown() {
        try? FileManager.default.removeItem(at: bin)
        try? FileManager.default.removeItem(at: root)
    }
}

private func makeConcurrentCallFixture(
    maximumConcurrentCalls: Int
) async throws -> ConcurrentCallFixture {
    let bin = try makeWorkspaceRoot()
    try writeExecutableMCPProxyScript(at: bin.appendingPathComponent("mcp-atlassian"))
    let arrival = bin.appendingPathComponent("arrival.log")
    let sessionClient = RecordingMCPProxySessionClient(
        environment: [
            "AUTHSIA_TEST_TOOLS": "slow,fast",
            "AUTHSIA_TEST_ARRIVAL": arrival.path,
        ]
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
    let proxy = AuthsiaMCPProxy(
        version: "test",
        upstreamName: "jira",
        runtimeContext: MCPRuntimeContext(startingDirectory: root),
        mcpAccessEnabled: { true },
        sessionClient: sessionClient,
        parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
        initializeTimeoutSeconds: 15,
        maximumConcurrentCalls: maximumConcurrentCalls,
        toolCallRecorder: NoopMCPProxyToolCallRecorder()
    )
    let connection = try await connectMCPProxy(proxy, clientName: "MCP concurrent cap")
    return ConcurrentCallFixture(
        bin: bin,
        root: root,
        arrival: arrival,
        proxy: proxy,
        connection: connection
    )
}
