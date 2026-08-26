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

    @Test("SDK Client multiplexes overlapping tools/call against the in-repo stdio double")
    func sdkClientSpikeAgainstStdioDouble() async throws {
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
        let connection = try await connectMCPProxy(proxy, clientName: "MCP sdk spike")
        let slow: RequestContext<CallTool.Result> = try await connection.client.callTool(name: "slow")
        let fast: RequestContext<CallTool.Result> = try await connection.client.callTool(name: "fast")
        let fastResult = try await fast.value
        let slowResult = try await slow.value
        #expect(fastResult.isError != true)
        #expect(slowResult.isError != true)

        let log = try String(contentsOf: arrival, encoding: .utf8)
        let lines = log.split(whereSeparator: \.isNewline)
        #expect(lines.contains { $0.hasPrefix("slow ") })
        #expect(lines.contains { $0.hasPrefix("fast ") })
        let arrivals = lines.compactMap { line -> (String, Double)? in
            let parts = line.split(separator: " ")
            guard parts.count == 2, let time = Double(parts[1]) else { return nil }
            return (String(parts[0]), time)
        }
        if let slowTime = arrivals.first(where: { $0.0 == "slow" })?.1,
           let fastTime = arrivals.first(where: { $0.0 == "fast" })?.1 {
            #expect(abs(fastTime - slowTime) < 0.4)
        }

        await connection.client.disconnect()
        await proxy.waitUntilCompleted()
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
}
