import Darwin
import Foundation
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
            acceptsToolWorkspace: true,
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
            initializeTimeoutSeconds: 15
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
            acceptsToolWorkspace: true,
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            parentEnvironment: ["PATH": "/usr/bin:/bin"],
            initializeTimeoutSeconds: 15
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
            acceptsToolWorkspace: true,
            mcpAccessEnabled: { true },
            sessionClient: sessionClient,
            parentEnvironment: ["PATH": "\(bin.path):/usr/bin:/bin"],
            initializeTimeoutSeconds: 15
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
}
