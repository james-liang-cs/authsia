import AuthenticatorBridge
import Foundation
import MCP
@testable import authsia

func mcpProxyStdioScript() -> String {
    #"""
    import json, os, sys, threading, time

    dump = os.environ.get("AUTHSIA_TEST_DUMP")
    if dump:
        with open(dump, "w") as handle:
            json.dump(dict(os.environ), handle)

    pgid_path = os.environ.get("AUTHSIA_TEST_PGID")
    if pgid_path:
        with open(pgid_path, "w") as handle:
            handle.write("%s %s" % (os.getpid(), os.getpgrp()))

    sigterm_path = os.environ.get("AUTHSIA_TEST_SIGTERM")
    if sigterm_path:
        import signal
        handler = signal.getsignal(signal.SIGTERM)
        with open(sigterm_path, "w") as handle:
            handle.write("DEFAULT" if handler == signal.SIG_DFL else "other")

    extra_fd = os.environ.get("AUTHSIA_TEST_PARENT_FD")
    extra_path = os.environ.get("AUTHSIA_TEST_PARENT_FD_RESULT")
    if extra_fd and extra_path:
        try:
            os.fstat(int(extra_fd))
            inherited = "inherited"
        except OSError:
            inherited = "closed"
        with open(extra_path, "w") as handle:
            handle.write(inherited)

    stderr_text = os.environ.get("AUTHSIA_TEST_STDERR")
    if stderr_text:
        sys.stderr.write(os.path.expandvars(stderr_text) + "\n")
        sys.stderr.flush()

    caught_path = os.environ.get("AUTHSIA_TEST_SIGTERM_CAUGHT")
    if caught_path:
        import signal

        def record_sigterm(signum, frame):
            with open(caught_path, "w") as handle:
                handle.write("SIGTERM")
            os._exit(0)

        signal.signal(signal.SIGTERM, record_sigterm)

    if os.environ.get("AUTHSIA_TEST_HANG"):
        time.sleep(3)
        raise SystemExit(0)

    arrival = os.environ.get("AUTHSIA_TEST_ARRIVAL")
    tools = [
        name for name in os.environ.get(
            "AUTHSIA_TEST_TOOLS",
            "jira_get_issue,jira_search,jira_create_issue",
        ).split(",")
        if name
    ]

    def send(message):
        sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
        sys.stdout.flush()

    def handle(request):
        method = request.get("method")
        ident = request.get("id")
        if method == "initialize":
            version = (request.get("params") or {}).get("protocolVersion") or "2025-11-25"
            return {
                "jsonrpc": "2.0",
                "id": ident,
                "result": {
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "fixture", "version": "1"},
                },
            }
        if method in ("notifications/initialized", "notifications/cancelled"):
            return None
        if method == "ping":
            return {"jsonrpc": "2.0", "id": ident, "result": {}}
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": ident,
                "result": {
                    "tools": [
                        {
                            "name": name,
                            "description": "",
                            "inputSchema": {"type": "object", "additionalProperties": True},
                        }
                        for name in tools
                    ]
                },
            }
        if method == "tools/call":
            params = request.get("params") or {}
            name = params.get("name") or ""
            if arrival:
                with open(arrival, "a") as handle:
                    handle.write("%s %.6f\n" % (name, time.time()))
            if name == "slow":
                time.sleep(0.4)
            text = name
            if os.environ.get("AUTHSIA_TEST_ECHO_ARGUMENTS"):
                text += " request=" + json.dumps(
                    params.get("arguments") or {},
                    separators=(",", ":"),
                    sort_keys=True,
                )
            result_secret = os.environ.get("AUTHSIA_TEST_RESULT_SECRET")
            if result_secret:
                text += " result=" + result_secret
            return {
                "jsonrpc": "2.0",
                "id": ident,
                "result": {
                    "content": [{"type": "text", "text": text}],
                    "isError": False,
                },
            }
        return {
            "jsonrpc": "2.0",
            "id": ident,
            "error": {"code": -32601, "message": "Method not found"},
        }

    def process_line(line):
        response = handle(json.loads(line))
        if response is not None:
            send(response)

    for line in sys.stdin:
        threading.Thread(target=process_line, args=(line,), daemon=True).start()
    """#
}

func writeExecutableMCPProxyScript(
    at url: URL,
    fileManager: FileManager = .default
) throws {
    try fileManager.createDirectory(
        at: url.deletingLastPathComponent(),
        withIntermediateDirectories: true
    )
    let contents = "#!/usr/bin/python3\n" + mcpProxyStdioScript()
    try contents.write(to: url, atomically: true, encoding: .utf8)
    try fileManager.setAttributes(
        [.posixPermissions: 0o755],
        ofItemAtPath: url.path
    )
}

func makeMCPProxyWorkspace(
    upstreams: [MCPUpstreamConfig]
) throws -> URL {
    let root = try makeWorkspaceRoot()
    try WorkspaceConfigStore.write(
        WorkspaceConfig(
            schemaVersion: 2,
            workspace: .init(name: "proxy", authsiaFolder: "Workspaces/proxy"),
            managedEnvFiles: [],
            agents: nil,
            mcpUpstreams: upstreams
        ),
        toWorkspaceRoot: root
    )
    return root
}

func stdioJiraUpstream(
    command: String = "mcp-atlassian",
    args: [String] = [],
    env: [String: String] = [
        "JIRA_API_TOKEN": "authsia://api-key/Atlassian/key?folder=Workspaces%2Fproxy",
        "JIRA_URL": "https://example.atlassian.net",
    ],
    allow: [String] = ["jira_get_issue", "jira_search"],
    approve: [String] = ["jira_create_issue"],
    deny: [String] = ["jira_delete_issue"]
) -> MCPUpstreamConfig {
    MCPUpstreamConfig(
        name: "jira",
        command: command,
        args: args,
        env: env,
        tools: MCPUpstreamToolPolicy(allow: allow, approve: approve, deny: deny),
        catalog: [
            MCPUpstreamToolDescriptor(
                name: "jira_get_issue",
                description: "Get one Jira issue by key"
            )
        ]
    )
}

final class RecordingMCPProxySessionClient: MCPProxySessionClient, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var prepareCount = 0
    private(set) var contexts: [AgentRuntimeContext] = []
    private(set) var mcpUpstreamNames: [String?] = []
    private(set) var mcpUpstreamCommands: [String?] = []
    private(set) var mcpToolNames: [String?] = []
    private(set) var mcpToolPolicies: [AgentJITMCPToolPolicy?] = []
    var environment: [String: String]
    var secrets: [String]
    var grantIDs: [UUID]
    var error: (any Error)?
    var delayNanoseconds: UInt64

    init(
        environment: [String: String] = ["JIRA_URL": "https://example.atlassian.net"],
        secrets: [String] = [],
        grantIDs: [UUID] = [],
        error: (any Error)? = nil,
        delayNanoseconds: UInt64 = 0
    ) {
        self.environment = environment
        self.secrets = secrets
        self.grantIDs = grantIDs
        self.error = error
        self.delayNanoseconds = delayNanoseconds
    }

    func prepareChildEnvironment(
        declared: [String: String],
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL,
        mcpUpstreamName: String?,
        mcpUpstreamCommand: String?,
        mcpToolName: String?,
        mcpToolPolicy: AgentJITMCPToolPolicy?
    ) throws -> (environment: [String: String], secrets: [String], grantIDs: [UUID]) {
        lock.lock()
        prepareCount += 1
        contexts.append(agentRuntimeContext)
        mcpUpstreamNames.append(mcpUpstreamName)
        mcpUpstreamCommands.append(mcpUpstreamCommand)
        mcpToolNames.append(mcpToolName)
        mcpToolPolicies.append(mcpToolPolicy)
        let error = self.error
        var environment = declared.merging(self.environment) { _, override in override }
        environment["PYTHONUNBUFFERED"] = "1"
        let secrets = self.secrets
        let grantIDs = self.grantIDs
        let delay = delayNanoseconds
        lock.unlock()
        if delay > 0 {
            Thread.sleep(forTimeInterval: Double(delay) / 1_000_000_000)
        }
        if let error {
            throw error
        }
        _ = workspaceRoot
        return (environment, secrets, grantIDs)
    }
}

final class RecordingMCPProxyChildLauncher: MCPProxyChildLaunching, @unchecked Sendable {
    private let lock = NSLock()
    private let inner: any MCPProxyChildLaunching
    private(set) var spawnCount = 0
    private(set) var environments: [[String: String]] = []
    private(set) var lastSpawned: MCPProxySpawnedChild?

    init(inner: any MCPProxyChildLaunching = MCPProxyPosixLauncher()) {
        self.inner = inner
    }

    func spawn(
        executable: URL,
        arguments: [String],
        environment: [String: String],
        currentDirectory: URL
    ) throws -> MCPProxySpawnedChild {
        lock.lock()
        spawnCount += 1
        environments.append(environment)
        lock.unlock()
        let spawned = try inner.spawn(
            executable: executable,
            arguments: arguments,
            environment: environment,
            currentDirectory: currentDirectory
        )
        lock.lock()
        lastSpawned = spawned
        lock.unlock()
        return spawned
    }
}

func connectMCPProxy(_ proxy: AuthsiaMCPProxy, clientName: String) async throws -> (
    client: Client,
    serverTransport: InMemoryTransport
) {
    let transports = await InMemoryTransport.createConnectedPair()
    let client = Client(name: clientName, version: "1")
    try await proxy.start(transport: transports.server)
    _ = try await client.connect(transport: transports.client)
    return (client, transports.server)
}

func toolErrorCode(_ result: CallTool.Result) -> String? {
    result.structuredContent?.objectValue?["code"]?.stringValue
}

func toolErrorInvocationID(_ result: CallTool.Result) -> String? {
    result.structuredContent?.objectValue?["invocationID"]?.stringValue
}

func waitForMCPProxyTestFile(
    _ url: URL,
    minimumLineCount: Int = 1,
    timeoutSeconds: Double = 5
) -> String {
    let deadline = Date().addingTimeInterval(timeoutSeconds)
    while Date() < deadline {
        if let contents = try? String(contentsOf: url, encoding: .utf8),
           contents.split(whereSeparator: \.isNewline).count >= minimumLineCount {
            return contents.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        Thread.sleep(forTimeInterval: 0.02)
    }
    return (try? String(contentsOf: url, encoding: .utf8)) ?? ""
}

final class RecordingMCPProxyBridgeSession: MCPProxyBridgeSession, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var requestedCommands: [String] = []
    private(set) var resolveContexts: [AgentRuntimeContext] = []
    private(set) var payloads: [AgentJITPreflightPayload] = []
    var allowedSessionID: String?
    var secretValue = "synthetic-token"
    var preflightGrantIDs = [UUID()]

    func withRequestedCommand<R>(
        _ command: String,
        includeAutomationCredential: Bool,
        _ body: () throws -> R
    ) rethrows -> R {
        lock.lock()
        requestedCommands.append(command)
        lock.unlock()
        _ = includeAutomationCredential
        return try body()
    }

    func agentJITPreflight(
        _ payload: AgentJITPreflightPayload,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?
    ) throws -> AgentJITPreflightResultPayload {
        lock.lock()
        payloads.append(payload)
        lock.unlock()
        _ = agentRuntimeContext
        _ = workspaceRoot
        return AgentJITPreflightResultPayload(grantIDs: preflightGrantIDs)
    }

    func resolveSecret(
        type: SecretReference.ItemType,
        query: String,
        field: String,
        folder: String?,
        isFolderScoped: Bool,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL
    ) throws -> String {
        _ = type
        _ = query
        _ = field
        _ = folder
        _ = isFolderScoped
        _ = workspaceRoot
        lock.lock()
        resolveContexts.append(agentRuntimeContext)
        let allowed = allowedSessionID
        let secret = secretValue
        lock.unlock()
        if let allowed, allowed != agentRuntimeContext.sessionID {
            throw BridgeClientError.bridgeError(
                code: "notAuthorized",
                message: "Access denied. Approval was not granted in the Authsia app.",
                query: query
            )
        }
        return secret
    }
}

final class RecordingMCPProxyToolCallRecorder: MCPProxyToolCallRecording, @unchecked Sendable {
    struct Call: Equatable {
        let upstreamName: String
        let upstreamCommand: String?
        let toolName: String
        let agentRuntimeContext: AgentRuntimeContext
        let workspaceRoot: URL?
        let grantID: UUID?
    }

    struct Outcome: Equatable {
        let toolName: String
        let outcome: MCPProxyCallOutcome
        let grantID: UUID?
    }

    private let lock = NSLock()
    private(set) var calls: [Call] = []
    private(set) var outcomes: [Outcome] = []
    var error: (any Error)?
    var remainingOutcomeFailures = 0

    func record(
        upstreamName: String,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?,
        grantID: UUID?
    ) throws {
        try lock.withLock {
            if let error { throw error }
            calls.append(Call(
                upstreamName: upstreamName,
                upstreamCommand: upstreamCommand,
                toolName: toolName,
                agentRuntimeContext: agentRuntimeContext,
                workspaceRoot: workspaceRoot,
                grantID: grantID
            ))
        }
    }

    func recordRejected(
        upstreamName: String,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?,
        grantID: UUID?,
        outcome: MCPProxyCallOutcome
    ) throws {
        try lock.withLock {
            if let error { throw error }
            outcomes.append(Outcome(toolName: toolName, outcome: outcome, grantID: grantID))
        }
        _ = (upstreamName, upstreamCommand, agentRuntimeContext, workspaceRoot)
    }

    func recordOutcome(
        upstreamName: String,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?,
        grantID: UUID?,
        outcome: MCPProxyCallOutcome
    ) throws {
        try lock.withLock {
            if remainingOutcomeFailures > 0 {
                remainingOutcomeFailures -= 1
                if let error { throw error }
                throw RecordingMCPProxyOutcomeError.failed
            }
            if let error { throw error }
            outcomes.append(Outcome(toolName: toolName, outcome: outcome, grantID: grantID))
        }
        _ = (upstreamName, upstreamCommand, agentRuntimeContext, workspaceRoot)
    }
}

private enum RecordingMCPProxyOutcomeError: Error {
    case failed
}

struct NoopMCPProxyToolCallRecorder: MCPProxyToolCallRecording {
    func record(
        upstreamName: String,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?,
        grantID: UUID?
    ) throws {
        _ = (upstreamName, upstreamCommand, toolName, agentRuntimeContext, workspaceRoot, grantID)
    }
}

final class MutableMCPProxyGrantClient: MCPGrantClient, @unchecked Sendable {
    private let lock = NSLock()
    private var snapshot: AgentJITGrantSnapshotPayload
    private var storedRevokedIDs: [UUID] = []

    init(snapshot: AgentJITGrantSnapshotPayload) {
        self.snapshot = snapshot
    }

    var revokedIDs: [UUID] {
        lock.withLock { storedRevokedIDs }
    }

    func setSnapshot(_ snapshot: AgentJITGrantSnapshotPayload) {
        lock.withLock { self.snapshot = snapshot }
    }

    func agentJITSnapshot(
        agentRuntimeContext: AgentRuntimeContext
    ) throws -> AgentJITGrantSnapshotPayload {
        _ = agentRuntimeContext
        return lock.withLock { snapshot }
    }

    func revokeAgentJITGrant(
        id: UUID,
        agentRuntimeContext: AgentRuntimeContext
    ) throws -> AgentJITGrantMutationPayload {
        _ = agentRuntimeContext
        lock.withLock { storedRevokedIDs.append(id) }
        return AgentJITGrantMutationPayload(revokedGrantIDs: [id])
    }
}

func mcpProxyGrant(
    id: UUID,
    serverID: UUID,
    revokedAt: Date? = nil
) -> AgentJITGrant {
    AgentJITGrant(
        id: id,
        agentName: "Codex",
        callerFingerprint: AgentJITCallerFingerprint(
            processName: "authsia",
            bundleIdentifier: "app.authsia.cli",
            signingTeamId: "TEAM",
            signingIdentity: "Developer ID",
            parentProcessName: "Codex",
            parentBundleIdentifier: "com.openai.codex",
            sessionScope: nil,
            workingDirectory: "/tmp/project"
        ),
        folderScope: .folder("Team/API"),
        capabilities: [.exec],
        createdAt: Date(timeIntervalSince1970: 1_700_000_000),
        expiresAt: Date.distantFuture,
        revokedAt: revokedAt,
        lastUsedAt: nil,
        requestedItems: [],
        agentRuntimeContext: AgentRuntimeContext(
            platform: "Codex",
            sessionID: "mcp:\(serverID.uuidString)",
            turnID: "mcp-call:test",
            agentType: "authsia-mcp",
            toolUseID: "mcp-call:test"
        ),
        approvedBy: "mac-panel",
        environmentScope: nil
    )
}

func mcpProxyProcessGroupIsAlive(_ processGroupID: pid_t) -> Bool {
    Darwin.kill(-processGroupID, 0) == 0 || errno == EPERM
}

func waitForMCPProxyProcessGroupExit(
    _ processGroupID: pid_t,
    timeoutSeconds: Double = 2
) -> Bool {
    let deadline = Date().addingTimeInterval(timeoutSeconds)
    while Date() < deadline {
        if !mcpProxyProcessGroupIsAlive(processGroupID) {
            return true
        }
        Thread.sleep(forTimeInterval: 0.02)
    }
    return !mcpProxyProcessGroupIsAlive(processGroupID)
}
