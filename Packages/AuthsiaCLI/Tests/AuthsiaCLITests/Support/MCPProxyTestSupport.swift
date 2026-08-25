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
            name = ((request.get("params") or {}).get("name")) or ""
            if arrival:
                with open(arrival, "a") as handle:
                    handle.write("%s %.6f\n" % (name, time.time()))
            if name == "slow":
                time.sleep(0.4)
            return {
                "jsonrpc": "2.0",
                "id": ident,
                "result": {
                    "content": [{"type": "text", "text": name}],
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
    var environment: [String: String]
    var secrets: [String]
    var error: (any Error)?
    var delayNanoseconds: UInt64

    init(
        environment: [String: String] = ["JIRA_URL": "https://example.atlassian.net"],
        secrets: [String] = [],
        error: (any Error)? = nil,
        delayNanoseconds: UInt64 = 0
    ) {
        self.environment = environment
        self.secrets = secrets
        self.error = error
        self.delayNanoseconds = delayNanoseconds
    }

    func prepareChildEnvironment(
        declared: [String: String],
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL
    ) throws -> (environment: [String: String], secrets: [String]) {
        lock.lock()
        prepareCount += 1
        contexts.append(agentRuntimeContext)
        let error = self.error
        var environment = declared.merging(self.environment) { _, override in override }
        environment["PYTHONUNBUFFERED"] = "1"
        let secrets = self.secrets
        let delay = delayNanoseconds
        lock.unlock()
        if delay > 0 {
            Thread.sleep(forTimeInterval: Double(delay) / 1_000_000_000)
        }
        if let error {
            throw error
        }
        _ = workspaceRoot
        return (environment, secrets)
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

func waitForMCPProxyTestFile(_ url: URL, timeoutSeconds: Double = 5) -> String {
    let deadline = Date().addingTimeInterval(timeoutSeconds)
    while Date() < deadline {
        if let contents = try? String(contentsOf: url, encoding: .utf8),
           !contents.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
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
    var allowedSessionID: String?
    var secretValue = "synthetic-token"

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
        _ = payload
        _ = agentRuntimeContext
        _ = workspaceRoot
        return AgentJITPreflightResultPayload(grantIDs: [UUID()])
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
