import Darwin
import Dispatch
import Foundation
import AuthenticatorBridge
import MCP

#if canImport(System)
import System
#endif

actor AuthsiaMCPProxy {
    private let server: Server
    private let proxyVersion: String
    private let upstreamName: String
    private let runtimeContext: MCPRuntimeContext
    private let acceptsToolWorkspace: Bool
    private let mcpAccessEnabled: @Sendable () -> Bool
    private let sessionClient: any MCPProxySessionClient
    private let childLauncher: any MCPProxyChildLaunching
    private let parentEnvironment: [String: String]
    private let initializeTimeoutSeconds: Double
    private let killGraceSeconds: Double
    private let grantService: MCPGrantService
    private var handlersRegistered = false
    private var childSession: ChildSession?
    private var spawnTask: Task<ChildSession, Error>?

    init(
        version: String,
        upstreamName: String,
        runtimeContext: MCPRuntimeContext,
        acceptsToolWorkspace: Bool,
        mcpAccessEnabled: @escaping @Sendable () -> Bool,
        sessionClient: (any MCPProxySessionClient)? = nil,
        childLauncher: (any MCPProxyChildLaunching)? = nil,
        parentEnvironment: [String: String] = ProcessInfo.processInfo.environment,
        initializeTimeoutSeconds: Double = 30,
        killGraceSeconds: Double = 2,
        grantService: MCPGrantService? = nil
    ) {
        self.server = Server(
            name: "authsia-mcp-proxy",
            version: version,
            title: "Authsia MCP Proxy",
            instructions: "Proxies the '\(upstreamName)' MCP upstream. Tools are filtered by workspace policy.",
            capabilities: .init(tools: .init(listChanged: false)),
            configuration: .strict
        )
        self.proxyVersion = version
        self.upstreamName = upstreamName
        self.runtimeContext = runtimeContext
        self.acceptsToolWorkspace = acceptsToolWorkspace
        self.mcpAccessEnabled = mcpAccessEnabled
        self.sessionClient = sessionClient ?? LiveMCPProxySessionClient()
        self.childLauncher = childLauncher ?? MCPProxyPosixLauncher()
        self.parentEnvironment = parentEnvironment
        self.initializeTimeoutSeconds = initializeTimeoutSeconds
        self.killGraceSeconds = killGraceSeconds
        self.grantService = grantService ?? MCPGrantService(
            serverInstanceID: runtimeContext.instanceID
        )
    }

    func start(transport: any Transport) async throws {
        await registerHandlersIfNeeded()
        try await server.start(transport: transport) { [runtimeContext] client, _ in
            await runtimeContext.updateClientInfo(name: client.name, version: client.version)
        }
    }

    func runStdio() async throws {
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)

        let interruptSource = shutdownSource(signal: SIGINT)
        let terminateSource = shutdownSource(signal: SIGTERM)
        interruptSource.resume()
        terminateSource.resume()

        try await start(transport: StdioTransport())
        await server.waitUntilCompleted()
        await stop()

        interruptSource.cancel()
        terminateSource.cancel()
    }

    func stop() async {
        await dropChild()
        grantService.revokeActiveOwnedGrants()
        await server.stop()
    }

    func waitUntilCompleted() async {
        await server.waitUntilCompleted()
        await dropChild()
    }

    private func registerHandlersIfNeeded() async {
        guard !handlersRegistered else { return }
        handlersRegistered = true

        await server.withMethodHandler(ListTools.self) { _ in
            let upstream = await self.stdioUpstream()
            return ListTools.Result(tools: MCPProxyCatalog.listedTools(for: upstream))
        }
        await server.withMethodHandler(CallTool.self) { parameters in
            try await self.callTool(parameters)
        }
    }

    private func callTool(_ parameters: CallTool.Parameters) async throws -> CallTool.Result {
        guard mcpAccessEnabled() else {
            return try Self.errorResult(
                code: .mcpAccessDisabled,
                message: "MCP integrations are disabled in Authsia. Enable them in Settings > Developer Access."
            )
        }
        switch boundPolicy() {
        case .unbound:
            return try Self.errorResult(
                code: .workspaceUnavailable,
                message: "The MCP proxy is not bound to a valid managed workspace."
            )
        case .missingUpstream:
            return try Self.errorResult(
                code: .upstreamUnavailable,
                message: "The named MCP upstream is not declared in this workspace."
            )
        case .httpUpstream:
            return try Self.errorResult(
                code: .httpUpstreamUnsupported,
                message: "HTTP MCP upstreams are not supported."
            )
        case .stdio(let upstream):
            let advertised = Set(MCPProxyCatalog.advertisedNames(in: upstream.tools))
            guard advertised.contains(parameters.name) else {
                return try Self.errorResult(
                    code: .upstreamDenied,
                    message: "This upstream tool is denied by workspace policy."
                )
            }
            do {
                let session = try await ensureChild(upstream: upstream, toolName: parameters.name)
                guard session.childToolNames.contains(parameters.name) else {
                    return try Self.errorResult(
                        code: .upstreamUnavailable,
                        message: "The upstream MCP server does not implement this tool."
                    )
                }
                return try await forward(parameters, using: session)
            } catch let error as MCPToolInputError {
                return try Self.errorResult(
                    code: .invalidInput,
                    message: error.localizedDescription
                )
            } catch let error as BridgeClientError {
                return try Self.errorResult(
                    code: MCPChildFailureReporter.code(for: error),
                    message: error.localizedDescription
                )
            } catch is MCPProxySpawnError {
                return try Self.errorResult(
                    code: .upstreamUnavailable,
                    message: "The upstream MCP server could not be started."
                )
            } catch is CancellationError {
                return try Self.errorResult(
                    code: .cancelled,
                    message: "The upstream tool call was cancelled."
                )
            } catch {
                return try Self.errorResult(
                    code: .upstreamUnavailable,
                    message: "The upstream MCP server is unavailable."
                )
            }
        }
    }

    private func forward(
        _ parameters: CallTool.Parameters,
        using session: ChildSession
    ) async throws -> CallTool.Result {
        let request: RequestContext<CallTool.Result> = try await session.client.callTool(
            name: parameters.name,
            arguments: parameters.arguments
        )
        return try await withTaskCancellationHandler {
            try await request.value
        } onCancel: {
            Task { try? await session.client.cancelRequest(request.requestID) }
        }
    }

    private func ensureChild(
        upstream: MCPUpstreamConfig,
        toolName: String
    ) async throws -> ChildSession {
        if let session = liveSession() {
            return session
        }
        if let spawnTask {
            let session = try await spawnTask.value
            if session.isAlive {
                return session
            }
        }
        let task = Task {
            try await self.spawnAndInitialize(upstream: upstream, toolName: toolName)
        }
        spawnTask = task
        do {
            let session = try await task.value
            spawnTask = nil
            return session
        } catch {
            spawnTask = nil
            throw error
        }
    }

    private func spawnAndInitialize(
        upstream: MCPUpstreamConfig,
        toolName: String
    ) async throws -> ChildSession {
        if let session = liveSession() {
            return session
        }
        guard let workspaceRoot = runtimeContext.workspaceRoot else {
            throw MCPRuntimeContextError.workspaceUnavailable
        }
        let command = upstream.command?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !command.isEmpty else {
            throw MCPProxySpawnError.commandNotFound
        }
        let invocationID = UUID()
        let agentRuntimeContext = await runtimeContext.makeProxyAgentRuntimeContext(
            upstreamName: upstreamName,
            invocationID: invocationID
        )
        let prepared = try sessionClient.prepareChildEnvironment(
            declared: upstream.env,
            agentRuntimeContext: agentRuntimeContext,
            workspaceRoot: workspaceRoot
        )
        let childEnvironment = MCPProxyChildEnvironment.make(
            parent: parentEnvironment,
            declared: prepared.environment
        )
        let executable = try MCPProxyCommandResolver.resolve(
            command: command,
            workspaceRoot: workspaceRoot,
            path: childEnvironment["PATH"] ?? ""
        )
        let spawned = try childLauncher.spawn(
            executable: executable,
            arguments: upstream.args,
            environment: childEnvironment,
            currentDirectory: workspaceRoot
        )
        MCPProxyStderrDrain.start(fileDescriptor: spawned.stderrRead)
        let terminator = MCPProcessTerminator(
            processID: spawned.processID,
            processGroupID: spawned.processGroupID,
            killGraceSeconds: killGraceSeconds
        )
        let transport = StdioTransport(
            input: FileDescriptor(rawValue: spawned.stdoutRead),
            output: FileDescriptor(rawValue: spawned.stdinWrite)
        )
        let client = Client(
            name: "authsia-mcp-proxy",
            version: proxyVersion,
            configuration: .default
        )
        do {
            try await withTimeout(initializeTimeoutSeconds) {
                _ = try await client.connect(transport: transport)
            }
        } catch {
            terminator.start()
            await terminator.waitUntilFinished()
            Darwin.close(spawned.stdinWrite)
            Darwin.close(spawned.stdoutRead)
            throw MCPProxySpawnError.launchFailed
        }
        let listed: Set<String>
        do {
            listed = try await withTimeout(initializeTimeoutSeconds) {
                let tools = try await client.listTools()
                return Set(tools.tools.map(\.name))
            }
        } catch {
            terminator.start()
            await client.disconnect()
            await terminator.waitUntilFinished()
            throw MCPProxySpawnError.launchFailed
        }
        let session = ChildSession(
            processID: spawned.processID,
            processGroupID: spawned.processGroupID,
            client: client,
            childToolNames: listed,
            terminator: terminator,
            stdinWrite: spawned.stdinWrite,
            stdoutRead: spawned.stdoutRead
        )
        childSession = session
        watchChild(session)
        _ = toolName
        return session
    }

    private func liveSession() -> ChildSession? {
        guard let childSession, childSession.isAlive else {
            if childSession != nil {
                childSession = nil
            }
            return nil
        }
        return childSession
    }

    private func watchChild(_ session: ChildSession) {
        let processID = session.processID
        Thread.detachNewThread { [weak self] in
            var status: Int32 = 0
            _ = waitpid(processID, &status, 0)
            Task { await self?.childDidExit(processID) }
        }
    }

    private func childDidExit(_ processID: pid_t) async {
        guard childSession?.processID == processID else { return }
        await dropChild(notifyClient: false)
    }

    private func dropChild(notifyClient: Bool = true) async {
        guard let session = childSession else { return }
        childSession = nil
        if notifyClient {
            await session.client.disconnect()
        }
        session.terminator.start()
        await session.terminator.waitUntilFinished()
        Darwin.close(session.stdinWrite)
        Darwin.close(session.stdoutRead)
    }

    private func stdioUpstream() -> MCPUpstreamConfig? {
        if case .stdio(let upstream) = boundPolicy() {
            return upstream
        }
        return nil
    }

    private func boundPolicy() -> BoundPolicy {
        guard let root = runtimeContext.workspaceRoot,
              let config = try? WorkspaceConfigStore.read(fromWorkspaceRoot: root) else {
            return .unbound
        }
        guard let upstream = config.mcpUpstreams.first(where: { $0.name == upstreamName }) else {
            return .missingUpstream
        }
        guard upstream.requiresStdioPolicy else {
            return .httpUpstream
        }
        return .stdio(upstream)
    }

    private static func errorResult(
        code: MCPToolErrorCode,
        message: String
    ) throws -> CallTool.Result {
        let output = MCPToolErrorOutput(code: code, message: message, invocationID: nil)
        return try CallTool.Result(
            content: [.text(text: message, annotations: nil, _meta: nil)],
            structuredContent: output,
            isError: true
        )
    }

    private func shutdownSource(signal signalNumber: Int32) -> DispatchSourceSignal {
        let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: .global())
        source.setEventHandler { [weak self] in
            Task { await self?.stop() }
        }
        return source
    }

    private func withTimeout<T: Sendable>(
        _ seconds: Double,
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask {
                try await operation()
            }
            group.addTask {
                let nanoseconds = UInt64(max(seconds, 0) * 1_000_000_000)
                try await Task.sleep(nanoseconds: nanoseconds)
                throw MCPProxySpawnError.launchFailed
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }
}

private struct ChildSession: Sendable {
    let processID: pid_t
    let processGroupID: pid_t
    let client: Client
    let childToolNames: Set<String>
    let terminator: MCPProcessTerminator
    let stdinWrite: Int32
    let stdoutRead: Int32

    var isAlive: Bool {
        Darwin.kill(processID, 0) == 0 || errno == EPERM
    }
}

private enum BoundPolicy {
    case unbound
    case missingUpstream
    case httpUpstream
    case stdio(MCPUpstreamConfig)
}
