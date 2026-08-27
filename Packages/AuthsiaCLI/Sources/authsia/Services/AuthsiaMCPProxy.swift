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
    private let mcpAccessEnabled: @Sendable () -> Bool
    private let sessionClient: any MCPProxySessionClient
    private let childLauncher: any MCPProxyChildLaunching
    private let parentEnvironment: [String: String]
    private let initializeTimeoutSeconds: Double
    private let killGraceSeconds: Double
    private let grantPollIntervalSeconds: Double
    private let grantService: MCPGrantService
    private let toolCallRecorder: any MCPProxyToolCallRecording
    private let stderrOutput: FileHandle
    private var handlersRegistered = false
    private var childSession: ChildSession?
    private var spawnTask: Task<ChildSession, Error>?
    private var inFlight: InFlightSpawn?
    private var grantWatchTask: Task<Void, Never>?
    private var isStopped = false
    private var discoveredChildTools: [Tool]?
    private var discoveryTask: Task<[Tool]?, Never>?

    init(
        version: String,
        upstreamName: String,
        runtimeContext: MCPRuntimeContext,
        mcpAccessEnabled: @escaping @Sendable () -> Bool,
        sessionClient: (any MCPProxySessionClient)? = nil,
        childLauncher: (any MCPProxyChildLaunching)? = nil,
        parentEnvironment: [String: String] = ProcessInfo.processInfo.environment,
        initializeTimeoutSeconds: Double = 30,
        killGraceSeconds: Double = 2,
        grantPollIntervalSeconds: Double = 2,
        grantService: MCPGrantService? = nil,
        toolCallRecorder: (any MCPProxyToolCallRecording)? = nil,
        stderrOutput: FileHandle = .standardError
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
        self.mcpAccessEnabled = mcpAccessEnabled
        self.sessionClient = sessionClient ?? LiveMCPProxySessionClient()
        self.childLauncher = childLauncher ?? MCPProxyPosixLauncher()
        self.parentEnvironment = parentEnvironment
        self.initializeTimeoutSeconds = initializeTimeoutSeconds
        self.killGraceSeconds = killGraceSeconds
        self.grantPollIntervalSeconds = grantPollIntervalSeconds
        self.grantService = grantService ?? MCPGrantService(
            serverInstanceID: runtimeContext.instanceID
        )
        self.toolCallRecorder = toolCallRecorder ?? LiveMCPProxyToolCallRecorder()
        self.stderrOutput = stderrOutput
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
        await shutdownChild()
        grantService.revokeActiveOwnedGrants()
        await server.stop()
    }

    func waitUntilCompleted() async {
        await server.waitUntilCompleted()
        await shutdownChild()
    }

    private func shutdownChild() async {
        isStopped = true
        grantWatchTask?.cancel()
        grantWatchTask = nil
        let task = spawnTask
        task?.cancel()
        await dropChild()
        await consumeInFlight()
        if let task {
            _ = try? await task.value
        }
        spawnTask = nil
    }

    private func registerHandlersIfNeeded() async {
        guard !handlersRegistered else { return }
        handlersRegistered = true

        await server.withMethodHandler(ListTools.self) { _ in
            ListTools.Result(tools: await self.listedTools())
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
            let advertised = await advertisedNames(for: upstream)
            guard advertised.contains(parameters.name) else {
                return try Self.errorResult(
                    code: .upstreamDenied,
                    message: "This upstream tool is denied by workspace policy."
                )
            }
            do {
                let invocationID = UUID()
                let agentRuntimeContext = await runtimeContext.makeProxyAgentRuntimeContext(
                    upstreamName: upstreamName,
                    invocationID: invocationID
                )
                let session = try await ensureChild(
                    upstream: upstream,
                    toolName: parameters.name,
                    agentRuntimeContext: agentRuntimeContext
                )
                guard session.childToolNames.contains(parameters.name) else {
                    return try Self.errorResult(
                        code: .upstreamUnavailable,
                        message: "The upstream MCP server does not implement this tool."
                    )
                }
                try toolCallRecorder.record(
                    upstreamName: upstreamName,
                    upstreamCommand: upstream.command,
                    toolName: parameters.name,
                    agentRuntimeContext: agentRuntimeContext,
                    workspaceRoot: runtimeContext.workspaceRoot,
                    grantID: session.grantIDs.sorted { $0.uuidString < $1.uuidString }.first
                )
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
            } catch MCPProxySpawnError.grantUnavailable {
                return try Self.errorResult(
                    code: .grantUnavailable,
                    message: "No revocable Authsia grant covers this upstream's secret references."
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
        let masker = MCPProxyJSONMasker(secrets: session.secrets)
        let maskedParameters: CallTool.Parameters = try masker.mask(parameters)
        let request: RequestContext<CallTool.Result> = try await session.client.callTool(
            name: maskedParameters.name,
            arguments: maskedParameters.arguments
        )
        return try await withTaskCancellationHandler {
            let result = try await request.value
            return try masker.mask(result)
        } onCancel: {
            Task { try? await session.client.cancelRequest(request.requestID) }
        }
    }

    private func ensureChild(
        upstream: MCPUpstreamConfig,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext
    ) async throws -> ChildSession {
        if let session = await liveSession() {
            return session
        }
        if let spawnTask {
            do {
                let session = try await spawnTask.value
                if let live = await liveSession() {
                    return live
                }
                if session.isAlive {
                    return session
                }
                await dropChild()
            } catch {
                throw error
            }
        }
        if isStopped {
            throw CancellationError()
        }
        let task = Task {
            try await self.spawnAndInitialize(
                upstream: upstream,
                toolName: toolName,
                agentRuntimeContext: agentRuntimeContext
            )
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
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext
    ) async throws -> ChildSession {
        if let session = await liveSession() {
            return session
        }
        try Task.checkCancellation()
        guard !isStopped else { throw CancellationError() }
        guard let workspaceRoot = runtimeContext.workspaceRoot else {
            throw MCPRuntimeContextError.workspaceUnavailable
        }
        let command = upstream.command?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !command.isEmpty else {
            throw MCPProxySpawnError.commandNotFound
        }
        let declaredEnv = upstream.env
        let sessionClient = self.sessionClient
        let upstreamName = self.upstreamName
        let commandLabel = Self.commandLabel(for: upstream)
        let mcpToolPolicy: AgentJITMCPToolPolicy?
        if upstream.tools.approve.contains(toolName) {
            mcpToolPolicy = .approve
        } else if upstream.tools.allow.contains(toolName) {
            mcpToolPolicy = .allow
        } else {
            mcpToolPolicy = nil
        }
        let prepared = try await Task.detached {
            try sessionClient.prepareChildEnvironment(
                declared: declaredEnv,
                agentRuntimeContext: agentRuntimeContext,
                workspaceRoot: workspaceRoot,
                mcpUpstreamName: upstreamName,
                mcpUpstreamCommand: commandLabel,
                mcpToolName: toolName,
                mcpToolPolicy: mcpToolPolicy
            )
        }.value
        try Task.checkCancellation()
        guard !isStopped else { throw CancellationError() }
        // Revocation is the only thing that stops a long-lived child, and it
        // works by watching owned grant IDs. Injected secrets with no grant to
        // watch would be unrevokable, so refuse instead of spawning.
        guard prepared.secrets.isEmpty || !prepared.grantIDs.isEmpty else {
            throw MCPProxySpawnError.grantUnavailable
        }
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
        MCPProxyStderrDrain.start(
            fileDescriptor: spawned.stderrRead,
            secrets: prepared.secrets,
            output: stderrOutput
        )
        let terminator = MCPProcessTerminator(
            processID: spawned.processID,
            processGroupID: spawned.processGroupID,
            killGraceSeconds: killGraceSeconds
        )
        let client = Client(
            name: "authsia-mcp-proxy",
            version: proxyVersion,
            configuration: .default
        )
        inFlight = InFlightSpawn(
            terminator: terminator,
            stdinWrite: spawned.stdinWrite,
            stdoutRead: spawned.stdoutRead,
            client: client
        )
        if isStopped || Task.isCancelled {
            await consumeInFlight()
            throw CancellationError()
        }
        let transport = StdioTransport(
            input: FileDescriptor(rawValue: spawned.stdoutRead),
            output: FileDescriptor(rawValue: spawned.stdinWrite)
        )
        let timeout = initializeTimeoutSeconds
        do {
            let listed = try await mcpProxyWithTimeout(timeout) {
                _ = try await client.connect(transport: transport)
                let tools = try await client.listTools()
                return Set(tools.tools.map(\.name))
            }
            try Task.checkCancellation()
            guard !isStopped else {
                await consumeInFlight()
                throw CancellationError()
            }
            let session = ChildSession(
                processID: spawned.processID,
                client: client,
                childToolNames: listed,
                secrets: prepared.secrets,
                grantIDs: Set(prepared.grantIDs),
                terminator: terminator,
                stdinWrite: spawned.stdinWrite,
                stdoutRead: spawned.stdoutRead
            )
            childSession = session
            inFlight = nil
            watchChild(session)
            watchGrants(session)
            return session
        } catch {
            await consumeInFlight()
            throw MCPProxySpawnError.launchFailed
        }
    }

    private func liveSession() async -> ChildSession? {
        guard let session = childSession else { return nil }
        guard session.isAlive else {
            await dropChild()
            return nil
        }
        guard associatedGrantsRemainActive(for: session) else {
            await dropChild(processID: session.processID)
            return nil
        }
        return session
    }

    private func associatedGrantsRemainActive(for session: ChildSession) -> Bool {
        guard !session.grantIDs.isEmpty else { return true }
        guard let active = try? grantService.activeOwnedGrantIDs() else { return false }
        return session.grantIDs.isSubset(of: active)
    }

    private func watchGrants(_ session: ChildSession) {
        guard !session.grantIDs.isEmpty else { return }
        grantWatchTask?.cancel()
        let processID = session.processID
        let interval = max(grantPollIntervalSeconds, 0.01)
        grantWatchTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(interval))
                guard !Task.isCancelled, let self else { return }
                guard await self.childSession?.processID == processID else { return }
                guard await self.associatedGrantsRemainActive(for: session) else {
                    await self.dropChild(processID: processID)
                    return
                }
            }
        }
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
        await dropChild()
    }

    private func dropChild(processID: pid_t? = nil) async {
        guard let session = childSession,
              processID == nil || processID == session.processID else { return }
        childSession = nil
        grantWatchTask?.cancel()
        grantWatchTask = nil
        await teardownSpawn(
            client: session.client,
            terminator: session.terminator,
            stdinWrite: session.stdinWrite,
            stdoutRead: session.stdoutRead
        )
    }

    private func consumeInFlight() async {
        guard let inFlight else { return }
        self.inFlight = nil
        await teardownSpawn(
            client: inFlight.client,
            terminator: inFlight.terminator,
            stdinWrite: inFlight.stdinWrite,
            stdoutRead: inFlight.stdoutRead
        )
    }

    private func teardownSpawn(
        client: Client?,
        terminator: MCPProcessTerminator,
        stdinWrite: Int32,
        stdoutRead: Int32
    ) async {
        // The terminator owns the whole escalation: SIGTERM to the group, a
        // grace window, then SIGKILL. It also checks the group still exists
        // before signalling, so a reaped leader whose pid has been recycled is
        // never signalled here.
        terminator.start()
        await terminator.waitUntilFinished()
        if let client {
            await client.disconnect()
        }
        Darwin.close(stdinWrite)
        Darwin.close(stdoutRead)
    }

    private func listedTools() async -> [Tool] {
        let upstream = stdioUpstream()
        let policyTools = MCPProxyCatalog.listedTools(for: upstream)
        if !policyTools.isEmpty {
            return policyTools
        }
        guard let upstream,
              MCPProxyCatalog.shouldDiscoverChildCatalog(upstream),
              mcpAccessEnabled() else {
            return []
        }
        return await discoveredTools(for: upstream)
    }

    private func advertisedNames(for upstream: MCPUpstreamConfig) async -> Set<String> {
        let names = MCPProxyCatalog.advertisedNames(in: upstream.tools)
        if !names.isEmpty {
            return Set(names)
        }
        guard MCPProxyCatalog.shouldDiscoverChildCatalog(upstream) else {
            return []
        }
        return Set((await discoveredTools(for: upstream)).map(\.name))
    }

    private func discoveredTools(for upstream: MCPUpstreamConfig) async -> [Tool] {
        if let discoveredChildTools {
            return discoveredChildTools
        }
        // Probing suspends, so a concurrent list or call must join the in-flight
        // probe. Publishing the cache before it finished would answer those with
        // an empty catalog and fail their calls as policy-denied.
        if let discoveryTask {
            return await discoveryTask.value ?? []
        }
        let task = Task { await self.probeChildCatalog(upstream) }
        discoveryTask = task
        let discovered = await task.value
        discoveryTask = nil
        // A transient probe failure caches nothing so a later list retries. A
        // declined admission and a genuinely empty child both cache.
        if let discovered {
            discoveredChildTools = discovered
        }
        return discovered ?? []
    }

    private func probeChildCatalog(_ upstream: MCPUpstreamConfig) async -> [Tool]? {
        guard !isStopped, let workspaceRoot = runtimeContext.workspaceRoot else { return nil }
        let command = upstream.command?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !command.isEmpty else { return [] }
        // Discovery starts the declared child, so it takes the same admission
        // grant the long-lived spawn takes. The Bridge reuses that grant for
        // this caller, workspace, upstream, and server instance, so the first
        // tools/call after a discovered list does not prompt a second time.
        do {
            try await admitCatalogDiscovery(upstream: upstream, workspaceRoot: workspaceRoot)
        } catch {
            // A denial is a decision, not a transient fault: cache it so a
            // client that lists repeatedly cannot re-prompt on every list.
            let denied = BridgeClientError.isApprovalDenied(error)
                || error is MCPProxySpawnError
            return denied ? [] : nil
        }
        guard !isStopped else { return nil }
        let childEnvironment = MCPProxyChildEnvironment.make(
            parent: parentEnvironment,
            declared: upstream.env
        )
        let executable: URL
        let spawned: MCPProxySpawnedChild
        do {
            executable = try MCPProxyCommandResolver.resolve(
                command: command,
                workspaceRoot: workspaceRoot,
                path: childEnvironment["PATH"] ?? ""
            )
            spawned = try childLauncher.spawn(
                executable: executable,
                arguments: upstream.args,
                environment: childEnvironment,
                currentDirectory: workspaceRoot
            )
        } catch {
            return nil
        }
        MCPProxyStderrDrain.start(
            fileDescriptor: spawned.stderrRead,
            secrets: [],
            output: stderrOutput
        )
        let terminator = MCPProcessTerminator(
            processID: spawned.processID,
            processGroupID: spawned.processGroupID,
            killGraceSeconds: killGraceSeconds
        )
        let client = Client(
            name: "authsia-mcp-proxy",
            version: proxyVersion,
            configuration: .default
        )
        if isStopped {
            await teardownSpawn(
                client: client,
                terminator: terminator,
                stdinWrite: spawned.stdinWrite,
                stdoutRead: spawned.stdoutRead
            )
            return nil
        }
        let transport = StdioTransport(
            input: FileDescriptor(rawValue: spawned.stdoutRead),
            output: FileDescriptor(rawValue: spawned.stdinWrite)
        )
        do {
            let listed = try await mcpProxyWithTimeout(initializeTimeoutSeconds) {
                _ = try await client.connect(transport: transport)
                return try await client.listTools()
            }
            let tools = MCPProxyCatalog.listedTools(fromChild: listed.tools, deny: upstream.tools.deny)
            await teardownSpawn(
                client: client,
                terminator: terminator,
                stdinWrite: spawned.stdinWrite,
                stdoutRead: spawned.stdoutRead
            )
            return tools
        } catch {
            await teardownSpawn(
                client: client,
                terminator: terminator,
                stdinWrite: spawned.stdinWrite,
                stdoutRead: spawned.stdoutRead
            )
            return nil
        }
    }

    /// Takes the local `mcp-admission` grant that authorizes starting the
    /// declared child. Discovery only runs for upstreams with no `authsia://`
    /// references, so this never resolves a secret.
    private func admitCatalogDiscovery(
        upstream: MCPUpstreamConfig,
        workspaceRoot: URL
    ) async throws {
        let agentRuntimeContext = await runtimeContext.makeProxyAgentRuntimeContext(
            upstreamName: upstreamName,
            invocationID: UUID()
        )
        let sessionClient = self.sessionClient
        let upstreamName = self.upstreamName
        let commandLabel = Self.commandLabel(for: upstream)
        let prepared = try await Task.detached {
            try sessionClient.prepareChildEnvironment(
                declared: [:],
                agentRuntimeContext: agentRuntimeContext,
                workspaceRoot: workspaceRoot,
                mcpUpstreamName: upstreamName,
                mcpUpstreamCommand: commandLabel,
                mcpToolName: nil,
                mcpToolPolicy: nil
            )
        }.value
        guard !prepared.grantIDs.isEmpty else {
            throw MCPProxySpawnError.grantUnavailable
        }
    }

    /// The argv the admission prompt shows. Policy names the child, but the
    /// name is repo-supplied, so the human needs the binary it resolves to.
    private static func commandLabel(for upstream: MCPUpstreamConfig) -> String? {
        guard let command = upstream.command?.trimmingCharacters(in: .whitespacesAndNewlines),
              !command.isEmpty else {
            return nil
        }
        return ([command] + upstream.args).joined(separator: " ")
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

}

private func mcpProxyWithTimeout<T: Sendable>(
    _ seconds: Double,
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask {
            try await operation()
        }
        group.addTask {
            try await Task.sleep(for: .seconds(max(seconds, 0)))
            throw MCPProxySpawnError.launchFailed
        }
        let result = try await group.next()!
        group.cancelAll()
        return result
    }
}

private struct InFlightSpawn {
    let terminator: MCPProcessTerminator
    let stdinWrite: Int32
    let stdoutRead: Int32
    let client: Client
}

private struct ChildSession: Sendable {
    let processID: pid_t
    let client: Client
    let childToolNames: Set<String>
    let secrets: [String]
    let grantIDs: Set<UUID>
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
