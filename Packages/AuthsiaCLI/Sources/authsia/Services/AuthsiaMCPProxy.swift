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
    private let callTimeoutSeconds: Double
    private let maximumConcurrentCalls: Int
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
    private var inFlightCallCount = 0
    /// What the child advertised, sanitized and capped, before `deny`.
    private var discoveredChildTools: [Tool]?
    private var discoveryTask: Task<[Tool]?, Never>?
    private var warnedMissingCatalog = false
    private var pendingChildExitStatus: [pid_t: Int32] = [:]
    private var consecutiveGrantCheckFailures = 0
    private var loggedGrantWatcherUnreachable = false
    private var loggedInvalidWorkspace = false
    private var spawnFailureCache: (label: String, status: Int32, until: Date)?
    private let grantCheckFailureLimit = 3
    private let spawnFailureCacheSeconds = 5.0

    init(
        version: String,
        upstreamName: String,
        runtimeContext: MCPRuntimeContext,
        mcpAccessEnabled: @escaping @Sendable () -> Bool,
        sessionClient: (any MCPProxySessionClient)? = nil,
        childLauncher: (any MCPProxyChildLaunching)? = nil,
        parentEnvironment: [String: String] = ProcessInfo.processInfo.environment,
        initializeTimeoutSeconds: Double = 30,
        callTimeoutSeconds: Double = 120,
        maximumConcurrentCalls: Int = 8,
        killGraceSeconds: Double = 2,
        grantPollIntervalSeconds: Double = 2,
        grantService: MCPGrantService? = nil,
        toolCallRecorder: any MCPProxyToolCallRecording,
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
        self.callTimeoutSeconds = callTimeoutSeconds
        self.maximumConcurrentCalls = maximumConcurrentCalls
        self.killGraceSeconds = killGraceSeconds
        self.grantPollIntervalSeconds = grantPollIntervalSeconds
        self.grantService = grantService ?? MCPGrantService(
            serverInstanceID: runtimeContext.instanceID
        )
        self.toolCallRecorder = toolCallRecorder
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
        signal(SIGHUP, SIG_IGN)

        let interruptSource = shutdownSource(signal: SIGINT)
        let terminateSource = shutdownSource(signal: SIGTERM)
        let hangupSource = shutdownSource(signal: SIGHUP)
        interruptSource.resume()
        terminateSource.resume()
        hangupSource.resume()

        try await start(transport: StdioTransport())
        await server.waitUntilCompleted()
        await stop()

        interruptSource.cancel()
        terminateSource.cancel()
        hangupSource.cancel()
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
        let invocationID = UUID()
        let agentRuntimeContext = await runtimeContext.makeProxyAgentRuntimeContext(
            upstreamName: upstreamName,
            invocationID: invocationID
        )

        guard mcpAccessEnabled() else {
            return try proxyFailureResult(
                invocationID: invocationID,
                upstreamCommand: nil,
                toolName: parameters.name,
                agentRuntimeContext: agentRuntimeContext,
                grantID: nil,
                outcome: .denied,
                code: .mcpAccessDisabled,
                message: "MCP integrations are disabled in Authsia. Enable them in Settings > Developer Access.",
                recordAttempted: false,
                recordedInvocationID: nil
            )
        }
        switch boundPolicy() {
        case .unbound:
            return try proxyFailureResult(
                invocationID: invocationID,
                upstreamCommand: nil,
                toolName: parameters.name,
                agentRuntimeContext: agentRuntimeContext,
                grantID: nil,
                outcome: .upstreamUnavailable,
                code: .workspaceUnavailable,
                message: runtimeContext.workspaceUnavailableMessage,
                recordAttempted: false,
                recordedInvocationID: nil
            )
        case .invalidWorkspace(let detail):
            return try proxyFailureResult(
                invocationID: invocationID,
                upstreamCommand: nil,
                toolName: parameters.name,
                agentRuntimeContext: agentRuntimeContext,
                grantID: nil,
                outcome: .upstreamUnavailable,
                code: .workspaceUnavailable,
                message: detail,
                recordAttempted: false,
                recordedInvocationID: nil
            )
        case .missingUpstream:
            return try proxyFailureResult(
                invocationID: invocationID,
                upstreamCommand: nil,
                toolName: parameters.name,
                agentRuntimeContext: agentRuntimeContext,
                grantID: nil,
                outcome: .upstreamUnavailable,
                code: .upstreamUnavailable,
                stage: .policy,
                message: "The named MCP upstream is not declared in this workspace.",
                recordAttempted: false,
                recordedInvocationID: nil
            )
        case .httpUpstream:
            return try proxyFailureResult(
                invocationID: invocationID,
                upstreamCommand: nil,
                toolName: parameters.name,
                agentRuntimeContext: agentRuntimeContext,
                grantID: nil,
                outcome: .denied,
                code: .httpUpstreamUnsupported,
                message: "HTTP MCP upstreams are not supported.",
                recordAttempted: false,
                recordedInvocationID: nil
            )
        case .stdio(let upstream):
            let advertised = await advertisedNames(for: upstream)
            guard advertised.contains(parameters.name) else {
                return try proxyFailureResult(
                    invocationID: invocationID,
                    upstreamCommand: upstream.command,
                    toolName: parameters.name,
                    agentRuntimeContext: agentRuntimeContext,
                    grantID: currentChildGrantID(),
                    outcome: .denied,
                    code: .upstreamDenied,
                    message: "This upstream tool is denied by workspace policy.",
                    recordAttempted: false,
                    recordedInvocationID: nil
                )
            }
            guard inFlightCallCount < maximumConcurrentCalls else {
                return try proxyFailureResult(
                    invocationID: invocationID,
                    upstreamCommand: upstream.command,
                    toolName: parameters.name,
                    agentRuntimeContext: agentRuntimeContext,
                    grantID: currentChildGrantID(),
                    outcome: .busy,
                    code: .busy,
                    message: "Too many concurrent calls are in flight for this MCP upstream.",
                    recordAttempted: false,
                    recordedInvocationID: nil
                )
            }
            inFlightCallCount += 1
            defer { inFlightCallCount -= 1 }
            var recordedInvocationID: UUID?
            var recordAttempted = false
            var recordedGrantID: UUID?
            do {
                let session = try await ensureChild(
                    upstream: upstream,
                    toolName: parameters.name,
                    agentRuntimeContext: agentRuntimeContext
                )
                let grantIDs = orderedGrantIDs(from: session)
                let grantID = grantIDs.first
                recordedGrantID = grantID
                guard session.childToolNames.contains(parameters.name) else {
                    return try proxyFailureResult(
                        invocationID: invocationID,
                        upstreamCommand: upstream.command,
                        toolName: parameters.name,
                        agentRuntimeContext: agentRuntimeContext,
                        grantID: grantID,
                        outcome: .upstreamUnavailable,
                        code: .upstreamUnavailable,
                        message: "The upstream MCP server does not implement this tool.",
                        recordAttempted: false,
                        recordedInvocationID: nil
                    )
                }
                recordAttempted = true
                do {
                    try toolCallRecorder.record(
                        upstreamName: upstreamName,
                        upstreamCommand: upstream.command,
                        toolName: parameters.name,
                        agentRuntimeContext: agentRuntimeContext,
                        workspaceRoot: runtimeContext.workspaceRoot,
                        grantID: grantID,
                        grantIDs: grantIDs
                    )
                } catch {
                    return try proxyFailureResult(
                        invocationID: invocationID,
                        upstreamCommand: upstream.command,
                        toolName: parameters.name,
                        agentRuntimeContext: agentRuntimeContext,
                        grantID: grantID,
                        outcome: .upstreamUnavailable,
                        code: .auditUnavailable,
                        message: "The call was not recorded, so it was not forwarded.",
                        recordAttempted: false,
                        recordedInvocationID: nil
                    )
                }
                recordedInvocationID = invocationID
                let result = try await forward(parameters, using: session)
                recordMCPProxyOutcome(
                    result.isError == true ? .mcpError : .succeeded,
                    upstreamCommand: upstream.command,
                    toolName: parameters.name,
                    agentRuntimeContext: agentRuntimeContext,
                    grantID: grantID,
                    grantIDs: grantIDs,
                    errorCode: nil,
                    stage: .forward
                )
                return result
            } catch let error as MCPToolInputError {
                return try proxyFailureResult(
                    invocationID: invocationID,
                    upstreamCommand: upstream.command,
                    toolName: parameters.name,
                    agentRuntimeContext: agentRuntimeContext,
                    grantID: recordedGrantID ?? currentChildGrantID(),
                    outcome: .mcpError,
                    code: .invalidInput,
                    message: error.localizedDescription,
                    recordAttempted: recordAttempted,
                    recordedInvocationID: recordedInvocationID
                )
            } catch let error as BridgeClientError {
                return try proxyFailureResult(
                    invocationID: invocationID,
                    upstreamCommand: upstream.command,
                    toolName: parameters.name,
                    agentRuntimeContext: agentRuntimeContext,
                    grantID: recordedGrantID ?? currentChildGrantID(),
                    outcome: .upstreamUnavailable,
                    code: MCPChildFailureReporter.code(for: error),
                    message: error.localizedDescription,
                    recordAttempted: recordAttempted,
                    recordedInvocationID: recordedInvocationID
                )
            } catch MCPProxySpawnError.grantUnavailable {
                return try proxyFailureResult(
                    invocationID: invocationID,
                    upstreamCommand: upstream.command,
                    toolName: parameters.name,
                    agentRuntimeContext: agentRuntimeContext,
                    grantID: recordedGrantID,
                    outcome: .denied,
                    code: .grantUnavailable,
                    message: "No revocable Authsia grant covers this upstream's secret references.",
                    recordAttempted: recordAttempted,
                    recordedInvocationID: recordedInvocationID
                )
            } catch MCPProxySpawnError.childExited(let status) {
                return try proxyFailureResult(
                    invocationID: invocationID,
                    upstreamCommand: upstream.command,
                    toolName: parameters.name,
                    agentRuntimeContext: agentRuntimeContext,
                    grantID: recordedGrantID,
                    outcome: .upstreamUnavailable,
                    code: .upstreamUnavailable,
                    message: MCPProxySpawnError.childExitedMessage(status),
                    recordAttempted: recordAttempted,
                    recordedInvocationID: recordedInvocationID
                )
            } catch is MCPProxySpawnError {
                return try proxyFailureResult(
                    invocationID: invocationID,
                    upstreamCommand: upstream.command,
                    toolName: parameters.name,
                    agentRuntimeContext: agentRuntimeContext,
                    grantID: recordedGrantID,
                    outcome: .upstreamUnavailable,
                    code: .upstreamUnavailable,
                    message: "The upstream MCP server could not be started.",
                    recordAttempted: recordAttempted,
                    recordedInvocationID: recordedInvocationID
                )
            } catch is MCPProxyCallError {
                return try proxyFailureResult(
                    invocationID: invocationID,
                    upstreamCommand: upstream.command,
                    toolName: parameters.name,
                    agentRuntimeContext: agentRuntimeContext,
                    grantID: recordedGrantID,
                    outcome: .timedOut,
                    code: .timedOut,
                    message: "The upstream MCP server did not answer this tool call in time.",
                    recordAttempted: recordAttempted,
                    recordedInvocationID: recordedInvocationID
                )
            } catch is CancellationError {
                return try proxyFailureResult(
                    invocationID: invocationID,
                    upstreamCommand: upstream.command,
                    toolName: parameters.name,
                    agentRuntimeContext: agentRuntimeContext,
                    grantID: recordedGrantID ?? currentChildGrantID(),
                    outcome: .cancelled,
                    code: .cancelled,
                    message: "The upstream tool call was cancelled.",
                    recordAttempted: recordAttempted,
                    recordedInvocationID: recordedInvocationID
                )
            } catch {
                return try proxyFailureResult(
                    invocationID: invocationID,
                    upstreamCommand: upstream.command,
                    toolName: parameters.name,
                    agentRuntimeContext: agentRuntimeContext,
                    grantID: recordedGrantID ?? currentChildGrantID(),
                    outcome: .upstreamUnavailable,
                    code: .upstreamUnavailable,
                    message: "The upstream MCP server is unavailable.",
                    recordAttempted: recordAttempted,
                    recordedInvocationID: recordedInvocationID
                )
            }
        }
    }

    private func currentChildGrantID() -> UUID? {
        orderedGrantIDs().first
    }

    private func orderedGrantIDs(from session: ChildSession? = nil) -> [UUID] {
        let ids = session?.grantIDs ?? childSession?.grantIDs ?? []
        return ids.sorted { $0.uuidString < $1.uuidString }
    }

    private func attributedGrantIDs(primary: UUID?) -> [UUID] {
        let fromSession = orderedGrantIDs()
        if !fromSession.isEmpty {
            return fromSession
        }
        if let primary {
            return [primary]
        }
        return []
    }

    private func proxyFailureResult(
        invocationID: UUID,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        grantID: UUID?,
        outcome: MCPProxyCallOutcome,
        code: MCPToolErrorCode,
        stage: MCPProxyCallStage? = nil,
        message: String,
        recordAttempted: Bool,
        recordedInvocationID: UUID?
    ) throws -> CallTool.Result {
        let grantIDs = attributedGrantIDs(primary: grantID)
        let responseID = proxyFailureInvocationID(
            outcome: outcome,
            invocationID: invocationID,
            upstreamCommand: upstreamCommand,
            toolName: toolName,
            agentRuntimeContext: agentRuntimeContext,
            grantID: grantIDs.first ?? grantID,
            grantIDs: grantIDs,
            errorCode: code.rawValue,
            stage: stage ?? code.mcpProxyCallStage,
            recordAttempted: recordAttempted,
            recordedInvocationID: recordedInvocationID
        )
        return try Self.errorResult(code: code, message: message, invocationID: responseID)
    }

    @discardableResult
    private func recordRejectedCall(
        invocationID: UUID,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        grantID: UUID?,
        grantIDs: [UUID],
        outcome: MCPProxyCallOutcome,
        errorCode: String?,
        stage: MCPProxyCallStage?
    ) -> UUID? {
        do {
            try toolCallRecorder.recordRejected(
                upstreamName: upstreamName,
                upstreamCommand: upstreamCommand,
                toolName: toolName,
                agentRuntimeContext: agentRuntimeContext,
                workspaceRoot: runtimeContext.workspaceRoot,
                grantID: grantID,
                grantIDs: grantIDs,
                outcome: outcome,
                errorCode: errorCode,
                stage: stage
            )
            return invocationID
        } catch {
            return nil
        }
    }

    private func recordMCPProxyOutcome(
        _ outcome: MCPProxyCallOutcome,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        grantID: UUID?,
        grantIDs: [UUID],
        errorCode: String?,
        stage: MCPProxyCallStage?
    ) {
        var lastError: (any Error)?
        for attempt in 0..<2 {
            do {
                try toolCallRecorder.recordOutcome(
                    upstreamName: upstreamName,
                    upstreamCommand: upstreamCommand,
                    toolName: toolName,
                    agentRuntimeContext: agentRuntimeContext,
                    workspaceRoot: runtimeContext.workspaceRoot,
                    grantID: grantID,
                    grantIDs: grantIDs,
                    outcome: outcome,
                    errorCode: errorCode,
                    stage: stage
                )
                return
            } catch {
                lastError = error
            }
            _ = attempt
        }
        if lastError != nil {
            stderrOutput.write(Data("Authsia could not record the MCP call outcome.\n".utf8))
        }
    }

    private func proxyFailureInvocationID(
        outcome: MCPProxyCallOutcome,
        invocationID: UUID,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        grantID: UUID?,
        grantIDs: [UUID],
        errorCode: String?,
        stage: MCPProxyCallStage?,
        recordAttempted: Bool,
        recordedInvocationID: UUID?
    ) -> UUID? {
        if recordAttempted {
            if recordedInvocationID != nil {
                recordMCPProxyOutcome(
                    outcome,
                    upstreamCommand: upstreamCommand,
                    toolName: toolName,
                    agentRuntimeContext: agentRuntimeContext,
                    grantID: grantID,
                    grantIDs: grantIDs,
                    errorCode: errorCode,
                    stage: stage
                )
            }
            return recordedInvocationID
        }
        return recordRejectedCall(
            invocationID: invocationID,
            upstreamCommand: upstreamCommand,
            toolName: toolName,
            agentRuntimeContext: agentRuntimeContext,
            grantID: grantID,
            grantIDs: grantIDs,
            outcome: outcome,
            errorCode: errorCode,
            stage: stage
        )
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
        let callTimeout = callTimeoutSeconds
        return try await withTaskCancellationHandler {
            let result: CallTool.Result
            do {
                // The SDK has no per-request deadline over stdio, so a wedged
                // child would hold the caller until the grant expires. Bound
                // the wait, then tell the child to drop the request.
                result = try await mcpProxyWithTimeout(
                    callTimeout,
                    timeoutError: MCPProxyCallError.timedOut
                ) {
                    try await request.value
                }
            } catch let error as MCPProxyCallError {
                // Do not await cancel: a child that is ignoring stdin would
                // hold timedOut on the caller the same way request.value did.
                Task { try? await session.client.cancelRequest(request.requestID) }
                throw error
            }
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
                _ = try await spawnTask.value
                if let live = await liveSession() {
                    return live
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
        if let cache = spawnFailureCache,
           cache.label == commandLabel,
           cache.until > Date() {
            throw MCPProxySpawnError.childExited(cache.status)
        }
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
        MCPProxyChildRegistry.register(
            grantIDs: Set(prepared.grantIDs),
            processGroupID: spawned.processGroupID,
            childProcessID: spawned.processID,
            proxyProcessID: getpid()
        )
        let client = Client(
            name: "authsia-mcp-proxy",
            version: proxyVersion,
            configuration: .default
        )
        let exitBox = MCPChildExitBox()
        watchSpawnedChild(spawned.processID, exitBox: exitBox, onExit: {
            Darwin.shutdown(spawned.stdoutRead, SHUT_RDWR)
            Darwin.shutdown(spawned.stdinWrite, SHUT_RDWR)
            Task { await client.disconnect() }
        })
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
            let listed: Set<String>
            do {
                listed = try await mcpProxyWithTimeout(
                    timeout,
                    timeoutError: MCPProxySpawnError.launchFailed
                ) {
                    _ = try await client.connect(transport: transport)
                    let tools = try await client.listTools()
                    return Set(tools.tools.map(\.name))
                }
            } catch {
                if let status = exitBox.status {
                    throw MCPProxySpawnError.childExited(status)
                }
                throw error
            }
            try Task.checkCancellation()
            guard !isStopped else {
                await consumeInFlight()
                throw CancellationError()
            }
            if let status = exitBox.status ?? pendingChildExitStatus[spawned.processID] {
                await consumeInFlight()
                rememberSpawnFailure(label: commandLabel, status: status)
                throw MCPProxySpawnError.childExited(status)
            }
            let session = ChildSession(
                processID: spawned.processID,
                processGroupID: spawned.processGroupID,
                commandLabel: commandLabel,
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
            watchGrants(session)
            return session
        } catch let error as MCPProxySpawnError {
            // launchFailed is the initialize deadline: the child is still
            // wedged, and awaiting teardown/disconnect held the caller until
            // the live driver gave up (D6). Tear down in the background.
            if case .childExited(let status) = error {
                await consumeInFlight()
                rememberSpawnFailure(label: commandLabel, status: status)
            } else {
                abandonInFlight()
            }
            throw error
        } catch is CancellationError {
            await consumeInFlight()
            throw CancellationError()
        } catch {
            abandonInFlight()
            throw MCPProxySpawnError.launchFailed
        }
    }

    private func liveSession() async -> ChildSession? {
        guard let session = childSession else { return nil }
        guard session.isAlive else {
            await dropChild()
            return nil
        }
        if let upstream = stdioUpstream(),
           session.commandLabel != Self.commandLabel(for: upstream) {
            await dropChild(processID: session.processID)
            return nil
        }
        switch associatedGrantsRemainActive(for: session) {
        case .active, .unreachable:
            return session
        case .inactive:
            await dropChild(processID: session.processID)
            return nil
        }
    }

    private func associatedGrantsRemainActive(for session: ChildSession) -> GrantWatchVerdict {
        guard !session.grantIDs.isEmpty else { return .active }
        do {
            let active = try grantService.activeOwnedGrantIDs()
            return session.grantIDs.isSubset(of: active) ? .active : .inactive
        } catch {
            return .unreachable
        }
    }

    private func watchGrants(_ session: ChildSession) {
        guard !session.grantIDs.isEmpty else { return }
        grantWatchTask?.cancel()
        consecutiveGrantCheckFailures = 0
        loggedGrantWatcherUnreachable = false
        let processID = session.processID
        let interval = max(grantPollIntervalSeconds, 0.01)
        grantWatchTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(interval))
                guard !Task.isCancelled, let self else { return }
                guard await self.childSession?.processID == processID else { return }
                switch await self.associatedGrantsRemainActive(for: session) {
                case .active:
                    await self.resetGrantWatchFailures()
                case .inactive:
                    await self.dropChild(processID: processID)
                    return
                case .unreachable:
                    if await self.grantWatchFailedUnreachable(processID: processID) {
                        return
                    }
                }
            }
        }
    }

    private func resetGrantWatchFailures() {
        consecutiveGrantCheckFailures = 0
    }

    private func grantWatchFailedUnreachable(processID: pid_t) async -> Bool {
        consecutiveGrantCheckFailures += 1
        if !loggedGrantWatcherUnreachable {
            loggedGrantWatcherUnreachable = true
            stderrOutput.write(Data(
                "authsia mcp proxy: Authsia Bridge is unreachable; wrapped child stays up for a short grace window.\n".utf8
            ))
        }
        guard consecutiveGrantCheckFailures >= grantCheckFailureLimit else {
            return false
        }
        stderrOutput.write(Data(
            "authsia mcp proxy: Authsia Bridge stayed unreachable; stopping the wrapped child.\n".utf8
        ))
        await dropChild(processID: processID)
        return true
    }

    private func rememberSpawnFailure(label: String?, status: Int32) {
        guard let label else { return }
        spawnFailureCache = (
            label,
            status,
            Date().addingTimeInterval(spawnFailureCacheSeconds)
        )
    }

    private static func reapChild(_ processID: pid_t) {
        Thread.detachNewThread {
            var status: Int32 = 0
            _ = waitpid(processID, &status, 0)
        }
    }

    private func watchSpawnedChild(
        _ processID: pid_t,
        exitBox: MCPChildExitBox? = nil,
        onExit: (@Sendable () -> Void)? = nil
    ) {
        Thread.detachNewThread { [weak self] in
            var status: Int32 = 0
            _ = waitpid(processID, &status, 0)
            exitBox?.record(status)
            onExit?()
            Task { await self?.spawnedChildDidExit(processID, status: status) }
        }
    }

    private func spawnedChildDidExit(_ processID: pid_t, status: Int32) async {
        pendingChildExitStatus[processID] = status
        if childSession?.processID == processID {
            await dropChild()
        }
    }

    private func dropChild(processID: pid_t? = nil) async {
        guard let session = childSession,
              processID == nil || processID == session.processID else { return }
        childSession = nil
        grantWatchTask?.cancel()
        grantWatchTask = nil
        MCPProxyChildRegistry.unregister(grantIDs: session.grantIDs)
        MCPProxyChildRegistry.unregister(processGroupID: session.processGroupID)
        pendingChildExitStatus.removeValue(forKey: session.processID)
        await teardownSpawn(
            client: session.client,
            terminator: session.terminator,
            stdinWrite: session.stdinWrite,
            stdoutRead: session.stdoutRead
        )
    }

    private func consumeInFlight() async {
        guard let snapshot = takeInFlight() else { return }
        await teardownSpawn(
            client: snapshot.client,
            terminator: snapshot.terminator,
            stdinWrite: snapshot.stdinWrite,
            stdoutRead: snapshot.stdoutRead
        )
    }

    /// Drop a wedged in-flight spawn without waiting for kill or disconnect.
    /// Shut the child's stdio first so a stuck `connect()` unblocks; SIGTERM
    /// still comes from the terminator in the background.
    private func abandonInFlight() {
        guard let snapshot = takeInFlight() else { return }
        Darwin.shutdown(snapshot.stdinWrite, SHUT_RDWR)
        Darwin.shutdown(snapshot.stdoutRead, SHUT_RDWR)
        snapshot.terminator.start()
        Task {
            await self.teardownSpawn(
                client: snapshot.client,
                terminator: snapshot.terminator,
                stdinWrite: snapshot.stdinWrite,
                stdoutRead: snapshot.stdoutRead
            )
        }
    }

    private func takeInFlight() -> InFlightSpawn? {
        guard let inFlight else { return nil }
        self.inFlight = nil
        if let processGroupID = inFlight.terminator.recordedProcessGroupID {
            MCPProxyChildRegistry.unregister(processGroupID: processGroupID)
        }
        return inFlight
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

    private func listedTools() -> [Tool] {
        let upstream = stdioUpstream()
        let policyTools = MCPProxyCatalog.listedTools(for: upstream)
        if !policyTools.isEmpty {
            return policyTools
        }
        // Discovery starts the declared child, so it takes admission. Clients
        // list on connect, which would prompt the human for merely opening the
        // workspace. Listing answers from committed policy only; the approval
        // belongs on the first tools/call, where a tool is actually invoked.
        if let upstream, MCPProxyCatalog.shouldDiscoverChildCatalog(upstream) {
            warnMissingCatalog()
        }
        return []
    }

    /// An upstream with no recorded catalog lists nothing, which reads as a
    /// broken server from the client. Name the command that records one, once
    /// per proxy session, on the stream clients surface as MCP server logs.
    private func warnMissingCatalog() {
        guard !warnedMissingCatalog else { return }
        warnedMissingCatalog = true
        let message = """
            authsia mcp proxy: no tool catalog recorded for upstream '\(upstreamName)'. \
            Run: authsia mcp catalog --server \(upstreamName) --write

            """
        stderrOutput.write(Data(message.utf8))
    }

    /// One-shot catalog capture for `authsia mcp catalog`. Takes the same
    /// admission the call path takes, probes the declared child, then drops the
    /// grant: no child outlives the command, and the next client call must
    /// raise its own approval.
    /// Records what a declared child advertises, or says which precondition
    /// stopped it. One sentence covering every refusal leaves the human unable
    /// to tell "credentialed, by design" from "the setting is off" from "the
    /// server is broken", which are three different next actions.
    func captureCatalog() async -> Result<[Tool], MCPCatalogProbeFailure> {
        guard mcpAccessEnabled() else { return .failure(.mcpAccessDisabled) }
        switch boundPolicy() {
        case .unbound:
            return .failure(.workspaceUnavailable(
                runtimeContext.workspaceUnavailableMessage
            ))
        case .invalidWorkspace(let detail):
            return .failure(.workspaceUnavailable(detail))
        case .missingUpstream:
            return .failure(.notDeclared(upstreamName))
        case .httpUpstream:
            return .failure(.notStdio(upstreamName))
        case .stdio(let upstream):
            guard MCPProxyCatalog.canProbeChildCatalog(upstream) else {
                return .failure(.declaresEnvironment(upstreamName))
            }
            let discovered = await probeChildCatalog(upstream)
            grantService.revokeActiveOwnedGrants()
            guard let discovered else {
                return .failure(.childUnavailable(upstreamName))
            }
            return .success(discovered)
        }
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
        // `deny` is subtracted on every read, not baked into the cache, so a
        // deny added to workspace policy after the probe takes effect without
        // restarting the proxy.
        MCPProxyCatalog.subtractingDeny(
            await discoveredChildCatalog(upstream),
            deny: upstream.tools.deny
        )
    }

    private func discoveredChildCatalog(_ upstream: MCPUpstreamConfig) async -> [Tool] {
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
        // Nothing else waits on the probe child. Unreaped, it stays a zombie
        // whose process group still answers `kill(-pgid, 0)` with EPERM, so the
        // terminator could never observe its death and would burn the whole
        // grace and force window on every discovery.
        Self.reapChild(spawned.processID)
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
            let listed = try await mcpProxyWithTimeout(
                initializeTimeoutSeconds,
                timeoutError: MCPProxySpawnError.launchFailed
            ) {
                _ = try await client.connect(transport: transport)
                return try await client.listTools()
            }
            let tools = MCPProxyCatalog.listedTools(fromChild: listed.tools)
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
    /// declared child. Discovery only runs for upstreams with an empty
    /// environment, so it never resolves or forwards a credential.
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
        guard let root = runtimeContext.workspaceRoot else {
            if case .unreadableConfig = runtimeContext.workspaceBindingFailure {
                return invalidWorkspaceDetail(
                    "workspace.json failed validation. \(runtimeContext.workspaceUnavailableMessage)"
                )
            }
            return .unbound
        }
        let config: WorkspaceConfig
        do {
            config = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        } catch WorkspaceConfigError.missingConfig {
            return .unbound
        } catch {
            return invalidWorkspaceDetail(
                "workspace.json failed validation. \(error.localizedDescription)"
            )
        }
        guard let upstream = config.mcpUpstreams.first(where: { $0.name == upstreamName }) else {
            return .missingUpstream
        }
        guard upstream.requiresStdioPolicy else {
            return .httpUpstream
        }
        return .stdio(upstream)
    }

    private func invalidWorkspaceDetail(_ detail: String) -> BoundPolicy {
        if !loggedInvalidWorkspace {
            loggedInvalidWorkspace = true
            stderrOutput.write(Data("authsia mcp proxy: \(detail)\n".utf8))
        }
        return .invalidWorkspace(detail)
    }

    private static func errorResult(
        code: MCPToolErrorCode,
        message: String,
        invocationID: UUID? = nil
    ) throws -> CallTool.Result {
        let output = MCPToolErrorOutput(
            code: code,
            message: message,
            invocationID: invocationID?.uuidString
        )
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

enum MCPProxyCallError: Error, Equatable, Sendable {
    case timedOut
}

/// Races `operation` against a deadline and returns as soon as either finishes.
///
/// A throwing task group cannot do this: on timeout it still waits for the
/// cancelled operation, and MCP stdio `connect` / `request.value` ignore
/// cancellation, so the caller never saw `timedOut` or `launchFailed` until
/// the child unblocked.
private func mcpProxyWithTimeout<T: Sendable, Failure: Error & Sendable>(
    _ seconds: Double,
    timeoutError: Failure,
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    let gate = MCPProxyTimeoutGate<T>()
    let work = MCPProxyTimeoutWork()
    let timer = MCPProxyTimeoutWork()
    do {
        let value = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<T, any Error>) in
                gate.attach(continuation)
                if Task.isCancelled {
                    gate.finish(.failure(CancellationError()))
                    return
                }
                let operationTask = Task {
                    do {
                        gate.finish(.success(try await operation()))
                    } catch {
                        gate.finish(.failure(error))
                    }
                }
                let timeoutTask = Task {
                    do {
                        try await Task.sleep(for: .seconds(max(seconds, 0)))
                    } catch {
                        return
                    }
                    gate.finish(.failure(timeoutError))
                    operationTask.cancel()
                }
                work.store(operationTask)
                timer.store(timeoutTask)
            }
        } onCancel: {
            work.cancel()
            timer.cancel()
            gate.finish(.failure(CancellationError()))
        }
        work.cancel()
        timer.cancel()
        return value
    } catch {
        work.cancel()
        timer.cancel()
        throw error
    }
}

/// One-shot resume for `mcpProxyWithTimeout`. Two tasks may finish; only the first resumes.
private final class MCPProxyTimeoutGate<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, any Error>?
    private var resumed = false

    func attach(_ continuation: CheckedContinuation<T, any Error>) {
        lock.lock()
        self.continuation = continuation
        lock.unlock()
    }

    func finish(_ result: Result<T, Error>) {
        lock.lock()
        let pending = continuation
        let shouldResume = !resumed && pending != nil
        if shouldResume {
            resumed = true
            continuation = nil
        }
        lock.unlock()
        guard shouldResume, let pending else { return }
        pending.resume(with: result)
    }
}

private final class MCPProxyTimeoutWork: @unchecked Sendable {
    private let lock = NSLock()
    private var task: Task<Void, Never>?

    func store(_ task: Task<Void, Never>) {
        lock.lock()
        self.task = task
        lock.unlock()
    }

    func cancel() {
        lock.lock()
        let task = self.task
        lock.unlock()
        task?.cancel()
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
    let processGroupID: pid_t
    let commandLabel: String?
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

/// Why `captureCatalog` could not record a catalog.
enum MCPCatalogProbeFailure: Error, Equatable {
    case mcpAccessDisabled
    case workspaceUnavailable(String)
    case notDeclared(String)
    case notStdio(String)
    case declaresEnvironment(String)
    case childUnavailable(String)

    var message: String {
        switch self {
        case .mcpAccessDisabled:
            return "MCP Integrations is off. Turn it on in Authsia Settings > Developer Access, "
                + "then run this again."
        case .workspaceUnavailable(let detail):
            return detail
        case .notDeclared(let name):
            return "'\(name)' is not declared in this workspace's mcpUpstreams. "
                + "Declare it, or run `authsia mcp wrap --write --server \(name) --yes`."
        case .notStdio(let name):
            return "'\(name)' is not a local stdio upstream. HTTP, SSE, and URL upstreams "
                + "are not executed by this proxy."
        case .declaresEnvironment(let name):
            return "'\(name)' declares environment values, so Authsia will not start it to "
                + "read its tool list. Name its tools under mcpUpstreams.tools.allow in "
                + WorkspaceConfigStore.relativeConfigPath + "."
        case .childUnavailable(let name):
            return "'\(name)' could not be started or did not answer tools/list. "
                + "Check that its command resolves on PATH."
        }
    }
}

private enum BoundPolicy {
    case unbound
    case invalidWorkspace(String)
    case missingUpstream
    case httpUpstream
    case stdio(MCPUpstreamConfig)
}

private enum GrantWatchVerdict {
    case active
    case inactive
    case unreachable
}

extension MCPToolErrorCode {
    var mcpProxyCallStage: MCPProxyCallStage {
        switch self {
        case .mcpAccessDisabled, .cliAccessDisabled:
            return .settings
        case .workspaceUnavailable:
            return .binding
        case .upstreamDenied, .httpUpstreamUnsupported:
            return .policy
        case .grantUnavailable, .grantNotOwned, .approvalDenied:
            return .admission
        case .upstreamUnavailable, .executionFailed:
            return .spawn
        case .busy, .timedOut, .cancelled, .invalidInput, .internalError,
             .auditUnavailable, .bridgeUnavailable:
            return .forward
        }
    }
}
