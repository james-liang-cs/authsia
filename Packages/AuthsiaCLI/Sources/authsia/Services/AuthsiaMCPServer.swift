import Darwin
import Dispatch
import Foundation
import MCP

actor AuthsiaMCPServer {
    typealias Diagnostics = @Sendable (String) -> Void

    private let server: Server
    private let runtimeContext: MCPRuntimeContext
    private let acceptsClientRoots: Bool
    private let workspaceInspection: MCPWorkspaceInspectionService
    private let grantService: MCPGrantService
    private let listService: any MCPListProviding
    private let childRunner: (any MCPChildRunning)?
    private let diagnostics: Diagnostics
    private var handlersRegistered = false
    private var mediatedOperationInProgress = false
    private var activeExecution: ActiveExecution?
    private var activeList: ActiveListOperation?
    private var isStopping = false
    private var didUseMediatedTool = false
    private var didCleanupGrants = false
    private var clientSupportsRoots = false
    private var clientRootsNeedRefresh = true
    private var clientRootsRefreshTask: Task<Bool, Never>?

    init(
        version: String,
        runtimeContext: MCPRuntimeContext = MCPRuntimeContext(
            startingDirectory: URL(
                fileURLWithPath: FileManager.default.currentDirectoryPath,
                isDirectory: true
            )
        ),
        acceptsClientRoots: Bool = true,
        workspaceInspection: MCPWorkspaceInspectionService? = nil,
        grantService: MCPGrantService? = nil,
        listService: (any MCPListProviding)? = nil,
        childRunner: (any MCPChildRunning)? = nil,
        diagnostics: @escaping Diagnostics = AuthsiaMCPServer.standardErrorDiagnostic
    ) {
        self.server = Server(
            name: "authsia",
            version: version,
            title: "Authsia",
            instructions: "Local, JIT-mediated Authsia access. Tools never return plaintext secrets.",
            capabilities: .init(tools: .init()),
            configuration: .strict
        )
        self.runtimeContext = runtimeContext
        self.acceptsClientRoots = acceptsClientRoots
        self.workspaceInspection = workspaceInspection ?? MCPWorkspaceInspectionService(
            runtimeContext: runtimeContext
        )
        self.grantService = grantService ?? MCPGrantService(
            serverInstanceID: runtimeContext.instanceID
        )
        self.listService = listService ?? MCPListService(runtimeContext: runtimeContext)
        self.childRunner = childRunner
        self.diagnostics = diagnostics
    }

    func start(transport: any Transport) async throws {
        await registerHandlersIfNeeded()
        try await server.start(transport: transport) { [weak self, runtimeContext] client, capabilities in
            await runtimeContext.updateClientInfo(name: client.name, version: client.version)
            await self?.updateClientRootsCapability(capabilities.roots != nil)
        }
        diagnostics("Authsia MCP server started")
    }

    func runStdio() async throws {
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)

        let interruptSource = shutdownSource(signal: SIGINT)
        let terminateSource = shutdownSource(signal: SIGTERM)
        interruptSource.resume()
        terminateSource.resume()

        try await start(transport: StdioTransport())
        await waitUntilCompleted()

        interruptSource.cancel()
        terminateSource.cancel()
    }

    func stop() async {
        isStopping = true
        await cancelActiveListAndWait()
        await cancelActiveExecutionAndWait()
        cleanupGrantsIfNeeded()
        await server.stop()
    }

    func waitUntilCompleted() async {
        await server.waitUntilCompleted()
        isStopping = true
        await cancelActiveListAndWait()
        await cancelActiveExecutionAndWait()
        cleanupGrantsIfNeeded()
        diagnostics("Authsia MCP server stopped")
    }

    private func registerHandlersIfNeeded() async {
        guard !handlersRegistered else { return }
        handlersRegistered = true

        await server.withMethodHandler(ListTools.self) { _ in
            ListTools.Result(tools: MCPToolCatalog.tools)
        }
        await server.withMethodHandler(CallTool.self) { parameters in
            guard let name = AuthsiaMCPToolName(rawValue: parameters.name) else {
                throw MCPError.invalidParams("Unknown Authsia MCP tool: \(parameters.name)")
            }
            switch name {
            case .status, .workspaceInspect, .list, .exec:
                await self.refreshClientRootsIfNeeded()
            case .accessStatus, .accessRevoke:
                break
            }
            var invocationID: UUID?
            do {
                switch name {
                case .status:
                    _ = try Self.decodeInput(
                        MCPEmptyInput.self,
                        arguments: parameters.arguments
                    )
                    return try Self.successResult(self.workspaceInspection.status())
                case .workspaceInspect:
                    let input = try Self.decodeInput(
                        MCPWorkspaceInspectInput.self,
                        arguments: parameters.arguments
                    )
                    return try Self.successResult(self.workspaceInspection.inspect(input))
                case .list:
                    let input = try Self.decodeInput(
                        MCPListInput.self,
                        arguments: parameters.arguments
                    ).validated()
                    return try await self.listMetadata(input)
                case .exec:
                    let input = try Self.decodeInput(
                        MCPExecInput.self,
                        arguments: parameters.arguments
                    ).validated()
                    return try await self.execute(input)
                case .accessStatus:
                    _ = try Self.decodeInput(
                        MCPEmptyInput.self,
                        arguments: parameters.arguments
                    )
                    return try Self.successResult(self.grantService.status())
                case .accessRevoke:
                    let input = try Self.decodeInput(
                        MCPAccessRevokeInput.self,
                        arguments: parameters.arguments
                    )
                    let invocation = await self.runtimeContext.makeInvocation()
                    invocationID = invocation.id
                    guard let agentRuntimeContext = invocation.agentRuntimeContext else {
                        return try Self.errorResult(
                            code: .internalError,
                            message: "The MCP invocation context could not be created.",
                            invocationID: invocation.id
                        )
                    }
                    return try Self.successResult(self.grantService.revoke(
                        input.grantID,
                        agentRuntimeContext: agentRuntimeContext
                    ))
                }
            } catch let error as MCPToolInputError {
                return try Self.errorResult(
                    code: .invalidInput,
                    message: error.localizedDescription,
                    invocationID: invocationID
                )
            } catch let error as MCPGrantServiceError {
                switch error {
                case .invalidGrantID:
                    return try Self.errorResult(
                        code: .invalidInput,
                        message: "grantID must be a valid UUID.",
                        invocationID: invocationID
                    )
                case .grantNotOwned:
                    return try Self.errorResult(
                        code: .grantNotOwned,
                        message: "The grant does not belong to this MCP server instance.",
                        invocationID: invocationID
                    )
                case .grantUnavailable:
                    return try Self.errorResult(
                        code: .grantUnavailable,
                        message: "The grant is no longer active.",
                        invocationID: invocationID
                    )
                }
            } catch let error as MCPRuntimeContextError {
                _ = error
                return try Self.errorResult(
                    code: .workspaceUnavailable,
                    message: "The MCP server is not bound to a valid managed workspace.",
                    invocationID: invocationID
                )
            } catch let error as BridgeClientError {
                let code = MCPChildFailureReporter.code(for: error)
                return try Self.errorResult(
                    code: code,
                    message: Self.toolErrorMessage(for: code),
                    invocationID: invocationID
                )
            } catch {
                return try Self.errorResult(
                    code: .internalError,
                    message: "The requested Authsia operation could not be completed.",
                    invocationID: invocationID
                )
            }
        }
        await server.onNotification(RootsListChangedNotification.self) { [weak self] _ in
            await self?.markClientRootsChanged()
        }
    }

    private func updateClientRootsCapability(_ supported: Bool) {
        clientSupportsRoots = supported
        clientRootsNeedRefresh = supported
    }

    private func markClientRootsChanged() {
        guard acceptsClientRoots, clientSupportsRoots else { return }
        clientRootsNeedRefresh = true
    }

    private func refreshClientRootsIfNeeded() async {
        if let clientRootsRefreshTask {
            _ = await clientRootsRefreshTask.value
            return
        }
        guard acceptsClientRoots,
              clientSupportsRoots,
              clientRootsNeedRefresh,
              !mediatedOperationInProgress else {
            return
        }
        clientRootsNeedRefresh = false
        let previousRoot = runtimeContext.workspaceRoot
        let shouldRevokeGrants = didUseMediatedTool
        let task = Task { [server, runtimeContext, grantService] in
            do {
                let roots = try await server.listRoots()
                await runtimeContext.bindToClientRoots(Self.fileRootURLs(from: roots))
                if shouldRevokeGrants,
                   runtimeContext.workspaceRoot?.path != previousRoot?.path {
                    grantService.revokeActiveOwnedGrants()
                }
                return true
            } catch {
                return false
            }
        }
        clientRootsRefreshTask = task
        let didResolveRoots = await task.value
        clientRootsRefreshTask = nil
        if !didResolveRoots {
            diagnostics("Authsia MCP client roots unavailable; using launch workspace context")
        } else if runtimeContext.workspaceRoot == nil {
            diagnostics("Authsia MCP client roots are ambiguous or unavailable; workspace tools are closed")
        }
    }

    private static func fileRootURLs(from roots: [Root]) -> [URL] {
        roots.compactMap { root in
            guard root.uri.unicodeScalars.allSatisfy({
                !CharacterSet.controlCharacters.contains($0)
            }),
            let url = URL(string: root.uri),
            url.isFileURL,
            url.query == nil,
            url.fragment == nil,
            url.path.hasPrefix("/"),
            url.host == nil || url.host == "" || url.host == "localhost" else {
                return nil
            }
            return url
        }
    }

    private func cleanupGrantsIfNeeded() {
        guard !didCleanupGrants else { return }
        didCleanupGrants = true
        guard didUseMediatedTool else { return }
        grantService.revokeActiveOwnedGrants()
    }

    private func cancelActiveExecutionAndWait() async {
        guard let activeExecution else { return }
        activeExecution.task.cancel()
        _ = await activeExecution.task.value
        if self.activeExecution?.invocationID == activeExecution.invocationID {
            self.activeExecution = nil
            mediatedOperationInProgress = false
        }
    }

    private func cancelActiveListAndWait() async {
        guard let activeList else { return }
        activeList.task.cancel()
        _ = try? await activeList.task.value
        if self.activeList?.invocationID == activeList.invocationID {
            self.activeList = nil
            mediatedOperationInProgress = false
        }
    }

    private func shutdownSource(signal signalNumber: Int32) -> DispatchSourceSignal {
        let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: .global())
        source.setEventHandler { [weak self] in
            Task { await self?.stop() }
        }
        return source
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

    private static func successResult<Output: Codable>(_ output: Output) throws -> CallTool.Result {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let text = String(decoding: try encoder.encode(output), as: UTF8.self)
        return try CallTool.Result(
            content: [.text(text: text, annotations: nil, _meta: nil)],
            structuredContent: output
        )
    }

    private static func decodeInput<Input: MCPClosedToolInput>(
        _ type: Input.Type,
        arguments: [String: Value]?
    ) throws -> Input {
        let data = try JSONEncoder().encode(arguments ?? [:])
        return try MCPToolInputDecoder.decode(type, from: data)
    }

    static func execArguments(_ input: MCPExecInput) -> [String] {
        var arguments = ["workspace", "run"]
        if let environment = input.environment {
            arguments += ["--environment", environment]
        } else if input.defaultOnly {
            arguments.append("--default-only")
        }
        for path in input.envFiles {
            arguments += ["--env-file", path]
        }
        arguments.append("--")
        arguments += input.argv
        return arguments
    }

    private func listMetadata(_ input: MCPListInput) async throws -> CallTool.Result {
        guard !isStopping else {
            return try Self.errorResult(
                code: .cancelled,
                message: "The Authsia MCP server is stopping."
            )
        }
        guard !mediatedOperationInProgress else {
            return try Self.errorResult(
                code: .busy,
                message: "Another Authsia MCP mediated operation is already active."
            )
        }
        mediatedOperationInProgress = true
        defer { mediatedOperationInProgress = false }
        didUseMediatedTool = true
        let invocation = await runtimeContext.makeInvocation()
        let task = Task {
            try await listService.list(input, invocation: invocation)
        }
        activeList = ActiveListOperation(invocationID: invocation.id, task: task)
        defer {
            if activeList?.invocationID == invocation.id {
                activeList = nil
            }
        }
        let output: MCPListOutput
        do {
            output = try await withTaskCancellationHandler {
                try await task.value
            } onCancel: {
                task.cancel()
            }
        } catch is CancellationError {
            return try Self.errorResult(
                code: .cancelled,
                message: "The Authsia MCP list operation was cancelled.",
                invocationID: invocation.id
            )
        } catch let error as MCPToolInputError {
            return try Self.errorResult(
                code: .invalidInput,
                message: error.localizedDescription,
                invocationID: invocation.id
            )
        } catch is MCPRuntimeContextError {
            return try Self.errorResult(
                code: .workspaceUnavailable,
                message: "The MCP server is not bound to a valid managed workspace.",
                invocationID: invocation.id
            )
        } catch let error as BridgeClientError {
            let code = MCPChildFailureReporter.code(for: error)
            return try Self.errorResult(
                code: code,
                message: Self.toolErrorMessage(for: code),
                invocationID: invocation.id
            )
        } catch {
            return try Self.errorResult(
                code: .internalError,
                message: "The requested Authsia operation could not be completed.",
                invocationID: invocation.id
            )
        }
        guard !task.isCancelled, !Task.isCancelled else {
            return try Self.errorResult(
                code: .cancelled,
                message: "The Authsia MCP list operation was cancelled.",
                invocationID: invocation.id
            )
        }
        return try Self.successResult(output)
    }

    private func execute(_ input: MCPExecInput) async throws -> CallTool.Result {
        guard !isStopping else {
            return try Self.errorResult(
                code: .cancelled,
                message: "The Authsia MCP server is stopping."
            )
        }
        guard !mediatedOperationInProgress else {
            return try Self.errorResult(
                code: .busy,
                message: "Another Authsia MCP execution is already active."
            )
        }
        let activeChildRunner = childRunner ?? runtimeContext.workspaceRoot.map {
            MCPSameBinaryRunner(workspaceRoot: $0)
        }
        guard let activeChildRunner else {
            return try Self.errorResult(
                code: .workspaceUnavailable,
                message: "The MCP server is not bound to a managed workspace."
            )
        }

        mediatedOperationInProgress = true
        defer { mediatedOperationInProgress = false }
        didUseMediatedTool = true
        let invocation = await runtimeContext.makeInvocation()
        guard !isStopping else {
            return try Self.errorResult(
                code: .cancelled,
                message: "The Authsia MCP server is stopping.",
                invocationID: invocation.id
            )
        }
        let task = Task {
            await activeChildRunner.run(
                arguments: Self.execArguments(input),
                invocation: invocation,
                timeoutSeconds: input.timeoutSeconds
            )
        }
        activeExecution = ActiveExecution(invocationID: invocation.id, task: task)
        let result = await withTaskCancellationHandler {
            await task.value
        } onCancel: {
            task.cancel()
        }
        if activeExecution?.invocationID == invocation.id {
            activeExecution = nil
        }
        if result.cancelled {
            return try Self.errorResult(
                code: .cancelled,
                message: "The Authsia MCP execution was cancelled.",
                invocationID: result.invocationID
            )
        }
        if result.timedOut {
            return try Self.errorResult(
                code: .timedOut,
                message: "The Authsia MCP execution exceeded its timeout.",
                invocationID: result.invocationID
            )
        }
        if result.launchFailed {
            return try Self.errorResult(
                code: .executionFailed,
                message: "The mediated Authsia process could not be launched.",
                invocationID: result.invocationID
            )
        }
        if let failureCode = result.failureCode {
            return try Self.errorResult(
                code: failureCode,
                message: Self.toolErrorMessage(for: failureCode),
                invocationID: result.invocationID
            )
        }
        let termination: MCPExecutionTermination
        if result.signalled {
            termination = .signalled
        } else {
            termination = .exited
        }
        return try Self.successResult(MCPExecOutput(
            invocationID: result.invocationID.uuidString,
            termination: termination,
            exitCode: result.exitCode,
            stdout: result.stdout,
            stderr: result.stderr,
            stdoutTruncated: result.stdoutTruncated,
            stderrTruncated: result.stderrTruncated,
            durationMilliseconds: result.durationMilliseconds
        ))
    }

    private static func standardErrorDiagnostic(_ message: String) {
        FileHandle.standardError.write(Data((message + "\n").utf8))
    }

    private static func toolErrorMessage(for code: MCPToolErrorCode) -> String {
        switch code {
        case .bridgeUnavailable:
            return "The local Authsia Bridge is unavailable."
        case .cliAccessDisabled:
            return "CLI access is disabled in Authsia."
        case .approvalDenied:
            return "Authsia approval was denied or cancelled."
        default:
            return "The mediated Authsia operation failed."
        }
    }
}

private struct ActiveExecution: Sendable {
    let invocationID: UUID
    let task: Task<MCPChildResult, Never>
}

private struct ActiveListOperation: Sendable {
    let invocationID: UUID
    let task: Task<MCPListOutput, Error>
}
