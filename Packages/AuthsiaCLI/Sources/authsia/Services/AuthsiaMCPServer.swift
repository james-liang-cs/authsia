import Darwin
import Dispatch
import Foundation
import MCP

actor AuthsiaMCPServer {
    typealias Diagnostics = @Sendable (String) -> Void

    private let server: Server
    private let runtimeContext: MCPRuntimeContext
    private let workspaceInspection: MCPWorkspaceInspectionService
    private let childRunner: (any MCPChildRunning)?
    private let diagnostics: Diagnostics
    private var handlersRegistered = false
    private var executionInProgress = false

    init(
        version: String,
        runtimeContext: MCPRuntimeContext = MCPRuntimeContext(
            startingDirectory: URL(
                fileURLWithPath: FileManager.default.currentDirectoryPath,
                isDirectory: true
            )
        ),
        workspaceInspection: MCPWorkspaceInspectionService? = nil,
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
        self.workspaceInspection = workspaceInspection ?? MCPWorkspaceInspectionService(
            runtimeContext: runtimeContext
        )
        if let childRunner {
            self.childRunner = childRunner
        } else if let root = runtimeContext.workspaceRoot {
            self.childRunner = MCPSameBinaryRunner(workspaceRoot: root)
        } else {
            self.childRunner = nil
        }
        self.diagnostics = diagnostics
    }

    func start(transport: any Transport) async throws {
        try runtimeContext.requireWorkspace()
        await registerHandlersIfNeeded()
        try await server.start(transport: transport) { [runtimeContext] client, _ in
            await runtimeContext.updateClientInfo(name: client.name, version: client.version)
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
        await server.stop()
    }

    func waitUntilCompleted() async {
        await server.waitUntilCompleted()
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
                return try Self.errorResult(
                    code: .invalidInput,
                    message: "Unknown Authsia MCP tool."
                )
            }
            do {
                switch name {
                case .status:
                    return try Self.successResult(self.workspaceInspection.status())
                case .workspaceInspect:
                    let input = try Self.decodeInput(
                        MCPWorkspaceInspectInput.self,
                        arguments: parameters.arguments
                    )
                    return try Self.successResult(self.workspaceInspection.inspect(input))
                case .exec:
                    let input = try Self.decodeInput(
                        MCPExecInput.self,
                        arguments: parameters.arguments
                    ).validated()
                    return try await self.execute(input)
                case .accessStatus, .accessRevoke:
                    break
                }
            } catch let error as MCPToolInputError {
                return try Self.errorResult(
                    code: .invalidInput,
                    message: error.localizedDescription
                )
            } catch {
                return try Self.errorResult(
                    code: .internalError,
                    message: "The requested Authsia operation could not be completed."
                )
            }
            return try Self.errorResult(
                code: .internalError,
                message: "The tool runtime is not available yet."
            )
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
        message: String
    ) throws -> CallTool.Result {
        let output = MCPToolErrorOutput(code: code, message: message, invocationID: nil)
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

    private func execute(_ input: MCPExecInput) async throws -> CallTool.Result {
        guard !executionInProgress else {
            return try Self.errorResult(
                code: .busy,
                message: "Another Authsia MCP execution is already active."
            )
        }
        guard let childRunner else {
            return try Self.errorResult(
                code: .workspaceUnavailable,
                message: "The MCP server is not bound to a managed workspace."
            )
        }

        executionInProgress = true
        defer { executionInProgress = false }
        let invocation = await runtimeContext.makeInvocation()
        let result = await childRunner.run(
            arguments: Self.execArguments(input),
            invocation: invocation,
            timeoutSeconds: input.timeoutSeconds
        )
        let termination: MCPExecutionTermination
        if result.cancelled {
            termination = .cancelled
        } else if result.timedOut {
            termination = .timedOut
        } else if result.launchFailed {
            termination = .launchFailed
        } else if result.signalled {
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
}
