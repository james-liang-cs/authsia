import Darwin
import Dispatch
import Foundation
import MCP

actor AuthsiaMCPServer {
    typealias Diagnostics = @Sendable (String) -> Void

    private let server: Server
    private let runtimeContext: MCPRuntimeContext
    private let workspaceInspection: MCPWorkspaceInspectionService
    private let diagnostics: Diagnostics
    private var handlersRegistered = false

    init(
        version: String,
        runtimeContext: MCPRuntimeContext = MCPRuntimeContext(
            startingDirectory: URL(
                fileURLWithPath: FileManager.default.currentDirectoryPath,
                isDirectory: true
            )
        ),
        workspaceInspection: MCPWorkspaceInspectionService? = nil,
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
                case .accessStatus, .exec, .accessRevoke:
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

    private static func standardErrorDiagnostic(_ message: String) {
        FileHandle.standardError.write(Data((message + "\n").utf8))
    }
}
