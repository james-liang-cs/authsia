import Darwin
import Dispatch
import Foundation
import MCP

actor AuthsiaMCPServer {
    typealias Diagnostics = @Sendable (String) -> Void

    private let server: Server
    private let diagnostics: Diagnostics
    private var handlersRegistered = false

    init(
        version: String,
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
        self.diagnostics = diagnostics
    }

    func start(transport: any Transport) async throws {
        await registerHandlersIfNeeded()
        try await server.start(transport: transport)
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
            guard AuthsiaMCPToolName(rawValue: parameters.name) != nil else {
                return try Self.errorResult(
                    code: .invalidInput,
                    message: "Unknown Authsia MCP tool."
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

    private static func standardErrorDiagnostic(_ message: String) {
        FileHandle.standardError.write(Data((message + "\n").utf8))
    }
}
