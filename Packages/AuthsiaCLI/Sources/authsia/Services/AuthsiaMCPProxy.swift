import Darwin
import Dispatch
import Foundation
import MCP

actor AuthsiaMCPProxy {
    private let server: Server
    private let runtimeContext: MCPRuntimeContext
    private let acceptsToolWorkspace: Bool
    private var handlersRegistered = false

    init(
        version: String,
        runtimeContext: MCPRuntimeContext,
        acceptsToolWorkspace: Bool
    ) {
        self.server = Server(
            name: "authsia-mcp-proxy",
            version: version,
            title: "Authsia MCP Proxy",
            capabilities: .init(tools: .init()),
            configuration: .strict
        )
        self.runtimeContext = runtimeContext
        self.acceptsToolWorkspace = acceptsToolWorkspace
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
        await server.stop()
    }

    private func registerHandlersIfNeeded() async {
        guard !handlersRegistered else { return }
        handlersRegistered = true
        await server.withMethodHandler(ListTools.self) { _ in
            ListTools.Result(tools: [])
        }
    }

    private func shutdownSource(signal signalNumber: Int32) -> DispatchSourceSignal {
        let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: .global())
        source.setEventHandler { [weak self] in
            Task { await self?.stop() }
        }
        return source
    }
}
