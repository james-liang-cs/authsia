import Darwin
import Dispatch
import Foundation
import MCP

actor AuthsiaMCPProxy {
    private let server: Server
    private let upstreamName: String
    private let runtimeContext: MCPRuntimeContext
    private let acceptsToolWorkspace: Bool
    private let mcpAccessEnabled: @Sendable () -> Bool
    private var handlersRegistered = false

    init(
        version: String,
        upstreamName: String,
        runtimeContext: MCPRuntimeContext,
        acceptsToolWorkspace: Bool,
        mcpAccessEnabled: @escaping @Sendable () -> Bool
    ) {
        self.server = Server(
            name: "authsia-mcp-proxy",
            version: version,
            title: "Authsia MCP Proxy",
            instructions: "Proxies the '\(upstreamName)' MCP upstream. Tools are filtered by workspace policy.",
            capabilities: .init(tools: .init(listChanged: false)),
            configuration: .strict
        )
        self.upstreamName = upstreamName
        self.runtimeContext = runtimeContext
        self.acceptsToolWorkspace = acceptsToolWorkspace
        self.mcpAccessEnabled = mcpAccessEnabled
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

    func waitUntilCompleted() async {
        await server.waitUntilCompleted()
    }

    private func registerHandlersIfNeeded() async {
        guard !handlersRegistered else { return }
        handlersRegistered = true

        await server.withMethodHandler(ListTools.self) { _ in
            let upstream = await self.stdioUpstream()
            return ListTools.Result(tools: MCPProxyCatalog.listedTools(for: upstream))
        }
        await server.withMethodHandler(CallTool.self) { parameters in
            try await self.callTool(named: parameters.name)
        }
    }

    private func callTool(named name: String) throws -> CallTool.Result {
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
            guard advertised.contains(name) else {
                return try Self.errorResult(
                    code: .upstreamDenied,
                    message: "This upstream tool is denied by workspace policy."
                )
            }
            return try Self.errorResult(
                code: .internalError,
                message: "Upstream tool forwarding is not available yet."
            )
        }
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

private enum BoundPolicy {
    case unbound
    case missingUpstream
    case httpUpstream
    case stdio(MCPUpstreamConfig)
}
