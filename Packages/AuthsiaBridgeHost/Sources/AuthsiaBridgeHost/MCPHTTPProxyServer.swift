#if os(macOS)
import AuthenticatorBridge
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix

final class MCPHTTPProxyServer: @unchecked Sendable {
    private let router: MCPHTTPRouter
    private var group: MultiThreadedEventLoopGroup?
    private var channel: Channel?
    private let children = MCPHTTPChannels()
    init(dependencies: MCPManagerRuntimeDependencies) { router = MCPHTTPRouter(dependencies: dependencies) }
    func start(host: String, port: Int) async throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        do {
            let router = router, children = children
            channel = try await ServerBootstrap(group: group).serverChannelOption(ChannelOptions.backlog, value: 32)
                .childChannelInitializer { channel in
                    guard children.insert(channel) else { return channel.close() }
                    return channel.pipeline.configureHTTPServerPipeline().flatMap {
                        channel.pipeline.addHandler(MCPHTTPHandler(router: router))
                    }
                }.bind(host: host, port: port).get()
            self.group = group
        } catch { try? await group.shutdownGracefully(); throw error }
    }
    func stop() async throws {
        await router.shutdown()
        try? await channel?.close().get()
        await children.close()
        try await group?.shutdownGracefully()
        channel = nil; group = nil
    }
    func revoke(_ grantID: UUID) async throws { try await router.revoke(grantID) }
    func revoke(_ binding: MCPHTTPAssociationBinding) async throws { try await router.revoke(binding) }
}

final class MCPHTTPChannels: @unchecked Sendable {
    private let lock = NSLock()
    private var channels: [ObjectIdentifier: Channel] = [:]
    @discardableResult func insert(_ channel: Channel) -> Bool {
        let id = ObjectIdentifier(channel)
        // At most 16 concurrent connections each retain <= 4 MiB request and
        // <= 4 MiB decoded response. Backpressure prevents queued output growth.
        guard lock.withLock({ () -> Bool in
            guard channels.count < 16 else { return false }
            channels[id] = channel; return true
        }) else { return false }
        channel.closeFuture.whenComplete { [weak self] _ in _ = self?.lock.withLock { self?.channels.removeValue(forKey: id) } }
        return true
    }
    func close() async {
        let all = lock.withLock { Array(channels.values) }
        for channel in all { try? await channel.close().get() }
    }
}

struct MCPHTTPRequest: Sendable { let method: String; let uri: String; let headers: HTTPHeaders; let body: Data }
struct MCPHTTPResponse: Sendable {
    let status: Int
    var headers = HTTPHeaders()
    var body = Data()
    var stream: (@Sendable (@escaping @Sendable (Data) async throws -> Void) async throws -> Void)?
    var disconnect: (@Sendable () async -> Void)?
    static func json(_ object: [String: Any], status: Int = 200) -> Self {
        .init(status: status, headers: HTTPHeaders([("Content-Type", "application/json")]),
              body: (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data())
    }
    static func error(_ code: Int, id: Any? = nil, status: Int = 400) -> Self {
        json(["jsonrpc":"2.0", "id": id ?? NSNull(), "error": ["code":code, "message":"MCP request was rejected"]], status: status)
    }
}

private final class MCPHTTPSession: @unchecked Sendable {
    let id = UUID().uuidString
    let principal: MCPHTTPPrincipal
    let server: MCPServerSnapshot
    let version: String
    let connection = MCPHTTPUpstreamConnection()
    var upstreamID: String?
    var initialization: Task<Void, Error>?
    var grant: MCPHTTPGrantSummary?
    var lastUsed = Date()
    var requests = 0
    var emittedBytes = 0
    var inFlight = Set<String>()
    var cancelled = Set<String>()
    var requestTasks: [String: URLSessionTask] = [:]
    var pendingRequests: [String: Task<(URLSession.AsyncBytes, HTTPURLResponse), Error>] = [:]
    var streams: [UUID: URLSessionTask] = [:]
    var lifetime: Task<Void, Never>?
    init(principal: MCPHTTPPrincipal, server: MCPServerSnapshot, version: String) {
        self.principal = principal; self.server = server; self.version = version
    }
}

/// Owns downstream identities. No client-supplied session ID reaches upstream.
actor MCPHTTPRouter {
    private let dependencies: MCPManagerRuntimeDependencies
    private var sessions: [String: MCPHTTPSession] = [:]
    private var stopped = false
    private static let versions = ["2025-11-25", "2025-06-18", "2025-03-26"]
    init(dependencies: MCPManagerRuntimeDependencies) { self.dependencies = dependencies }

    func handle(_ request: MCPHTTPRequest) async -> MCPHTTPResponse {
        guard !stopped, request.headers["Host"].count == 1, request.headers.first(name: "Host") == "127.0.0.1:8788",
              request.headers["Origin"].isEmpty, request.body.count <= 4_194_304,
              request.headers["Authorization"].count == 1,
              let authorization = request.headers.first(name: "Authorization"), authorization.hasPrefix("Bearer ") else {
            return .error(-32001, status: 401)
        }
        let parts = request.uri.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[1] == "mcp", !parts[2].isEmpty, !request.uri.contains("?") else { return .error(-32600) }
        let serverID = String(parts[2])
        let principal: MCPHTTPPrincipal
        do {
            guard dependencies.mcpAccessEnabled(),
                  let value = try await dependencies.httpAuthority(.authenticate(serverID: serverID, token: String(authorization.dropFirst(7)))).principal else {
                return .error(-32001, status: 401)
            }
            principal = value
        } catch { return .error(-32001, status: 401) }
        guard !stopped else { return .error(-32001, status: 503) }
        prune()
        let object = (try? JSONSerialization.jsonObject(with: request.body)) as? [String: Any]
        let method = object?["method"] as? String
        let id = object?["id"]
        if request.method == "POST", method == "initialize" {
            guard request.headers["MCP-Session-Id"].isEmpty, object?["jsonrpc"] as? String == "2.0", id != nil,
                  sessions.count < 32, sessions.values.filter({ $0.principal.id == principal.id }).count < 4,
                  let parameters = object?["params"] as? [String: Any], let version = parameters["protocolVersion"] as? String,
                  Self.versions.contains(version),
                  let server = try? dependencies.registrySnapshot().servers.first(where: { $0.id == serverID }),
                  server.identity == principal.binding.identity, [.http, .streamableHTTP].contains(server.transport),
                  let endpoint = server.endpointLabel, (try? MCPLocalHTTPEndpointValidator.validate(endpoint)) != nil else {
                return .error(-32602, id: id)
            }
            let session = MCPHTTPSession(principal: principal, server: server, version: version)
            sessions[session.id] = session
            var response = MCPHTTPResponse.json(["jsonrpc":"2.0", "id":id!, "result":[
                "protocolVersion":version, "capabilities":["tools":["listChanged":false]],
                "serverInfo":["name":"authsia-http-proxy", "version":"1.0"]]])
            response.headers.add(name: "MCP-Session-Id", value: session.id)
            return response
        }
        guard request.headers["MCP-Session-Id"].count == 1,
              let sessionID = request.headers.first(name: "MCP-Session-Id"), let session = sessions[sessionID],
              session.principal == principal else { return .error(-32004, id: id, status: 404) }
        guard request.headers.first(name: "MCP-Protocol-Version") == session.version else { return .error(-32600, id: id) }
        guard let live = try? dependencies.registrySnapshot().servers.first(where: { $0.id == serverID }),
              live.authorizationRevision == session.server.authorizationRevision else {
            retire(session); return .error(-32004, id: id, status: 404)
        }
        session.lastUsed = Date(); session.requests += 1
        guard session.requests <= 512 else { retire(session); return .error(-32004, id: id, status: 404) }
        if request.method == "DELETE" { retire(session); return .init(status: 200) }
        if request.method == "GET" {
            guard request.headers["Last-Event-ID"].isEmpty else { return .error(-32602, status: 400) }
            do {
                let lease = try await lease(for: session, tool: "initialize")
                try await initializeUpstream(session, lease: lease)
                return try await forward(session, method: "GET", body: nil, lease: lease, invocation: nil, tool: nil)
            } catch { retire(session); return .error(-32020, status: 502) }
        }
        guard request.method == "POST", object?["jsonrpc"] as? String == "2.0", let method else { return .error(-32600, id: id) }
        if method == "notifications/initialized" { return .init(status: 202) }
        if method == "ping" { return .json(["jsonrpc":"2.0", "id":id ?? NSNull(), "result":[:]]) }
        if method == "tools/list" {
            var catalog: [String: MCPUpstreamToolDescriptor] = [:]
            for entry in session.server.catalog where catalog[entry.name] == nil { catalog[entry.name] = entry }
            let tools: [[String: Any]] = MCPToolPolicyEvaluator.advertisedToolNames(in: session.server.policy).map { name in
                let entry = catalog[name]
                let data = try? JSONEncoder().encode(entry?.inputSchema ?? .object(["type":.string("object")]))
                let schema = data.flatMap { try? JSONSerialization.jsonObject(with: $0) } ?? ["type":"object"]
                return ["name":name, "description":entry?.description ?? "", "inputSchema":schema]
            }
            return .json(["jsonrpc":"2.0", "id":id ?? NSNull(), "result":["tools":tools]])
        }
        if method == "notifications/cancelled" {
            if let p = object?["params"] as? [String: Any], let target = p["requestId"], session.inFlight.contains(String(describing: target)) {
                let key = String(describing: target)
                session.cancelled.insert(key)
                session.requestTasks[key]?.cancel()
                session.pendingRequests[key]?.cancel()
            }
            return .init(status: 202)
        }
        guard method == "tools/call", let id, let p = object?["params"] as? [String: Any],
              let name = p["name"] as? String else { return .error(-32601, id: id, status: 200) }
        let decision = MCPToolPolicyEvaluator.decision(for: name, policy: session.server.policy)
        guard decision == .allow || decision == .approve else { return .error(-32010, id: id, status: 200) }
        let requestKey = String(describing: id)
        guard session.inFlight.count < 8, session.inFlight.insert(requestKey).inserted else { return .error(-32013, id: id, status: 200) }
        let invocation = UUID()
        do {
            let lease = try await lease(for: session, tool: name)
            try await record(session, tool: name, id: invocation, outcome: .started)
            try await initializeUpstream(session, lease: lease)
            guard try await valid(session, lease: lease) else { throw MCPManagementError.denied }
            guard !session.cancelled.contains(requestKey) else { throw CancellationError() }
            let data = try MCPHTTPMessageMasker(secrets: lease.secrets).mask(request.body)
            return try await forward(session, method: "POST", body: data, lease: lease, invocation: invocation, tool: name,
                                     requestKey: requestKey, rpcID: requestKey)
        } catch {
            session.inFlight.remove(requestKey); session.cancelled.remove(requestKey)
            session.pendingRequests.removeValue(forKey: requestKey)
            let cancelled = error is CancellationError || (error as? URLError)?.code == .cancelled
            try? await record(session, tool: name, id: invocation, outcome: cancelled ? .cancelled : .upstreamUnavailable)
            if !cancelled { retire(session) }
            return .error(error as? MCPManagementError == .auditUnavailable ? -32030 : -32020, id: id, status: 200)
        }
    }

    private func lease(for session: MCPHTTPSession, tool: String) async throws -> MCPHTTPLease {
        let reply = try await dependencies.httpAuthority(.authorize(principal: session.principal, sessionID: session.id,
            revision: session.server.authorizationRevision, tool: tool))
        guard let lease = reply.lease, sessions[session.id] === session, !stopped,
              lease.grant.principal == session.principal, lease.grant.sessionID == session.id,
              lease.grant.revision == session.server.authorizationRevision else { throw MCPManagementError.denied }
        session.grant = lease.grant; session.lifetime?.cancel()
        let duration = max(0, lease.grant.expiresAt.timeIntervalSinceNow)
        session.lifetime = Task { [weak self, weak session] in
            do { try await Task.sleep(for: .seconds(duration)) } catch { return }
            if let session { await self?.retire(session) }
        }
        return lease
    }
    private func valid(_ session: MCPHTTPSession, lease: MCPHTTPLease) async throws -> Bool {
        guard !stopped, sessions[session.id] === session, dependencies.mcpAccessEnabled() else { return false }
        let valid = try await dependencies.httpAuthority(.validate(grantID: lease.grant.id, principal: session.principal,
            sessionID: session.id, revision: session.server.authorizationRevision)).valid
        return valid && !stopped && sessions[session.id] === session
    }
    private func initializeUpstream(_ session: MCPHTTPSession, lease: MCPHTTPLease) async throws {
        if let task = session.initialization { try await task.value; return }
        let task = Task { try await self.connect(session, lease: lease) }
        session.initialization = task
        do { try await task.value } catch { retire(session); throw error }
    }
    private func connect(_ session: MCPHTTPSession, lease: MCPHTTPLease) async throws {
        guard try await valid(session, lease: lease), let endpoint = session.server.endpointLabel.flatMap(URL.init(string:)) else { throw MCPManagementError.denied }
        let body = try JSONSerialization.data(withJSONObject: ["jsonrpc":"2.0", "id":"authsia-initialize", "method":"initialize",
            "params":["protocolVersion":session.version, "capabilities":[:], "clientInfo":["name":"authsia", "version":"1.0"]]])
        let (bytes,response) = try await session.connection.request(endpoint: endpoint, method: "POST", body: body,
            version: session.version, sessionID: nil, headers: lease.headers)
        let data = try await MCPHTTPUpstreamConnection.collect(bytes, response: response)
        guard response.statusCode == 200,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let result = object["result"] as? [String: Any], result["protocolVersion"] as? String == session.version,
              sessions[session.id] === session else { throw MCPManagementError.unavailable }
        if let id = response.value(forHTTPHeaderField: "MCP-Session-Id") {
            guard !id.isEmpty, id.utf8.count <= 256, id.utf8.allSatisfy({ (0x21...0x7e).contains($0) }) else { throw MCPManagementError.invalidRequest }
            session.upstreamID = id
        }
        let initialized = Data(#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.utf8)
        guard try await valid(session, lease: lease) else { throw MCPManagementError.denied }
        let (notification, status) = try await session.connection.request(endpoint: endpoint, method: "POST", body: initialized,
            version: session.version, sessionID: session.upstreamID, headers: lease.headers)
        notification.task.cancel()
        guard (200...299).contains(status.statusCode) else { throw MCPManagementError.unavailable }
    }
    private func forward(_ session: MCPHTTPSession, method: String, body: Data?, lease: MCPHTTPLease,
                         invocation: UUID?, tool: String?, requestKey: String? = nil, rpcID: String? = nil) async throws -> MCPHTTPResponse {
        guard try await valid(session, lease: lease), let endpoint = session.server.endpointLabel.flatMap(URL.init(string:)) else { throw MCPManagementError.denied }
        if let requestKey, session.cancelled.contains(requestKey) { throw CancellationError() }
        let task = Task { try await session.connection.request(endpoint: endpoint, method: method, body: body,
            version: session.version, sessionID: session.upstreamID, headers: lease.headers) }
        if let requestKey { session.pendingRequests[requestKey] = task }
        let (bytes,response) = try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
        if let requestKey { session.pendingRequests.removeValue(forKey: requestKey) }
        guard (200...299).contains(response.statusCode) else { bytes.task.cancel(); throw MCPManagementError.unavailable }
        let streamID = UUID(); session.streams[streamID] = bytes.task
        if let requestKey {
            session.requestTasks[requestKey] = bytes.task
            if session.cancelled.contains(requestKey) { bytes.task.cancel(); throw CancellationError() }
        }
        let sse = response.value(forHTTPHeaderField: "Content-Type")?.hasPrefix("text/event-stream") == true
        guard sse || response.value(forHTTPHeaderField: "Content-Type")?.hasPrefix("application/json") == true else {
            bytes.task.cancel(); throw MCPManagementError.unsupported
        }
        return MCPHTTPResponse(status: response.statusCode,
            headers: HTTPHeaders([("Content-Type", sse ? "text/event-stream" : "application/json"), ("MCP-Session-Id", session.id)]),
            stream: { send in
                do {
                    var decoder = MCPHTTPSSEDecoder(), json = Data()
                    var terminal: MCPHTTPActivityOutcome?
                    for try await byte in bytes {
                        if sse {
                            if let data = try decoder.append(byte), !data.isEmpty {
                                terminal = try await self.emit(data, session: session, lease: lease, sse: true, rpcID: rpcID, send: send)
                                if terminal != nil { break }
                            }
                        } else {
                            guard json.count < 4_194_304 else { throw MCPManagementError.busy }; json.append(byte)
                        }
                    }
                    if !sse { terminal = try await self.emit(json, session: session, lease: lease, sse: false, rpcID: rpcID, send: send) }
                    if tool != nil, terminal == nil { throw MCPManagementError.unavailable }
                    bytes.task.cancel()
                    if let invocation, let tool { try await self.record(session, tool: tool, id: invocation, outcome: terminal ?? .upstreamUnavailable) }
                    await self.finished(session, streamID: streamID, requestKey: requestKey)
                } catch {
                    bytes.task.cancel()
                    let cancelled = error is CancellationError || (error as? URLError)?.code == .cancelled
                    if let invocation, let tool { try? await self.record(session, tool: tool, id: invocation, outcome: cancelled ? .cancelled : .upstreamUnavailable) }
                    if let reason = error as? MCPManagementError, [.denied, .stale, .invalidRequest, .busy].contains(reason) { await self.retire(session) }
                    else { await self.finished(session, streamID: streamID, requestKey: requestKey) }
                    throw error
                }
            }, disconnect: {
                bytes.task.cancel()
                await self.disconnected(session, streamID: streamID, requestKey: requestKey, invocation: invocation, tool: tool)
            })
    }
    private func emit(_ data: Data, session: MCPHTTPSession, lease: MCPHTTPLease, sse: Bool, rpcID: String?,
                      send: @escaping @Sendable (Data) async throws -> Void) async throws -> MCPHTTPActivityOutcome? {
        guard try await valid(session, lease: lease),
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw MCPManagementError.denied }
        if let method = object["method"] as? String {
            guard object["id"] == nil, method == "notifications/progress" else { throw MCPManagementError.unsupported }
        } else if let rpcID {
            guard object["id"].map({ String(describing: $0) }) == rpcID else { throw MCPManagementError.invalidRequest }
        }
        let masked = try MCPHTTPMessageMasker(secrets: lease.secrets).mask(data)
        session.emittedBytes += masked.count
        guard session.emittedBytes <= 16_777_216 else { throw MCPManagementError.busy }
        try await send(sse ? Data("data: ".utf8) + masked + Data("\n\n".utf8) : masked)
        if object["error"] != nil || (object["result"] as? [String: Any])?["isError"] as? Bool == true { return .mcpError }
        return object["result"] != nil ? .succeeded : nil
    }
    private func record(_ session: MCPHTTPSession, tool: String, id: UUID, outcome: MCPHTTPActivityOutcome) async throws {
        do { try await dependencies.recordHTTPActivity(MCPHTTPActivityEvent(id: id, serverID: session.server.id,
            serverName: session.server.displayName, workspacePath: session.server.identity.workspacePath,
            toolName: tool, outcome: outcome, attribution: session.principal.binding.client.rawValue)) }
        catch { throw MCPManagementError.auditUnavailable }
    }
    private func disconnected(_ session: MCPHTTPSession, streamID: UUID, requestKey: String?, invocation: UUID?, tool: String?) async {
        guard session.streams[streamID] != nil else { return }
        finished(session, streamID: streamID, requestKey: requestKey)
        if let invocation, let tool { try? await record(session, tool: tool, id: invocation, outcome: .cancelled) }
    }
    private func finished(_ session: MCPHTTPSession, streamID: UUID, requestKey: String?) {
        session.streams.removeValue(forKey: streamID)
        if let requestKey { session.inFlight.remove(requestKey); session.requestTasks.removeValue(forKey: requestKey); session.cancelled.remove(requestKey) }
    }
    private func prune() {
        for session in Array(sessions.values) where session.lastUsed < Date().addingTimeInterval(-600) { retire(session) }
    }
    private func retire(_ session: MCPHTTPSession) {
        sessions.removeValue(forKey: session.id)
        session.lifetime?.cancel(); session.initialization?.cancel()
        session.streams.values.forEach { $0.cancel() }; session.connection.close()
        session.pendingRequests.values.forEach { $0.cancel() }
        if let grant = session.grant { Task { _ = try? await dependencies.httpAuthority(.revoke(grantID: grant.id)) } }
    }
    func shutdown() { stopped = true; for session in Array(sessions.values) { retire(session) } }
    func revoke(_ grantID: UUID) async throws {
        for session in Array(sessions.values) where session.grant?.id == grantID { retire(session) }
        _ = try await dependencies.httpAuthority(.revoke(grantID: grantID))
    }
    func revoke(_ binding: MCPHTTPAssociationBinding) async throws {
        for session in Array(sessions.values) where session.principal.binding == binding { retire(session) }
        _ = try await dependencies.httpAuthority(.revokeBinding(binding))
    }
}

private final class MCPHTTPHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart
    private let router: MCPHTTPRouter
    private var head: HTTPRequestHead?
    private var body = Data()
    private var processing = false
    private var work: Task<Void, Never>?
    init(router: MCPHTTPRouter) { self.router = router }
    func channelInactive(context: ChannelHandlerContext) { work?.cancel(); context.fireChannelInactive() }
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let value):
            guard !processing, head == nil else { context.close(promise: nil); return }
            head = value; body.removeAll(keepingCapacity: true)
        case .body(var chunk):
            guard body.count + chunk.readableBytes <= 4_194_304 else { context.close(promise: nil); return }
            body.append(contentsOf: chunk.readBytes(length: chunk.readableBytes) ?? [])
        case .end:
            guard let head else { return }; self.head = nil; processing = true
            let request = MCPHTTPRequest(method: head.method.rawValue, uri: head.uri, headers: head.headers, body: body)
            body.removeAll(keepingCapacity: false)
            let channel = context.channel
            work = Task { [router] in
                var disconnect: (@Sendable () async -> Void)?
                do {
                    var response = await router.handle(request)
                    disconnect = response.disconnect
                    response.headers.add(name: "Cache-Control", value: "no-store")
                    response.headers.add(name: "Connection", value: "close")
                    if response.stream != nil { response.headers.add(name: "Transfer-Encoding", value: "chunked") }
                    else { response.headers.add(name: "Content-Length", value: String(response.body.count)) }
                    try await channel.writeAndFlush(HTTPServerResponsePart.head(HTTPResponseHead(version: .http1_1,
                        status: HTTPResponseStatus(statusCode: response.status), headers: response.headers))).get()
                    let send: @Sendable (Data) async throws -> Void = { data in
                        try Task.checkCancellation()
                        var buffer = channel.allocator.buffer(capacity: data.count); buffer.writeBytes(data)
                        try await channel.writeAndFlush(HTTPServerResponsePart.body(.byteBuffer(buffer))).get()
                    }
                    if let stream = response.stream { try await stream(send) } else { try await send(response.body) }
                    try await channel.writeAndFlush(HTTPServerResponsePart.end(nil)).get()
                } catch { await disconnect?() }
                try? await channel.close().get()
            }
        }
    }
}
#endif
