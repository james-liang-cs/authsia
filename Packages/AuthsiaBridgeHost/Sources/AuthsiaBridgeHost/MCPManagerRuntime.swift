#if os(macOS)
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import Security
import CryptoKit
@preconcurrency import AuthenticatorBridge

final class MCPNIOContextBox: @unchecked Sendable {
    let value: ChannelHandlerContext
    init(_ value: ChannelHandlerContext) { self.value = value }
}

public struct MCPManagerRuntimeDependencies: @unchecked Sendable {
    public var registrySnapshot: () throws -> MCPRegistrySnapshot
    public var portalDocument: () -> String
    public var mcpAccessEnabled: () -> Bool
    public var httpAuthority: @Sendable (MCPHTTPAuthorityCommand) async throws -> MCPHTTPAuthorityReply
    public var prepareOperation: @Sendable (MCPManagementOperationRequest) async throws -> MCPPreparedManagementChange
    public var confirmOperation: @Sendable (MCPManagementOperationView) async -> Bool
    public var credentialOptions: @Sendable () async throws -> [MCPCredentialOption]
    public var listGrants: @Sendable () async throws -> [MCPManagerGrantView]
    public var loadHTTPActivity: @Sendable (MCPActivityQuery) -> MCPActivityPage
    public var recordHTTPActivity: @Sendable (MCPHTTPActivityEvent) async throws -> Void
    public var openAccessCenter: @Sendable () async -> Bool

    public init(
        registrySnapshot: @escaping () throws -> MCPRegistrySnapshot,
        portalDocument: @escaping () -> String,
        mcpAccessEnabled: @escaping () -> Bool,
        httpAuthority: @escaping @Sendable (MCPHTTPAuthorityCommand) async throws -> MCPHTTPAuthorityReply = { _ in throw MCPManagementError.denied },
        prepareOperation: @escaping @Sendable (MCPManagementOperationRequest) async throws -> MCPPreparedManagementChange = { _ in throw MCPManagementError.unsupported },
        confirmOperation: @escaping @Sendable (MCPManagementOperationView) async -> Bool = { _ in false },
        credentialOptions: @escaping @Sendable () async throws -> [MCPCredentialOption] = { [] },
        listGrants: @escaping @Sendable () async throws -> [MCPManagerGrantView] = { [] },
        loadHTTPActivity: @escaping @Sendable (MCPActivityQuery) -> MCPActivityPage = { _ in .unavailable("Activity is unavailable.") },
        recordHTTPActivity: @escaping @Sendable (MCPHTTPActivityEvent) async throws -> Void = { _ in throw MCPManagementError.auditUnavailable },
        openAccessCenter: @escaping @Sendable () async -> Bool = { false }
    ) {
        self.registrySnapshot = registrySnapshot
        self.portalDocument = portalDocument
        self.mcpAccessEnabled = mcpAccessEnabled
        self.httpAuthority = httpAuthority
        self.prepareOperation = prepareOperation
        self.confirmOperation = confirmOperation
        self.credentialOptions = credentialOptions
        self.listGrants = listGrants
        self.loadHTTPActivity = loadHTTPActivity
        self.recordHTTPActivity = recordHTTPActivity
        self.openAccessCenter = openAccessCenter
    }
}

public actor MCPManagerRuntime {
    public static let portalHost = "127.0.0.1"
    public static let portalPort = 8787
    public static let portalURL = "http://127.0.0.1:8787"

    private let dependencies: MCPManagerRuntimeDependencies
    private var server: MCPManagerPortalServer?
    private var httpProxy: MCPHTTPProxyServer?
    private var state: MCPManagerRunState = .stopped
    private var failureCode: String?
    private var lifecycleBusy = false
    private var lifecycleWaiters: [CheckedContinuation<Void, Never>] = []

    public init(dependencies: MCPManagerRuntimeDependencies) {
        self.dependencies = dependencies
    }

    public func start() async throws -> URL {
        await acquireLifecycle()
        defer { releaseLifecycle() }
        try Task.checkCancellation()
        return try await startListeners()
    }

    private func startListeners() async throws -> URL {
        if state == .running, let server {
            return try server.makeBootstrapURL()
        }
        state = .starting
        failureCode = nil
        let next = MCPManagerPortalServer(dependencies: dependencies)
        do {
            try await next.start(host: Self.portalHost, port: Self.portalPort)
            let proxy = MCPHTTPProxyServer(dependencies: dependencies)
            try await proxy.start(host: Self.portalHost, port: 8788)
            server = next
            httpProxy = proxy
            state = .running
            return try next.makeBootstrapURL()
        } catch {
            state = .failed
            failureCode = Self.failureCode(for: error)
            try? await next.stop()
            throw error
        }
    }

    public func stop() async {
        await acquireLifecycle()
        defer { releaseLifecycle() }
        await stopListeners()
    }

    private func stopListeners() async {
        guard state != .stopped else { return }
        state = .stopping
        if let server {
            try? await server.stop()
        }
        if let httpProxy {
            try? await httpProxy.stop()
        }
        server = nil
        httpProxy = nil
        failureCode = nil
        state = .stopped
    }

    public func restart() async throws -> URL {
        await acquireLifecycle()
        defer { releaseLifecycle() }
        await stopListeners()
        return try await startListeners()
    }

    private func acquireLifecycle() async {
        if !lifecycleBusy {
            lifecycleBusy = true
            return
        }
        await withCheckedContinuation { lifecycleWaiters.append($0) }
    }

    private func releaseLifecycle() {
        if lifecycleWaiters.isEmpty { lifecycleBusy = false }
        else { lifecycleWaiters.removeFirst().resume() }
    }

    public func status() -> MCPManagerStatusPayload {
        MCPManagerStatusPayload(
            state: state,
            portalURL: state == .running ? Self.portalURL : nil,
            registryLoaded: state == .running,
            stdioProxyAvailable: true,
            httpProxyAvailable: state == .running,
            failureCode: failureCode
        )
    }
    public func revokeHTTPGrant(_ id: UUID) async throws {
        guard let httpProxy else { throw MCPManagementError.unavailable }
        try await httpProxy.revoke(id)
    }
    public func revokeHTTPBinding(_ binding: MCPHTTPAssociationBinding) async throws {
        if let httpProxy { try await httpProxy.revoke(binding) }
        else { _ = try await dependencies.httpAuthority(.revokeBinding(binding)) }
    }

    private static func failureCode(for error: Error) -> String {
        return "portalUnavailable"
    }
}

private final class MCPManagerPortalServer: @unchecked Sendable {
    private let dependencies: MCPManagerRuntimeDependencies
    private let sessions = MCPPortalSessionStore()
    private var group: MultiThreadedEventLoopGroup?
    private var channel: Channel?
    private let children = MCPHTTPChannels()

    init(dependencies: MCPManagerRuntimeDependencies) {
        self.dependencies = dependencies
    }

    func start(host: String, port: Int) async throws {
        let nextGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        do {
            let router = MCPPortalRouter(dependencies: dependencies, sessions: sessions)
            let children = children
            let bootstrap = ServerBootstrap(group: nextGroup)
                .serverChannelOption(ChannelOptions.backlog, value: 16)
                .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
                .childChannelInitializer { channel in
                    guard children.insert(channel) else { return channel.close() }
                    return channel.pipeline.configureHTTPServerPipeline().flatMap {
                        channel.pipeline.addHandler(MCPPortalHTTPHandler(router: router))
                    }
                }
                .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)

            let nextChannel = try await bootstrap.bind(host: host, port: port).get()
            group = nextGroup
            channel = nextChannel
        } catch {
            try await nextGroup.shutdownGracefully()
            throw error
        }
    }

    func stop() async throws {
        sessions.invalidateAll()
        let activeChannel = channel
        let activeGroup = group
        channel = nil
        group = nil
        try await activeChannel?.close().get()
        await children.close()
        try await activeGroup?.shutdownGracefully()
    }

    func makeBootstrapURL() throws -> URL {
        let capability = try sessions.issueBootstrapCapability()
        guard let url = URL(string: "\(MCPManagerRuntime.portalURL)/#bootstrap=\(capability)") else {
            throw MCPPortalSessionError.randomUnavailable
        }
        return url
    }
}

private enum MCPPortalSessionError: Error {
    case randomUnavailable
    case invalidCapability
}

private final class MCPPortalSessionStore: @unchecked Sendable {
    struct ExchangeResult {
        let sessionID: String
        let proof: String
    }

    private struct Session {
        let proof: String
        let createdAt: Date
        var lastUsedAt: Date
    }

    private let lock = NSLock()
    private var capabilities: [String: Date] = [:]
    private var sessions: [String: Session] = [:]
    private let bootstrapLifetime: TimeInterval = 60
    private let idleLifetime: TimeInterval = 30 * 60
    private let absoluteLifetime: TimeInterval = 8 * 60 * 60

    func issueBootstrapCapability(now: Date = Date()) throws -> String {
        let value = try Self.randomValue()
        lock.lock()
        purgeExpired(now: now)
        capabilities[value] = now.addingTimeInterval(bootstrapLifetime)
        lock.unlock()
        return value
    }

    func exchange(_ capability: String, now: Date = Date()) throws -> ExchangeResult {
        lock.lock()
        purgeExpired(now: now)
        guard let expiry = capabilities.removeValue(forKey: capability), expiry > now else {
            lock.unlock()
            throw MCPPortalSessionError.invalidCapability
        }
        lock.unlock()

        let sessionID = try Self.randomValue()
        let proof = try Self.randomValue()
        lock.lock()
        sessions[sessionID] = Session(proof: proof, createdAt: now, lastUsedAt: now)
        lock.unlock()
        return ExchangeResult(sessionID: sessionID, proof: proof)
    }

    func authenticate(sessionID: String?, proof: String?, now: Date = Date()) -> Bool {
        guard let sessionID, let proof else { return false }
        lock.lock()
        defer { lock.unlock() }
        purgeExpired(now: now)
        guard var session = sessions[sessionID], Self.constantTimeEqual(session.proof, proof) else {
            return false
        }
        session.lastUsedAt = now
        sessions[sessionID] = session
        return true
    }

    func logout(sessionID: String?) {
        guard let sessionID else { return }
        lock.lock()
        sessions.removeValue(forKey: sessionID)
        lock.unlock()
    }

    func invalidateAll() {
        lock.lock()
        capabilities.removeAll()
        sessions.removeAll()
        lock.unlock()
    }

    private func purgeExpired(now: Date) {
        capabilities = capabilities.filter { $0.value > now }
        sessions = sessions.filter {
            now.timeIntervalSince($0.value.lastUsedAt) < idleLifetime
                && now.timeIntervalSince($0.value.createdAt) < absoluteLifetime
        }
    }

    private static func randomValue() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw MCPPortalSessionError.randomUnavailable
        }
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func constantTimeEqual(_ lhs: String, _ rhs: String) -> Bool {
        let left = Array(lhs.utf8)
        let right = Array(rhs.utf8)
        var difference = UInt8(left.count == right.count ? 0 : 1)
        let count = max(left.count, right.count)
        for index in 0..<count {
            difference |= (index < left.count ? left[index] : 0)
                ^ (index < right.count ? right[index] : 0)
        }
        return difference == 0
    }
}

private struct MCPPortalRequest {
    let method: HTTPMethod
    let uri: String
    let headers: HTTPHeaders
    let body: Data
}

private struct MCPPortalResponse {
    let status: HTTPResponseStatus
    var headers: HTTPHeaders
    let body: Data

    static func json(_ status: HTTPResponseStatus, _ value: Any) -> Self {
        let data = (try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])) ?? Data()
        return Self(
            status: status,
            headers: HTTPHeaders([("Content-Type", "application/json; charset=utf-8")]),
            body: data
        )
    }
}

private final class MCPPortalRouter: @unchecked Sendable {
    private let dependencies: MCPManagerRuntimeDependencies
    private let sessions: MCPPortalSessionStore
    private let operations = MCPManagementOperationStore(audit: MCPManagementAuditStore())
    private let encoder = JSONEncoder()
    private let allowedHost = "127.0.0.1:8787"
    private let allowedOrigin = "http://127.0.0.1:8787"

    init(dependencies: MCPManagerRuntimeDependencies, sessions: MCPPortalSessionStore) {
        self.dependencies = dependencies
        self.sessions = sessions
        encoder.outputFormatting = [.sortedKeys]
    }

    func handle(_ request: MCPPortalRequest) async -> MCPPortalResponse {
        guard request.headers.first(name: "Host") == allowedHost else {
            return .json(.forbidden, ["code": "invalidHost"])
        }
        let path = request.uri.split(separator: "?", maxSplits: 1).first.map(String.init) ?? request.uri
        if path == "/" && request.method == .GET {
            return documentResponse()
        }
        guard path.hasPrefix("/api/v1/") else {
            return .json(.notFound, ["code": "notFound"])
        }
        guard validOrigin(request.headers, method: request.method) else {
            return .json(.forbidden, ["code": "invalidOrigin"])
        }
        if path == "/api/v1/session/exchange" && request.method == .POST {
            return exchange(request)
        }

        let sessionID = Self.cookie(named: "authsia_mcp_session", in: request.headers)
        let proof = request.headers.first(name: "X-Authsia-Proof")
        guard sessions.authenticate(sessionID: sessionID, proof: proof) else {
            return .json(.unauthorized, ["code": "authenticationRequired"])
        }

        switch (request.method, path) {
        case (.POST, "/api/v1/session/logout"):
            sessions.logout(sessionID: sessionID)
            var response = MCPPortalResponse.json(.ok, ["loggedOut": true])
            response.headers.add(
                name: "Set-Cookie",
                value: "authsia_mcp_session=; HttpOnly; SameSite=Strict; Path=/api/v1; Max-Age=0"
            )
            return response
        case (.GET, "/api/v1/status"):
            return .json(.ok, [
                "state": "running",
                "registryLoaded": true,
                "stdioProxyAvailable": true,
                "httpProxyAvailable": true,
                "mcpAccessEnabled": dependencies.mcpAccessEnabled(),
            ] as [String: Any])
        case (.GET, "/api/v1/registry"):
            do {
                return encodedResponse(try dependencies.registrySnapshot())
            } catch {
                return .json(.serviceUnavailable, ["code": "registryUnavailable"])
            }
        case (.GET, "/api/v1/activity"):
            return encodedResponse(dependencies.loadHTTPActivity(MCPActivityQuery.parse(uri: request.uri)))
        case (.POST, "/api/v1/operations"):
            do {
                guard let owner = sessionID else { throw MCPManagementError.denied }
                let command = try JSONDecoder().decode(MCPManagementOperationRequest.self, from: request.body)
                let change = try await dependencies.prepareOperation(command)
                return encodedResponse(try await operations.prepare(owner: owner, kind: command.kind, change: change))
            } catch {
                let failure = error as? MCPManagementError ?? .invalidRequest
                return .json(.badRequest, ["code": failure.rawValue, "message": failure.localizedDescription])
            }
        case (.GET, "/api/v1/credentials"):
            do { return encodedResponse(try await dependencies.credentialOptions()) }
            catch { return .json(.serviceUnavailable, ["code":"credentialsUnavailable"]) }
        case (.GET, "/api/v1/grants"):
            do { return encodedResponse(try await dependencies.listGrants()) }
            catch { return .json(.serviceUnavailable, ["code":"grantsUnavailable"]) }
        case (.POST, "/api/v1/open-access-center"):
            return encodedResponse(["opened": await dependencies.openAccessCenter()])
        default:
            do {
                if request.method == .GET, path.hasPrefix("/api/v1/servers/") {
                    let id = String(path.dropFirst("/api/v1/servers/".count))
                    guard let server = try dependencies.registrySnapshot().servers.first(where: { $0.id == id }) else { throw MCPManagementError.notFound }
                    return encodedResponse(server)
                }
                let parts = path.split(separator: "/")
                if parts.count >= 4, parts[2] == "operations", let id = UUID(uuidString: String(parts[3])), let owner = sessionID {
                    if request.method == .GET, parts.count == 4 { return encodedResponse(try await operations.get(id, owner: owner)) }
                    if request.method == .POST, parts.count == 5, parts[4] == "request-confirmation" {
                        let sessions = sessions
                        let view = try await operations.confirm(id, owner: owner, present: dependencies.confirmOperation,
                            sessionValid: { sessions.authenticate(sessionID: owner, proof: proof) })
                        return encodedResponse(view)
                    }
                }
                return .json(.notFound, ["code": "notFound"])
            } catch { return .json(.badRequest, ["code": (error as? MCPManagementError ?? .invalidRequest).rawValue]) }
        }
    }

    private func exchange(_ request: MCPPortalRequest) -> MCPPortalResponse {
        guard request.body.count <= 4_096,
              let object = try? JSONSerialization.jsonObject(with: request.body) as? [String: Any],
              let capability = object["capability"] as? String else {
            return .json(.badRequest, ["code": "invalidRequest"])
        }
        do {
            let exchanged = try sessions.exchange(capability)
            var response = MCPPortalResponse.json(.ok, ["proof": exchanged.proof])
            response.headers.add(
                name: "Set-Cookie",
                value: "authsia_mcp_session=\(exchanged.sessionID); HttpOnly; SameSite=Strict; Path=/api/v1; Max-Age=28800"
            )
            return response
        } catch {
            return .json(.unauthorized, ["code": "invalidCapability"])
        }
    }

    private func documentResponse() -> MCPPortalResponse {
        let document = dependencies.portalDocument()
        let regex = try! NSRegularExpression(pattern: "<script>([\\s\\S]*?)</script>")
        let range = NSRange(document.startIndex..., in: document)
        let hashes = regex.matches(in: document, range: range).compactMap { match -> String? in
            guard let range = Range(match.range(at: 1), in: document) else { return nil }
            return "'sha256-" + Data(SHA256.hash(data: Data(document[range].utf8))).base64EncodedString() + "'"
        }.joined(separator: " ")
        return MCPPortalResponse(
            status: .ok,
            headers: HTTPHeaders([
                ("Content-Type", "text/html; charset=utf-8"),
                ("Cache-Control", "no-store"),
                ("Content-Security-Policy", "default-src 'none'; script-src \(hashes.isEmpty ? "'none'" : hashes); style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
                ("Referrer-Policy", "no-referrer"),
                ("X-Content-Type-Options", "nosniff"),
            ]),
            body: Data(document.utf8)
        )
    }

    private func encodedResponse<T: Encodable>(_ value: T) -> MCPPortalResponse {
        guard let data = try? encoder.encode(value) else {
            return .json(.internalServerError, ["code": "encodingFailed"])
        }
        return MCPPortalResponse(
            status: .ok,
            headers: HTTPHeaders([("Content-Type", "application/json; charset=utf-8")]),
            body: data
        )
    }

    private func validOrigin(_ headers: HTTPHeaders, method: HTTPMethod) -> Bool {
        if let origin = headers.first(name: "Origin") {
            return origin == allowedOrigin
        }
        // Read requests still require both the cookie and the unguessable proof.
        // Browsers omit Origin on same-origin GET, and our no-referrer policy
        // intentionally omits Referer. Never weaken the mutation Origin check.
        return method == .GET && headers.first(name: "Sec-Fetch-Site") != "cross-site"
    }

    private static func cookie(named name: String, in headers: HTTPHeaders) -> String? {
        for header in headers[canonicalForm: "cookie"] {
            for pair in header.split(separator: ";") {
                let parts = pair.split(separator: "=", maxSplits: 1).map {
                    $0.trimmingCharacters(in: .whitespaces)
                }
                if parts.count == 2, parts[0] == name {
                    return parts[1]
                }
            }
        }
        return nil
    }
}

private final class MCPPortalHTTPHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let router: MCPPortalRouter
    private var head: HTTPRequestHead?
    private var body = ByteBuffer()
    private let maximumBodyBytes = 1_048_576

    init(router: MCPPortalRouter) {
        self.router = router
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let requestHead):
            head = requestHead
            body.clear()
        case .body(var buffer):
            guard body.readableBytes + buffer.readableBytes <= maximumBodyBytes else {
                write(
                    MCPPortalResponse.json(.payloadTooLarge, ["code": "requestTooLarge"]),
                    keepAlive: false,
                    context: context
                )
                head = nil
                body.clear()
                return
            }
            body.writeBuffer(&buffer)
        case .end:
            guard let head else { return }
            self.head = nil
            let request = MCPPortalRequest(
                method: head.method,
                uri: head.uri,
                headers: head.headers,
                body: Data(body.readBytes(length: body.readableBytes) ?? [])
            )
            body.clear()
            let contextBox = MCPNIOContextBox(context)
            context.eventLoop.makeFutureWithTask { [router] in
                await router.handle(request)
            }.whenSuccess { response in
                self.write(response, keepAlive: head.isKeepAlive, context: contextBox.value)
            }
        }
    }

    private func write(
        _ response: MCPPortalResponse,
        keepAlive: Bool,
        context: ChannelHandlerContext
    ) {
        var headers = response.headers
        headers.replaceOrAdd(name: "Content-Length", value: String(response.body.count))
        headers.replaceOrAdd(name: "Cache-Control", value: "no-store")
        if keepAlive {
            headers.replaceOrAdd(name: "Connection", value: "keep-alive")
        } else {
            headers.replaceOrAdd(name: "Connection", value: "close")
        }
        let head = HTTPResponseHead(version: .http1_1, status: response.status, headers: headers)
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        var buffer = context.channel.allocator.buffer(capacity: response.body.count)
        buffer.writeBytes(response.body)
        context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
        let contextBox = MCPNIOContextBox(context)
        context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in
            if !keepAlive {
                contextBox.value.close(promise: nil)
            }
        }
    }
}
#endif
