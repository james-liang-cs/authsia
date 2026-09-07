import AuthenticatorBridge
import Foundation

protocol MCPManagerControlling: Sendable {
    func start(openPortal: Bool) throws -> MCPManagerStatusPayload
    func status() throws -> MCPManagerStatusPayload
    func stop() throws -> MCPManagerStatusPayload
    func restart(openPortal: Bool) throws -> MCPManagerStatusPayload
}

enum MCPManagerControlClientError: LocalizedError {
    case managerUnavailable
    case connectionFailed
    case timedOut
    case invalidResponse
    case remote(String)

    var errorDescription: String? {
        switch self {
        case .managerUnavailable:
            return "Authsia MCP Manager is not running. Run `authsia mcp start`."
        case .connectionFailed:
            return "Could not connect to Authsia MCP Manager."
        case .timedOut:
            return "Authsia MCP Manager did not respond."
        case .invalidResponse:
            return "Authsia MCP Manager returned an invalid response."
        case .remote(let message):
            return message
        }
    }
}

final class MCPManagerControlClient: MCPManagerControlling, @unchecked Sendable {
    static let shared = MCPManagerControlClient()

    private enum Action {
        case start
        case status
        case stop
        case restart
    }

    private let bridgeServiceName = "Authsia.Bridge"
    private let requestTimeout: TimeInterval
    private let startupTimeout: TimeInterval
    private let appLauncher: @Sendable () -> Bool

    init(
        requestTimeout: TimeInterval = 5,
        startupTimeout: TimeInterval = 15,
        appLauncher: @escaping @Sendable () -> Bool = {
            AuthsiaBridgeClient.shared.launchGUIForMCPManager()
        }
    ) {
        self.requestTimeout = requestTimeout
        self.startupTimeout = startupTimeout
        self.appLauncher = appLauncher
    }

    func start(openPortal: Bool) throws -> MCPManagerStatusPayload {
        try callLaunchingIfNeeded(.start, openPortal: openPortal)
    }

    func status() throws -> MCPManagerStatusPayload {
        do {
            return try call(.status, openPortal: false)
        } catch MCPManagerControlClientError.managerUnavailable {
            return MCPManagerStatusPayload(state: .stopped)
        }
    }

    func stop() throws -> MCPManagerStatusPayload {
        do {
            return try call(.stop, openPortal: false)
        } catch MCPManagerControlClientError.managerUnavailable {
            return MCPManagerStatusPayload(state: .stopped)
        }
    }

    func restart(openPortal: Bool) throws -> MCPManagerStatusPayload {
        try callLaunchingIfNeeded(.restart, openPortal: openPortal)
    }

    private func callLaunchingIfNeeded(
        _ action: Action,
        openPortal: Bool
    ) throws -> MCPManagerStatusPayload {
        do {
            return try call(action, openPortal: openPortal)
        } catch MCPManagerControlClientError.managerUnavailable {
            guard appLauncher() else {
                throw MCPManagerControlClientError.managerUnavailable
            }
            let deadline = Date().addingTimeInterval(startupTimeout)
            repeat {
                Thread.sleep(forTimeInterval: 0.1)
                if let status = try? call(action, openPortal: openPortal) {
                    return status
                }
            } while Date() < deadline
            throw MCPManagerControlClientError.managerUnavailable
        }
    }

    private func call(_ action: Action, openPortal: Bool) throws -> MCPManagerStatusPayload {
        let endpoint = try managerEndpoint()
        let connection = NSXPCConnection(listenerEndpoint: endpoint)
        connection.remoteObjectInterface = NSXPCInterface(with: MCPManagerControlProtocol.self)
        connection.resume()
        defer { connection.invalidate() }

        let request = MCPManagerControlRequest(openPortal: openPortal)
        let data = try JSONEncoder().encode(request)
        let result: Result<Data, Error> = awaitResult { finish in
            let proxy = connection.remoteObjectProxyWithErrorHandler {
                finish(.failure($0))
            } as? MCPManagerControlProtocol
            guard let proxy else {
                finish(.failure(MCPManagerControlClientError.connectionFailed))
                return
            }
            let reply: (Data?, NSError?) -> Void = { response, error in
                if let error {
                    finish(.failure(MCPManagerControlClientError.remote(error.localizedDescription)))
                } else if let response {
                    finish(.success(response))
                } else {
                    finish(.failure(MCPManagerControlClientError.invalidResponse))
                }
            }
            switch action {
            case .start: proxy.start(data, reply)
            case .status: proxy.status(data, reply)
            case .stop: proxy.stop(data, reply)
            case .restart: proxy.restart(data, reply)
            }
        }
        return try JSONDecoder().decode(MCPManagerStatusPayload.self, from: result.get())
    }

    private func managerEndpoint() throws -> NSXPCListenerEndpoint {
        let connection = NSXPCConnection(machServiceName: bridgeServiceName, options: [])
        connection.remoteObjectInterface = NSXPCInterface(with: AuthsiaBridgeXPCProtocol.self)
        connection.resume()
        defer { connection.invalidate() }

        let result: Result<NSXPCListenerEndpoint, Error> = awaitResult { finish in
            let proxy = connection.remoteObjectProxyWithErrorHandler {
                finish(.failure($0))
            } as? AuthsiaBridgeXPCProtocol
            guard let proxy else {
                finish(.failure(MCPManagerControlClientError.connectionFailed))
                return
            }
            proxy.mcpManagerEndpoint { endpoint, error in
                if let endpoint {
                    finish(.success(endpoint))
                } else if let error,
                          error.userInfo["BridgeErrorCode"] as? String == "appUnavailable" {
                    finish(.failure(MCPManagerControlClientError.managerUnavailable))
                } else if let error {
                    finish(.failure(MCPManagerControlClientError.remote(error.localizedDescription)))
                } else {
                    finish(.failure(MCPManagerControlClientError.managerUnavailable))
                }
            }
        }
        return try result.get()
    }

    private func awaitResult<Value>(
        _ operation: (@escaping (Result<Value, Error>) -> Void) -> Void
    ) -> Result<Value, Error> {
        let lock = NSLock()
        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<Value, Error>?
        operation { value in
            lock.lock()
            guard result == nil else {
                lock.unlock()
                return
            }
            result = value
            lock.unlock()
            semaphore.signal()
        }
        guard semaphore.wait(timeout: .now() + requestTimeout) == .success else {
            return .failure(MCPManagerControlClientError.timedOut)
        }
        lock.lock()
        let resolved = result
        lock.unlock()
        return resolved ?? .failure(MCPManagerControlClientError.invalidResponse)
    }
}
