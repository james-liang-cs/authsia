#if os(macOS)
import Foundation

public enum MCPManagerRunState: String, Codable, Equatable, Sendable {
    case stopped
    case starting
    case running
    case stopping
    case failed
}

public struct MCPManagerControlRequest: Codable, Equatable, Sendable {
    public let id: UUID
    public let openPortal: Bool

    public init(id: UUID = UUID(), openPortal: Bool = true) {
        self.id = id
        self.openPortal = openPortal
    }
}

public struct MCPManagerStatusPayload: Codable, Equatable, Sendable {
    public let state: MCPManagerRunState
    public let portalURL: String?
    public let registryLoaded: Bool
    public let stdioProxyAvailable: Bool
    public let httpProxyAvailable: Bool
    public let failureCode: String?

    public init(
        state: MCPManagerRunState,
        portalURL: String? = nil,
        registryLoaded: Bool = false,
        stdioProxyAvailable: Bool = true,
        httpProxyAvailable: Bool = false,
        failureCode: String? = nil
    ) {
        self.state = state
        self.portalURL = portalURL
        self.registryLoaded = registryLoaded
        self.stdioProxyAvailable = stdioProxyAvailable
        self.httpProxyAvailable = httpProxyAvailable
        self.failureCode = failureCode
    }
}

public struct MCPHTTPEnrollmentRequest: Codable, Equatable, Sendable {
    public let serverID: String
    public let client: MCPClientConfigSource

    public init(serverID: String, client: MCPClientConfigSource) {
        self.serverID = serverID
        self.client = client
    }
}

public struct MCPHTTPEnrollmentResult: Codable, Equatable, Sendable {
    public let succeeded: Bool
    public let message: String
    public let configPathLabel: String?

    public init(succeeded: Bool, message: String, configPathLabel: String? = nil) {
        self.succeeded = succeeded
        self.message = message
        self.configPathLabel = configPathLabel
    }
}

/// Narrow anonymous-XPC surface owned by the regular Authsia GUI process.
@objc public protocol MCPManagerControlProtocol {
    func start(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
    func status(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
    func stop(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
    func restart(_ request: Data, _ reply: @escaping (Data?, NSError?) -> Void)
}
#endif
