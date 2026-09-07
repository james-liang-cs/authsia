#if os(macOS)
import Foundation
import AuthenticatorBridge

enum MCPManagerEndpointRegistryError: Error, Equatable {
    case unauthorized
    case unavailable
}

/// Process-bound broker for the GUI's anonymous manager listener endpoint.
public final class MCPManagerEndpointRegistry: @unchecked Sendable {
    public static let shared = MCPManagerEndpointRegistry()

    private let lock = NSLock()
    private var registration: Registration?

    private struct Registration {
        let endpoint: NSXPCListenerEndpoint
        let ownerProcessID: Int32
        let connectionID: ObjectIdentifier
    }

    public init() {}

    func register(
        endpoint: NSXPCListenerEndpoint,
        caller: CallerIdentity?,
        connectionID: ObjectIdentifier
    ) throws {
        guard let caller, caller.bundleIdentifier == "app.authsia" else {
            throw MCPManagerEndpointRegistryError.unauthorized
        }
        lock.lock()
        registration = Registration(endpoint: endpoint, ownerProcessID: caller.pid, connectionID: connectionID)
        lock.unlock()
    }

    func endpoint(caller: CallerIdentity?, cliAccessEnabled: Bool) throws -> NSXPCListenerEndpoint {
        guard let caller else {
            throw MCPManagerEndpointRegistryError.unauthorized
        }
        switch caller.bundleIdentifier {
        case "app.authsia":
            break
        case "authsia", "com.authsia.cli":
            guard cliAccessEnabled else {
                throw MCPManagerEndpointRegistryError.unauthorized
            }
        default:
            throw MCPManagerEndpointRegistryError.unauthorized
        }

        lock.lock()
        let endpoint = registration?.endpoint
        lock.unlock()
        guard let endpoint else {
            throw MCPManagerEndpointRegistryError.unavailable
        }
        return endpoint
    }

    func clear(caller: CallerIdentity?, connectionID: ObjectIdentifier) throws {
        guard let caller, caller.bundleIdentifier == "app.authsia" else {
            throw MCPManagerEndpointRegistryError.unauthorized
        }
        clear(connectionID: connectionID)
    }

    func clear(connectionID: ObjectIdentifier) {
        lock.lock()
        if registration?.connectionID == connectionID {
            registration = nil
        }
        lock.unlock()
    }
}
#endif
