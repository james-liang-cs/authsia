#if os(macOS)
import Foundation
@preconcurrency import AuthenticatorBridge

extension XPCRequestHandler {
    public func registerMCPManagerEndpoint(
        _ endpoint: NSXPCListenerEndpoint,
        _ rawReply: @escaping (NSError?) -> Void
    ) {
        do {
            guard let connection = NSXPCConnection.current() else { throw MCPManagerEndpointRegistryError.unauthorized }
            try mcpManagerEndpointRegistry.register(
                endpoint: endpoint,
                caller: callerIdentityProvider(),
                connectionID: ObjectIdentifier(connection)
            )
            rawReply(nil)
        } catch {
            rawReply(makeNSError(
                code: .policyDenied,
                message: "MCP manager registration is restricted to Authsia.app"
            ))
        }
    }

    public func mcpManagerEndpoint(
        _ rawReply: @escaping (NSXPCListenerEndpoint?, NSError?) -> Void
    ) {
        do {
            let endpoint = try mcpManagerEndpointRegistry.endpoint(
                caller: callerIdentityProvider(),
                cliAccessEnabled: BridgeSettings.isCliAccessEnabled()
            )
            rawReply(endpoint, nil)
        } catch MCPManagerEndpointRegistryError.unavailable {
            rawReply(nil, makeNSError(
                code: .appUnavailable,
                message: "Authsia MCP Manager is not running"
            ))
        } catch {
            rawReply(nil, makeNSError(
                code: .policyDenied,
                message: "MCP manager access is restricted to Authsia.app and the Authsia CLI"
            ))
        }
    }

    public func clearMCPManagerEndpoint(_ rawReply: @escaping (NSError?) -> Void) {
        do {
            guard let connection = NSXPCConnection.current() else { throw MCPManagerEndpointRegistryError.unauthorized }
            try mcpManagerEndpointRegistry.clear(caller: callerIdentityProvider(), connectionID: ObjectIdentifier(connection))
            rawReply(nil)
        } catch {
            rawReply(makeNSError(
                code: .policyDenied,
                message: "MCP manager registration is restricted to Authsia.app"
            ))
        }
    }

    func mcpManagerConnectionDidInvalidate(connectionID: ObjectIdentifier) {
        mcpManagerEndpointRegistry.clear(connectionID: connectionID)
    }
}
#endif
