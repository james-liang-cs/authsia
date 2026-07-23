#if os(macOS)
import AuthenticatorBridge

public enum BridgeRequestPolicy {
    public static func denial(for request: BridgeRequest) -> BridgeErrorPayload? {
        if requiresCurrentSecurityProtocol(request.type),
           request.context.securityProtocolVersion != BridgeContext.securityProtocolVersion {
            return BridgeErrorPayload(
                code: .policyDenied,
                message: "Authsia CLI and app security protocols do not match. Upgrade both before retrying."
            )
        }
        if request.context.isSSH {
            return BridgeErrorPayload(code: .policyDenied, message: "SSH access not allowed")
        }
        if request.context.isCI {
            return BridgeErrorPayload(code: .policyDenied, message: "CI environment access not allowed")
        }
        // Piped output is needed by the Chrome native host, jq, and local scripts.
        // SSH and CI checks are the security boundaries.
        return nil
    }

    private static func requiresCurrentSecurityProtocol(_ type: BridgeRequestType) -> Bool {
        switch type {
        case .list, .workspaceMetadata,
             .getOTP, .getPassword, .getAPIKey, .getCertificate, .getNote, .getSSH,
             .createAccess, .validateAccess, .agentJITPreflight:
            return true
        default:
            return false
        }
    }
}
#endif
