#if os(macOS)
import AuthenticatorBridge

public enum BridgeRequestPolicy {
    public static func denial(for request: BridgeRequest) -> BridgeErrorPayload? {
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
}
#endif
