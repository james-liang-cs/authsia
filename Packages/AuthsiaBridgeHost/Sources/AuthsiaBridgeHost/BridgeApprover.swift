import AuthenticatorBridge

@MainActor
public protocol BridgeApprover {
    func requestApproval(
        prompt: String,
        command: BridgeRequestType,
        itemLabel: String?,
        field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?
    ) async -> Bool
}
