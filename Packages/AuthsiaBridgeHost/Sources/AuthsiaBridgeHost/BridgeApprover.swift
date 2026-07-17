import AuthenticatorBridge

@MainActor
public protocol BridgeApprover {
    func requestApproval(
        prompt: String,
        command: BridgeRequestType,
        itemLabel: String?,
        field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?,
        remoteRequests: [RemoteJITApprovalRequest]
    ) async -> RemoteJITApprovalOutcome
}

public extension BridgeApprover {
    func requestApproval(
        prompt: String,
        command: BridgeRequestType,
        itemLabel: String?,
        field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?
    ) async -> RemoteJITApprovalOutcome {
        await requestApproval(
            prompt: prompt,
            command: command,
            itemLabel: itemLabel,
            field: field,
            callback: callback,
            remoteRequests: []
        )
    }
}
