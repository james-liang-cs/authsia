import Foundation
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

@MainActor
public protocol TerminalPairingApproving: BridgeApprover {
    func requestTerminalPairingApproval(_ request: TerminalPairingApprovalRequest) async -> Bool
    func finishTerminalPairing(id: UUID)
}

public extension TerminalPairingApproving {
    func finishTerminalPairing(id: UUID) {}
}

@MainActor
public protocol AgentJITDescriptorApproving: BridgeApprover {
    func requestApproval(
        prompt: String,
        command: BridgeRequestType,
        itemLabel: String?,
        field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?,
        approvalDescriptors: [AgentJITApprovalDescriptor],
        remoteRequests: [RemoteJITApprovalRequest]
    ) async -> RemoteJITApprovalOutcome
}

public extension AgentJITDescriptorApproving {
    func requestApproval(
        prompt: String,
        command: BridgeRequestType,
        itemLabel: String?,
        field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?,
        remoteRequests: [RemoteJITApprovalRequest]
    ) async -> RemoteJITApprovalOutcome {
        await requestApproval(
            prompt: prompt,
            command: command,
            itemLabel: itemLabel,
            field: field,
            callback: callback,
            approvalDescriptors: [],
            remoteRequests: remoteRequests
        )
    }
}
