import AuthenticatorBridge

@MainActor
public protocol RemoteJITApprovalRequestBuilding: AnyObject {
    func buildRequests(
        for inputs: [RemoteJITApprovalDescriptorInput],
        agentRuntimeContext: AgentRuntimeContext?
    ) async throws -> [RemoteJITApprovalRequest]
}

extension RemoteJITApprovalRequestBuilding {
    func buildRequests(
        for inputs: [RemoteJITApprovalDescriptorInput]
    ) async throws -> [RemoteJITApprovalRequest] {
        try await buildRequests(for: inputs, agentRuntimeContext: nil)
    }
}
