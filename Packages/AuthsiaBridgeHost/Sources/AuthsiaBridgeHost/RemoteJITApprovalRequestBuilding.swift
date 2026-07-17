import AuthenticatorBridge

@MainActor
public protocol RemoteJITApprovalRequestBuilding: AnyObject {
    func buildRequests(
        for inputs: [RemoteJITApprovalDescriptorInput]
    ) async throws -> [RemoteJITApprovalRequest]
}
