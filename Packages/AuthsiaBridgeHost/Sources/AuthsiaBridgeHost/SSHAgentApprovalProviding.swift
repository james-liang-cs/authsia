import Foundation
import AuthenticatorBridge
import AuthenticatorCore

public enum SSHAgentApprovalDecision: Equatable, Sendable {
    case approved
    case denied
}

public struct SSHAgentRequester: Equatable {
    public let peer: SSHAgentProcessRef?
    public let instigator: SSHAgentProcessRef?
    public let ancestry: [SSHAgentProcessRef]
    public let targetHost: String?
    public let sessionScope: String?

    public init(
        peer: SSHAgentProcessRef?,
        instigator: SSHAgentProcessRef?,
        ancestry: [SSHAgentProcessRef],
        targetHost: String?,
        sessionScope: String?
    ) {
        self.peer = peer
        self.instigator = instigator
        self.ancestry = ancestry
        self.targetHost = targetHost
        self.sessionScope = sessionScope
    }
}

public struct SSHAgentApprovalRequest: Equatable {
    public let keyID: UUID
    public let keyName: String
    public let approvalPolicy: SSHKeyApprovalPolicy
    public let requester: SSHAgentRequester

    public init(
        keyID: UUID,
        keyName: String,
        approvalPolicy: SSHKeyApprovalPolicy,
        requester: SSHAgentRequester
    ) {
        self.keyID = keyID
        self.keyName = keyName
        self.approvalPolicy = approvalPolicy
        self.requester = requester
    }
}

public protocol SSHAgentApprovalProviding {
    func evaluateApproval(_ request: SSHAgentApprovalRequest) -> SSHAgentApprovalDecision
    func clearSessions()
}
