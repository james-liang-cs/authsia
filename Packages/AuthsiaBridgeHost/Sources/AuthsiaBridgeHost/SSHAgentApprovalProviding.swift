import Foundation
import AuthenticatorBridge
import AuthenticatorCore

public enum SSHAgentApprovalDecision: Equatable, Sendable {
    /// The user was shown a prompt and allowed it.
    case approved
    /// An unexpired session grant covered the request; no prompt was shown.
    case approvedFromSession
    /// The key's policy is `autoApprove`; no prompt was shown.
    case approvedByKeyPolicy
    case denied

    public var isApproved: Bool {
        self != .denied
    }

    /// Value recorded in `BridgeAuditRecord.approvedBy`. Separates a signature the
    /// user actually authorized from one an existing grant covered silently: the
    /// log wrote `biometric` for all three, so prompt volume could not be measured
    /// from it and every cached signature read as a Touch ID the user never saw.
    public var auditLabel: String {
        switch self {
        case .approved:
            return "biometric"
        case .approvedFromSession:
            return "ssh-session"
        case .approvedByKeyPolicy:
            return "key-policy"
        case .denied:
            return "denied"
        }
    }
}

public struct SSHAgentRequester: Equatable {
    public let peer: SSHAgentProcessRef?
    public let instigator: SSHAgentProcessRef?
    public let ancestry: [SSHAgentProcessRef]
    public let targetHost: String?
    public let sessionScope: String?
    /// Known coding-agent platform when the prompt names an interactive agent CLI.
    /// Display-only. Not a JIT grant and not persisted command text.
    public let agentPlatform: String?
    /// Human label for the approval sheet (`Claude Code`, `A Claude Code plugin`).
    public let agentDisplayName: String?
    /// Allowlisted Git verb, e.g. `git fetch`. Never a remote URL or full argv.
    public let sourceOperation: String?

    public init(
        peer: SSHAgentProcessRef?,
        instigator: SSHAgentProcessRef?,
        ancestry: [SSHAgentProcessRef],
        targetHost: String?,
        sessionScope: String?,
        agentPlatform: String? = nil,
        agentDisplayName: String? = nil,
        sourceOperation: String? = nil
    ) {
        self.peer = peer
        self.instigator = instigator
        self.ancestry = ancestry
        self.targetHost = targetHost
        self.sessionScope = sessionScope
        self.agentPlatform = agentPlatform
        self.agentDisplayName = agentDisplayName
        self.sourceOperation = sourceOperation
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
