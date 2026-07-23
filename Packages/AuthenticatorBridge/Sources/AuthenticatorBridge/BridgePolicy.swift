import Foundation

public enum BridgePolicyDecision: Equatable {
    case allow
    case requireApproval
    case deny(String)
}

/// Represents an authenticated CLI session with anti-replay protection
public struct BridgeSession: Equatable {
    public let id: UUID
    public let expiresAt: Date
    public let sessionToken: String

    public enum SessionError: LocalizedError {
        case cryptographyFailure

        public var errorDescription: String? {
            switch self {
            case .cryptographyFailure:
                return "Failed to generate secure random bytes for session token."
            }
        }
    }

    public init(expiresAt: Date) throws {
        self.id = UUID()
        self.expiresAt = expiresAt
        // Generate a cryptographically secure random session token
        var bytes = [UInt8](repeating: 0, count: 32)
        let result = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard result == errSecSuccess else {
            throw SessionError.cryptographyFailure
        }
        self.sessionToken = Data(bytes).base64EncodedString()
    }

    /// Restore a previously persisted session
    public init(id: UUID, expiresAt: Date, sessionToken: String) {
        self.id = id
        self.expiresAt = expiresAt
        self.sessionToken = sessionToken
    }

    public var isValid: Bool {
        expiresAt > Date()
    }
}

public enum BridgePolicy {
    public static func evaluate(
        command: BridgeRequestType,
        context: BridgeContext,
        session: BridgeSession?,
        requiresApproval: Bool
    ) -> BridgePolicyDecision {
        if context.isSSH { return .deny("ssh") }
        if context.isCI { return .deny("ci") }
        if context.hasAutomationCredential {
            return .allow
        }
        if requiresApproval { return .requireApproval }
        if (command == .getOTP || command == .list), let session, session.isValid {
            return .allow
        }
        return .requireApproval
    }
}
