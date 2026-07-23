import Foundation

public extension Notification.Name {
    static let agentLeakIncidentDidRecord = Notification.Name(
        "com.authsia.agentLeakIncidentDidRecord"
    )
}

public enum AgentLeakResponseMode: String, Codable, CaseIterable, Equatable, Sendable {
    case observe
    case confirm
    case block
}

public enum AgentLeakResponseOutcome: String, Codable, Equatable, Sendable {
    case allow
    case warn
    case deny
    case revokeAndDeny
}

public enum AgentLeakHookPhase: String, Codable, Equatable, Sendable {
    case preTool
    case postTool
}

public enum AgentLeakHookPermissionDecision: String, Codable, Equatable, Sendable {
    case allow
    case ask
    case deny
}

public enum AgentLeakEvidence: String, Codable, Equatable, Sendable {
    case directEnvironmentDump
    case environmentFileRead
    case repeatedDeniedTokenUse
    case callerBindingMismatch
    case outsideApprovedItemScope

    var isAuthorityViolation: Bool {
        switch self {
        case .repeatedDeniedTokenUse, .callerBindingMismatch, .outsideApprovedItemScope:
            return true
        case .directEnvironmentDump, .environmentFileRead:
            return false
        }
    }
}

public struct AgentLeakResponseDecision: Codable, Equatable, Sendable {
    public let outcome: AgentLeakResponseOutcome
    public let evidence: AgentLeakEvidence?
    public let phase: AgentLeakHookPhase
    public let hookPermissionDecision: AgentLeakHookPermissionDecision?
    public let preventedAction: Bool
    public let shouldRevokeAuthority: Bool
    public let reason: String
}

public enum AgentLeakResponsePolicy {
    private static let environmentExecutables: Set<String> = ["env", "printenv"]
    private static let environmentFileReaders: Set<String> = [
        ".",
        "awk",
        "cat",
        "grep",
        "head",
        "less",
        "more",
        "rg",
        "sed",
        "source",
        "tail",
    ]

    public static func decision(
        command: String?,
        hookEventName: String?,
        mode: AgentLeakResponseMode
    ) -> AgentLeakResponseDecision {
        let phase = hookPhase(hookEventName)
        guard let evidence = evidence(command) else {
            return AgentLeakResponseDecision(
                outcome: .allow,
                evidence: nil,
                phase: phase,
                hookPermissionDecision: phase == .preTool ? .allow : nil,
                preventedAction: false,
                shouldRevokeAuthority: false,
                reason: "No mediated leak-risk rule matched."
            )
        }
        return decision(evidence: evidence, phase: phase, mode: mode)
    }

    public static func decision(
        evidence: AgentLeakEvidence,
        phase: AgentLeakHookPhase,
        mode: AgentLeakResponseMode
    ) -> AgentLeakResponseDecision {
        if phase == .postTool {
            return AgentLeakResponseDecision(
                outcome: evidence.isAuthorityViolation && mode == .block ? .revokeAndDeny : .warn,
                evidence: evidence,
                phase: phase,
                hookPermissionDecision: nil,
                preventedAction: false,
                shouldRevokeAuthority: evidence.isAuthorityViolation && mode == .block,
                reason: postToolReason(for: evidence)
            )
        }

        switch mode {
        case .observe:
            return AgentLeakResponseDecision(
                outcome: .warn,
                evidence: evidence,
                phase: phase,
                hookPermissionDecision: .allow,
                preventedAction: false,
                shouldRevokeAuthority: false,
                reason: reason(for: evidence)
            )
        case .confirm:
            return AgentLeakResponseDecision(
                outcome: .warn,
                evidence: evidence,
                phase: phase,
                hookPermissionDecision: .ask,
                preventedAction: true,
                shouldRevokeAuthority: false,
                reason: reason(for: evidence)
            )
        case .block:
            let revoke = evidence.isAuthorityViolation
            return AgentLeakResponseDecision(
                outcome: revoke ? .revokeAndDeny : .deny,
                evidence: evidence,
                phase: phase,
                hookPermissionDecision: .deny,
                preventedAction: true,
                shouldRevokeAuthority: revoke,
                reason: reason(for: evidence)
            )
        }
    }

    private static func hookPhase(_ hookEventName: String?) -> AgentLeakHookPhase {
        let normalized = hookEventName?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        return normalized?.hasPrefix("posttool") == true ? .postTool : .preTool
    }

    private static func evidence(_ command: String?) -> AgentLeakEvidence? {
        guard let command else { return nil }
        let segments = command
            .replacingOccurrences(of: "&&", with: "|")
            .replacingOccurrences(of: "||", with: "|")
            .split { ";|".contains($0) }

        for segment in segments {
            let tokens = segment
                .split(whereSeparator: \.isWhitespace)
                .map { $0.trimmingCharacters(in: CharacterSet(charactersIn: "\"'")) }
            guard let first = tokens.first else { continue }
            let executable = URL(fileURLWithPath: first).lastPathComponent.lowercased()
            if environmentExecutables.contains(executable) {
                return .directEnvironmentDump
            }
            if environmentFileReaders.contains(executable),
               tokens.dropFirst().contains(where: isEnvironmentFilePath) {
                return .environmentFileRead
            }
        }
        return nil
    }

    private static func isEnvironmentFilePath(_ token: String) -> Bool {
        let name = URL(fileURLWithPath: token).lastPathComponent.lowercased()
        return name == ".env" || name == ".envrc" || name.hasPrefix(".env.")
    }

    private static func reason(for evidence: AgentLeakEvidence) -> String {
        switch evidence {
        case .directEnvironmentDump:
            return "Authsia detected a direct environment dump while agent access may be active."
        case .environmentFileRead:
            return "Authsia detected a direct read of a local environment file."
        case .repeatedDeniedTokenUse:
            return "Authsia detected repeated use of denied authority."
        case .callerBindingMismatch:
            return "Authsia detected use from a caller that does not match the approved identity."
        case .outsideApprovedItemScope:
            return "Authsia detected an item request outside the approved exact scope."
        }
    }

    private static func postToolReason(for evidence: AgentLeakEvidence) -> String {
        reason(for: evidence) + " The tool had already completed, so this record does not claim prevention."
    }
}
