import Foundation

public enum MCPToolPolicyDecision: String, Codable, Equatable, Sendable {
    case allow
    case approve
    case deny
    case unlisted
}

/// Transport-independent interpretation of one upstream's declared tool policy.
public enum MCPToolPolicyEvaluator {
    public static func decision(
        for toolName: String,
        policy: MCPUpstreamToolPolicy
    ) -> MCPToolPolicyDecision {
        if policy.deny.contains(toolName) {
            return .deny
        }
        if policy.approve.contains(toolName) {
            return .approve
        }
        if policy.allow.contains(toolName) {
            return .allow
        }
        return .unlisted
    }

    public static func advertisedToolNames(in policy: MCPUpstreamToolPolicy) -> [String] {
        var seen = Set<String>()
        return (policy.allow + policy.approve).filter { name in
            decision(for: name, policy: policy) != .deny && seen.insert(name).inserted
        }
    }
}
