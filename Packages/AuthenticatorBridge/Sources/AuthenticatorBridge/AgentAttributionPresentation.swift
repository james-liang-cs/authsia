import Foundation

/// Display-only strings for hook/env agent identity. Never an authorization input.
public enum AgentAttributionPresentation {
    public static let hookTrustHelp = "Reported by the agent's hook; not verified by Authsia."
    public static let hookTrustSuffix = "reported by hook"

    public static func platformDisplayName(_ platform: String?) -> String? {
        switch platform?.lowercased() {
        case "claude", "claude-code":
            return "Claude Code"
        case "codex":
            return "Codex"
        case "vscode", "vs-code", "visual-studio-code":
            return "Visual Studio Code"
        case "copilot", "github-copilot", "githubcopilot":
            return "GitHub Copilot"
        case "cursor":
            return "Cursor"
        case "windsurf", "devin", "devin-desktop":
            return "Devin Desktop"
        case let value?:
            return value
        case nil:
            return nil
        }
    }

    public static func shortAgentID(_ agentID: String?) -> String? {
        guard let agentID else { return nil }
        return agentID.count > 12 ? String(agentID.prefix(12)) : agentID
    }

    public static func caption(for context: AgentRuntimeContext?) -> String? {
        guard let identity = identityText(for: context, separator: " / ") else { return nil }
        return "\(identity) (\(hookTrustSuffix))"
    }

    public static func promptValue(for context: AgentRuntimeContext?) -> String? {
        guard let identity = identityText(for: context, separator: " · ") else { return nil }
        return "\(identity) (\(hookTrustSuffix))"
    }

    public static func commandToolText(
        platform: String?,
        agentType: String?,
        fallback: String
    ) -> String {
        let name = platformDisplayName(platform)
        if let name, let agentType, !agentType.isEmpty {
            return "\(name) · \(agentType)"
        }
        return name ?? fallback
    }

    public static func usedByLabels(
        creator: AgentRuntimeContext?,
        contexts: [AgentRuntimeContext]
    ) -> [String] {
        let creatorLabel = subAgentLabel(creator)
        var seen = Set<String>()
        var labels: [String] = []
        for context in contexts {
            let value = subAgentLabel(context)
            if seen.insert(value).inserted {
                labels.append(value)
            }
        }
        if labels.isEmpty || labels == [creatorLabel] {
            return []
        }
        return labels.sorted()
    }

    public static func usedByCaption(labels: [String]) -> String? {
        guard !labels.isEmpty else { return nil }
        return "Used by: " + labels.joined(separator: ", ")
    }

    private static func identityText(for context: AgentRuntimeContext?, separator: String) -> String? {
        guard let context else { return nil }
        let platform = platformDisplayName(context.platform)
        if context.attributionConfidence == .ambiguous {
            return platform.map { "\($0)\(separator == " / " ? " · " : separator)sub-agent unknown" }
                ?? "sub-agent unknown"
        }
        let label = context.agentType ?? shortAgentID(context.agentID)
        if let platform, let label {
            return "\(platform)\(separator)\(label)"
        }
        if let label {
            return "Agent: \(label)"
        }
        return platform
    }

    private static func subAgentLabel(_ context: AgentRuntimeContext?) -> String {
        guard let context else { return "main thread" }
        if context.attributionConfidence == .ambiguous {
            return "sub-agent unknown"
        }
        return context.agentType ?? "main thread"
    }
}
