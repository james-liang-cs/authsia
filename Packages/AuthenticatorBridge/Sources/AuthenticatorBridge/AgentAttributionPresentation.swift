import Foundation

/// Display-only strings for hook/env agent identity. Never an authorization input.
public enum AgentAttributionPresentation {
    public static let hookTrustHelp = "Reported by the agent's hook; not verified by Authsia."
    public static let hookTrustSuffix = "reported by hook"

    public static func platformDisplayName(_ platform: String?) -> String? {
        // Match on a normalized key, but fall back to the caller's own casing:
        // returning the lowercased key rendered unmapped tools as
        // "visual studio code".
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
        case .some:
            return platform
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

    public static func shortSessionID(_ sessionID: String) -> String {
        let trimmed = sessionID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return sessionID }
        if trimmed.count <= 8 { return trimmed }
        return "\(trimmed.prefix(4))…\(trimmed.suffix(2))"
    }

    public static func sessionGroupHeader(
        platform: String?,
        sessionID: String,
        grantCount: Int,
        subAgentCount: Int
    ) -> String {
        let name = platformDisplayName(platform) ?? "Agent"
        let session = shortSessionID(sessionID)
        let grants = grantCount == 1 ? "1 grant" : "\(grantCount) grants"
        let agents = subAgentCount == 1 ? "1 sub-agent" : "\(subAgentCount) sub-agents"
        return "\(name) · session \(session) · \(grants) · \(agents)"
    }

    public static func lineageCaption(
        agentType: String?,
        startedAt: Date?,
        endedAt: Date?,
        timeZone: TimeZone = .current
    ) -> String? {
        let type = agentType?.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let type, !type.isEmpty else { return nil }
        let formatter = timeFormatters.formatter(for: timeZone)
        var parts = [type]
        if let startedAt {
            parts.append("started \(formatter.string(from: startedAt))")
        }
        if let endedAt {
            parts.append("ended \(formatter.string(from: endedAt))")
        }
        guard parts.count > 1 else { return type }
        return parts.joined(separator: " · ")
    }

    public static func topAgentLabel(platform: String?, agentType: String?) -> String? {
        identityText(
            for: AgentRuntimeContext(platform: platform, agentType: agentType),
            separator: " / "
        )
    }

    public static func platformSymbolName(_ platform: String?) -> String {
        switch platform?.lowercased() {
        case "claude", "claude-code":
            return "text.bubble.fill"
        case "codex":
            return "terminal.fill"
        case "vscode", "vs-code", "visual-studio-code":
            return "chevron.left.forwardslash.chevron.right"
        case "copilot", "github-copilot", "githubcopilot":
            return "sparkle"
        case "cursor":
            return "cursorarrow"
        case "windsurf", "devin", "devin-desktop":
            return "desktopcomputer"
        default:
            return "app.dashed"
        }
    }

    public static func platformMonogram(_ platform: String?, processName: String? = nil) -> String {
        let source = platformDisplayName(platform) ?? processName ?? "A"
        let trimmed = source.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let first = trimmed.first else { return "A" }
        return String(first).uppercased()
    }

    private static func identityText(for context: AgentRuntimeContext?, separator: String) -> String? {
        guard let context else { return nil }
        let platform = platformDisplayName(context.platform)
        if context.attributionConfidence == .ambiguous {
            return platform.map { "\($0) · sub-agent unknown" } ?? "sub-agent unknown"
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

    /// `lineageCaption` runs per row while the activity list renders, and configuring a
    /// `DateFormatter` parses its pattern every time. Formatters are safe to share once configured.
    private final class TimeFormatterCache: @unchecked Sendable {
        private let lock = NSLock()
        private var formatters: [String: DateFormatter] = [:]

        func formatter(for timeZone: TimeZone) -> DateFormatter {
            lock.lock()
            defer { lock.unlock() }
            if let cached = formatters[timeZone.identifier] {
                return cached
            }
            let formatter = DateFormatter()
            formatter.timeZone = timeZone
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.dateFormat = "HH:mm"
            formatters[timeZone.identifier] = formatter
            return formatter
        }
    }

    private static let timeFormatters = TimeFormatterCache()

    private static func subAgentLabel(_ context: AgentRuntimeContext?) -> String {
        guard let context else { return "main thread" }
        if context.attributionConfidence == .ambiguous {
            return "sub-agent unknown"
        }
        return context.agentType ?? "main thread"
    }
}
