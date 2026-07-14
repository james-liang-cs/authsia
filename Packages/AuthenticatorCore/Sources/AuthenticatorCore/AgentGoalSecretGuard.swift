import Foundation

public enum AgentGoalSecretGuard {
    public static func containsLikelySecret(_ text: String) -> Bool {
        likelySecretPatterns.contains { pattern in
            text.range(of: pattern, options: [.regularExpression]) != nil
        }
    }

    private static let likelySecretPatterns = [
        #"\bsk-(proj-|svcacct-)?[A-Za-z0-9_-]{24,}\b"#,
        #"\bsk-ant-[A-Za-z0-9_-]{20,}\b"#,
        #"sk_live_[A-Za-z0-9]{16,}"#,
        #"\bgh[oprsu]_[A-Za-z0-9]{20,}\b"#,
        #"github_pat_[A-Za-z0-9_]{22,}"#,
        #"\bglpat-[A-Za-z0-9_-]{20,}\b"#,
        #"\bAIza[0-9A-Za-z_-]{30,}\b"#,
        #"\bhf_[A-Za-z0-9]{24,}\b"#,
        #"\b(AKIA|ASIA)[0-9A-Z]{16}\b"#,
        #"xox[baprs]-[A-Za-z0-9-]{20,}"#,
        #"-----BEGIN [A-Z ]*PRIVATE KEY-----"#,
    ]
}

public enum AgentWorkspaceGoalValidationFailure: Equatable {
    case empty
    case likelySecret
}

public struct AgentWorkspaceGoalHandoff: Equatable {
    public let workspaceName: String
    public let toolName: String
    public let launchCommand: String
    public let goal: String
    public let clipboardText: String

    public static func make(
        workspaceName: String,
        toolName: String,
        launchCommand: String,
        goal: String
    ) -> AgentWorkspaceGoalHandoff? {
        guard let trimmedGoal = validatedGoal(goal) else { return nil }
        let clipboardText = [
            "Agent goal",
            "Workspace: \(workspaceName)",
            "Tool: \(toolName)",
            "Launch: \(launchCommand)",
            "",
            trimmedGoal,
            "",
            "Workspace preflight: run authsia workspace status first, " +
                "then use authsia workspace run --dry-run -- <command> before secret-bearing commands.",
            "Secret handling: use Authsia JIT or automation token per command through authsia workspace run -- <command> or authsia exec; do not paste plaintext secrets.",
        ].joined(separator: "\n")
        return AgentWorkspaceGoalHandoff(
            workspaceName: workspaceName,
            toolName: toolName,
            launchCommand: launchCommand,
            goal: trimmedGoal,
            clipboardText: clipboardText
        )
    }

    public static func validatedGoal(_ goal: String) -> String? {
        validationFailure(for: goal) == nil
            ? goal.trimmingCharacters(in: .whitespacesAndNewlines)
            : nil
    }

    public static func validationFailure(for goal: String) -> AgentWorkspaceGoalValidationFailure? {
        let trimmedGoal = goal.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmedGoal.isEmpty {
            return .empty
        }
        if AgentGoalSecretGuard.containsLikelySecret(trimmedGoal) {
            return .likelySecret
        }
        return nil
    }
}
