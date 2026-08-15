import Foundation
import AuthenticatorBridge

/// Prompt copy and argv parsing for SSH signing approvals.
/// Display-only: does not persist command text and is not a JIT grant.
public enum SSHAgentApprovalCopy {
    public static func touchIDReason(
        keyName: String,
        requester: SSHAgentRequester
    ) -> String {
        var reason = "\(actorPhrase(requester)) wants to use SSH key \"\(keyName)\""
        if let host = requester.targetHost {
            reason += " for \(host)"
        }
        if let operation = requester.sourceOperation {
            reason += " via \(operation)"
        }
        return reason
    }

    public static func fallbackInformativeText(
        keyName: String,
        requester: SSHAgentRequester
    ) -> String {
        var lines: [String] = []
        var lead = "\(actorPhrase(requester)) wants to use SSH key \"\(keyName)\""
        if let host = requester.targetHost {
            lead += " for \(host)"
        }
        if let operation = requester.sourceOperation {
            lead += " via \(operation)"
        }
        lines.append("\(lead).")

        if let peer = requester.peer {
            let path = peer.path ?? peer.name
            lines.append("Requested by: \(peer.name) (PID \(peer.pid), \(path))")
        }

        if requester.ancestry.count > 1 {
            let chain = requester.ancestry.reversed().map(\.name).joined(separator: " → ")
            lines.append("Parent chain: \(chain)")
        }

        if requester.targetHost != nil, requester.agentDisplayName != nil {
            lines.append("SSH is required to authenticate this Git remote.")
        }

        return lines.joined(separator: "\n")
    }

    public static func displayName(processName: String, platform: String) -> String {
        let normalized = processName
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .replacingOccurrences(of: "_", with: "-")
            .replacingOccurrences(of: " ", with: "-")

        if normalized.contains("claude") {
            return "Claude Code"
        }
        if normalized.contains("codex") {
            return "Codex"
        }
        if normalized.contains("cursor-agent")
            || (normalized.contains("cursor") && normalized.contains("agent")) {
            return "Cursor Agent"
        }
        if normalized.contains("copilot") {
            return "GitHub Copilot"
        }
        if normalized.contains("windsurf") {
            return "Windsurf Agent"
        }

        switch platform {
        case "claude-code":
            return "Claude Code"
        case "codex":
            return "Codex"
        case "cursor":
            return "Cursor Agent"
        case "copilot":
            return "GitHub Copilot"
        case "devin":
            return "Windsurf Agent"
        default:
            return processName
        }
    }

    /// First allowlisted Git subcommand. Skips `git` global options. Never returns
    /// remotes, URLs, or other operands.
    public static func gitOperation(fromArguments arguments: [String]) -> String? {
        guard let argv0 = arguments.first, isGitExecutable(argv0) else {
            return nil
        }

        var index = 1
        while index < arguments.count {
            let argument = arguments[index]
            if argument == "--" {
                index += 1
                break
            }
            if argument.hasPrefix("-") {
                if argument.contains("=") {
                    index += 1
                    continue
                }
                if gitOptionsTakingValue.contains(argument) {
                    let next = index + 1
                    if next < arguments.count, !isAllowlistedGitVerb(arguments[next]) {
                        index += 2
                        continue
                    }
                }
                index += 1
                continue
            }
            break
        }

        guard index < arguments.count, isAllowlistedGitVerb(arguments[index]) else {
            return nil
        }
        return "git \(arguments[index].lowercased())"
    }

    public static func isGitExecutable(_ argv0: String) -> Bool {
        let name = (argv0 as NSString).lastPathComponent.lowercased()
        return name == "git"
    }

    private static func actorPhrase(_ requester: SSHAgentRequester) -> String {
        if let agent = requester.agentDisplayName, !agent.isEmpty {
            return agent
        }
        let actor = requester.instigator?.name ?? requester.peer?.name ?? "An application"
        return "\"\(actor)\""
    }

    private static func isAllowlistedGitVerb(_ value: String) -> Bool {
        allowlistedGitVerbs.contains(value.lowercased())
    }

    private static let allowlistedGitVerbs: Set<String> = [
        "archive",
        "clone",
        "fetch",
        "lfs",
        "ls-remote",
        "pull",
        "push",
        "remote",
        "submodule",
    ]

    private static let gitOptionsTakingValue: Set<String> = [
        "-C",
        "-c",
        "--attr-source",
        "--config-env",
        "--exec-path",
        "--git-dir",
        "--list-cmds",
        "--namespace",
        "--super-prefix",
        "--work-tree",
    ]
}
