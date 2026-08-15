import Foundation
import AuthenticatorBridge

/// Prompt copy and argv parsing for SSH signing approvals.
/// Display-only: does not persist command text and is not a JIT grant.
public enum SSHAgentApprovalCopy {
    public struct PromptProcess: Equatable {
        public let name: String
        public let path: String?
        public let arguments: [String]

        public init(name: String, path: String?, arguments: [String] = []) {
            self.name = name
            self.path = path
            self.arguments = arguments
        }
    }

    public struct PromptAttribution: Equatable {
        public let agentPlatform: String?
        public let displayName: String?

        public init(agentPlatform: String? = nil, displayName: String? = nil) {
            self.agentPlatform = agentPlatform
            self.displayName = displayName
        }
    }

    /// Who the approval sheet should name. An interactive agent CLI wins. An
    /// Electron extension host / Helper (Plugin) is labeled as a plugin, even
    /// when the idle IDE is named `Claude`. A GUI `.app` binary is not treated
    /// as the agent.
    public static func promptAttribution(
        from ancestry: [PromptProcess]
    ) -> PromptAttribution {
        if let tool = ancestry.compactMap(agentToolAttribution).first {
            return tool
        }
        if let plugin = ancestry.first(where: isExtensionHostProcess) {
            return PromptAttribution(displayName: pluginDisplayName(processName: plugin.name))
        }
        return PromptAttribution()
    }

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

        if isPluginDisplayName(requester.agentDisplayName) {
            lines.append("This request came from an IDE plugin or extension host, not an interactive agent command.")
        } else if requester.targetHost != nil, requester.agentDisplayName != nil {
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

    private static func agentToolAttribution(_ process: PromptProcess) -> PromptAttribution? {
        guard !isAppBundleExecutable(process.path),
              !isExtensionHostProcess(process) else {
            return nil
        }
        let identity = Array(process.arguments.prefix(1))
        guard let platform = AgenticProcessDetector.agentPlatform(
            processName: process.name,
            bundleIdentifier: nil,
            arguments: identity
        ) else {
            return nil
        }
        return PromptAttribution(
            agentPlatform: platform,
            displayName: displayName(processName: process.name, platform: platform)
        )
    }

    private static func isExtensionHostProcess(_ process: PromptProcess) -> Bool {
        let loweredName = process.name.lowercased()
        if loweredName.contains("helper") && loweredName.contains("plugin") {
            return true
        }
        return process.arguments.contains { argument in
            argument == "--type=extensionHost" || argument.hasPrefix("--type=extensionHost")
        }
    }

    private static func isAppBundleExecutable(_ path: String?) -> Bool {
        guard let path else { return false }
        return path.contains(".app/Contents/MacOS/") || path.contains(".app/Contents/Helpers/")
    }

    private static func pluginDisplayName(processName: String) -> String {
        let lowered = processName.lowercased()
        if lowered.contains("claude") {
            return "A Claude Code plugin"
        }
        if lowered.contains("cursor") {
            return "A Cursor plugin"
        }
        if lowered.contains("windsurf") {
            return "A Windsurf plugin"
        }
        if lowered.contains("code helper") || lowered.hasPrefix("code ") {
            return "A VS Code plugin"
        }
        return "An IDE plugin"
    }

    private static func isPluginDisplayName(_ value: String?) -> Bool {
        guard let value else { return false }
        return value.localizedCaseInsensitiveContains("plugin")
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
