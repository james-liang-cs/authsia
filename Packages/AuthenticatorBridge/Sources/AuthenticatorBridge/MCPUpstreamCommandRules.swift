import Foundation

/// The single rule for "this declared argv is not a shell command string".
///
/// Two sides need the same answer. `MCPClientConfigScanner` decides what
/// Access Center may offer to wrap and declare, and `WorkspaceConfigStore`
/// decides what may be read back out of `.authsia/workspace.json`. A rule the
/// scanner accepts but the store rejects lets a declare write an entry that
/// makes the whole workspace config fail to load, which takes env bindings,
/// guard, and `workspace run` down with it.
public enum MCPUpstreamCommandRules {
    public static let shellExecutableNames: Set<String> = [
        "ash", "bash", "csh", "dash", "fish", "ksh", "mksh", "sh", "tcsh", "zsh",
    ]

    /// Absolute package launchers stay ineligible. A bare `npx` / `uvx` PATH
    /// basename remains wrap-eligible as today.
    public static let packageLauncherNames: Set<String> = ["npx", "uvx"]

    /// Command stored in workspace `mcpUpstreams` for a scanned client launch.
    /// Absolute Homebrew or system paths collapse to a PATH basename so
    /// committed policy stays machine-local.
    public static func policyCommand(fromScanned command: String) -> String? {
        let trimmed = command.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isSafeToken(trimmed), trimmed != ".", trimmed != ".." else {
            return nil
        }
        if trimmed.hasPrefix("/") {
            let base = URL(fileURLWithPath: trimmed).lastPathComponent
            guard isLegalPATHBasename(base),
                  !packageLauncherNames.contains(base.lowercased()) else {
                return nil
            }
            return base
        }
        if trimmed.contains("/") {
            let parts = trimmed.split(separator: "/", omittingEmptySubsequences: false)
            guard !parts.contains(where: { $0 == ".." || $0.isEmpty }) else {
                return nil
            }
            return trimmed
        }
        return isLegalPATHBasename(trimmed) ? trimmed : nil
    }

    /// Why Access Center may show a scanned launch without Protect.
    /// Absolute `npx` / `uvx` and shells cannot become `mcpUpstreams` policy.
    public static func accessCenterBlockReason(
        fromScanned command: String,
        arguments: [String]
    ) -> MCPClientWrapBlockReason? {
        let base = URL(fileURLWithPath: command).lastPathComponent.lowercased()
        if packageLauncherNames.contains(base), command.hasPrefix("/") {
            return .packageLauncher
        }
        if shellExecutableNames.contains(base)
            || containsShellCommandString([command] + arguments) {
            return .shell
        }
        return nil
    }

    public static func isLegalPATHBasename(_ name: String) -> Bool {
        guard isSafeToken(name),
              !name.contains("/"),
              name != ".",
              name != "..",
              !shellExecutableNames.contains(name.lowercased()) else {
            return false
        }
        return true
    }

    private static func isSafeToken(_ value: String) -> Bool {
        !value.isEmpty
            && !value.contains("\0")
            && value.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
    }

    /// True when `argv` runs a shell (directly, or through `env`) with an
    /// inline command string.
    public static func containsShellCommandString(_ argv: [String]) -> Bool {
        guard let first = argv.first else { return false }
        let executable = executableName(first)
        if shellExecutableNames.contains(executable) {
            return containsCommandStringOption(argv.dropFirst())
        }
        guard executable == "env" else { return false }
        if argv.dropFirst().contains(where: {
            $0 == "-S" || $0 == "--split-string" || $0.hasPrefix("--split-string=")
        }) {
            return true
        }
        guard let shellIndex = argv.indices.dropFirst().first(where: {
            shellExecutableNames.contains(executableName(argv[$0]))
        }) else {
            return false
        }
        return containsCommandStringOption(argv[argv.index(after: shellIndex)...])
    }

    private static func executableName(_ path: String) -> String {
        URL(fileURLWithPath: path).lastPathComponent.lowercased()
    }

    private static func containsCommandStringOption<S: Sequence>(_ arguments: S) -> Bool
    where S.Element == String {
        for argument in arguments {
            if argument == "--" { return false }
            if argument == "-c" || argument == "--command" { return true }
            if argument.hasPrefix("-"),
               !argument.hasPrefix("--"),
               argument.dropFirst().contains("c") {
                return true
            }
        }
        return false
    }
}
