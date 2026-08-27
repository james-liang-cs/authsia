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
