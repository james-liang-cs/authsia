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

    /// Recover client command-line launcher syntax without executing a shell.
    /// Existing argv entries are already parsed and must stay intact.
    public static func launch(command: String, arguments: [String]) -> (command: String, arguments: [String])? {
        let command = command.trimmingCharacters(in: .whitespacesAndNewlines)
        guard command.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else { return nil }
        guard let first = command.split(separator: " ").first,
              ["npx", "npm", "pnpm", "bunx", "uvx"].contains(String(first)),
              command.contains(" ") else { return (command, arguments) }
        var tokens: [String] = []
        var token = ""
        var quote: Character?
        var escaped = false
        var started = false
        for character in command {
            if escaped {
                token.append(character)
                escaped = false
                started = true
            } else if character == "\\", quote != "'" {
                escaped = true
                started = true
            } else if let current = quote {
                if character == current { quote = nil } else { token.append(character) }
            } else if character == "'" || character == "\"" {
                quote = character
                started = true
            } else if character.isWhitespace {
                if started { tokens.append(token); token = ""; started = false }
            } else if ";|&<>`$".contains(character) {
                return nil
            } else {
                token.append(character)
                started = true
            }
        }
        guard quote == nil, !escaped else { return nil }
        if started { tokens.append(token) }
        guard let program = tokens.first, tokens.count > 1 else { return nil }
        if program == "npm", tokens[1] != "exec" { return nil }
        if program == "pnpm", tokens[1] != "dlx" { return nil }
        return (program, Array(tokens.dropFirst()) + arguments)
    }

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
        guard isSafeToken(name), !name.contains(where: \.isWhitespace),
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
