import ArgumentParser
import Foundation

struct Completion: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "completion",
        abstract: "Generate shell completion script",
        discussion: """
            Outputs a completion script for the specified shell to stdout.

            Examples:
              authsia completion zsh >> ~/.zshrc
              authsia completion bash >> ~/.bash_profile
              authsia completion fish > ~/.config/fish/completions/authsia.fish
            """
    )

    enum Shell: String, ExpressibleByArgument, CaseIterable {
        case zsh
        case bash
        case fish

        static var allValueStrings: [String] { allCases.map(\.rawValue) }
    }

    @Argument(help: "Target shell (zsh, bash, fish)")
    var shell: Shell

    func run() throws {
        print(Self.completionScript(for: shell))
    }

    static func completionScript(for shell: Shell) -> String {
        switch shell {
        case .zsh:
            return zshEvalSafeScript(Authsia.completionScript(for: .zsh))
        case .bash:
            return Authsia.completionScript(for: .bash)
        case .fish:
            return Authsia.completionScript(for: .fish)
        }
    }

    private static func zshEvalSafeScript(_ script: String) -> String {
        var lines = script.components(separatedBy: .newlines)
        while lines.last?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == true {
            lines.removeLast()
        }
        if lines.last?.trimmingCharacters(in: .whitespacesAndNewlines) == "_authsia" {
            lines.removeLast()
        }

        return """
        \(zshInteractiveSafeScript(lines.joined(separator: "\n")))

        # zsh ignores #compdef for scripts evaluated from .zshrc.
        if ! whence -w compdef >/dev/null 2>&1; then
            autoload -Uz compinit
            compinit -i
        fi
        if whence -w compdef >/dev/null 2>&1; then
            compdef _authsia authsia
        fi
        """
    }

    private static func zshInteractiveSafeScript(_ script: String) -> String {
        let defaultValueCompletionHelper = """
        __authsia_complete() {
            local -ar non_empty_completions=("${@:#(|:*)}")
            local -ar empty_completions=("${(M)@:#(|:*)}")
            _describe -V '' non_empty_completions -- empty_completions -P $'\\'\\''
        }
        """
        let valueCompletionHelper = """
        __authsia_complete() {
            compadd -- "$@"
        }
        """
        let loneDashOptionHelper = """
        __authsia_complete_lone_dash_options() {
            [[ "${PREFIX}" == "-" ]] || return 1

            local -A seen_options
            local -a short_options
            local spec option_part normalized token
            for spec in "$@"; do
                option_part="${spec%%\\[*}"
                option_part="${option_part%%:*}"
                normalized="${option_part//\\(/ }"
                normalized="${normalized//\\)/ }"
                normalized="${normalized//\\{/ }"
                normalized="${normalized//\\}/ }"
                normalized="${normalized//,/ }"

                for token in ${(z)normalized}; do
                    token="${token#\\*}"
                    if [[ "${token}" == -? && "${#token}" -eq 2 ]]; then
                        if [[ -z "${seen_options[$token]}" ]]; then
                            seen_options[$token]=1
                            short_options+=("$token")
                        fi
                    fi
                done
            done

            (( ${#short_options[@]} )) || return 0
            compadd -- "${short_options[@]}"
        }
        """

        return script
            .replacingOccurrences(of: defaultValueCompletionHelper, with: valueCompletionHelper)
            .replacingOccurrences(of: valueCompletionHelper, with: "\(valueCompletionHelper)\n\n\(loneDashOptionHelper)")
            .replacingOccurrences(of: "_arguments -w -s -S :", with: "_arguments -w -S :")
            .replacingOccurrences(
                of: """
                    _arguments -w -S : "${arg_specs[@]}" && ret=0

                    return "${ret}"
                """,
                with: """
                __authsia_complete_lone_dash_options "${arg_specs[@]}" && return 0
                    _arguments -w -S : "${arg_specs[@]}" && ret=0

                    return "${ret}"
                """
            )
    }
}
