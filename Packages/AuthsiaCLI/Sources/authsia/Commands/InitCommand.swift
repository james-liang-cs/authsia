import ArgumentParser
import Foundation

struct Init: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "init",
        abstract: "Print shell integration script",
        discussion: """
            Prints shell integration that enables active-session export for:
              authsia load ... --silent

            Examples:
              eval "$(authsia init zsh)"
              eval "$(authsia init bash)"
            """
    )

    enum Shell: String, ExpressibleByArgument, CaseIterable {
        case zsh
        case bash

        static var allValueStrings: [String] { allCases.map(\.rawValue) }
    }

    @Argument(help: "Target shell")
    var shell: Shell

    func run() throws {
        print(Self.renderScript(for: shell))
    }

    static func renderScript(for shell: Shell) -> String {
        switch shell {
        case .zsh:
            return renderZSHScript()
        case .bash:
            return renderBashScript()
        }
    }

    static func resolveExecutablePath(
        rawExecutable: String,
        environment: [String: String],
        currentDirectoryPath: String
    ) -> String {
        if rawExecutable.contains("/") {
            let cwdURL = URL(fileURLWithPath: currentDirectoryPath, isDirectory: true)
            return URL(fileURLWithPath: rawExecutable, relativeTo: cwdURL).standardizedFileURL.path
        }

        let pathValue = environment["PATH"] ?? ""
        let fileManager = FileManager.default
        for component in pathValue.split(separator: ":") {
            let candidate = (String(component) as NSString).appendingPathComponent(rawExecutable)
            if fileManager.isExecutableFile(atPath: candidate) {
                return (candidate as NSString).standardizingPath
            }
        }

        return rawExecutable
    }

    private static func renderSharedHeader(shellName: String) -> String {
        return """
        # Authsia shell integration (\(shellName))
        # Enables active-shell export for: authsia load ... --silent
        unset -f authsia >/dev/null 2>&1 || true
        unfunction authsia >/dev/null 2>&1 || true
        export AUTHSIA_SHELL_INTEGRATION=1
        # SSH agent socket — only override if Authsia agent socket exists
        if [ -S "$HOME/.authsia/agent.sock" ]; then
            export SSH_AUTH_SOCK="$HOME/.authsia/agent.sock"
        fi
        # Workspace guard auto-start - no-ops unless the workspace opted in.
        if [ "${AUTHSIA_WORKSPACE_SKIP_AUTO_GUARD:-}" != "1" ]; then
            _AUTHSIA_WORKSPACE_GUARD_ENV="$(command authsia workspace guard --print-env --auto 2>/dev/null)"
            if [ -n "$_AUTHSIA_WORKSPACE_GUARD_ENV" ]; then
                eval "$_AUTHSIA_WORKSPACE_GUARD_ENV"
            fi
        fi
        unset _AUTHSIA_WORKSPACE_GUARD_ENV AUTHSIA_WORKSPACE_SKIP_AUTO_GUARD
        authsia() {
            if [ "$#" -eq 1 ] && [ "$1" = "guard" ]; then
                local _authsia_guard_status
                _AUTHSIA_WORKSPACE_GUARD_ENV="$(command authsia workspace guard --print-env)"
                _authsia_guard_status=$?
                if [ "$_authsia_guard_status" -eq 0 ] && [ -n "$_AUTHSIA_WORKSPACE_GUARD_ENV" ]; then
                    eval "$_AUTHSIA_WORKSPACE_GUARD_ENV"
                fi
                unset _AUTHSIA_WORKSPACE_GUARD_ENV
                return "$_authsia_guard_status"
            fi
            if [ "$#" -eq 1 ] && [ "$1" = "unguard" ]; then
                local _authsia_unguard_path="${AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH:-$PATH}"
                printf '%s\\n' "Authsia: restarting this tab in normal mode." >&2
                AUTHSIA_WORKSPACE_SKIP_AUTO_GUARD=1 PATH="$_authsia_unguard_path" exec /usr/bin/env \
                    -u AUTHSIA_WORKSPACE_GUARD \
                    -u AUTHSIA_WORKSPACE_GUARD_SHIM_DIR \
                    -u AUTHSIA_WORKSPACE_ROOT \
                    -u AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH \
                    -u AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION \
                    /bin/\(shellName)
                return $?
            fi
            command authsia "$@"
        }
        export AUTHSIA_SHELL_EXPORT_BASE="${XDG_STATE_HOME:-$HOME/.local/state}/authsia"
        export AUTHSIA_SHELL_EXPORT_DIR="$AUTHSIA_SHELL_EXPORT_BASE/authsia-shell-$$"
        export AUTHSIA_SHELL_EXPORT_FIFO="$AUTHSIA_SHELL_EXPORT_DIR/exports.fifo"
        mkdir -p "$AUTHSIA_SHELL_EXPORT_DIR"
        chmod 700 "$AUTHSIA_SHELL_EXPORT_DIR" 2>/dev/null || true
        if [ ! -d "$AUTHSIA_SHELL_EXPORT_DIR" ] || [ ! -O "$AUTHSIA_SHELL_EXPORT_DIR" ]; then
            echo "authsia: refusing unsafe shell export directory: $AUTHSIA_SHELL_EXPORT_DIR" >&2
            unset AUTHSIA_SHELL_EXPORT_FD
        else
            if [ -e "$AUTHSIA_SHELL_EXPORT_FIFO" ] && { [ ! -p "$AUTHSIA_SHELL_EXPORT_FIFO" ] || [ ! -O "$AUTHSIA_SHELL_EXPORT_FIFO" ]; }; then
                rm -f "$AUTHSIA_SHELL_EXPORT_FIFO"
            fi
            if [ ! -p "$AUTHSIA_SHELL_EXPORT_FIFO" ]; then
                (umask 077 && mkfifo "$AUTHSIA_SHELL_EXPORT_FIFO")
            fi
            chmod 600 "$AUTHSIA_SHELL_EXPORT_FIFO" 2>/dev/null || true
            exec 9>&- || true
            exec 9<&- || true
            exec 9<>"$AUTHSIA_SHELL_EXPORT_FIFO"
            export AUTHSIA_SHELL_EXPORT_FD=9
        fi
        _AUTHSIA_EXPORT_BUFFER="${_AUTHSIA_EXPORT_BUFFER:-}"

        _authsia_apply_pending_exports() {
            [ -n "${AUTHSIA_SHELL_EXPORT_FD:-}" ] || return
            local _authsia_line
            while IFS= read -r -t 0 -u "$AUTHSIA_SHELL_EXPORT_FD" _authsia_line; do
                if [ "$_authsia_line" = "__AUTHSIA_EOF__" ]; then
                    if [ -n "$_AUTHSIA_EXPORT_BUFFER" ]; then
                        eval "$_AUTHSIA_EXPORT_BUFFER"
                        _AUTHSIA_EXPORT_BUFFER=""
                    fi
                    continue
                fi
                if [ -z "$_AUTHSIA_EXPORT_BUFFER" ]; then
                    _AUTHSIA_EXPORT_BUFFER="$_authsia_line"
                else
                    _AUTHSIA_EXPORT_BUFFER="$(printf '%s\\n%s' "$_AUTHSIA_EXPORT_BUFFER" "$_authsia_line")"
                fi
            done
        }

        _authsia_bind_ssh_automation_grant() {
            [ -z "${_AUTHSIA_SSH_AUTOMATION_BUSY:-}" ] || return
            [ -n "${AUTHSIA_SSH_ACCESS_CREDENTIAL:-}${AUTHSIA_ACCESS_CREDENTIAL:-}" ] || return
            _AUTHSIA_SSH_AUTOMATION_BUSY=1
            _AUTHSIA_SSH_AUTOMATION_GRANT_ACTIVE=1
            command authsia __ssh-automation-grant >/dev/null 2>&1 || true
            unset _AUTHSIA_SSH_AUTOMATION_BUSY
        }

        _authsia_clear_ssh_automation_grant() {
            [ -n "${_AUTHSIA_SSH_AUTOMATION_GRANT_ACTIVE:-}" ] || return
            command authsia __ssh-automation-grant --clear >/dev/null 2>&1 || true
            unset _AUTHSIA_SSH_AUTOMATION_GRANT_ACTIVE
        """
    }

    private static func renderZSHScript() -> String {
        let shared = renderSharedHeader(shellName: "zsh")
        return """
        \(shared)
        }
        if typeset -p precmd_functions >/dev/null 2>&1; then
            if [[ -z "${precmd_functions[(r)_authsia_apply_pending_exports]}" ]]; then
                precmd_functions+=(_authsia_apply_pending_exports)
            fi
            if [[ -z "${precmd_functions[(r)_authsia_clear_ssh_automation_grant]}" ]]; then
                precmd_functions+=(_authsia_clear_ssh_automation_grant)
            fi
        else
            precmd_functions=(_authsia_apply_pending_exports _authsia_clear_ssh_automation_grant)
        fi
        if typeset -p preexec_functions >/dev/null 2>&1; then
            if [[ -z "${preexec_functions[(r)_authsia_bind_ssh_automation_grant]}" ]]; then
                preexec_functions+=(_authsia_bind_ssh_automation_grant)
            fi
        else
            preexec_functions=(_authsia_bind_ssh_automation_grant)
        fi
        """
    }

    private static func renderBashScript() -> String {
        let shared = renderSharedHeader(shellName: "bash")
        return """
        \(shared)
        }
        case ";${PROMPT_COMMAND};" in
            *";_authsia_apply_pending_exports;"*) ;;
            *) PROMPT_COMMAND="_authsia_apply_pending_exports;_authsia_clear_ssh_automation_grant${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
        esac
        """
    }
}
