import Testing
import Foundation
@testable import authsia

@Suite("Init SSH_AUTH_SOCK")
struct InitSSHAuthSockTests {

    @Test("zsh init script exports SSH_AUTH_SOCK")
    func zshExportsSSHAuthSock() {
        let script = Init.renderScript(for: .zsh)
        #expect(script.contains("SSH_AUTH_SOCK"))
        #expect(script.contains(".authsia/agent.sock"))
    }

    @Test("bash init script exports SSH_AUTH_SOCK")
    func bashExportsSSHAuthSock() {
        let script = Init.renderScript(for: .bash)
        #expect(script.contains("SSH_AUTH_SOCK"))
        #expect(script.contains(".authsia/agent.sock"))
    }

    @Test("SSH_AUTH_SOCK only set if socket exists")
    func conditionalExport() {
        let script = Init.renderScript(for: .zsh)
        #expect(script.contains("if [ -S"))
    }

    @Test("zsh init binds ssh automation grants before commands")
    func zshBindsSSHAutomationGrantBeforeCommands() {
        let script = Init.renderScript(for: .zsh)

        #expect(script.contains("_authsia_bind_ssh_automation_grant"))
        #expect(script.contains("preexec_functions"))
        #expect(script.contains("authsia __ssh-automation-grant"))
    }

    @Test("prompt hook clears ssh automation grants")
    func promptHookClearsSSHAutomationGrant() {
        let script = Init.renderScript(for: .zsh)

        #expect(script.contains("_authsia_clear_ssh_automation_grant"))
        #expect(script.contains("authsia __ssh-automation-grant --clear"))
    }

    @Test("init scripts enable workspace auto guard from shell startup")
    func initScriptsEnableWorkspaceAutoGuard() {
        for shell in Init.Shell.allCases {
            let script = Init.renderScript(for: shell)

            #expect(script.contains("authsia workspace guard --print-env --auto"))
            #expect(script.contains("_AUTHSIA_WORKSPACE_GUARD_ENV"))
            #expect(script.contains("eval \"$_AUTHSIA_WORKSPACE_GUARD_ENV\""))
        }
    }

    @Test("shell integration activates the current shell with authsia guard")
    func shellIntegrationAddsGuardCommand() {
        for shell in Init.Shell.allCases {
            let script = Init.renderScript(for: shell)

            #expect(script.contains("authsia()"))
            #expect(script.contains("[ \"$1\" = \"guard\" ]"))
            #expect(script.contains("command authsia workspace guard --print-env"))
            #expect(script.contains("command authsia \"$@\""))
        }
    }

    @Test("shell integration restarts the tab in normal mode with authsia unguard")
    func shellIntegrationAddsUnguardCommand() {
        for shell in Init.Shell.allCases {
            let script = Init.renderScript(for: shell)

            #expect(script.contains("[ \"$1\" = \"unguard\" ]"))
            #expect(script.contains("_authsia_unguard_path="))
            #expect(script.contains("PATH=\"$_authsia_unguard_path\" exec /usr/bin/env"))
            #expect(script.contains("-u AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH"))
            #expect(script.contains("if [ \"${AUTHSIA_WORKSPACE_SKIP_AUTO_GUARD:-}\" != \"1\" ]; then"))
            #expect(script.contains("unset _AUTHSIA_WORKSPACE_GUARD_ENV AUTHSIA_WORKSPACE_SKIP_AUTO_GUARD"))
        }
    }

    @Test("shell integration uses a private per-shell FIFO")
    func privatePerShellFIFO() {
        let script = Init.renderScript(for: .zsh)
        #expect(script.contains("AUTHSIA_SHELL_EXPORT_DIR"))
        #expect(script.contains("authsia-shell-$$"))
        #expect(script.contains("chmod 700"))
        #expect(script.contains("chmod 600"))
        #expect(!script.contains("$HOME/.local/state/authsia/exports.fifo"))
    }

    @Test("init script preserves shell stdout and stderr", arguments: Init.Shell.allCases)
    func initScriptPreservesShellOutput(shell: Init.Shell) throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-init-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let scriptURL = tempDir.appendingPathComponent("init.\(shell.rawValue)")
        try Init.renderScript(for: shell).write(to: scriptURL, atomically: true, encoding: .utf8)

        let result = try runShell(
            shell,
            command: """
            source "$AUTHSIA_TEST_INIT_SCRIPT"
            echo authsia-stdout-after-init
            echo authsia-stderr-after-init >&2
            """,
            environment: [
                "AUTHSIA_TEST_INIT_SCRIPT": scriptURL.path,
                "XDG_STATE_HOME": tempDir.path,
            ]
        )

        #expect(result.status == 0)
        #expect(result.stdout.contains("authsia-stdout-after-init"))
        #expect(result.stderr.contains("authsia-stderr-after-init"))
    }

    @Test("authsia guard evaluates guarded exports in the current shell", arguments: Init.Shell.allCases)
    func shellIntegrationGuardActivatesCurrentShell(shell: Init.Shell) throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-init-guard-test-\(UUID().uuidString)", isDirectory: true)
        let binDir = tempDir.appendingPathComponent("bin", isDirectory: true)
        try FileManager.default.createDirectory(at: binDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let scriptURL = tempDir.appendingPathComponent("init.\(shell.rawValue)")
        try Init.renderScript(for: shell).write(to: scriptURL, atomically: true, encoding: .utf8)

        let executableURL = binDir.appendingPathComponent("authsia")
        try """
        #!/bin/sh
        if [ "$1" = "workspace" ] && [ "$2" = "guard" ] && [ "$3" = "--print-env" ]; then
            [ "$4" = "--auto" ] && exit 0
            printf '%s\\n' 'export AUTHSIA_WORKSPACE_GUARD=1'
            exit 0
        fi
        if [ "$1" = "list" ]; then
            printf '%s\\n' 'command-forwarded'
            exit 0
        fi
        exit 1
        """.write(to: executableURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executableURL.path)

        let existingPath = ProcessInfo.processInfo.environment["PATH"] ?? ""
        let result = try runShell(
            shell,
            command: """
            source "$AUTHSIA_TEST_INIT_SCRIPT"
            authsia guard
            printf 'guard=%s\\n' "$AUTHSIA_WORKSPACE_GUARD"
            authsia list
            """,
            environment: [
                "AUTHSIA_TEST_INIT_SCRIPT": scriptURL.path,
                "PATH": "\(binDir.path):\(existingPath)",
                "XDG_STATE_HOME": tempDir.path,
            ]
        )

        #expect(result.status == 0)
        #expect(result.stdout.contains("guard=1"))
        #expect(result.stdout.contains("command-forwarded"))
    }

    private func runShell(
        _ shell: Init.Shell,
        command: String,
        environment: [String: String]
    ) throws -> (status: Int32, stdout: String, stderr: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/\(shell.rawValue)")
        process.arguments = ["-fc", command]
        process.environment = ProcessInfo.processInfo.environment.merging(environment) { _, new in new }

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        try process.run()
        process.waitUntilExit()

        let stdout = String(data: stdoutPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: stderrPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return (process.terminationStatus, stdout, stderr)
    }
}
