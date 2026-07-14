import Testing
import Foundation
import AuthenticatorBridge
@testable import authsia

@Suite("Bridge requested command context")
struct BridgeRequestedCommandTests {
    @Test("write requests inherit the surrounding requested command")
    func writeRequestsInheritRequestedCommand() throws {
        let body = try BridgeCoder.encode(
            PasswordWritePayload(
                name: "API_KEY",
                username: "",
                password: "secret",
                website: nil,
                notes: nil
            )
        )

        let request = AuthsiaBridgeClient.shared.withRequestedCommand(.exec) {
            WriteRequestBuilder.makeRequest(
                type: .addPassword,
                query: "",
                body: body,
                sessionToken: nil
            )
        }

        #expect(request.context.requestedCommand == "exec")
    }

    @Test("raw requested command names are preserved for non-automation commands")
    func rawRequestedCommandNamesArePreserved() {
        let context = AutomationAccessResolver.bridgeContext(requestedCommand: "scrape")

        #expect(context.requestedCommand == "scrape")
    }

    @Test("full invocation is shell-quoted and redacts sensitive flag values")
    func fullInvocationIsShellQuotedAndRedactsSensitiveFlagValues() {
        let command = AuthsiaBridgeClient.fullCommandForAudit(arguments: [
            "/usr/local/bin/authsia",
            "exec",
            "password",
            "R2 ENDPOINT",
            "--token",
            "secret-token",
            "--",
            "npm",
            "start",
        ])

        #expect(command == "authsia exec password 'R2 ENDPOINT' --token '<redacted>' -- npm start")
    }

    @Test("completion invocations are not captured as recent commands")
    func completionInvocationsAreNotCapturedAsRecentCommands() {
        let command = AuthsiaBridgeClient.fullCommandForAudit(arguments: [
            "/usr/local/bin/authsia",
            "---completion",
            "get",
            "--",
            "positional@1",
            "3",
            "2",
            "authsia",
            "get",
            "password",
            "--",
        ])

        #expect(command == nil)
    }

    @Test("agent plugin background workspace runs are not captured as recent commands")
    func agentPluginBackgroundWorkspaceRunsAreNotCapturedAsRecentCommands() {
        let command = AuthsiaBridgeClient.fullCommandForAudit(arguments: [
            "/usr/local/bin/authsia",
            "workspace",
            "run",
            "--",
            "/opt/homebrew/bin/node",
            "/Users/example/.claude/plugins/cache/example-author/example-plugin/1.0.0/scripts/bun-runner.js",
            "/Users/example/.claude/plugins/cache/example-author/example-plugin/1.0.0/scripts/worker-service.cjs",
            "hook",
            "claude-code",
            "summarize",
        ])

        #expect(command == nil)
    }

    @Test("async requested command names survive suspension")
    func asyncRequestedCommandNamesSurviveSuspension() async throws {
        let context = try await AuthsiaBridgeClient.shared.withRequestedCommand(
            "scrape",
            includeAutomationCredential: false
        ) {
            try await Task.sleep(nanoseconds: 1)
            return AuthsiaBridgeClient.currentContext()
        }

        #expect(context.requestedCommand == "scrape")
        #expect(context.automationCredentialID == nil)
    }

    @Test("shell completion metadata can request approval in regular terminals")
    func shellCompletionMetadataCanRequestApprovalInRegularTerminals() {
        #expect(AuthsiaBridgeClient.shouldRequestShellCompletionMetadata(
            sessionToken: nil,
            environment: [
                "TERM_PROGRAM": "iTerm.app",
            ]
        ))
        #expect(AuthsiaBridgeClient.shouldRequestShellCompletionMetadata(
            sessionToken: "",
            environment: [
                "TERM_PROGRAM": "ghostty",
            ]
        ))
    }

    @Test("shell completion metadata skips IDE terminals without an active session")
    func shellCompletionMetadataSkipsIDETerminalsWithoutActiveSession() {
        #expect(!AuthsiaBridgeClient.shouldRequestShellCompletionMetadata(
            sessionToken: nil,
            environment: [
                "TERM_PROGRAM": "vscode",
            ]
        ))
        #expect(!AuthsiaBridgeClient.shouldRequestShellCompletionMetadata(
            sessionToken: nil,
            environment: [
                "TERMINAL_EMULATOR": "JetBrains-JediTerm",
            ]
        ))
        #expect(AuthsiaBridgeClient.shouldRequestShellCompletionMetadata(
            sessionToken: "active",
            environment: [
                "TERM_PROGRAM": "vscode",
            ]
        ))
    }
}
