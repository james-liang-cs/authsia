import Testing
import Foundation
import AuthenticatorBridge
@testable import authsia

@Suite("Doctor command")
struct DoctorCommandTests {

    private static let healthyPing = BridgePingPayload(
        protocolVersion: "1",
        appVersion: "1.0.0",
        bundledCLIPath: "/Applications/Authsia.app/Contents/Helpers/authsia"
    )

    @Test("collectIssues flags missing bridge shell integration ssh agent and expired session")
    func collectIssuesFlagsCommonProblems() {
        let issues = Doctor.collectIssues(
            environment: [:],
            sessionExpiresAt: Date(timeIntervalSince1970: 1_700_000_000),
            pingPayload: nil,
            sshAgentRunning: false,
            currentDate: Date(timeIntervalSince1970: 1_700_000_001)
        )

        #expect(issues.contains(where: { $0.kind == .bridgeUnavailable }))
        #expect(issues.contains(where: { $0.kind == .shellIntegrationDisabled }))
        #expect(issues.contains(where: { $0.kind == .sshAgentMissing }))
        #expect(issues.contains(where: { $0.kind == .sessionExpired }))
    }

    @Test("collectIssues returns no issues when everything is healthy")
    func collectIssuesHealthySystem() {
        let issues = Doctor.collectIssues(
            environment: [
                "AUTHSIA_SHELL_INTEGRATION": "1",
                "SSH_AUTH_SOCK": "/tmp/agent.sock"
            ],
            sessionExpiresAt: Date(timeIntervalSince1970: 1_700_000_100),
            pingPayload: Self.healthyPing,
            sshAgentRunning: true,
            currentDate: Date(timeIntervalSince1970: 1_700_000_001),
            authsiaAgentSocketExists: false,
            runningCLIPath: "/Applications/Authsia.app/Contents/Helpers/authsia"
        )

        #expect(issues.isEmpty)
    }

    @Test("collectIssues flags a stale CLI symlink when paths diverge")
    func collectIssuesFlagsStaleCLI() {
        let issues = Doctor.collectIssues(
            environment: [
                "AUTHSIA_SHELL_INTEGRATION": "1",
                "SSH_AUTH_SOCK": "/tmp/agent.sock"
            ],
            sessionExpiresAt: Date(timeIntervalSince1970: 1_700_000_100),
            pingPayload: BridgePingPayload(
                protocolVersion: "1",
                appVersion: "1.0.2",
                bundledCLIPath: "/Applications/Authsia.app/Contents/Helpers/authsia"
            ),
            sshAgentRunning: true,
            currentDate: Date(timeIntervalSince1970: 1_700_000_001),
            authsiaAgentSocketExists: true,
            runningCLIPath: "/Users/dev/Build/Authsia.app/Contents/Helpers/authsia"
        )

        let mismatch = issues.first(where: { $0.kind == .cliBinaryMismatch })
        #expect(mismatch != nil)
        #expect(mismatch?.detail.contains("/Users/dev/Build/Authsia.app") == true)
        #expect(mismatch?.fix.contains("Update CLI") == true)
    }

    @Test("collectIssues does not flag a stale CLI when paths match")
    func collectIssuesNoFlagWhenPathsMatch() {
        let path = "/Applications/Authsia.app/Contents/Helpers/authsia"
        let issues = Doctor.collectIssues(
            environment: [
                "AUTHSIA_SHELL_INTEGRATION": "1",
                "SSH_AUTH_SOCK": "/tmp/agent.sock"
            ],
            sessionExpiresAt: Date(timeIntervalSince1970: 1_700_000_100),
            pingPayload: BridgePingPayload(
                protocolVersion: "1",
                appVersion: "1.0.2",
                bundledCLIPath: path
            ),
            sshAgentRunning: true,
            currentDate: Date(timeIntervalSince1970: 1_700_000_001),
            authsiaAgentSocketExists: true,
            runningCLIPath: path
        )

        #expect(!issues.contains(where: { $0.kind == .cliBinaryMismatch }))
    }

    @Test("renderIssues includes fixes")
    func renderIssuesIncludesFixes() {
        let issue = DoctorIssue(
            kind: .shellIntegrationDisabled,
            title: "Shell integration is not enabled",
            detail: "Run `eval \"$(authsia init zsh)\"` to enable active-shell export.",
            fix: "Enable shell integration with `authsia init zsh`."
        )

        let output = Doctor.renderIssues([issue])

        #expect(output.contains("Shell integration is not enabled"))
        #expect(output.contains("Enable shell integration"))
        #expect(output.contains("authsia init zsh"))
    }

    @Test("bridge unavailable fix mentions global CLI access")
    func bridgeUnavailableFixMentionsGlobalCLIAccess() {
        let issues = Doctor.collectIssues(
            environment: ["AUTHSIA_SHELL_INTEGRATION": "1"],
            sessionExpiresAt: nil,
            pingPayload: nil,
            sshAgentRunning: true,
            currentDate: Date(timeIntervalSince1970: 1_700_000_001)
        )

        let bridgeIssue = issues.first { $0.kind == .bridgeUnavailable }
        #expect(bridgeIssue?.fix.contains("CLI Access") == true)
    }

    @Test("collectIssues flags stale SSH_AUTH_SOCK when agent socket exists")
    func collectIssuesFlagsStaleSocket() {
        let issues = Doctor.collectIssues(
            environment: [
                "AUTHSIA_SHELL_INTEGRATION": "1",
                "SSH_AUTH_SOCK": "/var/run/com.apple.launchd.XYZ/Listeners"
            ],
            sessionExpiresAt: Date(timeIntervalSince1970: 1_700_000_100),
            pingPayload: Self.healthyPing,
            sshAgentRunning: true,
            currentDate: Date(timeIntervalSince1970: 1_700_000_001),
            authsiaAgentSocketExists: true,
            authsiaAgentSocketPath: "/Users/dev/.authsia/agent.sock",
            runningCLIPath: "/Applications/Authsia.app/Contents/Helpers/authsia"
        )

        let mismatch = issues.first { $0.kind == .sshAgentSocketMismatch }
        #expect(mismatch != nil)
        #expect(mismatch?.detail.contains("/Users/dev/.authsia/agent.sock") == true)
        #expect(mismatch?.fix.contains("authsia init zsh") == true)
    }

    @Test("collectIssues flags unset SSH_AUTH_SOCK when agent socket exists")
    func collectIssuesFlagsUnsetSocket() {
        let issues = Doctor.collectIssues(
            environment: ["AUTHSIA_SHELL_INTEGRATION": "1"],
            sessionExpiresAt: Date(timeIntervalSince1970: 1_700_000_100),
            pingPayload: Self.healthyPing,
            sshAgentRunning: true,
            currentDate: Date(timeIntervalSince1970: 1_700_000_001),
            authsiaAgentSocketExists: true,
            authsiaAgentSocketPath: "/Users/dev/.authsia/agent.sock",
            runningCLIPath: "/Applications/Authsia.app/Contents/Helpers/authsia"
        )

        let mismatch = issues.first { $0.kind == .sshAgentSocketMismatch }
        #expect(mismatch != nil)
        #expect(mismatch?.detail.contains("SSH_AUTH_SOCK is unset") == true)
    }

    @Test("collectIssues does not flag socket when SSH_AUTH_SOCK already matches")
    func collectIssuesNoFlagWhenSocketMatches() {
        let socket = "/Users/dev/.authsia/agent.sock"
        let issues = Doctor.collectIssues(
            environment: [
                "AUTHSIA_SHELL_INTEGRATION": "1",
                "SSH_AUTH_SOCK": socket
            ],
            sessionExpiresAt: Date(timeIntervalSince1970: 1_700_000_100),
            pingPayload: Self.healthyPing,
            sshAgentRunning: true,
            currentDate: Date(timeIntervalSince1970: 1_700_000_001),
            authsiaAgentSocketExists: true,
            authsiaAgentSocketPath: socket,
            runningCLIPath: "/Applications/Authsia.app/Contents/Helpers/authsia"
        )

        #expect(!issues.contains { $0.kind == .sshAgentSocketMismatch })
    }
}
