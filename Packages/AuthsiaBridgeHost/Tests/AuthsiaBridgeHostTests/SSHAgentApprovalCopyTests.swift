import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge

final class SSHAgentApprovalCopyTests: XCTestCase {
    func testGitOperationReadsAllowlistedVerbAfterGlobalOptions() {
        XCTAssertEqual(
            SSHAgentApprovalCopy.gitOperation(fromArguments: ["/usr/bin/git", "fetch", "origin"]),
            "git fetch"
        )
        XCTAssertEqual(
            SSHAgentApprovalCopy.gitOperation(fromArguments: ["git", "-C", "/tmp/repo", "push"]),
            "git push"
        )
        XCTAssertEqual(
            SSHAgentApprovalCopy.gitOperation(fromArguments: ["git", "--git-dir=/tmp/repo/.git", "ls-remote"]),
            "git ls-remote"
        )
        XCTAssertEqual(
            SSHAgentApprovalCopy.gitOperation(fromArguments: ["git", "pull"]),
            "git pull"
        )
        XCTAssertEqual(
            SSHAgentApprovalCopy.gitOperation(fromArguments: ["git", "clone"]),
            "git clone"
        )
    }

    func testGitOperationIgnoresNonGitAndNonAllowlistedVerbs() {
        XCTAssertNil(SSHAgentApprovalCopy.gitOperation(fromArguments: ["ssh", "git@github.com"]))
        XCTAssertNil(SSHAgentApprovalCopy.gitOperation(fromArguments: ["git", "status"]))
        XCTAssertNil(SSHAgentApprovalCopy.gitOperation(fromArguments: ["git", "git@github.com:org/repo.git"]))
        XCTAssertNil(SSHAgentApprovalCopy.gitOperation(fromArguments: []))
    }

    func testGitOperationDoesNotConsumeAFollowingVerbAsAnOptionValue() {
        XCTAssertEqual(
            SSHAgentApprovalCopy.gitOperation(fromArguments: ["git", "--exec-path", "fetch"]),
            "git fetch"
        )
    }

    func testTouchIDReasonNamesKnownAgentsAndGitVerb() {
        let cases: [(String, String, String)] = [
            ("claude", "claude-code", "Claude Code"),
            ("codex", "codex", "Codex"),
            ("cursor-agent", "cursor", "Cursor Agent"),
            ("github-copilot", "copilot", "GitHub Copilot"),
            ("windsurf-agent", "devin", "Windsurf Agent"),
        ]

        for (processName, platform, displayName) in cases {
            let reason = SSHAgentApprovalCopy.touchIDReason(
                keyName: "github",
                requester: makeRequester(
                    instigatorName: "git",
                    targetHost: "github.com",
                    agentPlatform: platform,
                    agentDisplayName: SSHAgentApprovalCopy.displayName(
                        processName: processName,
                        platform: platform
                    ),
                    sourceOperation: "git fetch"
                )
            )

            XCTAssertEqual(
                reason,
                "\(displayName) wants to use SSH key \"github\" for github.com via git fetch",
                processName
            )
            XCTAssertFalse(reason.contains("origin"), processName)
            XCTAssertFalse(reason.contains("git@"), processName)
        }
    }

    func testTouchIDReasonKeepsProcessNameWhenNoKnownAgent() {
        let reason = SSHAgentApprovalCopy.touchIDReason(
            keyName: "github",
            requester: makeRequester(
                instigatorName: "git",
                targetHost: "github.com",
                sourceOperation: "git push"
            )
        )

        XCTAssertEqual(reason, "\"git\" wants to use SSH key \"github\" for github.com via git push")
    }

    func testFallbackMentionsWhySSHIsNeededForAgentGit() {
        let text = SSHAgentApprovalCopy.fallbackInformativeText(
            keyName: "github",
            requester: makeRequester(
                instigatorName: "git",
                targetHost: "github.com",
                agentPlatform: "claude-code",
                agentDisplayName: "Claude Code",
                sourceOperation: "git fetch"
            )
        )

        XCTAssertTrue(text.contains("Claude Code wants to use SSH key \"github\" for github.com via git fetch."))
        XCTAssertTrue(text.contains("SSH is required to authenticate this Git remote."))
        XCTAssertTrue(text.contains("Parent chain:"))
    }

    private func makeRequester(
        instigatorName: String,
        targetHost: String?,
        agentPlatform: String? = nil,
        agentDisplayName: String? = nil,
        sourceOperation: String? = nil
    ) -> SSHAgentRequester {
        SSHAgentRequester(
            peer: SSHAgentProcessRef(pid: 10, name: "ssh", path: "/usr/bin/ssh"),
            instigator: SSHAgentProcessRef(pid: 11, name: instigatorName, path: "/usr/bin/git"),
            ancestry: [
                SSHAgentProcessRef(pid: 10, name: "ssh", path: "/usr/bin/ssh"),
                SSHAgentProcessRef(pid: 11, name: instigatorName, path: "/usr/bin/git"),
                SSHAgentProcessRef(pid: 12, name: "zsh", path: "/bin/zsh"),
            ],
            targetHost: targetHost,
            sessionScope: "agent:claude-code:pid:13",
            agentPlatform: agentPlatform,
            agentDisplayName: agentDisplayName,
            sourceOperation: sourceOperation
        )
    }
}
