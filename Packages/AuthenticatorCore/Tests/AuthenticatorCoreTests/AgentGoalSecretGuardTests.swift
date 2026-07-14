import XCTest
@testable import AuthenticatorCore

final class AgentGoalSecretGuardTests: XCTestCase {
    func testFlagsLikelyPastedSecrets() {
        let stripeKey = "sk_" + "live_51ABCDEF1234567890abcdef"
        let openAIKey = "sk-" + "proj-abcdefghijklmnopqrstuvwxyz1234567890"
        let anthropicKey = "sk-" + "ant-api03-abcdefghijklmnopqrstuvwxyz1234567890"
        let githubPAT = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456"
        let githubOAuthToken = "gho_" + "abcdefghijklmnopqrstuvwxyz123456"
        let githubServerToken = "ghs_" + "abcdefghijklmnopqrstuvwxyz123456"
        let gitlabPAT = "glpat-" + "abcdefghijklmnopqrstuvwxyz123456"
        let googleKey = "AIza" + "Syabcdefghijklmnopqrstuvwxyz123456789"
        let huggingFaceToken = "hf_" + "abcdefghijklmnopqrstuvwxyz123456"
        let awsAccessKey = "AKIA" + "ABCDEFGHIJKLMNOP"
        let privateKey = """
        -----BEGIN \("PRIVATE KEY")-----
        abcdef
        -----END PRIVATE KEY-----
        """

        XCTAssertTrue(AgentGoalSecretGuard.containsLikelySecret("Debug checkout with \(stripeKey)"))
        XCTAssertTrue(AgentGoalSecretGuard.containsLikelySecret("Debug with \(openAIKey)"))
        XCTAssertTrue(AgentGoalSecretGuard.containsLikelySecret("Debug with \(anthropicKey)"))
        XCTAssertTrue(AgentGoalSecretGuard.containsLikelySecret("Use token \(githubPAT)"))
        XCTAssertTrue(AgentGoalSecretGuard.containsLikelySecret("Use token \(githubOAuthToken)"))
        XCTAssertTrue(AgentGoalSecretGuard.containsLikelySecret("Use token \(githubServerToken)"))
        XCTAssertTrue(AgentGoalSecretGuard.containsLikelySecret("Use token \(gitlabPAT)"))
        XCTAssertTrue(AgentGoalSecretGuard.containsLikelySecret("Google key \(googleKey)"))
        XCTAssertTrue(AgentGoalSecretGuard.containsLikelySecret("Use model token \(huggingFaceToken)"))
        XCTAssertTrue(AgentGoalSecretGuard.containsLikelySecret("AWS key \(awsAccessKey)"))
        XCTAssertTrue(AgentGoalSecretGuard.containsLikelySecret(privateKey))
    }

    func testAllowsPlaceholdersAndAuthsiaReferences() {
        XCTAssertFalse(AgentGoalSecretGuard.containsLikelySecret("Fix checkout using $API_KEY and ${Var}"))
        XCTAssertFalse(AgentGoalSecretGuard.containsLikelySecret("Use curl $var ${Var} without printing values"))
        XCTAssertFalse(AgentGoalSecretGuard.containsLikelySecret("Use authsia://password/API_KEY/password?folder=Workspaces%2Fapi"))
        XCTAssertFalse(AgentGoalSecretGuard.containsLikelySecret("Replace sk_test_example with an Authsia reference"))
    }

    func testBuildsSharedWorkspaceGoalHandoff() throws {
        let handoff = try XCTUnwrap(AgentWorkspaceGoalHandoff.make(
            workspaceName: "My Project",
            toolName: "Codex",
            launchCommand: "cd '/tmp/My Project' && codex",
            goal: "Fix checkout without printing $API_KEY"
        ))

        XCTAssertEqual(handoff.goal, "Fix checkout without printing $API_KEY")
        XCTAssertEqual(handoff.clipboardText, """
        Agent goal
        Workspace: My Project
        Tool: Codex
        Launch: cd '/tmp/My Project' && codex

        Fix checkout without printing $API_KEY

        Workspace preflight: run authsia workspace status first, then use authsia workspace run --dry-run -- <command> before secret-bearing commands.
        Secret handling: use Authsia JIT or automation token per command through authsia workspace run -- <command> or authsia exec; do not paste plaintext secrets.
        """)
    }

    func testWorkspaceGoalValidationReportsReason() {
        let stripeKey = "sk_" + "live_51ABCDEF1234567890abcdef"

        XCTAssertNil(AgentWorkspaceGoalHandoff.validationFailure(for: "Fix checkout using ${API_KEY}"))
        XCTAssertEqual(AgentWorkspaceGoalHandoff.validationFailure(for: "   \n"), .empty)
        XCTAssertEqual(
            AgentWorkspaceGoalHandoff.validationFailure(for: "Debug checkout with \(stripeKey)"),
            .likelySecret
        )
    }
}
