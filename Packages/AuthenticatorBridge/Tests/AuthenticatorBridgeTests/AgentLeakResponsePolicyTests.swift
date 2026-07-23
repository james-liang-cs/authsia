import XCTest
@testable import AuthenticatorBridge

final class AgentLeakResponsePolicyTests: XCTestCase {
    func testBlockModeDeniesDirectEnvironmentDumpBeforeToolUse() {
        let decision = AgentLeakResponsePolicy.decision(
            command: "env",
            hookEventName: "PreToolUse",
            mode: .block
        )

        XCTAssertEqual(decision.outcome, .deny)
        XCTAssertTrue(decision.preventedAction)
        XCTAssertEqual(decision.evidence, .directEnvironmentDump)
    }

    func testConfirmModeAsksForKnownDotEnvRead() {
        let decision = AgentLeakResponsePolicy.decision(
            command: "cat .env.production",
            hookEventName: "PreToolUse",
            mode: .confirm
        )

        XCTAssertEqual(decision.outcome, .warn)
        XCTAssertEqual(decision.hookPermissionDecision, .ask)
        XCTAssertTrue(decision.preventedAction)
        XCTAssertEqual(decision.evidence, .environmentFileRead)
    }

    func testObserveModeRecordsButAllowsRiskyCommand() {
        let decision = AgentLeakResponsePolicy.decision(
            command: "printenv",
            hookEventName: "PreToolUse",
            mode: .observe
        )

        XCTAssertEqual(decision.outcome, .warn)
        XCTAssertEqual(decision.hookPermissionDecision, .allow)
        XCTAssertFalse(decision.preventedAction)
    }

    func testPostToolFindingNeverClaimsPrevention() {
        let decision = AgentLeakResponsePolicy.decision(
            command: "cat .env",
            hookEventName: "PostToolUse",
            mode: .block
        )

        XCTAssertEqual(decision.outcome, .warn)
        XCTAssertFalse(decision.preventedAction)
        XCTAssertNil(decision.hookPermissionDecision)
    }

    func testCriticalAuthorityViolationRevokesAndDeniesInBlockMode() {
        for evidence in [
            AgentLeakEvidence.repeatedDeniedTokenUse,
            .callerBindingMismatch,
            .outsideApprovedItemScope,
        ] {
            let decision = AgentLeakResponsePolicy.decision(
                evidence: evidence,
                phase: .preTool,
                mode: .block
            )

            XCTAssertEqual(decision.outcome, .revokeAndDeny)
            XCTAssertEqual(decision.hookPermissionDecision, .deny)
            XCTAssertTrue(decision.shouldRevokeAuthority)
        }
    }

    func testSafeCommandIsAllowed() {
        let decision = AgentLeakResponsePolicy.decision(
            command: "git status",
            hookEventName: "PreToolUse",
            mode: .block
        )

        XCTAssertEqual(decision.outcome, .allow)
        XCTAssertEqual(decision.hookPermissionDecision, .allow)
        XCTAssertNil(decision.evidence)
    }

    func testEnvironmentWordUsedAsDataIsNotMisclassifiedAsDump() {
        let decision = AgentLeakResponsePolicy.decision(
            command: "printf '%s\n' env",
            hookEventName: "PreToolUse",
            mode: .block
        )

        XCTAssertEqual(decision.outcome, .allow)
        XCTAssertNil(decision.evidence)
    }
}
