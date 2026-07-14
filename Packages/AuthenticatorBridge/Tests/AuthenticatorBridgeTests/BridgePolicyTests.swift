import XCTest
@testable import AuthenticatorBridge

final class BridgePolicyTests: XCTestCase {
    func testDenyWhenSSH() {
        let context = BridgeContext(isTTY: true, isPiped: false, isSSH: true, isCI: false, timestamp: Date())
        let decision = BridgePolicy.evaluate(command: .getOTP, context: context, session: nil, requiresApproval: false)
        XCTAssertEqual(decision, .deny("ssh"))
    }

    func testAllowOTPWithinSession() throws {
        let context = BridgeContext(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date())
        let session = try BridgeSession(expiresAt: Date().addingTimeInterval(10))
        let decision = BridgePolicy.evaluate(command: .getOTP, context: context, session: session, requiresApproval: false)
        XCTAssertEqual(decision, .allow)
    }

    func testListRequiresApprovalWithoutSession() {
        let context = BridgeContext(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date())
        let decision = BridgePolicy.evaluate(command: .list, context: context, session: nil, requiresApproval: false)
        XCTAssertEqual(decision, .requireApproval)
    }

    func testListAllowsWithinSession() throws {
        let context = BridgeContext(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date())
        let session = try BridgeSession(expiresAt: Date().addingTimeInterval(10))
        let decision = BridgePolicy.evaluate(command: .list, context: context, session: session, requiresApproval: false)
        XCTAssertEqual(decision, .allow)
    }

    func testAutomationContextAllowsWithoutSession() {
        let context = BridgeContext(
            isTTY: true,
            isPiped: false,
            isSSH: false,
            isCI: false,
            timestamp: Date(),
            automationCredentialID: UUID().uuidString,
            automationScope: "Team/API"
        )
        let decision = BridgePolicy.evaluate(command: .getPassword, context: context, session: nil, requiresApproval: true)
        XCTAssertEqual(decision, .allow)
    }

    func testAutomationContextAllowsNilScopeWithoutSession() {
        let context = BridgeContext(
            isTTY: true,
            isPiped: false,
            isSSH: false,
            isCI: false,
            timestamp: Date(),
            automationCredentialID: UUID().uuidString,
            automationScope: nil
        )
        let decision = BridgePolicy.evaluate(command: .getPassword, context: context, session: nil, requiresApproval: true)
        XCTAssertEqual(decision, .allow)
    }
}
