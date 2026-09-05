import XCTest
@testable import AuthenticatorBridge

final class BridgeRequestTypeSecretAccessTests: XCTestCase {
    /// A new vault category adds a `get…` case, and every audit surface that
    /// classifies secret reads has to learn about it. `.getAPIKey` was added
    /// without that update and stayed unclassified in Access Insights for two
    /// months, so pin the rule rather than the list.
    func testEveryReadCommandIsSecretAccess() {
        let readCommands = BridgeRequestType.allCases.filter { $0.rawValue.hasPrefix("get") }

        XCTAssertFalse(readCommands.isEmpty)
        for command in readCommands {
            XCTAssertTrue(
                command.isSecretAccess,
                "\(command.rawValue) reads a vault item but is not classified as secret access"
            )
        }
    }

    func testNonReadCommandsAreNotSecretAccess() {
        XCTAssertTrue(BridgeRequestType.sshAgentSign.isSecretAccess)
        XCTAssertFalse(BridgeRequestType.list.isSecretAccess)
        XCTAssertFalse(BridgeRequestType.addPassword.isSecretAccess)
        XCTAssertFalse(BridgeRequestType.agentJITPreflight.isSecretAccess)
        XCTAssertFalse(BridgeRequestType.mcpProxyActivity.isSecretAccess)
    }
}
