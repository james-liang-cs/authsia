import XCTest
import AuthenticatorBridge
import AuthenticatorCore
@testable import AuthsiaBridgeHost

final class ApprovalSeamTests: XCTestCase {
    @MainActor
    func testBridgeApproverDeniesWithoutExplicitDecision() async {
        let approver = BridgeApproverFake()

        let approved = await approver.requestApproval(
            prompt: "Approve fixture request",
            command: .getPassword,
            itemLabel: nil,
            field: nil,
            callback: nil
        )

        XCTAssertFalse(approved)
    }

    func testSSHApproverDeniesWithoutExplicitDecision() {
        let approver = SSHAgentApprovalProviderFake()

        let decision = approver.evaluateApproval(
            SSHAgentApprovalRequest(
                keyID: UUID(),
                keyName: "Fixture key",
                approvalPolicy: .alwaysPrompt,
                requester: SSHAgentRequester(
                    peer: nil,
                    instigator: nil,
                    ancestry: [],
                    targetHost: nil,
                    sessionScope: nil
                )
            )
        )

        XCTAssertEqual(decision, .denied)
    }

    func testPassphraseProviderReturnsNilWithoutExplicitValue() {
        let provider = SSHKeyPassphraseProviderFake()

        let passphrase = provider.passphrase(
            for: SSHKeyPassphraseRequest(keyID: UUID(), keyName: "Fixture key")
        )

        XCTAssertNil(passphrase)
    }
}

private struct BridgeApproverFake: BridgeApprover {
    var decision: Bool?

    init(decision: Bool? = nil) {
        self.decision = decision
    }

    func requestApproval(
        prompt: String,
        command: BridgeRequestType,
        itemLabel: String?,
        field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?
    ) async -> Bool {
        decision ?? false
    }
}

private struct SSHAgentApprovalProviderFake: SSHAgentApprovalProviding {
    var decision: SSHAgentApprovalDecision?

    init(decision: SSHAgentApprovalDecision? = nil) {
        self.decision = decision
    }

    func evaluateApproval(_ request: SSHAgentApprovalRequest) -> SSHAgentApprovalDecision {
        decision ?? .denied
    }

    func clearSessions() {}
}

private struct SSHKeyPassphraseProviderFake: SSHKeyPassphraseProviding {
    var value: String?

    init(value: String? = nil) {
        self.value = value
    }

    func passphrase(for request: SSHKeyPassphraseRequest) -> String? {
        value
    }
}
