import XCTest
import AuthenticatorBridge
import AuthenticatorCore
@testable import AuthsiaBridgeHost

final class SSHAgentListenerAuthorizationTests: XCTestCase {
    func testAutomationDenialDoesNotFallThroughToSigning() {
        let signer = SigningTracker()
        let listener = makeListener(approvalDecision: .approved, passphrase: "unused")

        let result = listener.authorizedSignature(
            approvalRequest: makeApprovalRequest(),
            automationDecision: .deny("denied by automation policy"),
            keyIsEncrypted: false,
            storedPassphrase: { nil },
            sign: signer.sign,
            persistPassphrase: { _ in XCTFail("passphrase must not be persisted") }
        )

        XCTAssertNil(result)
        XCTAssertEqual(signer.callCount, 0)
    }

    func testApprovalDenialDoesNotFallThroughToSigning() {
        let signer = SigningTracker()
        let listener = makeListener(approvalDecision: .denied, passphrase: "unused")

        let result = listener.authorizedSignature(
            approvalRequest: makeApprovalRequest(),
            automationDecision: .notAutomation,
            keyIsEncrypted: false,
            storedPassphrase: { nil },
            sign: signer.sign,
            persistPassphrase: { _ in XCTFail("passphrase must not be persisted") }
        )

        XCTAssertNil(result)
        XCTAssertEqual(signer.callCount, 0)
    }

    func testMissingPassphraseFailsWithoutSigningOrPersistingPassphrase() {
        let signer = SigningTracker()
        let persistence = PassphrasePersistenceTracker()
        let listener = makeListener(approvalDecision: .approved, passphrase: nil)

        let result = listener.authorizedSignature(
            approvalRequest: makeApprovalRequest(),
            automationDecision: .notAutomation,
            keyIsEncrypted: true,
            storedPassphrase: { nil },
            sign: signer.sign,
            persistPassphrase: persistence.persist
        )

        XCTAssertNil(result)
        XCTAssertEqual(signer.callCount, 0)
        XCTAssertEqual(persistence.values, [])
    }

    private func makeListener(
        approvalDecision: SSHAgentApprovalDecision,
        passphrase: String?
    ) -> SSHAgentListener {
        SSHAgentListener(
            approvalProvider: ApprovalProviderFake(decision: approvalDecision),
            passphraseProvider: PassphraseProviderFake(value: passphrase)
        )
    }

    private func makeApprovalRequest() -> SSHAgentApprovalRequest {
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
    }
}

private struct ApprovalProviderFake: SSHAgentApprovalProviding {
    let decision: SSHAgentApprovalDecision

    func evaluateApproval(_ request: SSHAgentApprovalRequest) -> SSHAgentApprovalDecision {
        decision
    }

    func clearSessions() {}
}

private struct PassphraseProviderFake: SSHKeyPassphraseProviding {
    let value: String?

    func passphrase(for request: SSHKeyPassphraseRequest) -> String? {
        value
    }
}

private final class SigningTracker {
    private(set) var callCount = 0

    func sign(passphrase: String?) -> Data? {
        callCount += 1
        return Data([0x01])
    }
}

private final class PassphrasePersistenceTracker {
    private(set) var values: [String] = []

    func persist(_ passphrase: String) {
        values.append(passphrase)
    }
}
