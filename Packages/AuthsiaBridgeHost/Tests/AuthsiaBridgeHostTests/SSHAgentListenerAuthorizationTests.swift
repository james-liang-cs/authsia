import XCTest
import AuthenticatorBridge
import AuthenticatorCore
@testable import AuthsiaBridgeHost

final class SSHAgentListenerAuthorizationTests: XCTestCase {
    func testApprovedUnencryptedKeySignsWithoutPassphrase() {
        let signer = SigningTracker()
        let persistence = PassphrasePersistenceTracker()
        let listener = makeListener(approvalDecision: .approved, passphrases: [])

        let result = listener.authorizedSignature(
            approvalRequest: makeApprovalRequest(),
            automationDecision: .notAutomation,
            keyIsEncrypted: false,
            storedPassphrase: { nil },
            sign: signer.sign,
            persistPassphrase: persistence.persist
        )

        XCTAssertEqual(result?.signature, Data([0x01]))
        XCTAssertEqual(result?.approvedBy, "biometric")
        XCTAssertEqual(signer.passphrases, [nil])
        XCTAssertEqual(persistence.values, [])
    }

    func testSessionGrantAndKeyPolicyApprovalsAreNotAuditedAsBiometric() {
        for (decision, expectedLabel) in [
            (SSHAgentApprovalDecision.approvedFromSession, "ssh-session"),
            (SSHAgentApprovalDecision.approvedByKeyPolicy, "key-policy"),
        ] {
            let listener = makeListener(approvalDecision: decision, passphrases: [])

            let result = listener.authorizedSignature(
                approvalRequest: makeApprovalRequest(),
                automationDecision: .notAutomation,
                keyIsEncrypted: false,
                storedPassphrase: { nil },
                sign: SigningTracker().sign,
                persistPassphrase: { _ in XCTFail("passphrase must not be persisted") }
            )

            XCTAssertEqual(result?.approvedBy, expectedLabel)
        }
    }

    func testAutomationApprovalSignsWithoutHumanApproval() {
        let approvalProvider = ApprovalProviderFake(decision: .denied)
        let signer = SigningTracker()
        let listener = SSHAgentListener(
            approvalProvider: approvalProvider,
            passphraseProvider: PassphraseProviderFake(values: [])
        )

        let result = listener.authorizedSignature(
            approvalRequest: makeApprovalRequest(),
            automationDecision: .allowWithoutApproval(scope: .global),
            keyIsEncrypted: false,
            storedPassphrase: { nil },
            sign: signer.sign,
            persistPassphrase: { _ in XCTFail("passphrase must not be persisted") }
        )

        XCTAssertEqual(result?.signature, Data([0x01]))
        XCTAssertEqual(result?.approvedBy, "automation")
        XCTAssertEqual(approvalProvider.callCount, 0)
        XCTAssertEqual(signer.passphrases, [nil])
    }

    func testStoredPassphraseSignsWithoutPromptingOrPersisting() {
        let passphraseProvider = PassphraseProviderFake(values: [])
        let signer = SigningTracker()
        let persistence = PassphrasePersistenceTracker()
        let listener = SSHAgentListener(
            approvalProvider: ApprovalProviderFake(decision: .approved),
            passphraseProvider: passphraseProvider
        )

        let result = listener.authorizedSignature(
            approvalRequest: makeApprovalRequest(),
            automationDecision: .notAutomation,
            keyIsEncrypted: true,
            storedPassphrase: { "stored" },
            sign: signer.sign,
            persistPassphrase: persistence.persist
        )

        XCTAssertEqual(result?.signature, Data([0x01]))
        XCTAssertEqual(signer.passphrases, ["stored"])
        XCTAssertEqual(passphraseProvider.callCount, 0)
        XCTAssertEqual(persistence.values, [])
    }

    func testFailedStoredPassphraseRetriesAndPersistsSuccessfulPromptedPassphrase() {
        let passphraseProvider = PassphraseProviderFake(values: ["prompted"])
        let signer = SigningTracker(results: [nil, Data([0x02])])
        let persistence = PassphrasePersistenceTracker()
        let listener = SSHAgentListener(
            approvalProvider: ApprovalProviderFake(decision: .approved),
            passphraseProvider: passphraseProvider
        )

        let result = listener.authorizedSignature(
            approvalRequest: makeApprovalRequest(),
            automationDecision: .notAutomation,
            keyIsEncrypted: true,
            storedPassphrase: { "stored" },
            sign: signer.sign,
            persistPassphrase: persistence.persist
        )

        XCTAssertEqual(result?.signature, Data([0x02]))
        XCTAssertEqual(signer.passphrases, ["stored", "prompted"])
        XCTAssertEqual(passphraseProvider.callCount, 1)
        XCTAssertEqual(persistence.values, ["prompted"])
    }

    func testPromptedPassphrasePersistsOnlyAfterSuccessfulSigning() {
        let passphraseProvider = PassphraseProviderFake(values: ["prompted"])
        let signer = SigningTracker()
        let persistence = PassphrasePersistenceTracker()
        let listener = SSHAgentListener(
            approvalProvider: ApprovalProviderFake(decision: .approved),
            passphraseProvider: passphraseProvider
        )

        let result = listener.authorizedSignature(
            approvalRequest: makeApprovalRequest(),
            automationDecision: .notAutomation,
            keyIsEncrypted: true,
            storedPassphrase: { nil },
            sign: signer.sign,
            persistPassphrase: persistence.persist
        )

        XCTAssertEqual(result?.signature, Data([0x01]))
        XCTAssertEqual(signer.passphrases, ["prompted"])
        XCTAssertEqual(persistence.values, ["prompted"])
    }

    func testFailedPromptedPassphraseDoesNotPersist() {
        let passphraseProvider = PassphraseProviderFake(values: ["prompted", nil])
        let signer = SigningTracker(results: [nil])
        let persistence = PassphrasePersistenceTracker()
        let listener = SSHAgentListener(
            approvalProvider: ApprovalProviderFake(decision: .approved),
            passphraseProvider: passphraseProvider
        )

        let result = listener.authorizedSignature(
            approvalRequest: makeApprovalRequest(),
            automationDecision: .notAutomation,
            keyIsEncrypted: true,
            storedPassphrase: { nil },
            sign: signer.sign,
            persistPassphrase: persistence.persist
        )

        XCTAssertNil(result)
        XCTAssertEqual(signer.passphrases, ["prompted"])
        XCTAssertEqual(passphraseProvider.callCount, 2)
        XCTAssertEqual(persistence.values, [])
    }

    func testAutomationDenialDoesNotFallThroughToSigning() {
        let signer = SigningTracker()
        let listener = makeListener(approvalDecision: .approved, passphrases: ["unused"])

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
        let listener = makeListener(approvalDecision: .denied, passphrases: ["unused"])

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
        let listener = makeListener(approvalDecision: .approved, passphrases: [nil])

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

    // MARK: - Session scope

    func testSessionScopePrefersTerminalOwningAncestor() {
        let scope = SSHAgentListener.sessionScope(
            from: makeAncestry([(10, "ssh"), (11, "git"), (12, "zsh"), (13, "Cursor")]),
            terminalScope: { $0 == 12 ? "tty:/dev/ttys004:sid:12" : nil },
            knownAgentPlatform: { _ in nil },
            automationHostPlatform: { $0.name == "Cursor" ? "cursor" : nil }
        )

        XCTAssertEqual(scope, "tty:/dev/ttys004:sid:12")
    }

    func testSessionScopePrefersKnownAgentOverTerminal() {
        let scope = SSHAgentListener.sessionScope(
            from: makeAncestry([
                (10, "ssh"),
                (11, "git"),
                (12, "zsh"),
                (13, "claude"),
                (14, "Cursor"),
            ]),
            terminalScope: { $0 == 12 ? "tty:/dev/ttys004:sid:12" : nil },
            knownAgentPlatform: { $0.name == "claude" ? "claude-code" : nil },
            automationHostPlatform: { $0.name == "Cursor" ? "cursor" : nil }
        )

        XCTAssertEqual(scope, "agent:claude-code:pid:13")
    }

    func testSessionScopePrefersOutermostKnownAgentOverTerminal() {
        let cases: [(String, String, String)] = [
            ("codex", "codex", "agent:codex:pid:13"),
            ("cursor-agent", "cursor", "agent:cursor:pid:13"),
            ("github-copilot", "copilot", "agent:copilot:pid:13"),
            ("windsurf-agent", "devin", "agent:devin:pid:13"),
        ]

        for (processName, platform, expected) in cases {
            let scope = SSHAgentListener.sessionScope(
                from: makeAncestry([(10, "ssh"), (11, "git"), (12, "zsh"), (13, processName)]),
                terminalScope: { $0 == 12 ? "tty:/dev/ttys009:sid:12" : nil },
                knownAgentPlatform: { $0.name == processName ? platform : nil },
                automationHostPlatform: { _ in nil }
            )
            XCTAssertEqual(scope, expected, processName)
        }
    }

    func testSessionScopeFallsBackToOutermostAgentHostWhenNoAncestorOwnsTerminal() {
        let scope = SSHAgentListener.sessionScope(
            from: makeAncestry([
                (10, "ssh"),
                (11, "git"),
                (12, "Cursor Helper (Plugin)"),
                (13, "Cursor"),
            ]),
            terminalScope: { _ in nil },
            knownAgentPlatform: { _ in nil },
            automationHostPlatform: { process in
                switch process.name {
                case "Cursor": return "cursor"
                case "Cursor Helper (Plugin)": return "cursor-helper"
                default: return nil
                }
            }
        )

        XCTAssertEqual(scope, "agent:cursor:pid:13")
    }

    func testSessionScopeIsNilWhenNoAncestorOwnsTerminalOrHostsAutomation() {
        let scope = SSHAgentListener.sessionScope(
            from: makeAncestry([(10, "ssh"), (11, "git"), (12, "zsh")]),
            terminalScope: { _ in nil },
            knownAgentPlatform: { _ in nil },
            automationHostPlatform: { _ in nil }
        )

        XCTAssertNil(scope)
    }

    func testAgentFallbackScopeResolvesBackToItsProcessIdentifier() {
        let scope = SSHAgentListener.sessionScope(
            from: makeAncestry([(10, "ssh"), (11, "Cursor")]),
            terminalScope: { _ in nil },
            knownAgentPlatform: { _ in nil },
            automationHostPlatform: { $0.name == "Cursor" ? "cursor" : nil }
        )

        XCTAssertEqual(TerminalSessionScope.agentScopedProcessIdentifier(from: scope), 11)
    }

    private func makeAncestry(_ entries: [(pid_t, String)]) -> [SSHAgentListener.ProcessRef] {
        entries.map { SSHAgentListener.ProcessRef(pid: $0.0, name: $0.1, path: nil) }
    }

    private func makeListener(
        approvalDecision: SSHAgentApprovalDecision,
        passphrases: [String?]
    ) -> SSHAgentListener {
        SSHAgentListener(
            approvalProvider: ApprovalProviderFake(decision: approvalDecision),
            passphraseProvider: PassphraseProviderFake(values: passphrases)
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

private final class ApprovalProviderFake: SSHAgentApprovalProviding {
    let decision: SSHAgentApprovalDecision
    private(set) var callCount = 0

    init(decision: SSHAgentApprovalDecision) {
        self.decision = decision
    }

    func evaluateApproval(_ request: SSHAgentApprovalRequest) -> SSHAgentApprovalDecision {
        callCount += 1
        return decision
    }

    func clearSessions() {}
}

private final class PassphraseProviderFake: SSHKeyPassphraseProviding {
    private var values: [String?]
    private(set) var callCount = 0

    init(values: [String?]) {
        self.values = values
    }

    func passphrase(for request: SSHKeyPassphraseRequest) -> String? {
        callCount += 1
        guard !values.isEmpty else { return nil }
        return values.removeFirst()
    }
}

private final class SigningTracker {
    private var results: [Data?]
    private(set) var passphrases: [String?] = []

    var callCount: Int { passphrases.count }

    init(results: [Data?] = [Data([0x01])]) {
        self.results = results
    }

    func sign(passphrase: String?) -> Data? {
        passphrases.append(passphrase)
        guard !results.isEmpty else { return nil }
        return results.removeFirst()
    }
}

private final class PassphrasePersistenceTracker {
    private(set) var values: [String] = []

    func persist(_ passphrase: String) {
        values.append(passphrase)
    }
}
