import XCTest
import AuthenticatorBridge
import AuthenticatorCore
@testable import AuthsiaBridgeHost

final class ApprovalSeamTests: XCTestCase {
    @MainActor
    func testBridgeApproverDeniesWithoutExplicitDecision() async {
        let approver = BridgeApproverFake()

        let outcome = await approver.requestApproval(
            prompt: "Approve fixture request",
            command: .getPassword,
            itemLabel: nil,
            field: nil,
            callback: nil
        )

        XCTAssertEqual(outcome, .denied(source: .macPanel))
        XCTAssertEqual(approver.remoteRequests, [[]])
    }

    @MainActor
    func testBridgeApproverFullRequirementForwardsRemoteRequests() async throws {
        let request = try makeRemoteRequest()
        let expected = RemoteJITApprovalOutcome.approved(source: .macBiometric)
        let approver = BridgeApproverFake(decision: expected)

        let outcome = await approver.requestApproval(
            prompt: "Approve fixture request",
            command: .agentJITPreflight,
            itemLabel: "Fixture",
            field: nil,
            callback: nil,
            remoteRequests: [request]
        )

        XCTAssertEqual(outcome, expected)
        XCTAssertEqual(approver.remoteRequests, [[request]])
    }

    @MainActor
    func testRemoteJITRequestBuilderReturnsBuiltRequests() async throws {
        let request = try makeRemoteRequest()
        let builder = RemoteJITRequestBuilderFake(requests: [request])

        let built = try await builder.buildRequests(for: [request.descriptor.input])

        XCTAssertEqual(built, [request])
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

@MainActor
private final class BridgeApproverFake: BridgeApprover {
    var decision: RemoteJITApprovalOutcome?
    private(set) var remoteRequests: [[RemoteJITApprovalRequest]] = []

    init(decision: RemoteJITApprovalOutcome? = nil) {
        self.decision = decision
    }

    func requestApproval(
        prompt: String,
        command: BridgeRequestType,
        itemLabel: String?,
        field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?,
        remoteRequests: [RemoteJITApprovalRequest]
    ) async -> RemoteJITApprovalOutcome {
        self.remoteRequests.append(remoteRequests)
        return decision ?? .denied(source: .macPanel)
    }
}

@MainActor
private final class RemoteJITRequestBuilderFake: RemoteJITApprovalRequestBuilding {
    let requests: [RemoteJITApprovalRequest]

    init(requests: [RemoteJITApprovalRequest]) {
        self.requests = requests
    }

    func buildRequests(
        for inputs: [RemoteJITApprovalDescriptorInput]
    ) async throws -> [RemoteJITApprovalRequest] {
        requests
    }
}

private func makeRemoteRequest() throws -> RemoteJITApprovalRequest {
    let input = try RemoteJITApprovalDescriptorInput(
        bridgeRequestID: UUID(uuidString: "11111111-2222-4333-8444-555555555555")!,
        requestIssuedAtMilliseconds: 1_700_000_000_000,
        callerFingerprint: AgentJITCallerFingerprint(
            processName: "FixtureAgent",
            bundleIdentifier: "com.example.fixture-agent",
            signingTeamId: "FIXTURETEAM",
            signingIdentity: "Fixture Identity",
            parentProcessName: "FixtureParent",
            parentBundleIdentifier: "com.example.fixture-parent",
            sessionScope: "fixture-session",
            workingDirectory: "/fixture/workspace"
        ),
        capabilities: [.list],
        folderScope: .root,
        environmentScope: nil,
        requestedItems: [
            try RemoteJITApprovalItemReference(
                id: UUID(uuidString: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE")!,
                kind: .password,
                name: "Fixture password",
                folderPath: nil
            )
        ],
        grantExpiresAtMilliseconds: 1_700_000_060_000
    )
    let pairing = try RemoteJITApprovalPairingBinding(
        pairingGenerationID: UUID(uuidString: "00112233-4455-6677-8899-AABBCCDDEEFF")!,
        macDeviceID: UUID(uuidString: "22222222-3333-4444-8555-666666666666")!,
        iphoneDeviceID: UUID(uuidString: "33333333-4444-4555-8666-777777777777")!,
        macSigningKeyFingerprint: Data(repeating: 0xA1, count: 32),
        iphoneSigningKeyFingerprint: Data(0..<32)
    )
    let descriptor = try RemoteJITApprovalDescriptor(
        input: input,
        approvalID: UUID(uuidString: "44444444-5555-4666-8777-888888888888")!,
        approvalNonce: Data(repeating: 0xC3, count: 32),
        pairing: pairing
    )
    return try RemoteJITApprovalRequest(
        descriptor: descriptor,
        requestDigest: Data(repeating: 0xD4, count: 32),
        requestSignature: Data(repeating: 0xE5, count: 64)
    )
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
