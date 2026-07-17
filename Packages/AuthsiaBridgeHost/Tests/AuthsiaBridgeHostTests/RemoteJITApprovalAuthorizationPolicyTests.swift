import Foundation
import XCTest
import AuthenticatorBridge
@testable import AuthsiaBridgeHost

final class RemoteJITApprovalAuthorizationPolicyTests: XCTestCase {
    func testMacBiometricAllowsLocalAndJITCommands() {
        for command in [BridgeRequestType.getPassword, .agentJITPreflight] {
            XCTAssertEqual(
                authorize(.approved(source: .macBiometric), command: command),
                .allowed(source: .macBiometric, attribution: "biometric")
            )
        }
    }

    func testMacBiometricAllowsMatchingJITRequests() throws {
        XCTAssertEqual(
            authorize(
                .approved(source: .macBiometric),
                command: .agentJITPreflight,
                remoteRequests: [try makeRequest()]
            ),
            .allowed(source: .macBiometric, attribution: "biometric")
        )
    }

    func testMacPanelAllowsLocalAndJITCommands() {
        for command in [BridgeRequestType.unlock, .agentJITPreflight] {
            XCTAssertEqual(
                authorize(.approved(source: .macPanel), command: command),
                .allowed(source: .macPanel, attribution: "mac-panel")
            )
        }
    }

    func testMacPanelAllowsMatchingJITRequests() throws {
        XCTAssertEqual(
            authorize(
                .approved(source: .macPanel),
                command: .agentJITPreflight,
                remoteRequests: [try makeRequest()]
            ),
            .allowed(source: .macPanel, attribution: "mac-panel")
        )
    }

    func testPairedIPhoneAllowsOnlyMatchingJITRequests() throws {
        let source = try makeSource()
        let request = try makeRequest()

        XCTAssertEqual(
            authorize(
                .approved(source: .pairedIPhone(source)),
                command: .agentJITPreflight,
                remoteRequests: [request]
            ),
            .allowed(
                source: .pairedIPhone(source),
                attribution: "ios-remote:0471b1e549c7"
            )
        )
    }

    func testPairedIPhoneDeniesEmptyRequests() throws {
        let source = try makeSource()

        XCTAssertEqual(
            authorize(.approved(source: .pairedIPhone(source)), command: .agentJITPreflight),
            .denied(attribution: "denied:ios-remote:0471b1e549c7")
        )
    }

    func testPairedIPhoneDeniesNonJITCommand() throws {
        let source = try makeSource()

        XCTAssertEqual(
            authorize(
                .approved(source: .pairedIPhone(source)),
                command: .getPassword,
                remoteRequests: [try makeRequest()]
            ),
            .denied(attribution: "denied:ios-remote:0471b1e549c7")
        )
    }

    func testPairedIPhoneDeniesWrongGeneration() throws {
        let source = try makeSource()
        let request = try makeRequest(
            pairingGenerationID: UUID(uuidString: "10112233-4455-6677-8899-AABBCCDDEEFF")!
        )

        XCTAssertEqual(
            authorize(
                .approved(source: .pairedIPhone(source)),
                command: .agentJITPreflight,
                remoteRequests: [request]
            ),
            .denied(attribution: "denied:ios-remote:0471b1e549c7")
        )
    }

    func testPairedIPhoneDeniesWrongFingerprint() throws {
        let source = try makeSource()
        let request = try makeRequest(iphoneFingerprint: Data(repeating: 0xFF, count: 32))

        XCTAssertEqual(
            authorize(
                .approved(source: .pairedIPhone(source)),
                command: .agentJITPreflight,
                remoteRequests: [request]
            ),
            .denied(attribution: "denied:ios-remote:0471b1e549c7")
        )
    }

    func testPairedIPhoneDeniesMixedBindings() throws {
        let source = try makeSource()
        let requests = [
            try makeRequest(),
            try makeRequest(iphoneFingerprint: Data(repeating: 0xFF, count: 32))
        ]

        XCTAssertEqual(
            authorize(
                .approved(source: .pairedIPhone(source)),
                command: .agentJITPreflight,
                remoteRequests: requests
            ),
            .denied(attribution: "denied:ios-remote:0471b1e549c7")
        )
    }

    func testNonJITCommandDeniesNonemptyRemoteRequestsForMacSource() throws {
        XCTAssertEqual(
            authorize(
                .approved(source: .macBiometric),
                command: .getPassword,
                remoteRequests: [try makeRequest()]
            ),
            .denied(attribution: "denied:biometric")
        )
    }

    func testNonJITCommandDeniesNonemptyRemoteRequestsForMacPanel() throws {
        XCTAssertEqual(
            authorize(
                .approved(source: .macPanel),
                command: .getPassword,
                remoteRequests: [try makeRequest()]
            ),
            .denied(attribution: "denied:mac-panel")
        )
    }

    func testDeniedSourcesHaveExactAttribution() throws {
        let remote = try makeSource()
        XCTAssertEqual(
            authorize(.denied(source: .macBiometric), command: .getPassword),
            .denied(attribution: "denied:biometric")
        )
        XCTAssertEqual(
            authorize(.denied(source: .macPanel), command: .getPassword),
            .denied(attribution: "denied:mac-panel")
        )
        XCTAssertEqual(
            authorize(.denied(source: .pairedIPhone(remote)), command: .agentJITPreflight),
            .denied(attribution: "denied:ios-remote:0471b1e549c7")
        )
    }

    func testSupersededAndTimedOutHaveExactAttribution() {
        XCTAssertEqual(
            authorize(.superseded, command: .agentJITPreflight),
            .denied(attribution: "denied:superseded")
        )
        XCTAssertEqual(
            authorize(.timedOut, command: .agentJITPreflight),
            .denied(attribution: "denied:timeout")
        )
    }

    private func authorize(
        _ outcome: RemoteJITApprovalOutcome,
        command: BridgeRequestType,
        remoteRequests: [RemoteJITApprovalRequest] = []
    ) -> RemoteJITApprovalAuthorizationPolicy.Result {
        RemoteJITApprovalAuthorizationPolicy.authorize(
            outcome: outcome,
            command: command,
            remoteRequests: remoteRequests
        )
    }
}

private func makeSource() throws -> RemoteJITApprovalPairedIPhoneSource {
    try RemoteJITApprovalPairedIPhoneSource(
        pairingGenerationID: UUID(uuidString: "00112233-4455-6677-8899-AABBCCDDEEFF")!,
        signingKeyFingerprint: Data(0..<32)
    )
}

private func makeRequest(
    pairingGenerationID: UUID = UUID(uuidString: "00112233-4455-6677-8899-AABBCCDDEEFF")!,
    iphoneFingerprint: Data = Data(0..<32)
) throws -> RemoteJITApprovalRequest {
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
                folderPath: nil
            )
        ],
        grantExpiresAtMilliseconds: 1_700_000_060_000
    )
    let pairing = try RemoteJITApprovalPairingBinding(
        pairingGenerationID: pairingGenerationID,
        macDeviceID: UUID(uuidString: "22222222-3333-4444-8555-666666666666")!,
        iphoneDeviceID: UUID(uuidString: "33333333-4444-4555-8666-777777777777")!,
        macSigningKeyFingerprint: Data(repeating: 0xA1, count: 32),
        iphoneSigningKeyFingerprint: iphoneFingerprint
    )
    let descriptor = try RemoteJITApprovalDescriptor(
        input: input,
        approvalID: UUID(),
        approvalNonce: Data(repeating: 0xC3, count: 32),
        pairing: pairing
    )
    return try RemoteJITApprovalRequest(
        descriptor: descriptor,
        requestDigest: Data(repeating: 0xD4, count: 32),
        requestSignature: Data(repeating: 0xE5, count: 64)
    )
}
