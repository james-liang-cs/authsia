import Foundation
import XCTest
@testable import AuthenticatorBridge

final class RemoteJITApprovalModelTests: XCTestCase {
    func testDescriptorInputNormalizesAuthorityAndFactoryRoundTripsWithoutPlaceholders() throws {
        let lowPassword = try makeItem(
            id: UUID(uuidString: "00000000-0000-4000-8000-000000000001")!,
            kind: .password,
            folderPath: " Team / API "
        )
        let highPassword = try makeItem(
            id: UUID(uuidString: "FFFFFFFF-FFFF-4FFF-8FFF-FFFFFFFFFFFF")!,
            kind: .password,
            folderPath: "Team/API/Build"
        )
        let apiKey = try makeItem(
            id: UUID(uuidString: "00000000-0000-4000-8000-000000000000")!,
            kind: .apiKey,
            folderPath: "Team/API"
        )
        let input = try makeValidDescriptorInput(
            callerFingerprint: makeCaller(processName: "De\u{301}mo"),
            capabilities: [.list, .exec],
            folderScope: .folder(" Team / API "),
            environmentScope: .named("\tProduc\u{301}tion \n"),
            items: [apiKey, highPassword, lowPassword]
        )

        XCTAssertEqual(input.callerFingerprint.processName, "Démo")
        XCTAssertEqual(input.capabilities, [.exec, .list])
        XCTAssertEqual(input.folderScope, .folder("Team/API"))
        XCTAssertEqual(input.environmentScope, .named("Produćtion"))
        XCTAssertEqual(input.requestedItems, [lowPassword, highPassword, apiKey])

        let approvalID = UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
        let approvalNonce = Data(repeating: 0x11, count: 32)
        let pairing = try makeValidPairingBinding()
        let descriptor = try RemoteJITApprovalDescriptor(
            input: input,
            approvalID: approvalID,
            approvalNonce: approvalNonce,
            pairing: pairing
        )

        XCTAssertEqual(descriptor.input, input)
        XCTAssertEqual(descriptor.approvalID, approvalID)
        XCTAssertEqual(descriptor.approvalNonce, approvalNonce)
        XCTAssertEqual(descriptor.pairingGenerationID, pairing.pairingGenerationID)
        XCTAssertEqual(descriptor.macDeviceID, pairing.macDeviceID)
        XCTAssertEqual(descriptor.iphoneDeviceID, pairing.iphoneDeviceID)
        XCTAssertEqual(descriptor.macSigningKeyFingerprint, pairing.macSigningKeyFingerprint)
        XCTAssertEqual(descriptor.iphoneSigningKeyFingerprint, pairing.iphoneSigningKeyFingerprint)
        XCTAssertEqual(
            descriptor.requestExpiresAtMilliseconds,
            input.requestIssuedAtMilliseconds + RemoteJITApprovalDescriptor.requestLifetimeMilliseconds
        )
        XCTAssertEqual(descriptor.grantIssuedAtMilliseconds, input.requestIssuedAtMilliseconds)
    }

    func testDescriptorInputRejectsInvalidTimeAndCallerAuthority() throws {
        assertValidationError(.invalidTime) {
            try makeValidDescriptorInput(grantExpiresAtMilliseconds: 2_000_000_000_000)
        }
        assertValidationError(.invalidTime) {
            try makeValidDescriptorInput(grantExpiresAtMilliseconds: 2_000_086_400_001)
        }
        assertValidationError(.invalidTime) {
            try makeValidDescriptorInput(requestIssuedAtMilliseconds: 253_402_300_799_999)
        }
        assertValidationError(.invalidString) {
            try makeValidDescriptorInput(callerFingerprint: makeCaller(processName: ""))
        }
    }

    func testDescriptorInputRejectsInvalidItemAuthorityAndEmptyItems() throws {
        let item = try makeItem()
        assertValidationError(.invalidItems) {
            try makeValidDescriptorInput(items: [])
        }
        assertValidationError(.duplicateItem) {
            try makeValidDescriptorInput(items: [item, item])
        }
        assertValidationError(.invalidItems) {
            try makeValidDescriptorInput(items: [try makeItem(folderPath: "Other")])
        }
    }

    func testValidDescriptorPreservesCanonicalAuthority() throws {
        let descriptor = try makeValidDescriptor()

        XCTAssertEqual(
            descriptor.requestExpiresAtMilliseconds - descriptor.requestIssuedAtMilliseconds,
            90_000
        )
        XCTAssertEqual(
            descriptor.grantIssuedAtMilliseconds,
            descriptor.requestIssuedAtMilliseconds
        )
        XCTAssertEqual(descriptor.capabilities, [.exec, .list])
        XCTAssertEqual(descriptor.requestedItems.count, 1)
    }

    func testFixedLengthModelsAcceptOnlyFrozenLengths() throws {
        XCTAssertNoThrow(try makeValidPairingBinding())
        assertValidationError(.invalidLength) {
            try makeValidPairingBinding(macFingerprint: Data(repeating: 0, count: 31))
        }
        assertValidationError(.invalidLength) {
            try makeValidDescriptor(approvalNonce: Data(repeating: 0, count: 31))
        }
        assertValidationError(.invalidLength) {
            try makeValidDescriptor(macFingerprint: Data(repeating: 0, count: 33))
        }

        let descriptor = try makeValidDescriptor()
        XCTAssertNoThrow(
            try RemoteJITApprovalRequest(
                descriptor: descriptor,
                requestDigest: Data(repeating: 1, count: 32),
                requestSignature: Data(repeating: 2, count: 64)
            )
        )
        assertValidationError(.invalidLength) {
            try RemoteJITApprovalRequest(
                descriptor: descriptor,
                requestDigest: Data(repeating: 1, count: 31),
                requestSignature: Data(repeating: 2, count: 64)
            )
        }

        let payload = try makeValidDecisionPayload()
        XCTAssertNoThrow(
            try RemoteJITApprovalDecision(
                payload: payload,
                decisionSignature: Data(repeating: 3, count: 64)
            )
        )
        assertValidationError(.invalidLength) {
            try RemoteJITApprovalDecision(
                payload: payload,
                decisionSignature: Data(repeating: 3, count: 63)
            )
        }
    }

    func testDescriptorRejectsInvalidRequestAndGrantTimes() throws {
        assertValidationError(.invalidTime) {
            try makeValidDescriptor(requestIssuedAtMilliseconds: -1)
        }
        assertValidationError(.invalidTime) {
            try makeValidDescriptor(requestIssuedAtMilliseconds: 253_402_300_799_999)
        }
        assertValidationError(.invalidTime) {
            try makeValidDescriptor(requestExpiresAtMilliseconds: 2_000_000_089_999)
        }
        assertValidationError(.invalidTime) {
            try makeValidDescriptor(grantIssuedAtMilliseconds: 2_000_000_000_001)
        }
        assertValidationError(.invalidTime) {
            try makeValidDescriptor(grantExpiresAtMilliseconds: 2_000_000_000_000)
        }
        assertValidationError(.invalidTime) {
            try makeValidDescriptor(grantExpiresAtMilliseconds: 2_000_086_400_001)
        }
    }

    func testDescriptorRequiresSafeBoundedCallerStringsAndRemoteContext() throws {
        assertValidationError(.invalidString) {
            try makeValidDescriptor(callerFingerprint: makeCaller(processName: ""))
        }
        assertValidationError(.oversized) {
            try makeValidDescriptor(callerFingerprint: makeCaller(processName: String(repeating: "x", count: 256)))
        }
        assertValidationError(.invalidString) {
            try makeValidDescriptor(callerFingerprint: makeCaller(bundleIdentifier: "example.\u{202E}unsafe"))
        }
        assertValidationError(.invalidString) {
            try makeValidDescriptor(callerFingerprint: makeCaller(sessionScope: nil))
        }
        assertValidationError(.invalidPath) {
            try makeValidDescriptor(callerFingerprint: makeCaller(workingDirectory: nil))
        }

        let descriptor = try makeValidDescriptor(
            callerFingerprint: makeCaller(processName: "De\u{301}mo")
        )
        XCTAssertEqual(descriptor.callerFingerprint.processName, "Démo")
    }

    func testRejectsRawCallerStringAboveSharedInputCeiling() {
        let oversizedProcessName = String(repeating: "x", count: remoteRawInputCeiling + 1)

        assertValidationError(.oversized) {
            try makeValidDescriptor(
                callerFingerprint: makeCaller(processName: oversizedProcessName)
            )
        }
    }

    func testRejectsRawEnvironmentAboveCeilingBeforeTrimming() {
        let oversizedEnvironment = String(repeating: " ", count: remoteRawInputCeiling) + "P"

        assertValidationError(.oversized) {
            try makeValidDescriptor(environmentScope: .named(oversizedEnvironment))
        }
    }

    func testRejectsRawFolderAboveCeilingBeforeSplitting() {
        let oversizedFolder = String(repeating: "/", count: remoteRawInputCeiling) + "T"

        assertValidationError(.oversized) {
            try makeItem(folderPath: oversizedFolder)
        }
    }

    func testRejectsRawWorkingDirectoryAboveCeilingBeforeSplitting() {
        let oversizedWorkingDirectory = String(repeating: "/", count: remoteRawInputCeiling) + "w"

        assertValidationError(.oversized) {
            try makeValidDescriptor(
                callerFingerprint: makeCaller(workingDirectory: oversizedWorkingDirectory)
            )
        }
    }

    func testDecomposedCallerInputNormalizesBeforeApplyingFieldLimit() throws {
        let decomposedProcessName = String(repeating: "e\u{301}", count: 127)
        XCTAssertGreaterThan(decomposedProcessName.utf8.count, 255)

        let descriptor = try makeValidDescriptor(
            callerFingerprint: makeCaller(processName: decomposedProcessName)
        )

        XCTAssertEqual(descriptor.callerFingerprint.processName, String(repeating: "é", count: 127))
        XCTAssertEqual(descriptor.callerFingerprint.processName.utf8.count, 254)
    }

    func testWorkingDirectoryNormalizationIsLexicalAbsoluteAndSafe() throws {
        let descriptor = try makeValidDescriptor(
            callerFingerprint: makeCaller(workingDirectory: "/workspace/./one/../De\u{301}mo//")
        )
        XCTAssertEqual(descriptor.callerFingerprint.workingDirectory, "/workspace/Démo")
        XCTAssertEqual(descriptor.workspaceLabel, "Démo")

        let root = try makeValidDescriptor(
            callerFingerprint: makeCaller(workingDirectory: "/workspace/..")
        )
        XCTAssertEqual(root.callerFingerprint.workingDirectory, "/")
        XCTAssertEqual(root.workspaceLabel, "/")

        for invalid in ["relative/path", "/../../escape", "/safe/\u{2066}unsafe"] {
            assertValidationError(.invalidPath) {
                try makeValidDescriptor(callerFingerprint: makeCaller(workingDirectory: invalid))
            }
        }
        assertValidationError(.oversized) {
            try makeValidDescriptor(
                callerFingerprint: makeCaller(
                    workingDirectory: "/" + String(repeating: "x", count: 4_096)
                )
            )
        }
    }

    func testCapabilitiesAreCanonicalAndRejectIllegalCombinations() throws {
        XCTAssertEqual(try makeValidDescriptor(capabilities: [.list]).capabilities, [.list])
        XCTAssertEqual(
            try makeValidDescriptor(capabilities: [.list, .exec]).capabilities,
            [.exec, .list]
        )

        for invalid: [AgentJITCapability] in [[], [.exec], [.list, .list], [.exec, .list, .exec]] {
            assertValidationError(.invalidCapabilities) {
                try makeValidDescriptor(capabilities: invalid)
            }
        }
    }

    func testRejectsMoreThanTwoCapabilities() {
        assertValidationError(.invalidCapabilities) {
            try makeValidDescriptor(capabilities: [.exec, .list, .list])
        }
    }

    func testFolderScopeAndItemsUseFrozenNormalizationAndContainment() throws {
        let item = try makeItem(folderPath: "  Team/\u{200B} API \u{200B}/Build  ")
        XCTAssertEqual(item.folderPath, "Team/API/Build")

        let descriptor = try makeValidDescriptor(
            folderScope: .folder(" Team / API "),
            items: [item]
        )
        XCTAssertEqual(descriptor.folderScope, .folder("Team/API"))

        assertValidationError(.invalidScope) {
            try makeValidDescriptor(folderScope: .folder("///"))
        }
        assertValidationError(.invalidItems) {
            try makeValidDescriptor(items: [try makeItem(folderPath: "Other")])
        }
        assertValidationError(.invalidItems) {
            try makeValidDescriptor(
                folderScope: .root,
                items: [try makeItem(folderPath: "Team")]
            )
        }
        XCTAssertNoThrow(
            try makeValidDescriptor(folderScope: .root, items: [try makeItem(folderPath: nil)])
        )
    }

    func testNamedEnvironmentNormalizationIsExact() throws {
        XCTAssertEqual(try normalizedRemoteEnvironmentName("\tDe\u{301}v \n"), "Dév")
        XCTAssertEqual(try normalizedRemoteEnvironmentName("PROD"), "PROD")

        let descriptor = try makeValidDescriptor(environmentScope: .named("\tDe\u{301}v \n"))
        XCTAssertEqual(descriptor.environmentScope, .named("Dév"))
        assertValidationError(.invalidEnvironment) {
            try makeValidDescriptor(environmentScope: .named(" \t\n "))
        }
        assertValidationError(.invalidEnvironment) {
            try makeValidDescriptor(environmentScope: .named("safe\u{200B}unsafe"))
        }
        assertValidationError(.oversized) {
            try makeValidDescriptor(environmentScope: .named(String(repeating: "e", count: 256)))
        }
        XCTAssertEqual(try makeValidDescriptor(environmentScope: nil).environmentScope, nil)
        XCTAssertEqual(try makeValidDescriptor(environmentScope: .defaultOnly).environmentScope, .defaultOnly)
    }

    func testRequestedItemsAreCanonicalAndRejectDuplicatesOrOversizedCollections() throws {
        let highPassword = try makeItem(
            id: UUID(uuidString: "FFFFFFFF-FFFF-4FFF-8FFF-FFFFFFFFFFFF")!,
            kind: .password
        )
        let lowPassword = try makeItem(
            id: UUID(uuidString: "00000000-0000-4000-8000-000000000001")!,
            kind: .password
        )
        let apiKey = try makeItem(
            id: UUID(uuidString: "00000000-0000-4000-8000-000000000000")!,
            kind: .apiKey
        )
        let descriptor = try makeValidDescriptor(items: [apiKey, highPassword, lowPassword])
        XCTAssertEqual(descriptor.requestedItems, [lowPassword, highPassword, apiKey])

        assertValidationError(.duplicateItem) {
            try makeValidDescriptor(items: [lowPassword, lowPassword])
        }
        assertValidationError(.invalidItems) {
            try makeValidDescriptor(items: [])
        }

        let manyItems = try (0..<1_025).map { index in
            try makeItem(id: UUID(uuidString: String(format: "00000000-0000-4000-8000-%012x", index))!)
        }
        assertValidationError(.oversized) {
            try makeValidDescriptor(items: manyItems)
        }
    }

    func testSSHItemsRejectExecAuthority() throws {
        let ssh = try makeItem(kind: .ssh)

        assertValidationError(.invalidItems) {
            try makeValidDescriptor(capabilities: [.exec, .list], items: [ssh])
        }
        XCTAssertNoThrow(try makeValidDescriptor(capabilities: [.list], items: [ssh]))
    }

    func testPairingSourceAndOutcomePreserveTypedIdentity() throws {
        let binding = try makeValidPairingBinding()
        let paired = try RemoteJITApprovalPairedIPhoneSource(
            pairingGenerationID: binding.pairingGenerationID,
            signingKeyFingerprint: binding.iphoneSigningKeyFingerprint
        )
        let source = RemoteJITApprovalSource.pairedIPhone(paired)

        XCTAssertEqual(RemoteJITApprovalOutcome.approved(source: source), .approved(source: source))
        XCTAssertNotEqual(RemoteJITApprovalOutcome.denied(source: source), .superseded)
        assertValidationError(.invalidLength) {
            try RemoteJITApprovalPairedIPhoneSource(
                pairingGenerationID: binding.pairingGenerationID,
                signingKeyFingerprint: Data(repeating: 0, count: 31)
            )
        }
    }

    func testDecisionPayloadRejectsInvalidLengthsAndTime() throws {
        XCTAssertNoThrow(try makeValidDecisionPayload())
        assertValidationError(.invalidLength) {
            try makeValidDecisionPayload(approvalNonce: Data(repeating: 0, count: 31))
        }
        assertValidationError(.invalidLength) {
            try makeValidDecisionPayload(requestDigest: Data(repeating: 0, count: 33))
        }
        assertValidationError(.invalidTime) {
            try makeValidDecisionPayload(requestExpiresAtMilliseconds: -1)
        }
        assertValidationError(.invalidTime) {
            try makeValidDecisionPayload(requestExpiresAtMilliseconds: 253_402_300_800_000)
        }
    }

    func testGoldenFixtureBuildsEveryPublicModelWithoutHiddenConstants() throws {
        let fixture = try RemoteJITApprovalGoldenFixture.load()

        XCTAssertEqual(try fixture.makeDescriptor().approvalID, fixture.input.approvalID)
        XCTAssertEqual(try fixture.makeApprovePayload().value, .approve)
        XCTAssertEqual(try fixture.makeDenyPayload().value, .deny)
        XCTAssertEqual(
            try fixture.makePairingBinding().pairingGenerationID,
            fixture.input.pairingGenerationID
        )
    }
}

private let syntheticItemID = UUID(uuidString: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")!
private let remoteRawInputCeiling = 1_048_576

private func makeItem(
    id: UUID = syntheticItemID,
    kind: RemoteJITApprovalItemKind = .password,
    folderPath: String? = "Team/API"
) throws -> RemoteJITApprovalItemReference {
    try RemoteJITApprovalItemReference(id: id, kind: kind, folderPath: folderPath)
}

private func makeCaller(
    processName: String = "synthetic-agent",
    bundleIdentifier: String? = "example.synthetic.agent",
    signingTeamId: String? = "SYNTHETIC",
    signingIdentity: String? = "Synthetic Development Identity",
    parentProcessName: String? = "synthetic-parent",
    parentBundleIdentifier: String? = nil,
    hostProcessName: String? = "synthetic-host",
    hostBundleIdentifier: String? = "example.synthetic.host",
    sessionScope: String? = "synthetic-session",
    workingDirectory: String? = "/workspace/synthetic-demo"
) -> AgentJITCallerFingerprint {
    AgentJITCallerFingerprint(
        processName: processName,
        bundleIdentifier: bundleIdentifier,
        signingTeamId: signingTeamId,
        signingIdentity: signingIdentity,
        parentProcessName: parentProcessName,
        parentBundleIdentifier: parentBundleIdentifier,
        hostProcessName: hostProcessName,
        hostBundleIdentifier: hostBundleIdentifier,
        sessionScope: sessionScope,
        workingDirectory: workingDirectory
    )
}

private func makeValidDescriptor(
    approvalNonce: Data = Data(repeating: 0x11, count: 32),
    macFingerprint: Data = Data(repeating: 0x22, count: 32),
    iphoneFingerprint: Data = Data(repeating: 0x33, count: 32),
    callerFingerprint: AgentJITCallerFingerprint = makeCaller(),
    capabilities: [AgentJITCapability] = [.list, .exec],
    folderScope: AgentJITFolderScope = .folder("Team/API"),
    environmentScope: EnvironmentAccessScope? = .named("Production"),
    items: [RemoteJITApprovalItemReference]? = nil,
    requestIssuedAtMilliseconds: Int64 = 2_000_000_000_000,
    requestExpiresAtMilliseconds: Int64 = 2_000_000_090_000,
    grantIssuedAtMilliseconds: Int64 = 2_000_000_000_000,
    grantExpiresAtMilliseconds: Int64 = 2_000_000_300_000
) throws -> RemoteJITApprovalDescriptor {
    try RemoteJITApprovalDescriptor(
        approvalID: UUID(uuidString: "11111111-1111-4111-8111-111111111111")!,
        approvalNonce: approvalNonce,
        bridgeRequestID: UUID(uuidString: "22222222-2222-4222-8222-222222222222")!,
        pairingGenerationID: UUID(uuidString: "33333333-3333-4333-8333-333333333333")!,
        macDeviceID: UUID(uuidString: "44444444-4444-4444-8444-444444444444")!,
        iphoneDeviceID: UUID(uuidString: "55555555-5555-4555-8555-555555555555")!,
        macSigningKeyFingerprint: macFingerprint,
        iphoneSigningKeyFingerprint: iphoneFingerprint,
        requestIssuedAtMilliseconds: requestIssuedAtMilliseconds,
        requestExpiresAtMilliseconds: requestExpiresAtMilliseconds,
        callerFingerprint: callerFingerprint,
        capabilities: capabilities,
        folderScope: folderScope,
        environmentScope: environmentScope,
        requestedItems: try items ?? [makeItem()],
        grantIssuedAtMilliseconds: grantIssuedAtMilliseconds,
        grantExpiresAtMilliseconds: grantExpiresAtMilliseconds
    )
}

private func makeValidDescriptorInput(
    callerFingerprint: AgentJITCallerFingerprint = makeCaller(),
    capabilities: [AgentJITCapability] = [.list, .exec],
    folderScope: AgentJITFolderScope = .folder("Team/API"),
    environmentScope: EnvironmentAccessScope? = .named("Production"),
    items: [RemoteJITApprovalItemReference]? = nil,
    requestIssuedAtMilliseconds: Int64 = 2_000_000_000_000,
    grantExpiresAtMilliseconds: Int64 = 2_000_000_300_000
) throws -> RemoteJITApprovalDescriptorInput {
    try RemoteJITApprovalDescriptorInput(
        bridgeRequestID: UUID(uuidString: "22222222-2222-4222-8222-222222222222")!,
        requestIssuedAtMilliseconds: requestIssuedAtMilliseconds,
        callerFingerprint: callerFingerprint,
        capabilities: capabilities,
        folderScope: folderScope,
        environmentScope: environmentScope,
        requestedItems: try items ?? [makeItem()],
        grantExpiresAtMilliseconds: grantExpiresAtMilliseconds
    )
}

private func makeValidPairingBinding(
    macFingerprint: Data = Data(repeating: 0x22, count: 32),
    iphoneFingerprint: Data = Data(repeating: 0x33, count: 32)
) throws -> RemoteJITApprovalPairingBinding {
    try RemoteJITApprovalPairingBinding(
        pairingGenerationID: UUID(uuidString: "33333333-3333-4333-8333-333333333333")!,
        macDeviceID: UUID(uuidString: "44444444-4444-4444-8444-444444444444")!,
        iphoneDeviceID: UUID(uuidString: "55555555-5555-4555-8555-555555555555")!,
        macSigningKeyFingerprint: macFingerprint,
        iphoneSigningKeyFingerprint: iphoneFingerprint
    )
}

private func makeValidDecisionPayload(
    approvalNonce: Data = Data(repeating: 0x11, count: 32),
    requestDigest: Data = Data(repeating: 0x44, count: 32),
    requestExpiresAtMilliseconds: Int64 = 2_000_000_090_000
) throws -> RemoteJITApprovalDecisionPayload {
    try RemoteJITApprovalDecisionPayload(
        approvalID: UUID(uuidString: "11111111-1111-4111-8111-111111111111")!,
        approvalNonce: approvalNonce,
        requestDigest: requestDigest,
        pairingGenerationID: UUID(uuidString: "33333333-3333-4333-8333-333333333333")!,
        macDeviceID: UUID(uuidString: "44444444-4444-4444-8444-444444444444")!,
        iphoneDeviceID: UUID(uuidString: "55555555-5555-4555-8555-555555555555")!,
        value: .approve,
        requestExpiresAtMilliseconds: requestExpiresAtMilliseconds
    )
}

private func assertValidationError<T>(
    _ expected: RemoteJITApprovalValidationError,
    file: StaticString = #filePath,
    line: UInt = #line,
    operation: () throws -> T
) {
    XCTAssertThrowsError(try operation(), file: file, line: line) {
        XCTAssertEqual($0 as? RemoteJITApprovalValidationError, expected, file: file, line: line)
    }
}
