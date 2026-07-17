import CryptoKit
import Foundation
import XCTest
@testable import AuthenticatorBridge

final class RemoteJITApprovalVerificationTests: XCTestCase {
    func testVerifiesGoldenRequestAndBothDecisionValues() throws {
        let fixture = try RemoteJITApprovalGoldenFixture.load()
        let request = try makeGoldenRequest(fixture)
        let binding = try fixture.makePairingBinding()
        let macPublicKey = try Data(hexadecimal: fixture.expected.requestPublicKeyX963Hex)
        let iphonePublicKey = try Data(hexadecimal: fixture.expected.decisionPublicKeyX963Hex)

        XCTAssertEqual(
            RemoteJITApprovalVerification.verifyRequest(
                request,
                trustedMacPublicKeyX963: macPublicKey,
                expectedPairing: binding,
                evaluatedAtMilliseconds: fixture.input.requestIssuedAtMilliseconds
            ),
            .valid
        )
        XCTAssertEqual(
            RemoteJITApprovalVerification.verifyDecision(
                try makeGoldenDecision(fixture, value: .approve),
                for: request,
                trustedIPhonePublicKeyX963: iphonePublicKey,
                expectedPairing: binding,
                evaluatedAtMilliseconds: fixture.input.requestIssuedAtMilliseconds
            ),
            .valid
        )
        XCTAssertEqual(
            RemoteJITApprovalVerification.verifyDecision(
                try makeGoldenDecision(fixture, value: .deny),
                for: request,
                trustedIPhonePublicKeyX963: iphonePublicKey,
                expectedPairing: binding,
                evaluatedAtMilliseconds: fixture.input.requestIssuedAtMilliseconds
            ),
            .valid
        )
    }

    func testSigningPreimagesMatchFrozenDomainsAndGoldenBytes() throws {
        let fixture = try RemoteJITApprovalGoldenFixture.load()
        let descriptor = try fixture.makeDescriptor()
        let digest = try Data(hexadecimal: fixture.expected.requestDigestHex)
        let requestDomain = Data("Authsia.RemoteJITApproval.RequestSignature.V1\0".utf8)
        let decisionDomain = Data("Authsia.RemoteJITApproval.DecisionSignature.V1\0".utf8)

        XCTAssertEqual(
            try RemoteJITApprovalVerification.requestDigest(for: descriptor),
            digest
        )
        XCTAssertEqual(
            try RemoteJITApprovalVerification.requestSigningPreimage(for: descriptor),
            requestDomain + digest
        )
        XCTAssertEqual(
            try RemoteJITApprovalVerification.decisionSigningPreimage(
                for: fixture.makeApprovePayload()
            ),
            decisionDomain
                + (try Data(hexadecimal: fixture.expected.unsignedApproveDecisionHex))
        )
    }

    func testRejectsRequestPairingAndFingerprintMismatches() throws {
        let context = try GoldenVerificationContext()
        let wrongID = UUID(uuidString: "99999999-9999-4999-8999-999999999999")!

        XCTAssertEqual(
            context.verifyRequest(expectedPairing: try replacingBinding(
                context.binding,
                pairingGenerationID: wrongID
            )),
            .invalid(.requestBindingMismatch)
        )
        XCTAssertEqual(
            context.verifyRequest(expectedPairing: try replacingBinding(
                context.binding,
                macDeviceID: wrongID
            )),
            .invalid(.requestBindingMismatch)
        )
        XCTAssertEqual(
            context.verifyRequest(expectedPairing: try replacingBinding(
                context.binding,
                iphoneDeviceID: wrongID
            )),
            .invalid(.requestBindingMismatch)
        )
        XCTAssertEqual(
            context.verifyRequest(expectedPairing: try replacingBinding(
                context.binding,
                macSigningKeyFingerprint: flipped(context.binding.macSigningKeyFingerprint)
            )),
            .invalid(.keyFingerprintMismatch)
        )
        XCTAssertEqual(
            context.verifyRequest(expectedPairing: try replacingBinding(
                context.binding,
                iphoneSigningKeyFingerprint: flipped(context.binding.iphoneSigningKeyFingerprint)
            )),
            .invalid(.keyFingerprintMismatch)
        )

        let wrongMacFingerprintDescriptor = try replacingDescriptor(
            context.request.descriptor,
            macSigningKeyFingerprint: flipped(context.request.descriptor.macSigningKeyFingerprint)
        )
        XCTAssertEqual(
            context.verifyRequest(request: try request(
                descriptor: wrongMacFingerprintDescriptor,
                signature: context.request.requestSignature
            )),
            .invalid(.keyFingerprintMismatch)
        )

        let wrongIPhoneFingerprintDescriptor = try replacingDescriptor(
            context.request.descriptor,
            iphoneSigningKeyFingerprint: flipped(context.request.descriptor.iphoneSigningKeyFingerprint)
        )
        XCTAssertEqual(
            context.verifyRequest(request: try request(
                descriptor: wrongIPhoneFingerprintDescriptor,
                signature: context.request.requestSignature
            )),
            .invalid(.keyFingerprintMismatch)
        )
        XCTAssertEqual(
            context.verifyRequest(trustedMacPublicKeyX963: context.iphonePublicKey),
            .invalid(.keyFingerprintMismatch)
        )
    }

    func testRejectsRequestDigestAndTimingMutations() throws {
        let context = try GoldenVerificationContext()
        let issued = context.request.descriptor.requestIssuedAtMilliseconds
        let expiry = context.request.descriptor.requestExpiresAtMilliseconds
        XCTAssertEqual(context.verifyRequest(evaluatedAt: issued), .valid)
        XCTAssertEqual(context.verifyRequest(evaluatedAt: issued - 1), .invalid(.expired))
        XCTAssertEqual(context.verifyRequest(evaluatedAt: expiry), .invalid(.expired))
        XCTAssertEqual(context.verifyRequest(evaluatedAt: expiry + 1), .invalid(.expired))

        XCTAssertEqual(
            context.verifyRequest(request: try RemoteJITApprovalRequest(
                descriptor: context.request.descriptor,
                requestDigest: flipped(context.request.requestDigest),
                requestSignature: context.request.requestSignature
            )),
            .invalid(.digestMismatch)
        )
    }

    func testRejectsDecisionCopiedFieldPairingAndReplayMutations() throws {
        let context = try GoldenVerificationContext()
        let descriptor = context.request.descriptor
        let approve = try context.fixture.makeApprovePayload()
        let wrongID = UUID(uuidString: "99999999-9999-4999-8999-999999999999")!

        let payloadMutations: [RemoteJITApprovalDecisionPayload] = [
            try replacingPayload(approve, approvalID: wrongID),
            try replacingPayload(approve, approvalNonce: flipped(approve.approvalNonce)),
            try replacingPayload(approve, requestDigest: flipped(approve.requestDigest)),
            try replacingPayload(approve, pairingGenerationID: wrongID),
            try replacingPayload(approve, macDeviceID: wrongID),
            try replacingPayload(approve, iphoneDeviceID: wrongID),
            try replacingPayload(
                approve,
                requestExpiresAtMilliseconds: approve.requestExpiresAtMilliseconds - 1
            ),
        ]
        for payload in payloadMutations {
            XCTAssertEqual(
                context.verifyDecision(try decision(
                    payload: payload,
                    signature: context.approveDecision.decisionSignature
                )),
                .invalid(.requestBindingMismatch)
            )
        }

        XCTAssertEqual(
            context.verifyDecision(
                context.approveDecision,
                expectedPairing: try replacingBinding(
                    context.binding,
                    pairingGenerationID: wrongID
                )
            ),
            .invalid(.requestBindingMismatch)
        )
        XCTAssertEqual(
            context.verifyDecision(
                context.approveDecision,
                expectedPairing: try replacingBinding(
                    context.binding,
                    iphoneSigningKeyFingerprint: flipped(
                        context.binding.iphoneSigningKeyFingerprint
                    )
                )
            ),
            .invalid(.keyFingerprintMismatch)
        )
        XCTAssertEqual(
            context.verifyDecision(
                context.approveDecision,
                trustedIPhonePublicKeyX963: context.macPublicKey
            ),
            .invalid(.keyFingerprintMismatch)
        )

        let replayDescriptor = try replacingDescriptor(
            descriptor,
            approvalID: wrongID,
            bridgeRequestID: wrongID
        )
        let replayRequest = try request(
            descriptor: replayDescriptor,
            signature: context.request.requestSignature
        )
        XCTAssertEqual(
            context.verifyDecision(context.approveDecision, request: replayRequest),
            .invalid(.requestBindingMismatch)
        )

        let wrongDigest = flipped(context.request.requestDigest)
        let sharedWrongDigestRequest = try RemoteJITApprovalRequest(
            descriptor: descriptor,
            requestDigest: wrongDigest,
            requestSignature: context.request.requestSignature
        )
        let sharedWrongDigestDecision = try decision(
            payload: replacingPayload(approve, requestDigest: wrongDigest),
            signature: context.approveDecision.decisionSignature
        )
        XCTAssertEqual(
            context.verifyDecision(sharedWrongDigestDecision, request: sharedWrongDigestRequest),
            .invalid(.digestMismatch)
        )
    }

    func testRejectsDecisionTimingAndSignatureMutations() throws {
        let context = try GoldenVerificationContext()
        let issued = context.request.descriptor.requestIssuedAtMilliseconds
        let expiry = context.request.descriptor.requestExpiresAtMilliseconds
        XCTAssertEqual(
            context.verifyDecision(context.approveDecision, evaluatedAt: issued - 1),
            .invalid(.expired)
        )
        XCTAssertEqual(
            context.verifyDecision(context.approveDecision, evaluatedAt: expiry),
            .invalid(.expired)
        )
        XCTAssertEqual(
            context.verifyDecision(context.approveDecision, evaluatedAt: expiry + 1),
            .invalid(.expired)
        )

        XCTAssertEqual(
            context.verifyDecision(try decision(
                payload: context.approveDecision.payload,
                signature: flipped(context.approveDecision.decisionSignature)
            )),
            .invalid(.invalidSignature)
        )
        XCTAssertEqual(
            context.verifyDecision(try decision(
                payload: replacingPayload(context.approveDecision.payload, value: .deny),
                signature: context.approveDecision.decisionSignature
            )),
            .invalid(.invalidSignature)
        )

        let mutatedDescriptor = try replacingDescriptor(
            context.request.descriptor,
            bridgeRequestID: UUID(uuidString: "99999999-9999-4999-8999-999999999999")!
        )
        XCTAssertEqual(
            context.verifyRequest(request: try request(
                descriptor: mutatedDescriptor,
                signature: context.request.requestSignature
            )),
            .invalid(.invalidSignature)
        )
    }

    func testRejectsMalformedPublicKeysAndInvalidCurvePoints() throws {
        let context = try GoldenVerificationContext()
        XCTAssertEqual(
            context.verifyRequest(trustedMacPublicKeyX963: Data(repeating: 0x04, count: 64)),
            .invalid(.malformedPublicKey)
        )
        var wrongPrefix = context.macPublicKey
        wrongPrefix[0] = 0x03
        XCTAssertEqual(
            context.verifyRequest(trustedMacPublicKeyX963: wrongPrefix),
            .invalid(.malformedPublicKey)
        )
        XCTAssertEqual(
            context.verifyRequest(trustedMacPublicKeyX963: Data([0x30, 0x59]) + context.macPublicKey),
            .invalid(.malformedPublicKey)
        )

        let invalidPoint = Data([0x04]) + Data(repeating: 0, count: 64)
        let invalidFingerprint = Data(SHA256.hash(data: invalidPoint))
        let descriptor = try replacingDescriptor(
            context.request.descriptor,
            macSigningKeyFingerprint: invalidFingerprint
        )
        let binding = try replacingBinding(
            context.binding,
            macSigningKeyFingerprint: invalidFingerprint
        )
        XCTAssertEqual(
            context.verifyRequest(
                request: try request(
                    descriptor: descriptor,
                    signature: context.request.requestSignature
                ),
                trustedMacPublicKeyX963: invalidPoint,
                expectedPairing: binding
            ),
            .invalid(.malformedPublicKey)
        )
    }

    func testRejectsMalformedAndNonCanonicalRawSignatures() throws {
        let context = try GoldenVerificationContext()
        let zero = Data(repeating: 0, count: 32)
        let one = Data(repeating: 0, count: 31) + Data([1])
        let order = try Data(hexadecimal: p256OrderHex)
        let halfOrder = try Data(hexadecimal: p256HalfOrderHex)
        let highS = incremented(halfOrder)

        XCTAssertThrowsError(
            try RemoteJITApprovalVerification.normalizeRawP256Signature(Data(repeating: 1, count: 63))
        ) { XCTAssertEqual($0 as? RemoteJITApprovalValidationError, .invalidLength) }
        XCTAssertThrowsError(
            try RemoteJITApprovalVerification.normalizeRawP256Signature(Data(repeating: 1, count: 65))
        ) { XCTAssertEqual($0 as? RemoteJITApprovalValidationError, .invalidLength) }
        XCTAssertThrowsError(
            try RemoteJITApprovalVerification.normalizeRawP256Signature(Data([0x30, 0x44]) + Data(repeating: 1, count: 68))
        ) { XCTAssertEqual($0 as? RemoteJITApprovalValidationError, .invalidLength) }
        for malformed in [zero + one, one + zero, order + one, one + order] {
            XCTAssertThrowsError(
                try RemoteJITApprovalVerification.normalizeRawP256Signature(malformed)
            ) { XCTAssertEqual($0 as? RemoteJITApprovalValidationError, .nonCanonical) }
            XCTAssertEqual(
                context.verifyRequest(request: try request(
                    descriptor: context.request.descriptor,
                    signature: malformed
                )),
                .invalid(.malformedSignature)
            )
        }

        let malformedRWithHighS = order + highS
        XCTAssertEqual(
            context.verifyRequest(request: try request(
                descriptor: context.request.descriptor,
                signature: malformedRWithHighS
            )),
            .invalid(.malformedSignature)
        )

        let highGolden = try highSSignature(fromLowS: context.request.requestSignature)
        XCTAssertEqual(
            try RemoteJITApprovalVerification.normalizeRawP256Signature(highGolden),
            context.request.requestSignature
        )
        XCTAssertEqual(
            context.verifyRequest(request: try request(
                descriptor: context.request.descriptor,
                signature: highGolden
            )),
            .invalid(.nonCanonicalSignature)
        )

        let fixedWidthHighS = one + decremented(order)
        XCTAssertEqual(
            try RemoteJITApprovalVerification.normalizeRawP256Signature(fixedWidthHighS),
            one + one
        )
        XCTAssertEqual(
            try RemoteJITApprovalVerification.normalizeRawP256Signature(
                context.request.requestSignature
            ),
            context.request.requestSignature
        )
    }
}

private struct GoldenVerificationContext {
    let fixture: RemoteJITApprovalGoldenFixture
    let request: RemoteJITApprovalRequest
    let approveDecision: RemoteJITApprovalDecision
    let binding: RemoteJITApprovalPairingBinding
    let macPublicKey: Data
    let iphonePublicKey: Data

    init() throws {
        fixture = try RemoteJITApprovalGoldenFixture.load()
        request = try makeGoldenRequest(fixture)
        approveDecision = try makeGoldenDecision(fixture, value: .approve)
        binding = try fixture.makePairingBinding()
        macPublicKey = try Data(hexadecimal: fixture.expected.requestPublicKeyX963Hex)
        iphonePublicKey = try Data(hexadecimal: fixture.expected.decisionPublicKeyX963Hex)
    }

    func verifyRequest(
        request: RemoteJITApprovalRequest? = nil,
        trustedMacPublicKeyX963: Data? = nil,
        expectedPairing: RemoteJITApprovalPairingBinding? = nil,
        evaluatedAt: Int64? = nil
    ) -> RemoteJITApprovalVerificationResult {
        RemoteJITApprovalVerification.verifyRequest(
            request ?? self.request,
            trustedMacPublicKeyX963: trustedMacPublicKeyX963 ?? macPublicKey,
            expectedPairing: expectedPairing ?? binding,
            evaluatedAtMilliseconds: evaluatedAt
                ?? self.request.descriptor.requestIssuedAtMilliseconds
        )
    }

    func verifyDecision(
        _ decision: RemoteJITApprovalDecision,
        request: RemoteJITApprovalRequest? = nil,
        trustedIPhonePublicKeyX963: Data? = nil,
        expectedPairing: RemoteJITApprovalPairingBinding? = nil,
        evaluatedAt: Int64? = nil
    ) -> RemoteJITApprovalVerificationResult {
        RemoteJITApprovalVerification.verifyDecision(
            decision,
            for: request ?? self.request,
            trustedIPhonePublicKeyX963: trustedIPhonePublicKeyX963 ?? iphonePublicKey,
            expectedPairing: expectedPairing ?? binding,
            evaluatedAtMilliseconds: evaluatedAt
                ?? self.request.descriptor.requestIssuedAtMilliseconds
        )
    }
}

private func makeGoldenRequest(
    _ fixture: RemoteJITApprovalGoldenFixture
) throws -> RemoteJITApprovalRequest {
    try RemoteJITApprovalRequest(
        descriptor: fixture.makeDescriptor(),
        requestDigest: Data(hexadecimal: fixture.expected.requestDigestHex),
        requestSignature: Data(hexadecimal: fixture.expected.requestSignatureHex)
    )
}

private func makeGoldenDecision(
    _ fixture: RemoteJITApprovalGoldenFixture,
    value: RemoteJITApprovalDecisionValue
) throws -> RemoteJITApprovalDecision {
    let payload = try value == .approve
        ? fixture.makeApprovePayload()
        : fixture.makeDenyPayload()
    let signatureHex = value == .approve
        ? fixture.expected.approveDecisionSignatureHex
        : fixture.expected.denyDecisionSignatureHex
    return try RemoteJITApprovalDecision(
        payload: payload,
        decisionSignature: Data(hexadecimal: signatureHex)
    )
}

private func request(
    descriptor: RemoteJITApprovalDescriptor,
    signature: Data
) throws -> RemoteJITApprovalRequest {
    try RemoteJITApprovalRequest(
        descriptor: descriptor,
        requestDigest: RemoteJITApprovalVerification.requestDigest(for: descriptor),
        requestSignature: signature
    )
}

private func decision(
    payload: RemoteJITApprovalDecisionPayload,
    signature: Data
) throws -> RemoteJITApprovalDecision {
    try RemoteJITApprovalDecision(payload: payload, decisionSignature: signature)
}

private func replacingBinding(
    _ binding: RemoteJITApprovalPairingBinding,
    pairingGenerationID: UUID? = nil,
    macDeviceID: UUID? = nil,
    iphoneDeviceID: UUID? = nil,
    macSigningKeyFingerprint: Data? = nil,
    iphoneSigningKeyFingerprint: Data? = nil
) throws -> RemoteJITApprovalPairingBinding {
    try RemoteJITApprovalPairingBinding(
        pairingGenerationID: pairingGenerationID ?? binding.pairingGenerationID,
        macDeviceID: macDeviceID ?? binding.macDeviceID,
        iphoneDeviceID: iphoneDeviceID ?? binding.iphoneDeviceID,
        macSigningKeyFingerprint: macSigningKeyFingerprint ?? binding.macSigningKeyFingerprint,
        iphoneSigningKeyFingerprint: iphoneSigningKeyFingerprint
            ?? binding.iphoneSigningKeyFingerprint
    )
}

private func replacingDescriptor(
    _ descriptor: RemoteJITApprovalDescriptor,
    approvalID: UUID? = nil,
    approvalNonce: Data? = nil,
    bridgeRequestID: UUID? = nil,
    pairingGenerationID: UUID? = nil,
    macDeviceID: UUID? = nil,
    iphoneDeviceID: UUID? = nil,
    macSigningKeyFingerprint: Data? = nil,
    iphoneSigningKeyFingerprint: Data? = nil
) throws -> RemoteJITApprovalDescriptor {
    try RemoteJITApprovalDescriptor(
        approvalID: approvalID ?? descriptor.approvalID,
        approvalNonce: approvalNonce ?? descriptor.approvalNonce,
        bridgeRequestID: bridgeRequestID ?? descriptor.bridgeRequestID,
        pairingGenerationID: pairingGenerationID ?? descriptor.pairingGenerationID,
        macDeviceID: macDeviceID ?? descriptor.macDeviceID,
        iphoneDeviceID: iphoneDeviceID ?? descriptor.iphoneDeviceID,
        macSigningKeyFingerprint: macSigningKeyFingerprint
            ?? descriptor.macSigningKeyFingerprint,
        iphoneSigningKeyFingerprint: iphoneSigningKeyFingerprint
            ?? descriptor.iphoneSigningKeyFingerprint,
        requestIssuedAtMilliseconds: descriptor.requestIssuedAtMilliseconds,
        requestExpiresAtMilliseconds: descriptor.requestExpiresAtMilliseconds,
        callerFingerprint: descriptor.callerFingerprint,
        capabilities: descriptor.capabilities,
        folderScope: descriptor.folderScope,
        environmentScope: descriptor.environmentScope,
        requestedItems: descriptor.requestedItems,
        grantIssuedAtMilliseconds: descriptor.grantIssuedAtMilliseconds,
        grantExpiresAtMilliseconds: descriptor.grantExpiresAtMilliseconds
    )
}

private func replacingPayload(
    _ payload: RemoteJITApprovalDecisionPayload,
    approvalID: UUID? = nil,
    approvalNonce: Data? = nil,
    requestDigest: Data? = nil,
    pairingGenerationID: UUID? = nil,
    macDeviceID: UUID? = nil,
    iphoneDeviceID: UUID? = nil,
    value: RemoteJITApprovalDecisionValue? = nil,
    requestExpiresAtMilliseconds: Int64? = nil
) throws -> RemoteJITApprovalDecisionPayload {
    try RemoteJITApprovalDecisionPayload(
        approvalID: approvalID ?? payload.approvalID,
        approvalNonce: approvalNonce ?? payload.approvalNonce,
        requestDigest: requestDigest ?? payload.requestDigest,
        pairingGenerationID: pairingGenerationID ?? payload.pairingGenerationID,
        macDeviceID: macDeviceID ?? payload.macDeviceID,
        iphoneDeviceID: iphoneDeviceID ?? payload.iphoneDeviceID,
        value: value ?? payload.value,
        requestExpiresAtMilliseconds: requestExpiresAtMilliseconds
            ?? payload.requestExpiresAtMilliseconds
    )
}

private func flipped(_ data: Data) -> Data {
    var result = data
    result[result.startIndex] ^= 0x01
    return result
}

private let p256OrderHex =
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
private let p256HalfOrderHex =
    "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8"

private func highSSignature(fromLowS signature: Data) throws -> Data {
    let order = try Data(hexadecimal: p256OrderHex)
    return signature.prefix(32) + subtract(signature.suffix(32), from: order)
}

private func subtract<T: DataProtocol>(_ subtrahend: T, from minuend: Data) -> Data {
    var result = [UInt8](repeating: 0, count: minuend.count)
    let left = [UInt8](minuend)
    let right = [UInt8](subtrahend)
    var borrow = 0
    for index in stride(from: left.count - 1, through: 0, by: -1) {
        var difference = Int(left[index]) - Int(right[index]) - borrow
        if difference < 0 {
            difference += 256
            borrow = 1
        } else {
            borrow = 0
        }
        result[index] = UInt8(difference)
    }
    return Data(result)
}

private func incremented(_ data: Data) -> Data {
    var bytes = [UInt8](data)
    for index in stride(from: bytes.count - 1, through: 0, by: -1) {
        if bytes[index] == 0xff {
            bytes[index] = 0
        } else {
            bytes[index] += 1
            break
        }
    }
    return Data(bytes)
}

private func decremented(_ data: Data) -> Data {
    var bytes = [UInt8](data)
    for index in stride(from: bytes.count - 1, through: 0, by: -1) {
        if bytes[index] == 0 {
            bytes[index] = 0xff
        } else {
            bytes[index] -= 1
            break
        }
    }
    return Data(bytes)
}
