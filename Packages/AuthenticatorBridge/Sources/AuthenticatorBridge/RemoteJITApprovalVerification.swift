import CryptoKit
import Foundation

public enum RemoteJITApprovalVerificationFailure: Equatable, Sendable {
    case malformedPublicKey
    case malformedSignature
    case nonCanonicalSignature
    case digestMismatch
    case keyFingerprintMismatch
    case requestBindingMismatch
    case expired
    case invalidSignature
}

public enum RemoteJITApprovalVerificationResult: Equatable, Sendable {
    case valid
    case invalid(RemoteJITApprovalVerificationFailure)
}

public enum RemoteJITApprovalVerification {
    private static let requestSignatureDomain = Data(
        "Authsia.RemoteJITApproval.RequestSignature.V1\0".utf8
    )
    private static let decisionSignatureDomain = Data(
        "Authsia.RemoteJITApproval.DecisionSignature.V1\0".utf8
    )

    public static func requestDigest(
        for descriptor: RemoteJITApprovalDescriptor
    ) throws -> Data {
        try RemoteJITApprovalCanonicalCoding.requestDigest(for: descriptor)
    }

    public static func requestSigningPreimage(
        for descriptor: RemoteJITApprovalDescriptor
    ) throws -> Data {
        requestSignatureDomain + (try requestDigest(for: descriptor))
    }

    public static func decisionSigningPreimage(
        for payload: RemoteJITApprovalDecisionPayload
    ) throws -> Data {
        decisionSignatureDomain
            + (try RemoteJITApprovalCanonicalCoding.unsignedDecisionBytes(payload))
    }

    public static func normalizeRawP256Signature(
        _ signature: Data
    ) throws -> Data {
        let scalars = try validatedSignatureScalars(signature)
        guard scalarIsGreater(scalars.s, than: p256HalfOrder) else {
            return signature
        }

        return scalars.r + subtract(scalars.s, from: p256Order)
    }

    public static func verifyRequest(
        _ request: RemoteJITApprovalRequest,
        trustedMacPublicKeyX963: Data,
        expectedPairing: RemoteJITApprovalPairingBinding,
        evaluatedAtMilliseconds: Int64
    ) -> RemoteJITApprovalVerificationResult {
        let descriptor = request.descriptor
        let digest: Data
        do {
            digest = try requestDigest(for: descriptor)
        } catch {
            return .invalid(.digestMismatch)
        }
        guard request.requestDigest == digest else {
            return .invalid(.digestMismatch)
        }
        guard descriptor.pairingGenerationID == expectedPairing.pairingGenerationID,
              descriptor.macDeviceID == expectedPairing.macDeviceID,
              descriptor.iphoneDeviceID == expectedPairing.iphoneDeviceID else {
            return .invalid(.requestBindingMismatch)
        }
        guard descriptor.macSigningKeyFingerprint == expectedPairing.macSigningKeyFingerprint,
              descriptor.iphoneSigningKeyFingerprint == expectedPairing.iphoneSigningKeyFingerprint else {
            return .invalid(.keyFingerprintMismatch)
        }
        guard validEvaluationTime(evaluatedAtMilliseconds, for: descriptor) else {
            return .invalid(.expired)
        }
        guard validX963Shape(trustedMacPublicKeyX963) else {
            return .invalid(.malformedPublicKey)
        }
        let trustedFingerprint = Data(SHA256.hash(data: trustedMacPublicKeyX963))
        guard trustedFingerprint == descriptor.macSigningKeyFingerprint,
              trustedFingerprint == expectedPairing.macSigningKeyFingerprint else {
            return .invalid(.keyFingerprintMismatch)
        }

        let preimage: Data
        do {
            preimage = try requestSigningPreimage(for: descriptor)
        } catch {
            return .invalid(.digestMismatch)
        }
        return verify(
            signature: request.requestSignature,
            preimage: preimage,
            publicKeyX963: trustedMacPublicKeyX963
        )
    }

    public static func verifyDecision(
        _ decision: RemoteJITApprovalDecision,
        for request: RemoteJITApprovalRequest,
        trustedIPhonePublicKeyX963: Data,
        expectedPairing: RemoteJITApprovalPairingBinding,
        evaluatedAtMilliseconds: Int64
    ) -> RemoteJITApprovalVerificationResult {
        let descriptor = request.descriptor
        let digest: Data
        do {
            digest = try requestDigest(for: descriptor)
        } catch {
            return .invalid(.digestMismatch)
        }
        guard request.requestDigest == digest else {
            return .invalid(.digestMismatch)
        }
        guard descriptor.pairingGenerationID == expectedPairing.pairingGenerationID,
              descriptor.macDeviceID == expectedPairing.macDeviceID,
              descriptor.iphoneDeviceID == expectedPairing.iphoneDeviceID else {
            return .invalid(.requestBindingMismatch)
        }
        guard descriptor.macSigningKeyFingerprint == expectedPairing.macSigningKeyFingerprint,
              descriptor.iphoneSigningKeyFingerprint == expectedPairing.iphoneSigningKeyFingerprint else {
            return .invalid(.keyFingerprintMismatch)
        }
        guard validEvaluationTime(evaluatedAtMilliseconds, for: descriptor) else {
            return .invalid(.expired)
        }

        let payload = decision.payload
        guard payload.approvalID == descriptor.approvalID,
              payload.approvalNonce == descriptor.approvalNonce,
              payload.requestDigest == digest,
              payload.pairingGenerationID == descriptor.pairingGenerationID,
              payload.macDeviceID == descriptor.macDeviceID,
              payload.iphoneDeviceID == descriptor.iphoneDeviceID,
              payload.requestExpiresAtMilliseconds == descriptor.requestExpiresAtMilliseconds else {
            return .invalid(.requestBindingMismatch)
        }
        guard validX963Shape(trustedIPhonePublicKeyX963) else {
            return .invalid(.malformedPublicKey)
        }
        let trustedFingerprint = Data(SHA256.hash(data: trustedIPhonePublicKeyX963))
        guard trustedFingerprint == descriptor.iphoneSigningKeyFingerprint,
              trustedFingerprint == expectedPairing.iphoneSigningKeyFingerprint else {
            return .invalid(.keyFingerprintMismatch)
        }

        let preimage: Data
        do {
            preimage = try decisionSigningPreimage(for: payload)
        } catch {
            return .invalid(.requestBindingMismatch)
        }
        return verify(
            signature: decision.decisionSignature,
            preimage: preimage,
            publicKeyX963: trustedIPhonePublicKeyX963
        )
    }
}

private let p256Order = Data([
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
])
private let p256HalfOrder = Data([
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
    0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
])

private func validatedSignatureScalars(
    _ signature: Data
) throws -> (r: Data, s: Data) {
    guard signature.count == 64 else {
        throw RemoteJITApprovalValidationError.invalidLength
    }
    let r = signature.prefix(32)
    let s = signature.suffix(32)
    guard !scalarIsZero(r), !scalarIsZero(s),
          r.lexicographicallyPrecedes(p256Order),
          s.lexicographicallyPrecedes(p256Order) else {
        throw RemoteJITApprovalValidationError.nonCanonical
    }
    return (Data(r), Data(s))
}

private func scalarIsZero(_ scalar: Data.SubSequence) -> Bool {
    scalar.allSatisfy { $0 == 0 }
}

private func scalarIsGreater<T: DataProtocol>(_ lhs: T, than rhs: Data) -> Bool {
    rhs.lexicographicallyPrecedes(lhs)
}

private func subtract(_ subtrahend: Data, from minuend: Data) -> Data {
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

private func validEvaluationTime(
    _ evaluatedAtMilliseconds: Int64,
    for descriptor: RemoteJITApprovalDescriptor
) -> Bool {
    descriptor.requestIssuedAtMilliseconds <= evaluatedAtMilliseconds
        && evaluatedAtMilliseconds < descriptor.requestExpiresAtMilliseconds
}

private func validX963Shape(_ publicKey: Data) -> Bool {
    publicKey.count == 65 && publicKey.first == 0x04
}

private func verify(
    signature: Data,
    preimage: Data,
    publicKeyX963: Data
) -> RemoteJITApprovalVerificationResult {
    if let failure = signatureFailure(signature) {
        return .invalid(failure)
    }

    let publicKey: P256.Signing.PublicKey
    do {
        publicKey = try P256.Signing.PublicKey(x963Representation: publicKeyX963)
    } catch {
        return .invalid(.malformedPublicKey)
    }
    guard let parsedSignature = try? P256.Signing.ECDSASignature(
        rawRepresentation: signature
    ) else {
        return .invalid(.malformedSignature)
    }
    return publicKey.isValidSignature(parsedSignature, for: preimage)
        ? .valid
        : .invalid(.invalidSignature)
}

private func signatureFailure(
    _ signature: Data
) -> RemoteJITApprovalVerificationFailure? {
    guard let scalars = try? validatedSignatureScalars(signature) else {
        return .malformedSignature
    }
    guard !scalarIsGreater(scalars.s, than: p256HalfOrder) else {
        return .nonCanonicalSignature
    }
    return nil
}
