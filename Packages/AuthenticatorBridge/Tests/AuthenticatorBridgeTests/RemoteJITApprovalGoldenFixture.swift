import CryptoKit
import Foundation
import XCTest
@testable import AuthenticatorBridge

struct RemoteJITApprovalGoldenFixture: Decodable {
    struct Input: Decodable {
        let approvalID: UUID
        let approvalNonceHex: String
        let bridgeRequestID: UUID
        let pairingGenerationID: UUID
        let macDeviceID: UUID
        let iphoneDeviceID: UUID
        let requestIssuedAtMilliseconds: Int64
        let requestExpiresAtMilliseconds: Int64
        let caller: Caller
        let capabilities: [String]
        let folderScope: String
        let environmentScope: String?
        let items: [Item]
        let grantIssuedAtMilliseconds: Int64
        let grantExpiresAtMilliseconds: Int64
    }

    struct Caller: Decodable {
        let processName: String
        let bundleIdentifier: String?
        let signingTeamIdentifier: String?
        let signingIdentity: String?
        let parentProcessName: String?
        let parentBundleIdentifier: String?
        let hostProcessName: String?
        let hostBundleIdentifier: String?
        let sessionScope: String
        let workingDirectory: String
    }

    struct Item: Decodable {
        let id: UUID
        let kind: String
        let folderPath: String?
    }

    struct Expected: Decodable {
        let descriptorHex: String
        let requestDigestHex: String
        let requestEnvelopeHex: String
        let requestPublicKeyX963Hex: String
        let requestSignatureHex: String
        let unsignedApproveDecisionHex: String
        let unsignedDenyDecisionHex: String
        let approveDecisionEnvelopeHex: String
        let approveDecisionSignatureHex: String
        let denyDecisionEnvelopeHex: String
        let denyDecisionSignatureHex: String
        let decisionPublicKeyX963Hex: String
    }

    let input: Input
    let expected: Expected

    static func load() throws -> Self {
        let url = try XCTUnwrap(
            Bundle.module.url(
                forResource: "remote-jit-approval-v1",
                withExtension: "json"
            )
        )
        return try JSONDecoder().decode(Self.self, from: Data(contentsOf: url))
    }

    func makeDescriptor() throws -> RemoteJITApprovalDescriptor {
        let requestPublicKey = try Data(hexadecimal: expected.requestPublicKeyX963Hex)
        let decisionPublicKey = try Data(hexadecimal: expected.decisionPublicKeyX963Hex)
        return try RemoteJITApprovalDescriptor(
            approvalID: input.approvalID,
            approvalNonce: Data(hexadecimal: input.approvalNonceHex),
            bridgeRequestID: input.bridgeRequestID,
            pairingGenerationID: input.pairingGenerationID,
            macDeviceID: input.macDeviceID,
            iphoneDeviceID: input.iphoneDeviceID,
            macSigningKeyFingerprint: Data(SHA256.hash(data: requestPublicKey)),
            iphoneSigningKeyFingerprint: Data(SHA256.hash(data: decisionPublicKey)),
            requestIssuedAtMilliseconds: input.requestIssuedAtMilliseconds,
            requestExpiresAtMilliseconds: input.requestExpiresAtMilliseconds,
            callerFingerprint: AgentJITCallerFingerprint(
                processName: input.caller.processName,
                bundleIdentifier: input.caller.bundleIdentifier,
                signingTeamId: input.caller.signingTeamIdentifier,
                signingIdentity: input.caller.signingIdentity,
                parentProcessName: input.caller.parentProcessName,
                parentBundleIdentifier: input.caller.parentBundleIdentifier,
                hostProcessName: input.caller.hostProcessName,
                hostBundleIdentifier: input.caller.hostBundleIdentifier,
                sessionScope: input.caller.sessionScope,
                workingDirectory: input.caller.workingDirectory
            ),
            capabilities: try input.capabilities.map(Self.capability),
            folderScope: .folder(input.folderScope),
            environmentScope: input.environmentScope.map(EnvironmentAccessScope.named),
            requestedItems: try input.items.map { item in
                try RemoteJITApprovalItemReference(
                    id: item.id,
                    kind: Self.itemKind(item.kind),
                    folderPath: item.folderPath
                )
            },
            grantIssuedAtMilliseconds: input.grantIssuedAtMilliseconds,
            grantExpiresAtMilliseconds: input.grantExpiresAtMilliseconds
        )
    }

    func makeApprovePayload() throws -> RemoteJITApprovalDecisionPayload {
        try makeDecisionPayload(value: .approve)
    }

    func makeDenyPayload() throws -> RemoteJITApprovalDecisionPayload {
        try makeDecisionPayload(value: .deny)
    }

    func makePairingBinding() throws -> RemoteJITApprovalPairingBinding {
        let requestPublicKey = try Data(hexadecimal: expected.requestPublicKeyX963Hex)
        let decisionPublicKey = try Data(hexadecimal: expected.decisionPublicKeyX963Hex)
        return try RemoteJITApprovalPairingBinding(
            pairingGenerationID: input.pairingGenerationID,
            macDeviceID: input.macDeviceID,
            iphoneDeviceID: input.iphoneDeviceID,
            macSigningKeyFingerprint: Data(SHA256.hash(data: requestPublicKey)),
            iphoneSigningKeyFingerprint: Data(SHA256.hash(data: decisionPublicKey))
        )
    }

    private func makeDecisionPayload(
        value: RemoteJITApprovalDecisionValue
    ) throws -> RemoteJITApprovalDecisionPayload {
        try RemoteJITApprovalDecisionPayload(
            approvalID: input.approvalID,
            approvalNonce: Data(hexadecimal: input.approvalNonceHex),
            requestDigest: Data(hexadecimal: expected.requestDigestHex),
            pairingGenerationID: input.pairingGenerationID,
            macDeviceID: input.macDeviceID,
            iphoneDeviceID: input.iphoneDeviceID,
            value: value,
            requestExpiresAtMilliseconds: input.requestExpiresAtMilliseconds
        )
    }

    private static func capability(_ value: String) throws -> AgentJITCapability {
        guard let capability = AgentJITCapability(rawValue: value) else {
            throw FixtureModelError.invalidCapability(value)
        }
        return capability
    }

    private static func itemKind(_ value: String) throws -> RemoteJITApprovalItemKind {
        switch value {
        case "password": .password
        case "apiKey": .apiKey
        case "certificate": .certificate
        case "note": .note
        case "ssh": .ssh
        default: throw FixtureModelError.invalidItemKind(value)
        }
    }
}

private enum FixtureModelError: Error {
    case invalidCapability(String)
    case invalidItemKind(String)
}

enum HexadecimalDecodingError: Error {
    case oddLength
    case invalidCharacter
}

extension Data {
    init(hexadecimal: String) throws {
        let encoded = Array(hexadecimal.utf8)
        guard encoded.count.isMultiple(of: 2) else {
            throw HexadecimalDecodingError.oddLength
        }

        func nibble(_ byte: UInt8) -> UInt8? {
            switch byte {
            case UInt8(ascii: "0")...UInt8(ascii: "9"):
                byte - UInt8(ascii: "0")
            case UInt8(ascii: "a")...UInt8(ascii: "f"):
                byte - UInt8(ascii: "a") + 10
            case UInt8(ascii: "A")...UInt8(ascii: "F"):
                byte - UInt8(ascii: "A") + 10
            default:
                nil
            }
        }

        var decoded = Data(capacity: encoded.count / 2)
        for index in stride(from: 0, to: encoded.count, by: 2) {
            guard let high = nibble(encoded[index]),
                  let low = nibble(encoded[index + 1]) else {
                throw HexadecimalDecodingError.invalidCharacter
            }
            decoded.append((high << 4) | low)
        }
        self = decoded
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
