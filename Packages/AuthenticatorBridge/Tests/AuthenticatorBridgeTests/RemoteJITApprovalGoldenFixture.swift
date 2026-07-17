import Foundation
import XCTest

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
}

enum HexadecimalDecodingError: Error {
    case oddLength
    case invalidCharacter
}

extension Data {
    init(hexadecimal: String) throws {
        guard hexadecimal.utf8.count.isMultiple(of: 2) else {
            throw HexadecimalDecodingError.oddLength
        }

        var decoded = Data(capacity: hexadecimal.utf8.count / 2)
        var index = hexadecimal.startIndex
        while index < hexadecimal.endIndex {
            let nextIndex = hexadecimal.index(index, offsetBy: 2)
            guard let byte = UInt8(hexadecimal[index..<nextIndex], radix: 16) else {
                throw HexadecimalDecodingError.invalidCharacter
            }
            decoded.append(byte)
            index = nextIndex
        }
        self = decoded
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
