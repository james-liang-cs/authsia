import Foundation
import XCTest
@testable import AuthenticatorBridge

final class RemoteJITApprovalGoldenVectorTests: XCTestCase {
    func testRequestAndDecisionsMatchIndependentGoldenBytes() throws {
        let fixture = try RemoteJITApprovalGoldenFixture.load()
        let request = try makeGoldenRequest(fixture)
        let approveDecision = try makeGoldenDecision(fixture, value: .approve)
        let denyDecision = try makeGoldenDecision(fixture, value: .deny)

        let requestBytes = try RemoteJITApprovalCanonicalCoding.encodeRequest(request)
        XCTAssertEqual(requestBytes.hexString, fixture.expected.requestEnvelopeHex)
        XCTAssertEqual(
            try RemoteJITApprovalCanonicalCoding.decodeRequest(requestBytes),
            request
        )

        XCTAssertEqual(
            try RemoteJITApprovalCanonicalCoding.unsignedDecisionBytes(approveDecision.payload).hexString,
            fixture.expected.unsignedApproveDecisionHex
        )
        XCTAssertEqual(
            try RemoteJITApprovalCanonicalCoding.unsignedDecisionBytes(denyDecision.payload).hexString,
            fixture.expected.unsignedDenyDecisionHex
        )

        let approveBytes = try RemoteJITApprovalCanonicalCoding.encodeDecision(approveDecision)
        XCTAssertEqual(approveBytes.hexString, fixture.expected.approveDecisionEnvelopeHex)
        XCTAssertEqual(
            try RemoteJITApprovalCanonicalCoding.decodeDecision(approveBytes),
            approveDecision
        )

        let denyBytes = try RemoteJITApprovalCanonicalCoding.encodeDecision(denyDecision)
        XCTAssertEqual(denyBytes.hexString, fixture.expected.denyDecisionEnvelopeHex)
        XCTAssertEqual(
            try RemoteJITApprovalCanonicalCoding.decodeDecision(denyBytes),
            denyDecision
        )
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
        let payload = switch value {
        case .approve: try fixture.makeApprovePayload()
        case .deny: try fixture.makeDenyPayload()
        }
        let signatureHex = switch value {
        case .approve: fixture.expected.approveDecisionSignatureHex
        case .deny: fixture.expected.denyDecisionSignatureHex
        }
        return try RemoteJITApprovalDecision(
            payload: payload,
            decisionSignature: Data(hexadecimal: signatureHex)
        )
    }
}
