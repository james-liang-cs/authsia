import Foundation
import XCTest

final class RemoteJITApprovalGoldenFixtureTests: XCTestCase {
    func testLoadsPublicOnlyGoldenFixture() throws {
        let fixture = try RemoteJITApprovalGoldenFixture.load()

        XCTAssertEqual(fixture.input.caller.processName, "synthetic-agent")
        XCTAssertEqual(fixture.input.capabilities, ["exec", "list"])
        XCTAssertFalse(fixture.input.items.isEmpty)
        XCTAssertFalse(fixture.expected.descriptorHex.isEmpty)
        XCTAssertFalse(fixture.expected.requestDigestHex.isEmpty)
        XCTAssertFalse(fixture.expected.requestPublicKeyX963Hex.isEmpty)
        XCTAssertFalse(fixture.expected.decisionPublicKeyX963Hex.isEmpty)
        XCTAssertFalse(fixture.expected.approveDecisionEnvelopeHex.isEmpty)
        XCTAssertFalse(fixture.expected.denyDecisionEnvelopeHex.isEmpty)
    }

    func testHexadecimalDataRejectsMalformedInput() throws {
        XCTAssertThrowsError(try Data(hexadecimal: "0"))
        XCTAssertThrowsError(try Data(hexadecimal: "gg"))

        let data = try Data(hexadecimal: "00a1ff")
        XCTAssertEqual(data.hexString, "00a1ff")
    }
}
