import XCTest
@testable import AuthenticatorBridge

final class AutomationCredentialTokenTests: XCTestCase {
    func testRoundTripWithBenignSecretBytes() throws {
        let id = UUID()
        let bytes = Data(repeating: 0x41, count: AutomationCredentialToken.randomByteCount)
        let token = try AutomationCredentialToken.issue(id: id, randomBytes: bytes)
        let parsed = try AutomationCredentialToken.parse(token)
        XCTAssertEqual(parsed.id, id)
        XCTAssertEqual(parsed.randomBytes, bytes)
    }

    /// Base64url maps '/' to '_', the same character used as the token field
    /// separator, so roughly half of all issued tokens contain extra underscores.
    /// 0xFF bytes encode to all-'/' base64, guaranteeing that worst case.
    func testRoundTripWhenSecretEncodesToUnderscores() throws {
        let id = UUID()
        let bytes = Data(repeating: 0xFF, count: AutomationCredentialToken.randomByteCount)
        let token = try AutomationCredentialToken.issue(id: id, randomBytes: bytes)
        let parsed = try AutomationCredentialToken.parse(token)
        XCTAssertEqual(parsed.id, id)
        XCTAssertEqual(parsed.randomBytes, bytes)
    }

    func testParseRejectsMissingSecret() {
        XCTAssertThrowsError(
            try AutomationCredentialToken.parse("authsia_ac1_\(UUID().uuidString.lowercased())")
        )
    }

    func testParseRejectsWrongPrefix() {
        XCTAssertThrowsError(try AutomationCredentialToken.parse("authsia_ac2_whatever"))
    }
}
