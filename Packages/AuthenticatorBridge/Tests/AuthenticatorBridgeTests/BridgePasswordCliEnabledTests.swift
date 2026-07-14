import XCTest
@testable import AuthenticatorBridge

final class BridgePasswordCliEnabledTests: XCTestCase {
    func testBridgePasswordStoresCliEnabledFlag() throws {
        let password = BridgePassword(
            id: UUID(),
            name: "Example",
            username: "user@example.com",
            website: "https://example.com",
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            createdAt: Date(),
            updatedAt: Date()
        )

        let encoded = try BridgeCoder.encode(password)
        let decoded = try BridgeCoder.decode(BridgePassword.self, from: encoded)

        XCTAssertTrue(decoded.isCliEnabled)
    }
}
