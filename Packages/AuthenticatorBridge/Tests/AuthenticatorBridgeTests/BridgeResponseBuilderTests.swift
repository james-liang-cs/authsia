import XCTest
@testable import AuthenticatorBridge

final class BridgeResponseBuilderTests: XCTestCase {
    func testErrorResponseIncludesCode() {
        let id = UUID()
        let response: BridgeResponse<String> = BridgeResponseBuilder.error(id: id, code: .invalidRequest, message: "bad")
        XCTAssertEqual(response.id, id)
        XCTAssertEqual(response.error?.code, .invalidRequest)
        XCTAssertNil(response.sessionExpiresAt)
    }

    func testSuccessResponseIncludesSessionExpiresAt() {
        let id = UUID()
        let expiry = Date().addingTimeInterval(7200)
        let response: BridgeResponse<String> = BridgeResponseBuilder.success(
            id: id,
            payload: "ok",
            sessionToken: "tok",
            sessionExpiresAt: expiry
        )
        XCTAssertEqual(response.id, id)
        XCTAssertEqual(response.payload, "ok")
        XCTAssertEqual(response.sessionToken, "tok")
        XCTAssertEqual(response.sessionExpiresAt, expiry)
    }

    func testSuccessResponseWithoutSessionExpiresAt() {
        let id = UUID()
        let response: BridgeResponse<String> = BridgeResponseBuilder.success(
            id: id,
            payload: "ok",
            sessionToken: "tok"
        )
        XCTAssertEqual(response.sessionToken, "tok")
        XCTAssertNil(response.sessionExpiresAt)
    }
}
