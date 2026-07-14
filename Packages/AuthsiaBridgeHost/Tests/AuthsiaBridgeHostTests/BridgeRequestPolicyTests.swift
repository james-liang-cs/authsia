import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge

final class BridgeRequestPolicyTests: XCTestCase {
    func testDeniesSSHRequests() {
        let denial = BridgeRequestPolicy.denial(for: makeRequest(isSSH: true))

        XCTAssertEqual(denial?.code, .policyDenied)
        XCTAssertEqual(denial?.message, "SSH access not allowed")
    }

    func testDeniesCIRequests() {
        let denial = BridgeRequestPolicy.denial(for: makeRequest(isCI: true))

        XCTAssertEqual(denial?.code, .policyDenied)
        XCTAssertEqual(denial?.message, "CI environment access not allowed")
    }

    func testAllowsPipedNonSSHNonCIRequests() {
        let denial = BridgeRequestPolicy.denial(for: makeRequest(isPiped: true))

        XCTAssertNil(denial)
    }

    private func makeRequest(
        isPiped: Bool = false,
        isSSH: Bool = false,
        isCI: Bool = false
    ) -> BridgeRequest {
        BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "prod",
            options: .init(field: nil, copy: false),
            context: .init(
                isTTY: !isPiped,
                isPiped: isPiped,
                isSSH: isSSH,
                isCI: isCI,
                timestamp: Date()
            )
        )
    }
}
