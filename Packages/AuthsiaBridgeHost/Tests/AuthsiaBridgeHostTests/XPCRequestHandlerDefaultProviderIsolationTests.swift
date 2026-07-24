#if os(macOS)
import Foundation
import XCTest
@testable import AuthenticatorBridge
@testable import AuthsiaBridgeHost

/// The default automation-credential providers are invoked during synchronous XPC
/// dispatch off the main actor. If they were built as closure literals inside the
/// @MainActor init they would inherit main-actor isolation and trap in
/// dispatch_assert_queue on first use (`authsia access list` crashed the headless
/// host this way). These tests run the factory-built providers off the main queue.
final class XPCRequestHandlerDefaultProviderIsolationTests: XCTestCase {
    private static let digestKey = Data(repeating: 7, count: 32)

    func testDefaultAuthorityProviderRunsOffMainActor() {
        let provider = XPCRequestHandler.defaultAutomationCredentialAuthorityProvider(
            authorityStore: TestAuthorityStore(),
            digestKeyLoader: { Self.digestKey }
        )
        let done = expectation(description: "authority provider ran off the main queue")
        DispatchQueue.global().async {
            dispatchPrecondition(condition: .notOnQueue(.main))
            do {
                _ = try provider().list(includeAll: true)
            } catch {
                XCTFail("default authority provider threw: \(error)")
            }
            done.fulfill()
        }
        wait(for: [done], timeout: 5)
    }

    func testDefaultValidationProviderRunsOffMainActor() {
        let validation = XPCRequestHandler.defaultAutomationCredentialValidationProvider(
            authorityProvider: XPCRequestHandler.defaultAutomationCredentialAuthorityProvider(
                authorityStore: TestAuthorityStore(),
                digestKeyLoader: { Self.digestKey }
            ),
            currentMachineIdProvider: { "machine" }
        )
        let done = expectation(description: "validation provider ran off the main queue")
        DispatchQueue.global().async {
            dispatchPrecondition(condition: .notOnQueue(.main))
            guard case .credentialNotFound = validation("not-a-real-token", .exec, false) else {
                return XCTFail("expected credentialNotFound for an unknown token")
            }
            done.fulfill()
        }
        wait(for: [done], timeout: 5)
    }
}
#endif
