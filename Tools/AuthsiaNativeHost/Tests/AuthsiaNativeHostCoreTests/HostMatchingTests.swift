import XCTest
@testable import AuthsiaNativeHostCore

// Host matching itself is covered by `ChromeAutofillMatchingTests` in
// `AuthenticatorBridge`, where the matcher now lives. What remains here is the
// native host's own input validation and single-match selection.
final class HostMatchingTests: XCTestCase {
    func testSanitizeHostRejectsInvalidCharacters() {
        XCTAssertNil(sanitizeHost("exa mple.com"))
        XCTAssertEqual(sanitizeHost("Example.COM"), "example.com")
    }

    func testSelectBestMatchPrefersSingleExact() {
        let candidates = [
            HostMatchCandidate(id: UUID(), storedHost: "example.com", isExact: false),
            HostMatchCandidate(id: UUID(), storedHost: "sub.example.com", isExact: true)
        ]

        let selection = selectBestMatch(from: candidates)
        XCTAssertEqual(selection?.reason, .singleExact)
        XCTAssertEqual(selection?.candidate.storedHost, "sub.example.com")
    }

    func testSelectBestMatchReturnsNoneWhenMultipleExactCandidates() {
        let candidates = [
            HostMatchCandidate(id: UUID(), storedHost: "example.com", isExact: true),
            HostMatchCandidate(id: UUID(), storedHost: "example.com", isExact: true)
        ]

        XCTAssertNil(selectBestMatch(from: candidates))
    }

    func testSelectBestMatchAcceptsSingleSubdomainCandidate() {
        let id = UUID()
        let selection = selectBestMatch(from: [
            HostMatchCandidate(id: id, storedHost: "example.com", isExact: false)
        ])

        XCTAssertEqual(selection?.reason, .singleSubdomain)
        XCTAssertEqual(selection?.candidate.id, id)
    }
}
