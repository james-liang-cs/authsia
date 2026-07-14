import XCTest
@testable import AuthsiaBridgeHost

final class BridgeQueryMatcherTests: XCTestCase {
    func testMatchesExactIDBeforeSearchableFields() {
        let expected = MatchCandidate(id: "abc-123", fields: ["shared"])
        let shadow = MatchCandidate(id: "other", fields: ["abc-123"])

        let match = BridgeQueryMatcher.firstMatch(
            query: "ABC-123",
            in: [shadow, expected],
            id: { $0.id },
            searchable: { $0.fields }
        )

        XCTAssertEqual(match, expected)
    }

    func testReturnsNilForAmbiguousExactName() {
        let first = MatchCandidate(id: "1", fields: ["prod"])
        let second = MatchCandidate(id: "2", fields: ["prod"])

        let match = BridgeQueryMatcher.firstMatch(
            query: "prod",
            in: [first, second],
            id: { $0.id },
            searchable: { $0.fields }
        )

        XCTAssertNil(match)
    }

    func testFallsBackToUniquePrefixThenUniqueContains() {
        let alpha = MatchCandidate(id: "1", fields: ["alpha"])
        let beta = MatchCandidate(id: "2", fields: ["db-prod"])

        let prefix = BridgeQueryMatcher.firstMatch(
            query: "alp",
            in: [alpha, beta],
            id: { $0.id },
            searchable: { $0.fields }
        )
        let contains = BridgeQueryMatcher.firstMatch(
            query: "prod",
            in: [alpha, beta],
            id: { $0.id },
            searchable: { $0.fields }
        )

        XCTAssertEqual(prefix, alpha)
        XCTAssertEqual(contains, beta)
    }

    private struct MatchCandidate: Equatable {
        let id: String
        let fields: [String]
    }
}
