import XCTest
@testable import AuthsiaNativeHostCore

final class HostMatchingTests: XCTestCase {
    func testSanitizeHostRejectsInvalidCharacters() {
        XCTAssertNil(sanitizeHost("exa mple.com"))
        XCTAssertEqual(sanitizeHost("Example.COM"), "example.com")
    }

    func testParseStoredHostFromUrl() {
        XCTAssertEqual(parseStoredHost(from: "https://example.com/login"), "example.com")
        XCTAssertEqual(parseStoredHost(from: "example.com/path"), "example.com")
        XCTAssertEqual(parseStoredHost(from: "http://localhost:3000/login"), "localhost")
        XCTAssertNil(parseStoredHost(from: "not a url"))
    }

    func testUrlPrefixMatchesPathSegmentBoundary() {
        XCTAssertTrue(
            storedURLMatches(
                currentURL: "https://example.com/app/login",
                storedWebsite: "https://example.com/app"
            )
        )
        XCTAssertFalse(
            storedURLMatches(
                currentURL: "https://example.com/application/login",
                storedWebsite: "https://example.com/app"
            )
        )
    }

    func testUrlPrefixRequiresSamePort() {
        XCTAssertTrue(
            storedURLMatches(
                currentURL: "http://localhost:3000/app/login",
                storedWebsite: "http://localhost:3000/app"
            )
        )
        XCTAssertFalse(
            storedURLMatches(
                currentURL: "http://localhost:4000/app/login",
                storedWebsite: "http://localhost:3000/app"
            )
        )
    }

    func testUrlPrefixTreatsWWWAndApexHostsAsEquivalent() {
        XCTAssertTrue(
            storedURLMatches(
                currentURL: "https://example.com/app/login",
                storedWebsite: "https://www.example.com/app"
            )
        )
        XCTAssertTrue(
            storedURLMatches(
                currentURL: "https://www.example.com/app/login",
                storedWebsite: "https://example.com/app"
            )
        )
    }

    func testAWSSignInRegionalOAuthRedirectMatchesAccountAliasConsoleURL() {
        XCTAssertTrue(
            storedURLMatches(
                currentURL: "https://ap-southeast-1.signin.aws.amazon.com/oauth?client_id=arn%3Aaws%3Asignin%3A%3A%3Aconsole%2Fcanvas",
                storedWebsite: "https://example-control-plane.signin.aws.amazon.com/console"
            )
        )
        XCTAssertFalse(
            storedURLMatches(
                currentURL: "https://signin.evil.example.com/oauth",
                storedWebsite: "https://example-control-plane.signin.aws.amazon.com/console"
            )
        )
    }

    func testAWSSignInAccountAliasConsoleURLMatchesRegionalHostWithoutCurrentURL() {
        XCTAssertTrue(
            storedAWSSignInWebsiteMatchesHost(
                currentHost: "ap-southeast-1.signin.aws.amazon.com",
                storedWebsite: "https://example-control-plane.signin.aws.amazon.com/console"
            )
        )
        XCTAssertFalse(
            storedAWSSignInWebsiteMatchesHost(
                currentHost: "signin.evil.example.com",
                storedWebsite: "https://example-control-plane.signin.aws.amazon.com/console"
            )
        )
    }

    func testHostMatchesSupportsSubdomainsOnlyWithDotBoundary() {
        XCTAssertTrue(hostMatches(currentHost: "example.com", storedHost: "example.com"))
        XCTAssertTrue(hostMatches(currentHost: "sub.example.com", storedHost: "example.com"))
        XCTAssertFalse(hostMatches(currentHost: "badexample.com", storedHost: "example.com"))
    }

    func testHostMatchesTreatsWWWAndApexAsEquivalent() {
        XCTAssertTrue(hostMatches(currentHost: "example.com", storedHost: "www.example.com"))
        XCTAssertTrue(hostMatches(currentHost: "www.example.com", storedHost: "example.com"))
    }

    func testHostMatchesRejectsObviousPublicSuffixStoredHosts() {
        XCTAssertFalse(hostMatches(currentHost: "example.com", storedHost: "com"))
        XCTAssertFalse(hostMatches(currentHost: "example.co.uk", storedHost: "co.uk"))
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
}
