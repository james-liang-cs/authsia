import XCTest
@testable import AuthenticatorBridge

final class ChromeAutofillMatchingTests: XCTestCase {

    // MARK: - Host parsing primitives

    func testSanitizeHostRejectsInvalidCharacters() {
        XCTAssertNil(ChromeAutofillMatcher.sanitizeHost("exa mple.com"))
        XCTAssertEqual(ChromeAutofillMatcher.sanitizeHost("Example.COM"), "example.com")
    }

    func testParseStoredHostFromUrl() {
        XCTAssertEqual(ChromeAutofillMatcher.parseStoredHost(from: "https://example.com/login"), "example.com")
        XCTAssertEqual(ChromeAutofillMatcher.parseStoredHost(from: "example.com/path"), "example.com")
        XCTAssertEqual(ChromeAutofillMatcher.parseStoredHost(from: "http://localhost:3000/login"), "localhost")
        XCTAssertNil(ChromeAutofillMatcher.parseStoredHost(from: "not a url"))
    }

    func testUrlPrefixMatchesPathSegmentBoundary() {
        XCTAssertTrue(
            ChromeAutofillMatcher.storedURLMatches(
                currentURL: "https://example.com/app/login",
                storedWebsite: "https://example.com/app"
            )
        )
        XCTAssertFalse(
            ChromeAutofillMatcher.storedURLMatches(
                currentURL: "https://example.com/application/login",
                storedWebsite: "https://example.com/app"
            )
        )
    }

    func testUrlPrefixRequiresSamePort() {
        XCTAssertTrue(
            ChromeAutofillMatcher.storedURLMatches(
                currentURL: "http://localhost:3000/app/login",
                storedWebsite: "http://localhost:3000/app"
            )
        )
        XCTAssertFalse(
            ChromeAutofillMatcher.storedURLMatches(
                currentURL: "http://localhost:4000/app/login",
                storedWebsite: "http://localhost:3000/app"
            )
        )
    }

    func testUrlPrefixTreatsWWWAndApexHostsAsEquivalent() {
        XCTAssertTrue(
            ChromeAutofillMatcher.storedURLMatches(
                currentURL: "https://example.com/app/login",
                storedWebsite: "https://www.example.com/app"
            )
        )
        XCTAssertTrue(
            ChromeAutofillMatcher.storedURLMatches(
                currentURL: "https://www.example.com/app/login",
                storedWebsite: "https://example.com/app"
            )
        )
    }

    func testAWSSignInRegionalOAuthRedirectMatchesAccountAliasConsoleURL() {
        XCTAssertTrue(
            ChromeAutofillMatcher.storedURLMatches(
                currentURL: "https://ap-southeast-1.signin.aws.amazon.com/oauth?client_id=arn%3Aaws%3Asignin%3A%3A%3Aconsole%2Fcanvas",
                storedWebsite: "https://example-control-plane.signin.aws.amazon.com/console"
            )
        )
        XCTAssertFalse(
            ChromeAutofillMatcher.storedURLMatches(
                currentURL: "https://signin.evil.example.com/oauth",
                storedWebsite: "https://example-control-plane.signin.aws.amazon.com/console"
            )
        )
    }

    func testAWSSignInAccountAliasConsoleURLMatchesRegionalHostWithoutCurrentURL() {
        XCTAssertTrue(
            ChromeAutofillMatcher.storedAWSSignInWebsiteMatchesHost(
                currentHost: "ap-southeast-1.signin.aws.amazon.com",
                storedWebsite: "https://example-control-plane.signin.aws.amazon.com/console"
            )
        )
        XCTAssertFalse(
            ChromeAutofillMatcher.storedAWSSignInWebsiteMatchesHost(
                currentHost: "signin.evil.example.com",
                storedWebsite: "https://example-control-plane.signin.aws.amazon.com/console"
            )
        )
    }

    func testHostMatchesSupportsSubdomainsOnlyWithDotBoundary() {
        XCTAssertTrue(ChromeAutofillMatcher.hostMatches(currentHost: "example.com", storedHost: "example.com"))
        XCTAssertTrue(ChromeAutofillMatcher.hostMatches(currentHost: "sub.example.com", storedHost: "example.com"))
        XCTAssertFalse(ChromeAutofillMatcher.hostMatches(currentHost: "badexample.com", storedHost: "example.com"))
    }

    func testHostMatchesTreatsWWWAndApexAsEquivalent() {
        XCTAssertTrue(ChromeAutofillMatcher.hostMatches(currentHost: "example.com", storedHost: "www.example.com"))
        XCTAssertTrue(ChromeAutofillMatcher.hostMatches(currentHost: "www.example.com", storedHost: "example.com"))
    }

    func testHostMatchesRejectsObviousPublicSuffixStoredHosts() {
        XCTAssertFalse(ChromeAutofillMatcher.hostMatches(currentHost: "example.com", storedHost: "com"))
        XCTAssertFalse(ChromeAutofillMatcher.hostMatches(currentHost: "example.co.uk", storedHost: "co.uk"))
    }

    // MARK: - Matcher

    func testUnrelatedHostMatchesNothing() {
        let matches = ChromeAutofillMatcher.matches(
            query: ChromeAutofillMatchQuery(host: "unrelated.example"),
            passwords: [password(id: Self.passwordID, name: "GitHub", website: "https://github.com")],
            accounts: [account(id: Self.otpID, issuer: "GitHub", hosts: ["https://github.com"])]
        )

        XCTAssertTrue(matches.isEmpty)
    }

    func testInvalidHostMatchesNothing() {
        let matches = ChromeAutofillMatcher.matches(
            query: ChromeAutofillMatchQuery(host: "exa mple.com"),
            passwords: [password(id: Self.passwordID, name: "Example", website: "https://example.com")],
            accounts: []
        )

        XCTAssertTrue(matches.isEmpty)
    }

    func testPasswordMatchCarriesStoredHostAndExactness() {
        let matches = ChromeAutofillMatcher.matches(
            query: ChromeAutofillMatchQuery(host: "sub.example.com"),
            passwords: [
                password(id: Self.passwordID, name: "Apex", website: "https://example.com"),
                password(id: Self.otherPasswordID, name: "Sub", website: "https://sub.example.com"),
            ],
            accounts: []
        )

        XCTAssertEqual(matches.map(\.id), [Self.passwordID, Self.otherPasswordID])
        XCTAssertEqual(matches.first?.storedHost, "example.com")
        XCTAssertEqual(matches.first?.isExact, false)
        XCTAssertEqual(matches.last?.storedHost, "sub.example.com")
        XCTAssertEqual(matches.last?.isExact, true)
    }

    func testPasswordKindReturnsOnlyPasswords() {
        let matches = ChromeAutofillMatcher.matches(
            query: ChromeAutofillMatchQuery(host: "github.com", kind: .password),
            passwords: [password(id: Self.passwordID, name: "GitHub", website: "https://github.com")],
            accounts: [account(id: Self.otpID, issuer: "GitHub", hosts: ["https://github.com"])]
        )

        XCTAssertEqual(matches.map(\.kind), [.password])
        XCTAssertEqual(matches.map(\.id), [Self.passwordID])
    }

    func testOTPKindReturnsOnlyOTPButStillUsesPasswordsForRelatedTokens() {
        let matches = ChromeAutofillMatcher.matches(
            query: ChromeAutofillMatchQuery(host: "github.com", kind: .otp),
            passwords: [password(id: Self.passwordID, name: "GitHub", website: "https://github.com")],
            accounts: [account(id: Self.otpID, issuer: "GitHub", hosts: nil)]
        )

        XCTAssertEqual(matches.map(\.kind), [.otp])
        XCTAssertEqual(matches.map(\.id), [Self.otpID])
    }

    func testMissingKindReturnsPasswordsThenOTP() {
        let matches = ChromeAutofillMatcher.matches(
            query: ChromeAutofillMatchQuery(host: "github.com"),
            passwords: [password(id: Self.passwordID, name: "GitHub", website: "https://github.com")],
            accounts: [account(id: Self.otpID, issuer: "GitHub", hosts: ["https://github.com"])]
        )

        XCTAssertEqual(matches.map(\.kind), [.password, .otp])
        XCTAssertEqual(matches.map(\.id), [Self.passwordID, Self.otpID])
    }

    func testPasswordMatchesByCurrentURLPrefix() {
        let stored = password(id: Self.passwordID, name: "App", website: "https://example.com/app")

        let onPath = ChromeAutofillMatcher.matches(
            query: ChromeAutofillMatchQuery(host: "example.com", currentURL: "https://example.com/app/login"),
            passwords: [stored],
            accounts: []
        )
        let offPath = ChromeAutofillMatcher.matches(
            query: ChromeAutofillMatchQuery(host: "example.com", currentURL: "https://example.com/other"),
            passwords: [stored],
            accounts: []
        )

        XCTAssertEqual(onPath.map(\.id), [Self.passwordID])
        XCTAssertTrue(offPath.isEmpty)
    }

    func testDoesNotSubstringMatchOTPIssuerInHost() {
        let gitID = UUID(uuidString: "73737373-7373-7373-7373-737373737373")!
        let githubID = UUID(uuidString: "74747474-7474-7474-7474-747474747474")!
        let accounts = [
            account(id: gitID, issuer: "Git", hosts: nil),
            account(id: githubID, issuer: "GitHub", hosts: ["https://github.com"]),
        ]

        XCTAssertTrue(
            ChromeAutofillMatcher.matches(
                query: ChromeAutofillMatchQuery(host: "digital.com"),
                passwords: [],
                accounts: accounts
            ).isEmpty
        )
        XCTAssertEqual(
            ChromeAutofillMatcher.matches(
                query: ChromeAutofillMatchQuery(host: "login.github.com"),
                passwords: [],
                accounts: accounts
            ).map(\.id),
            [githubID]
        )
    }

    func testDoesNotSubstringMatchShortOTPIssuerInHostLabel() {
        let matches = ChromeAutofillMatcher.matches(
            query: ChromeAutofillMatchQuery(host: "boring.com"),
            passwords: [],
            accounts: [account(id: Self.otpID, issuer: "ING", hosts: nil)]
        )

        XCTAssertTrue(matches.isEmpty)
    }

    func testDoesNotHostMatchOTPEmailLabel() {
        let matches = ChromeAutofillMatcher.matches(
            query: ChromeAutofillMatchQuery(host: "userexample.com"),
            passwords: [],
            accounts: [account(id: Self.otpID, issuer: "Acme Corp", label: "user@example.com", hosts: nil)]
        )

        XCTAssertTrue(matches.isEmpty)
    }

    func testDoesNotMatchOTPFromIssuerMatchingUnknownPublicSuffix() {
        let matches = ChromeAutofillMatcher.matches(
            query: ChromeAutofillMatchQuery(host: "attacker.cloud"),
            passwords: [],
            accounts: [account(id: Self.otpID, issuer: "Cloud", hosts: nil)]
        )

        XCTAssertTrue(matches.isEmpty)
    }

    func testMatchesOTPByMetadataHost() {
        let matches = ChromeAutofillMatcher.matches(
            query: ChromeAutofillMatchQuery(host: "ap-southeast-1.signin.aws.amazon.com"),
            passwords: [],
            accounts: [
                account(
                    id: Self.otpID,
                    issuer: "Amazon Web Services",
                    label: "chen_liang@example-control-plane",
                    hosts: ["https://example-control-plane.signin.aws.amazon.com/console"]
                )
            ]
        )

        XCTAssertEqual(matches.map(\.id), [Self.otpID])
    }

    func testSortsSpecificAWSOTPBeforeBroadAWSHosts() {
        let broadID = UUID(uuidString: "70707070-7070-7070-7070-707070707070")!
        let specificID = UUID(uuidString: "71717171-7171-7171-7171-717171717171")!

        let matches = ChromeAutofillMatcher.matches(
            query: ChromeAutofillMatchQuery(
                host: "ap-southeast-1.signin.aws.amazon.com",
                currentURL: "https://ap-southeast-1.signin.aws.amazon.com/mfa",
                kind: .otp
            ),
            passwords: [
                password(
                    id: Self.passwordID,
                    name: "example-control-plane",
                    website: "https://example-control-plane.signin.aws.amazon.com/console"
                )
            ],
            accounts: [
                account(
                    id: broadID,
                    issuer: "Amazon Web Services",
                    label: "root-account-mfa-device@example-control-plane",
                    hosts: ["aws.amazon.com"]
                ),
                account(
                    id: specificID,
                    issuer: "Amazon Web Services",
                    label: "chen_liang@example-control-plane",
                    hosts: ["https://example-control-plane.signin.aws.amazon.com/console"]
                ),
            ]
        )

        XCTAssertEqual(matches.map(\.id), [specificID, broadID])
    }

    func testMatchesAWSOTPUsingMatchedPasswordAlias() {
        let matches = ChromeAutofillMatcher.matches(
            query: ChromeAutofillMatchQuery(
                host: "ap-southeast-1.signin.aws.amazon.com",
                currentURL: "https://ap-southeast-1.signin.aws.amazon.com/oauth",
                kind: .otp
            ),
            passwords: [
                password(
                    id: Self.passwordID,
                    name: "example-control-plane",
                    username: "chen_liang",
                    website: "https://example-control-plane.signin.aws.amazon.com/console"
                )
            ],
            accounts: [
                account(
                    id: Self.otpID,
                    issuer: "Amazon Web Services",
                    label: "chen_liang@example-control-plane",
                    hosts: nil
                )
            ]
        )

        XCTAssertEqual(matches.map(\.id), [Self.otpID])
    }

    func testDoesNotMatchOTPBySameNameAsMatchedPasswordUsernameAlone() {
        let matches = ChromeAutofillMatcher.matches(
            query: ChromeAutofillMatchQuery(host: "example.com", kind: .otp),
            passwords: [
                password(
                    id: Self.passwordID,
                    name: "Example Login",
                    username: "acmecorp",
                    website: "https://example.com"
                )
            ],
            accounts: [account(id: Self.otpID, issuer: "Acme Corp", hosts: nil)]
        )

        XCTAssertTrue(matches.isEmpty)
    }

    func testMatchesOTPByMatchedPasswordName() {
        let matches = ChromeAutofillMatcher.matches(
            query: ChromeAutofillMatchQuery(host: "example.com", kind: .otp),
            passwords: [
                password(
                    id: Self.passwordID,
                    name: "Acme Corp",
                    username: "someone",
                    website: "https://example.com"
                )
            ],
            accounts: [account(id: Self.otpID, issuer: "Acme Corp", hosts: nil)]
        )

        XCTAssertEqual(matches.map(\.id), [Self.otpID])
    }

    // MARK: - Fixtures

    private static let passwordID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
    private static let otherPasswordID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
    private static let otpID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!

    private func password(
        id: UUID,
        name: String,
        username: String = "synthetic-user",
        website: String?
    ) -> ChromeAutofillPasswordMetadata {
        ChromeAutofillPasswordMetadata(id: id, name: name, username: username, website: website)
    }

    private func account(
        id: UUID,
        issuer: String,
        label: String = "synthetic-user",
        hosts: [String]?
    ) -> ChromeAutofillAccountMetadata {
        ChromeAutofillAccountMetadata(id: id, issuer: issuer, label: label, hosts: hosts)
    }
}
