import XCTest
@testable import AuthenticatorCore

final class SecretTextImportParserTests: XCTestCase {
    func testParsesExportAssignmentAsPasswordCandidate() throws {
        let result = try SecretTextImportParser.parse("export API_KEY=sk_live_123456789")

        XCTAssertEqual(result.candidates.count, 1)
        XCTAssertEqual(result.candidates[0].kind, .apiKey)
        XCTAssertEqual(result.candidates[0].name, "API_KEY")
        XCTAssertNil(result.candidates[0].username)
        XCTAssertEqual(result.candidates[0].secret, "sk_live_123456789")
        XCTAssertEqual(result.candidates[0].redactedSecret, "sk_live_••••")
    }

    func testParsesTokenAssignmentAsAPIKeyCandidate() throws {
        let result = try SecretTextImportParser.parse("SERVICE_TOKEN=tok_live_123456789")

        XCTAssertEqual(result.candidates.map(\.kind), [.apiKey])
        XCTAssertEqual(result.candidates[0].name, "SERVICE_TOKEN")
        XCTAssertNil(result.candidates[0].username)
        XCTAssertEqual(result.candidates[0].secret, "tok_live_123456789")
    }

    func testEnvAssignmentPreservesDoubleEqualsPadding() throws {
        let result = try SecretTextImportParser.parse(
            "SERVICE_TOKEN=AUTHSIA_FIXTURE_PADDED=="
        )

        XCTAssertEqual(result.candidates.map(\.name), ["SERVICE_TOKEN"])
        XCTAssertEqual(result.candidates.map(\.secret), ["AUTHSIA_FIXTURE_PADDED=="])
    }

    func testParsesBareAssignmentAsPasswordCandidate() throws {
        let result = try SecretTextImportParser.parse("DATABASE_URL=postgres://user:pass@example/db")

        XCTAssertEqual(result.candidates.map(\.name), ["DATABASE_URL"])
        XCTAssertEqual(result.candidates[0].kind, .password)
        XCTAssertEqual(result.candidates[0].secret, "postgres://user:pass@example/db")
    }

    func testParsesMultilineEnvTextInOrder() throws {
        let text = """
        # comment
        export API_KEY="abc123456789"
        DATABASE_URL='postgres://user:pass@example/db'
        EMPTY=
        """

        let result = try SecretTextImportParser.parse(text)

        XCTAssertEqual(result.candidates.map(\.name), ["API_KEY", "DATABASE_URL"])
        XCTAssertEqual(result.candidates.map(\.kind), [.apiKey, .password])
        XCTAssertEqual(result.candidates.map(\.secret), ["abc123456789", "postgres://user:pass@example/db"])
    }

    func testParsesColonKeyValueTextAsPasswordCandidates() throws {
        let text = """
        api-key: sk_live_123456
        client.email: service@example.com
        """

        let result = try SecretTextImportParser.parse(text)

        XCTAssertEqual(result.candidates.map(\.kind), [.apiKey, .password])
        XCTAssertEqual(result.candidates.map(\.name), ["api-key", "client.email"])
        XCTAssertNil(result.candidates[0].username)
        XCTAssertEqual(result.candidates.map(\.secret), ["sk_live_123456", "service@example.com"])
    }

    func testJsonObjectBecomesSecureNoteByDefault() throws {
        let json = #"{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"}"#

        let result = try SecretTextImportParser.parse(json)

        XCTAssertEqual(result.candidates.count, 1)
        XCTAssertEqual(result.candidates[0].kind, .secureNote)
        XCTAssertEqual(result.candidates[0].name, "JSON credentials")
        XCTAssertEqual(result.candidates[0].secret, json)
    }

    func testJsonRedactionKeepsKeysAndMasksValues() throws {
        let json = #"{"password":"hunter2secret","username":"admin"}"#

        let result = try SecretTextImportParser.parse(json)

        // Keys visible (sorted); string values reveal a leading hint then mask.
        XCTAssertEqual(
            result.candidates[0].redactedSecret,
            #"{"password":"hunter2s••••","username":"a••••"}"#
        )
    }

    func testFallbackTextBecomesUnnamedPasswordCandidate() throws {
        let result = try SecretTextImportParser.parse("plain-secret-token-value")

        XCTAssertEqual(result.candidates.count, 1)
        XCTAssertEqual(result.candidates[0].kind, .password)
        XCTAssertEqual(result.candidates[0].name, "")
        XCTAssertNil(result.candidates[0].username)
        XCTAssertEqual(result.candidates[0].secret, "plain-secret-token-value")
        XCTAssertTrue(result.candidates[0].requiresName)
        // "Show prefix only": reveal up to 8 leading chars, mask the rest.
        XCTAssertEqual(result.candidates[0].redactedSecret, "plain-se••••")
    }

    func testBareSecretWithDoubleEqualsPaddingRemainsWhole() throws {
        let secret = "AUTHSIA_FIXTURE_PADDED=="

        let result = try SecretTextImportParser.parse(secret)

        XCTAssertEqual(result.candidates.count, 1)
        XCTAssertEqual(result.candidates[0].name, "")
        XCTAssertEqual(result.candidates[0].secret, secret)
        XCTAssertTrue(result.candidates[0].requiresName)
    }

    func testRejectsEmptyAndOversizedInput() {
        XCTAssertThrowsError(try SecretTextImportParser.parse("   \n\t")) { error in
            XCTAssertEqual(error as? SecretTextImportError, .empty)
        }

        let oversized = String(repeating: "a", count: SecretTextImportParser.maxInputBytes + 1)
        XCTAssertThrowsError(try SecretTextImportParser.parse(oversized)) { error in
            XCTAssertEqual(error as? SecretTextImportError, .tooLarge)
        }
    }
}
