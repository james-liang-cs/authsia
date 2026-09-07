import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
import XCTest
@testable import AuthsiaBridgeHost

@MainActor
final class MCPHTTPVaultResolverTests: XCTestCase {
    func testDisabledAndAmbiguousItemsAreDeniedWithoutSecretReads() throws {
        let source = HTTPVaultFixture()
        let resolver = MCPHTTPVaultResolver(source: source)
        let header = MCPUpstreamCredentialHeader(headerName: "X-Key", reference: "authsia://api-key/Test/key", format: .raw)
        source.apiKeys = [APIKeyMetadata(from: APIKeyItem(name: "Test", key: Data(), isCliEnabled: false))]
        XCTAssertThrowsError(try resolver.metadata([header]))
        source.apiKeys = [APIKeyMetadata(from: APIKeyItem(name: "Test", key: Data(), isCliEnabled: true)),
                          APIKeyMetadata(from: APIKeyItem(name: "Test", key: Data(), isCliEnabled: true))]
        XCTAssertThrowsError(try resolver.metadata([header]))
        XCTAssertEqual(source.secretReads, 0)
    }
    func testMetadataRevocationBetweenResolutionAndReadIsRejected() throws {
        let source = HTTPVaultFixture()
        let resolver = MCPHTTPVaultResolver(source: source)
        source.apiKeys = [APIKeyMetadata(from: APIKeyItem(name: "Test", key: Data(), isCliEnabled: true))]
        let item = try resolver.metadata([.init(headerName: "X-Key", reference: "authsia://api-key/Test/key", format: .raw)])[0]
        source.apiKeys[0].isCliEnabled = false
        XCTAssertThrowsError(try resolver.value(item))
        XCTAssertEqual(source.secretReads, 0)
    }
}
@MainActor
private final class HTTPVaultFixture: MCPHTTPVaultSource {
    var passwords: [PasswordMetadata] = []
    var apiKeys: [APIKeyMetadata] = []
    var notes: [SecureNoteMetadata] = []
    var secretReads = 0
    func load() throws {}
    func getFullPassword(metadata: PasswordMetadata) throws -> PasswordItem { secretReads += 1; throw MCPManagementError.denied }
    func getFullAPIKey(metadata: APIKeyMetadata) throws -> APIKeyItem { secretReads += 1; throw MCPManagementError.denied }
    func getFullNote(metadata: SecureNoteMetadata) throws -> SecureNoteItem { secretReads += 1; throw MCPManagementError.denied }
}
