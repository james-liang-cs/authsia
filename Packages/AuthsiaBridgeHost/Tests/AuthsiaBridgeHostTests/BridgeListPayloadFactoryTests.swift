import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData

final class BridgeListPayloadFactoryTests: XCTestCase {
    func testMetadataWithSnapshotFallbackUsesSnapshotOnlyWhenLoadedMetadataIsEmpty() {
        XCTAssertEqual(
            BridgeListPayloadFactory.metadataWithSnapshotFallback(
                loaded: [String](),
                snapshot: [42],
                mapLoaded: { "loaded:\($0)" },
                mapSnapshot: { "snapshot:\($0)" }
            ),
            ["snapshot:42"]
        )
        XCTAssertEqual(
            BridgeListPayloadFactory.metadataWithSnapshotFallback(
                loaded: ["current"],
                snapshot: [42],
                mapLoaded: { "loaded:\($0)" },
                mapSnapshot: { "snapshot:\($0)" }
            ),
            ["loaded:current"]
        )
    }

    func testPasswordMetadataForLookupMergesSnapshotMissesWithoutNoteBodies() {
        let snapshotID = UUID()
        let snapshotSource = PasswordMetadata(
            id: snapshotID,
            name: "SERVICE_ACCESS_KEY_ID",
            username: "value",
            website: nil,
            notes: "snapshot must not carry note bodies",
            folderPath: "Authsia",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_001),
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false
        )
        let snapshot = VaultCLIMetadataSnapshot(
            passwords: [snapshotSource],
            certificates: [],
            notes: [],
            sshKeys: [],
            folders: [:]
        )
        let loaded = PasswordMetadata(
            id: UUID(),
            name: "Loaded",
            username: "value",
            website: nil,
            notes: "live metadata",
            createdAt: Date(timeIntervalSince1970: 1_700_000_002),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_003),
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false
        )

        let fallback = BridgeListPayloadFactory.passwordMetadataForLookup(
            loaded: [],
            snapshot: snapshot.passwords
        )
        XCTAssertEqual(fallback.first?.id, snapshotID)
        XCTAssertEqual(fallback.first?.folderPath, "Authsia")
        XCTAssertNil(fallback.first?.notes)

        let merged = BridgeListPayloadFactory.passwordMetadataForLookup(
            loaded: [loaded],
            snapshot: snapshot.passwords
        )
        XCTAssertEqual(merged.map { $0.id }, [loaded.id, snapshotID])
        XCTAssertNil(merged.last?.notes)
    }

    @MainActor
    func testRepositoryPayloadPreservesPasswordAndAPIKeyExpiresAt() {
        let passwordExpiresAt = Date(timeIntervalSince1970: 1_800_000_000)
        let apiKeyExpiresAt = Date(timeIntervalSince1970: 1_800_000_001)
        let repository = StubVaultRepositoryForListPayload(
            passwords: [
                PasswordMetadata(
                    id: UUID(),
                    name: "API_KEY",
                    username: "API_KEY",
                    website: nil,
                    notes: nil,
                    createdAt: Date(timeIntervalSince1970: 1_700_000_000),
                    modifiedAt: Date(timeIntervalSince1970: 1_700_000_001),
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    expiresAt: passwordExpiresAt,
                    environments: ["Production", "Development"]
                ),
            ],
            apiKeys: [
                APIKeyMetadata(
                    id: UUID(),
                    name: "STRIPE_API_KEY",
                    website: nil,
                    notes: nil,
                    createdAt: Date(timeIntervalSince1970: 1_700_000_000),
                    modifiedAt: Date(timeIntervalSince1970: 1_700_000_001),
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    expiresAt: apiKeyExpiresAt
                ),
            ],
            notes: []
        )

        let payload = BridgeListPayloadFactory.repositoryPayload(accounts: [], repository: repository)

        XCTAssertEqual(payload.passwords.first?.expiresAt, passwordExpiresAt)
        XCTAssertEqual(payload.apiKeys.first?.expiresAt, apiKeyExpiresAt)
        XCTAssertEqual(payload.passwords.first?.environments, ["Development", "Production"])
    }

    func testValidationPayloadProbesOnlyFilteredPasswordAndAPIKeyItems() {
        let passwordID = UUID()
        let apiKeyID = UUID()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                BridgePassword(
                    id: passwordID,
                    name: "DB_PASSWORD",
                    username: "user",
                    website: nil,
                    folderPath: "Workspaces/api",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now
                ),
            ],
            apiKeys: [
                BridgeAPIKey(
                    id: apiKeyID,
                    name: "API_KEY",
                    website: nil,
                    folderPath: "Workspaces/api",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now
                ),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )
        var probedPasswordIDs: [UUID] = []
        var probedAPIKeyIDs: [UUID] = []

        let validated = BridgeListPayloadFactory.validationPayload(
            payload,
            passwordHasSecret: {
                probedPasswordIDs.append($0)
                return true
            },
            apiKeyHasSecret: {
                probedAPIKeyIDs.append($0)
                return false
            }
        )

        XCTAssertEqual(probedPasswordIDs, [passwordID])
        XCTAssertEqual(probedAPIKeyIDs, [apiKeyID])
        XCTAssertEqual(validated.passwords.first?.hasSecret, true)
        XCTAssertEqual(validated.apiKeys.first?.hasSecret, false)
    }
}

@MainActor
private final class StubVaultRepositoryForListPayload: VaultRepositoryProviding {
    var passwords: [PasswordMetadata]
    var apiKeys: [APIKeyMetadata]
    var certificates: [CertificateMetadata] = []
    var notes: [SecureNoteMetadata]
    var sshKeys: [SSHKeyMetadata] = []
    var hasLoadedVaultState = false

    init(
        passwords: [PasswordMetadata],
        apiKeys: [APIKeyMetadata] = [],
        notes: [SecureNoteMetadata]
    ) {
        self.passwords = passwords
        self.apiKeys = apiKeys
        self.notes = notes
    }

    func load() throws {}

    func addPassword(_ item: PasswordItem) throws {}
    func updatePassword(_ item: PasswordItem) throws {}
    func deletePassword(id: UUID) throws {}
    func convertPasswordToAPIKey(id: UUID, modifiedAt: Date) throws -> APIKeyItem? { nil }
    func getFullPassword(metadata: PasswordMetadata) throws -> PasswordItem {
        throw NSError(domain: "StubVaultRepositoryForListPayload", code: 1)
    }

    func addAPIKey(_ item: APIKeyItem) throws {}
    func updateAPIKey(_ item: APIKeyItem) throws {}
    func deleteAPIKey(id: UUID) throws {}
    func getFullAPIKey(metadata: APIKeyMetadata) throws -> APIKeyItem {
        throw NSError(domain: "StubVaultRepositoryForListPayload", code: 1)
    }

    func addCertificate(_ item: CertificateItem) throws {}
    func updateCertificate(_ item: CertificateItem) throws {}
    func deleteCertificatePrivateKey(id: UUID) {}
    func deleteCertificate(id: UUID) throws {}
    func getFullCertificate(metadata: CertificateMetadata) throws -> CertificateItem {
        throw NSError(domain: "StubVaultRepositoryForListPayload", code: 1)
    }

    func addNote(_ item: SecureNoteItem) throws {}
    func updateNote(_ item: SecureNoteItem) throws {}
    func deleteNote(id: UUID) throws {}
    func getFullNote(metadata: SecureNoteMetadata) throws -> SecureNoteItem {
        throw NSError(domain: "StubVaultRepositoryForListPayload", code: 1)
    }

    func addSSHKey(_ item: SSHKeyItem) throws {}
    func updateSSHKey(_ item: SSHKeyItem) throws {}
    func deleteSSHKey(id: UUID) throws {}
    func getFullSSHKey(metadata: SSHKeyMetadata) throws -> SSHKeyItem {
        throw NSError(domain: "StubVaultRepositoryForListPayload", code: 1)
    }
    func addFolder(_ path: String, type: VaultItemType) throws {}
}
