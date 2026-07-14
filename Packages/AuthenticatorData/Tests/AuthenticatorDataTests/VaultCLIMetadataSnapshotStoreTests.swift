import XCTest
@testable import AuthenticatorData

final class VaultCLIMetadataSnapshotStoreTests: XCTestCase {
    func testSaveAndLoadSnapshotRoundTripsVaultMetadata() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = VaultCLIMetadataSnapshotStore(applicationSupportDirectory: tempDir)
        let password = PasswordMetadata(
            id: UUID(),
            name: "Example",
            username: "user",
            website: "https://example.com",
            notes: nil,
            folderPath: "Team/API",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_001),
            isFavorite: true,
            isCliEnabled: true,
            isScraped: false,
            environments: ["Production", "Development"]
        )
        let apiKey = APIKeyMetadata(
            id: UUID(),
            name: "Stripe",
            website: "https://dashboard.stripe.com",
            notes: nil,
            folderPath: "Team/API",
            createdAt: Date(timeIntervalSince1970: 1_700_000_001),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_002),
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
            environments: ["Production"]
        )
        let note = SecureNoteMetadata(
            id: UUID(),
            title: "Note",
            folderPath: "Team",
            createdAt: Date(timeIntervalSince1970: 1_700_000_003),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_004),
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            environments: ["Development"]
        )
        let sshKey = SSHKeyMetadata(
            id: UUID(),
            name: "id_ed25519",
            publicKey: "ssh-ed25519 AAAA",
            comment: "work",
            fingerprint: "SHA256:abc",
            folderPath: nil,
            createdAt: Date(timeIntervalSince1970: 1_700_000_005),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_006),
            isFavorite: false,
            isCliEnabled: true,
            isScraped: true,
            environments: ["Production"]
        )
        let snapshot = VaultCLIMetadataSnapshot(
            savedAt: Date(timeIntervalSince1970: 1_700_000_007),
            passwords: [password],
            apiKeys: [apiKey],
            certificates: [],
            notes: [note],
            sshKeys: [sshKey],
            folders: [.password: ["Team/API"], .apiKey: ["Team/API"]]
        )

        try store.save(snapshot)

        let loaded = try XCTUnwrap(try store.load())
        XCTAssertEqual(loaded, snapshot)
        XCTAssertEqual(loaded.passwords.first?.environments, ["Development", "Production"])
    }

    func testSnapshotFileDoesNotPersistPasswordOrCertificateNotes() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = VaultCLIMetadataSnapshotStore(applicationSupportDirectory: tempDir)
        let passwordNote = "do not write this password note"
        let certificateNote = "do not write this certificate note"
        let apiKeyNote = "do not write this api key note"
        let password = PasswordMetadata(
            id: UUID(),
            name: "Example",
            username: "user",
            website: nil,
            notes: passwordNote,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_001),
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false
        )
        let apiKey = APIKeyMetadata(
            id: UUID(),
            name: "Stripe",
            website: nil,
            notes: apiKeyNote,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_001),
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false
        )
        let certificate = CertificateMetadata(
            id: UUID(),
            name: "Certificate",
            expirationDate: nil,
            issuer: nil,
            subject: nil,
            notes: certificateNote,
            createdAt: Date(timeIntervalSince1970: 1_700_000_002),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_003),
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false
        )
        let snapshot = VaultCLIMetadataSnapshot(
            passwords: [password],
            apiKeys: [apiKey],
            certificates: [certificate],
            notes: [],
            sshKeys: [],
            folders: [:]
        )

        try store.save(snapshot)

        let snapshotData = try Data(contentsOf: snapshotFileURL(in: tempDir))
        let snapshotJSON = try XCTUnwrap(String(data: snapshotData, encoding: .utf8))
        XCTAssertFalse(snapshotJSON.contains(passwordNote))
        XCTAssertFalse(snapshotJSON.contains(certificateNote))
        XCTAssertFalse(snapshotJSON.contains(apiKeyNote))
    }

    func testLoadSnapshotDefaultsMissingAPIKeysForPreAPIKeySnapshots() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let snapshotURL = snapshotFileURL(in: tempDir)
        try FileManager.default.createDirectory(
            at: snapshotURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let legacyJSON = """
        {
          "savedAt": "2026-07-01T00:00:00Z",
          "passwords": [
            {
              "id": "11111111-1111-1111-1111-111111111111",
              "name": "Legacy Password",
              "username": "svc",
              "website": null,
              "folderPath": "Team/API",
              "createdAt": "2026-07-01T00:00:00Z",
              "modifiedAt": "2026-07-01T00:00:01Z",
              "isFavorite": false,
              "isCliEnabled": true,
              "isScraped": false,
              "scrapeMachineName": null,
              "scrapeMachineId": null,
              "expiresAt": null
            }
          ],
          "certificates": [],
          "notes": [],
          "sshKeys": [],
          "folders": {
            "password": ["Team/API"]
          }
        }
        """
        try Data(legacyJSON.utf8).write(to: snapshotURL)
        let store = VaultCLIMetadataSnapshotStore(applicationSupportDirectory: tempDir)

        let snapshot = try XCTUnwrap(try store.load())

        XCTAssertEqual(snapshot.passwords.map(\.name), ["Legacy Password"])
        XCTAssertEqual(snapshot.passwords.first?.environments, [])
        XCTAssertEqual(snapshot.apiKeys, [])
        XCTAssertEqual(snapshot.folders, [.password: ["Team/API"]])
    }

    private func makeTemporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func snapshotFileURL(in applicationSupportDirectory: URL) -> URL {
        applicationSupportDirectory
            .appendingPathComponent("Authsia", isDirectory: true)
            .appendingPathComponent("CLI", isDirectory: true)
            .appendingPathComponent("vault_metadata_snapshot.json")
    }
}
