import XCTest
@testable import AuthenticatorData
import AuthenticatorCore

final class MetadataLoadErrorTests: XCTestCase {
    func testKeychainUnavailableHasActionableDescription() {
        let error = MetadataLoadError.keychainUnavailable(errSecMissingEntitlement)

        XCTAssertEqual(
            error.localizedDescription,
            "Authsia could not read the keychain on this Mac. Open the Authsia app once and grant keychain access when prompted, or ask your administrator to allow team identifier 33M8QU65SP under managed keychain access."
        )
    }
}

final class AccountRepositoryTests: XCTestCase {

    
    @MainActor
    func testSaveAndRetrieve() async throws {
        let repository = makeInMemoryAccountRepository()
        let accountID = UUID()
        let secret = Data("1234567890".utf8)
        
        let account = Account(
            id: accountID,
            issuer: "TestIssuer",
            label: "TestLabel",
            secret: secret,
            algorithm: .sha1,
            digits: 6,
            type: .totp
        )
        
        try repository.addAccount(account)
        try repository.load()

        let metadata = try XCTUnwrap(repository.accounts.first(where: { $0.id == accountID }))
        XCTAssertEqual(metadata.issuer, "TestIssuer")

        let fullAccount = try repository.getFullAccount(metadata: metadata)
        XCTAssertEqual(fullAccount.secret, secret)

        try repository.deleteAccount(id: accountID)
    }

    func testMetadataDecodesScrapedDefaultFalse() throws {
        let json = """
        {"id":"00000000-0000-0000-0000-000000000000","name":"Example","username":"user","createdAt":"2024-01-01T00:00:00Z","modifiedAt":"2024-01-01T00:00:00Z"}
        """.data(using: .utf8)!
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(PasswordMetadata.self, from: json)
        XCTAssertEqual(decoded.isScraped, false)
    }

    func testMetadataRoundTripsFolderPath() throws {
        let now = Date()
        let metadata = PasswordMetadata(
            id: UUID(),
            name: "Example",
            username: "user",
            website: nil,
            notes: nil,
            folderPath: "Engineering/Prod",
            createdAt: now,
            modifiedAt: now,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: true
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(metadata)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(PasswordMetadata.self, from: data)

        XCTAssertEqual(decoded.folderPath, "Engineering/Prod")
        let item = decoded.toPasswordItem(password: Data("secret".utf8))
        XCTAssertEqual(item.folderPath, "Engineering/Prod")
    }

    func testMetadataRoundTripsScrapeMachine() throws {
        let now = Date()
        let metadata = PasswordMetadata(
            id: UUID(),
            name: "Example",
            username: "user",
            website: nil,
            notes: nil,
            folderPath: "Engineering/Prod",
            createdAt: now,
            modifiedAt: now,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: true,
            scrapeMachineName: "jamess-mac-mini",
            scrapeMachineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(metadata)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(PasswordMetadata.self, from: data)

        XCTAssertEqual(decoded.scrapeMachineName, "jamess-mac-mini")
        XCTAssertEqual(decoded.scrapeMachineId, "73C4AEA4-EB11-4AD7-AC14-DA296C404846")

        let item = decoded.toPasswordItem(password: Data("secret".utf8))
        XCTAssertEqual(item.scrapeMachineName, "jamess-mac-mini")
        XCTAssertEqual(item.scrapeMachineId, "73C4AEA4-EB11-4AD7-AC14-DA296C404846")
    }

    func testMetadataStoreLoadAllThrowsKeychainUnavailableInsteadOfReturningLocalFile() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let fileURL = directory.appendingPathComponent("accounts_metadata.json")
        let foldersFileURL = directory.appendingPathComponent("accounts_folders.json")
        let encoder = JSONEncoder()
        try encoder.encode([makeAccountMetadata()]).write(to: fileURL)

        let keychain = FakeMetadataKeychain(loadError: KeychainError.unknown(errSecMissingEntitlement))
        let store = MetadataStore(fileURL: fileURL, foldersFileURL: foldersFileURL, keychain: keychain)

        XCTAssertThrowsError(try store.loadAll()) { error in
            guard case MetadataLoadError.keychainUnavailable = error else {
                XCTFail("expected MetadataLoadError.keychainUnavailable, got \(error)")
                return
            }
        }
    }

    func testMetadataStoreLoadAllReturnsEmptyWhenKeychainItemIsMissing() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let fileURL = directory.appendingPathComponent("accounts_metadata.json")
        let foldersFileURL = directory.appendingPathComponent("accounts_folders.json")
        let encoder = JSONEncoder()
        try encoder.encode([makeAccountMetadata()]).write(to: fileURL)

        let keychain = FakeMetadataKeychain()
        let store = MetadataStore(fileURL: fileURL, foldersFileURL: foldersFileURL, keychain: keychain)

        let loaded = try store.loadAll()

        XCTAssertEqual(loaded, [])
        XCTAssertNil(keychain.storage["account_metadata"])
    }

    func testMetadataStoreSaveAllOnlyWritesKeychain() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let fileURL = directory.appendingPathComponent("accounts_metadata.json")
        let foldersFileURL = directory.appendingPathComponent("accounts_folders.json")
        let keychain = FakeMetadataKeychain()
        let store = MetadataStore(fileURL: fileURL, foldersFileURL: foldersFileURL, keychain: keychain)
        let metadata = [makeAccountMetadata()]

        try store.saveAll(metadata)

        XCTAssertEqual(keychain.savedKeys, ["account_metadata"])
        XCTAssertEqual(keychain.saveCount, 1)
        XCTAssertFalse(FileManager.default.fileExists(atPath: fileURL.path))
    }

    func testMetadataStoreLoadFoldersThrowsKeychainUnavailableInsteadOfReturningLocalFile() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let fileURL = directory.appendingPathComponent("accounts_metadata.json")
        let foldersFileURL = directory.appendingPathComponent("accounts_folders.json")
        let encoder = JSONEncoder()
        try encoder.encode(["Personal"]).write(to: foldersFileURL)

        let keychain = FakeMetadataKeychain(loadError: KeychainError.unknown(errSecMissingEntitlement))
        let store = MetadataStore(fileURL: fileURL, foldersFileURL: foldersFileURL, keychain: keychain)

        XCTAssertThrowsError(try store.loadFolders()) { error in
            guard case MetadataLoadError.keychainUnavailable = error else {
                XCTFail("expected MetadataLoadError.keychainUnavailable, got \(error)")
                return
            }
        }
    }

    func testMetadataStoreSaveFoldersOnlyWritesKeychain() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let fileURL = directory.appendingPathComponent("accounts_metadata.json")
        let foldersFileURL = directory.appendingPathComponent("accounts_folders.json")
        let keychain = FakeMetadataKeychain()
        let store = MetadataStore(fileURL: fileURL, foldersFileURL: foldersFileURL, keychain: keychain)

        try store.saveFolders(["Personal"])

        XCTAssertEqual(keychain.savedKeys, ["account_folders"])
        XCTAssertEqual(keychain.saveCount, 1)
        XCTAssertFalse(FileManager.default.fileExists(atPath: foldersFileURL.path))
    }

    @MainActor
    func testVaultRepositoryAddsAndLoadsSSHKey() throws {
        let repo = makeInMemoryVaultRepository()
        let createdAt = Date(timeIntervalSince1970: 1_700_000_000)
        let modifiedAt = Date(timeIntervalSince1970: 1_700_000_001)
        let item = SSHKeyItem(
            name: "Work",
            publicKey: Data("ssh-ed25519 AAAA".utf8),
            privateKey: Data("-----BEGIN OPENSSH PRIVATE KEY-----".utf8),
            comment: "laptop",
            fingerprint: "SHA256:abc",
            createdAt: createdAt,
            modifiedAt: modifiedAt,
            isScraped: true
        )
        try repo.addSSHKey(item)
        try repo.load()
        let metadata = try XCTUnwrap(repo.sshKeys.first(where: { $0.id == item.id }))
        let full = try repo.getFullSSHKey(metadata: metadata)
        XCTAssertEqual(full, item)
        try repo.deleteSSHKey(id: item.id)
    }

    private func makeTemporaryDirectory() throws -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func makeAccountMetadata(id: UUID = UUID()) -> AccountMetadata {
        AccountMetadata(from: Account(
            id: id,
            issuer: "Example",
            label: "user@example.com",
            secret: Data("secret".utf8),
            algorithm: .sha1,
            digits: 6,
            type: .totp
        ))
    }
}

final class FakeMetadataKeychain: MetadataKeychainStoring {
    var storage: [String: Data] = [:]
    var savedKeys: [String] = []
    var saveCount = 0
    var loadError: Error?

    init(loadError: Error? = nil) {
        self.loadError = loadError
    }

    func save(data: Data, for key: String) throws {
        savedKeys.append(key)
        saveCount += 1
        storage[key] = data
    }

    func retrieve(for key: String) throws -> Data {
        if let loadError { throw loadError }
        guard let data = storage[key] else {
            throw KeychainError.itemNotFound
        }
        return data
    }
}

@MainActor
func makeInMemoryAccountRepository() -> AccountRepository {
    let metadataStore = MetadataStore(
        fileURL: nil,
        foldersFileURL: nil,
        keychain: FakeMetadataKeychain()
    )
    return AccountRepository(
        keychainStore: InMemoryAccountKeychainStore(),
        metadataStore: metadataStore
    )
}

private final class InMemoryAccountKeychainStore: AccountKeychainStoring {
    private var secrets: [UUID: Data] = [:]

    func save(secret: Data, for accountID: UUID) throws {
        secrets[accountID] = secret
    }

    func retrieve(for accountID: UUID) throws -> Data {
        guard let secret = secrets[accountID] else { throw KeychainError.itemNotFound }
        return secret
    }

    func delete(for accountID: UUID) throws {
        secrets[accountID] = nil
    }
}
