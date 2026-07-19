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

    func testLoadAllUnionsCandidatesByID() throws {
        let keychain = FakeMetadataKeychain()
        let store = MetadataStore(fileURL: nil, foldersFileURL: nil, keychain: keychain)
        let localOnly = makeAccountMetadata(id: UUID())
        let syncedOnly = makeAccountMetadata(id: UUID())
        let encoder = JSONEncoder()
        keychain.candidatesByKey["account_metadata"] = [
            try encoder.encode([syncedOnly]),
            try encoder.encode([localOnly]),
        ]

        XCTAssertEqual(Set(try store.loadAll().map(\.id)), [localOnly.id, syncedOnly.id])
    }

    func testLoadAllKeepsRestoredFallbackWhenPreferredCandidateIsTombstoned() throws {
        let keychain = FakeMetadataKeychain()
        let store = MetadataStore(fileURL: nil, foldersFileURL: nil, keychain: keychain)
        let id = UUID()
        let stalePreferred = makeAccountMetadata(
            id: id,
            lastUsed: Date(timeIntervalSince1970: 1_700_000_010)
        )
        let restoredFallback = makeAccountMetadata(
            id: id,
            lastUsed: Date(timeIntervalSince1970: 1_700_000_030)
        )
        let encoder = JSONEncoder()
        keychain.candidatesByKey["account_metadata"] = [
            try encoder.encode([stalePreferred]),
            try encoder.encode([restoredFallback]),
        ]
        keychain.candidatesByKey["account_deletion_tombstones"] = [
            try encoder.encode([
                AccountDeletionTombstone(id: id, deletedAt: Date(timeIntervalSince1970: 1_700_000_020)),
            ]),
        ]

        XCTAssertEqual(try store.loadAll(), [restoredFallback])
    }

    func testLoadAllHealsMissingMetadataTarget() throws {
        let keychain = FakeMetadataKeychain()
        let store = MetadataStore(fileURL: nil, foldersFileURL: nil, keychain: keychain)
        let metadata = makeAccountMetadata()
        keychain.candidatesByKey["account_metadata"] = [try JSONEncoder().encode([metadata])]

        XCTAssertEqual(try store.loadAll(), [metadata])
        XCTAssertTrue(keychain.savedKeys.contains("account_metadata"))
    }

    func testLoadAllSuppressesAccountCoveredByTombstone() throws {
        let keychain = FakeMetadataKeychain()
        let store = MetadataStore(fileURL: nil, foldersFileURL: nil, keychain: keychain)
        let stale = makeAccountMetadata(
            id: UUID(),
            lastUsed: Date(timeIntervalSince1970: 1_700_000_010)
        )
        let current = makeAccountMetadata(
            id: UUID(),
            lastUsed: Date(timeIntervalSince1970: 1_700_000_010)
        )
        let encoder = JSONEncoder()
        keychain.candidatesByKey["account_metadata"] = [
            try encoder.encode([current]),
            try encoder.encode([current, stale]),
        ]
        keychain.candidatesByKey["account_deletion_tombstones"] = [
            try encoder.encode([
                AccountDeletionTombstone(id: stale.id, deletedAt: Date(timeIntervalSince1970: 1_700_000_020)),
            ]),
        ]

        XCTAssertEqual(try store.loadAll().map(\.id), [current.id])
    }

    func testLoadAllKeepsAccountWithLastUsedNewerThanTombstone() throws {
        let keychain = FakeMetadataKeychain()
        let store = MetadataStore(fileURL: nil, foldersFileURL: nil, keychain: keychain)
        let restored = makeAccountMetadata(
            id: UUID(),
            lastUsed: Date(timeIntervalSince1970: 1_700_000_020)
        )
        let encoder = JSONEncoder()
        keychain.candidatesByKey["account_metadata"] = [try encoder.encode([restored])]
        keychain.candidatesByKey["account_deletion_tombstones"] = [
            try encoder.encode([
                AccountDeletionTombstone(id: restored.id, deletedAt: Date(timeIntervalSince1970: 1_700_000_010)),
            ]),
        ]

        XCTAssertEqual(try store.loadAll().map(\.id), [restored.id])
    }

    func testSaveAllDoesNotPersistTombstonedAccountFromStaleCandidate() throws {
        let keychain = FakeMetadataKeychain()
        let store = MetadataStore(fileURL: nil, foldersFileURL: nil, keychain: keychain)
        let deleted = makeAccountMetadata(
            id: UUID(),
            lastUsed: Date(timeIntervalSince1970: 1_700_000_010)
        )
        let encoder = JSONEncoder()
        keychain.candidatesByKey["account_metadata"] = [try encoder.encode([deleted])]
        keychain.candidatesByKey["account_deletion_tombstones"] = [
            try encoder.encode([
                AccountDeletionTombstone(id: deleted.id, deletedAt: Date(timeIntervalSince1970: 1_700_000_020)),
            ]),
        ]

        try store.saveAll([])

        let persisted = try XCTUnwrap(keychain.storage["account_metadata"])
        XCTAssertEqual(try JSONDecoder().decode([AccountMetadata].self, from: persisted), [])
    }

    func testLoadAccountDeletionTombstonesReconcilesDivergentCandidates() throws {
        let keychain = FakeMetadataKeychain()
        let store = MetadataStore(fileURL: nil, foldersFileURL: nil, keychain: keychain)
        let first = AccountDeletionTombstone(id: UUID(), deletedAt: Date(timeIntervalSince1970: 1_800_000_010))
        let second = AccountDeletionTombstone(id: UUID(), deletedAt: Date(timeIntervalSince1970: 1_800_000_020))
        let encoder = JSONEncoder()
        keychain.candidatesByKey["account_deletion_tombstones"] = [
            try encoder.encode([first]),
            try encoder.encode([second]),
        ]

        let loaded = try store.loadAccountDeletionTombstones()

        XCTAssertEqual(Set(loaded.map(\.id)), [first.id, second.id])
        let persisted = try XCTUnwrap(keychain.storage["account_deletion_tombstones"])
        let persistedTombstones = try JSONDecoder().decode([AccountDeletionTombstone].self, from: persisted)
        XCTAssertEqual(Set(persistedTombstones.map(\.id)), [first.id, second.id])
    }

    func testLoadAccountDeletionTombstonesHealsMissingTarget() throws {
        let keychain = FakeMetadataKeychain()
        let store = MetadataStore(fileURL: nil, foldersFileURL: nil, keychain: keychain)
        let tombstone = AccountDeletionTombstone(
            id: UUID(),
            deletedAt: Date(timeIntervalSince1970: 1_800_000_010)
        )
        keychain.candidatesByKey["account_deletion_tombstones"] = [
            try JSONEncoder().encode([tombstone]),
        ]

        XCTAssertEqual(try store.loadAccountDeletionTombstones(), [tombstone])
        XCTAssertTrue(keychain.savedKeys.contains("account_deletion_tombstones"))
    }

    func testLoadAccountDeletionTombstonesDoesNotRewriteMissingReadOnlyFallback() throws {
        let keychain = FakeMetadataKeychain()
        let store = MetadataStore(fileURL: nil, foldersFileURL: nil, keychain: keychain)
        let tombstone = AccountDeletionTombstone(
            id: UUID(),
            deletedAt: Date(timeIntervalSince1970: 1_800_000_010)
        )
        keychain.targetedCandidatesByKey["account_deletion_tombstones"] = [
            false: try JSONEncoder().encode([tombstone]),
        ]

        let loaded = try KeychainSyncSettings.withICloudKeychainSyncEnabled(false) {
            try store.loadAccountDeletionTombstones()
        }

        XCTAssertEqual(loaded, [tombstone])
        XCTAssertFalse(keychain.savedKeys.contains("account_deletion_tombstones"))
    }

    @MainActor
    func testDeleteAccountRecordsTombstoneBeforeRemovingSource() throws {
        let deletedAt = Date(timeIntervalSince1970: 1_800_000_000)
        let metadataKeychain = FakeMetadataKeychain()
        let metadataStore = MetadataStore(fileURL: nil, foldersFileURL: nil, keychain: metadataKeychain)
        let secrets = InMemoryAccountKeychainStore()
        let repository = AccountRepository(keychainStore: secrets, metadataStore: metadataStore)
        let account = Account(
            id: UUID(),
            issuer: "Example",
            label: "Delete me",
            secret: Data("secret".utf8)
        )
        try repository.addAccount(account)

        try repository.deleteAccount(id: account.id, deletedAt: deletedAt)

        XCTAssertEqual(
            try metadataStore.loadAccountDeletionTombstones(),
            [AccountDeletionTombstone(id: account.id, deletedAt: deletedAt)]
        )
        XCTAssertThrowsError(try secrets.retrieve(for: account.id))
        XCTAssertTrue(repository.accounts.isEmpty)
    }

    @MainActor
    func testDeleteAllAccountsRecordsTombstonesForEveryAccount() throws {
        let metadataKeychain = FakeMetadataKeychain()
        let metadataStore = MetadataStore(fileURL: nil, foldersFileURL: nil, keychain: metadataKeychain)
        let secrets = InMemoryAccountKeychainStore()
        let repository = AccountRepository(keychainStore: secrets, metadataStore: metadataStore)
        let first = Account(id: UUID(), issuer: "Example", label: "First", secret: Data("one".utf8))
        let second = Account(id: UUID(), issuer: "Example", label: "Second", secret: Data("two".utf8))
        try repository.addAccount(first)
        try repository.addAccount(second)

        try repository.deleteAllAccounts()

        XCTAssertEqual(
            Set(try metadataStore.loadAccountDeletionTombstones().map(\.id)),
            [first.id, second.id]
        )
        XCTAssertThrowsError(try secrets.retrieve(for: first.id))
        XCTAssertThrowsError(try secrets.retrieve(for: second.id))
        XCTAssertTrue(repository.accounts.isEmpty)
    }

    @MainActor
    func testAccountRepositoryLoadDeletesStaleSecretCoveredByTombstone() throws {
        let id = UUID()
        let metadataKeychain = FakeMetadataKeychain()
        let encoder = JSONEncoder()
        metadataKeychain.storage["account_deletion_tombstones"] = try encoder.encode([
            AccountDeletionTombstone(id: id, deletedAt: Date(timeIntervalSince1970: 1_800_000_000)),
        ])
        let metadataStore = MetadataStore(fileURL: nil, foldersFileURL: nil, keychain: metadataKeychain)
        let secrets = InMemoryAccountKeychainStore()
        try secrets.save(secret: Data("stale".utf8), for: id)
        let repository = AccountRepository(keychainStore: secrets, metadataStore: metadataStore)

        try repository.load()

        XCTAssertThrowsError(try secrets.retrieve(for: id))
    }

    @MainActor
    func testAddAccountRestoresSameIDWithLastUsedNewerThanTombstone() throws {
        let id = UUID()
        let deletedAt = Date(timeIntervalSince1970: 1_800_000_000)
        let metadataKeychain = FakeMetadataKeychain()
        let encoder = JSONEncoder()
        metadataKeychain.storage["account_deletion_tombstones"] = try encoder.encode([
            AccountDeletionTombstone(id: id, deletedAt: deletedAt),
        ])
        let metadataStore = MetadataStore(fileURL: nil, foldersFileURL: nil, keychain: metadataKeychain)
        let repository = AccountRepository(
            keychainStore: InMemoryAccountKeychainStore(),
            metadataStore: metadataStore
        )
        let restored = Account(
            id: id,
            issuer: "Example",
            label: "Restored",
            secret: Data("restored".utf8),
            lastUsed: deletedAt.addingTimeInterval(-60)
        )

        try repository.addAccount(restored)

        let restoredMetadata = try XCTUnwrap(repository.accounts.first(where: { $0.id == id }))
        XCTAssertGreaterThan(restoredMetadata.lastUsed, deletedAt)
    }

    @MainActor
    func testDeleteAccountAfterRestoreRecordsNewerTombstone() throws {
        let id = UUID()
        let firstDeletion = Date(timeIntervalSince1970: 1_900_000_000)
        let metadataKeychain = FakeMetadataKeychain()
        metadataKeychain.storage["account_deletion_tombstones"] = try JSONEncoder().encode([
            AccountDeletionTombstone(id: id, deletedAt: firstDeletion),
        ])
        let metadataStore = MetadataStore(fileURL: nil, foldersFileURL: nil, keychain: metadataKeychain)
        let repository = AccountRepository(
            keychainStore: InMemoryAccountKeychainStore(),
            metadataStore: metadataStore
        )
        let restored = Account(
            id: id,
            issuer: "Example",
            label: "Restored",
            secret: Data("restored".utf8),
            lastUsed: firstDeletion.addingTimeInterval(-60)
        )
        try repository.addAccount(restored)
        let restoredMetadata = try XCTUnwrap(repository.accounts.first(where: { $0.id == id }))

        try repository.deleteAccount(id: id, deletedAt: firstDeletion.addingTimeInterval(0.5))

        let tombstone = try XCTUnwrap(
            metadataStore.loadAccountDeletionTombstones().first(where: { $0.id == id })
        )
        XCTAssertGreaterThan(tombstone.deletedAt, restoredMetadata.lastUsed)
        XCTAssertTrue(try metadataStore.loadAll().isEmpty)
    }

    @MainActor
    func testMutationReloadsStaleCacheBeforeSaving() throws {
        let metadataKeychain = FakeMetadataKeychain()
        let metadataStore = MetadataStore(fileURL: nil, foldersFileURL: nil, keychain: metadataKeychain)
        let secrets = InMemoryAccountKeychainStore()
        let first = AccountRepository(keychainStore: secrets, metadataStore: metadataStore)
        let second = AccountRepository(keychainStore: secrets, metadataStore: metadataStore)
        let doomed = Account(id: UUID(), issuer: "Example", label: "Doomed", secret: Data("x".utf8))
        let keeper = Account(id: UUID(), issuer: "Example", label: "Keeper", secret: Data("y".utf8))
        try first.addAccount(doomed)
        try first.load()
        try second.load()

        try first.deleteAccount(id: doomed.id)
        try second.addAccount(keeper)

        XCTAssertEqual(second.accounts.map(\.id), [keeper.id])
        XCTAssertEqual(try metadataStore.loadAll().map(\.id), [keeper.id])
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

    private func makeAccountMetadata(
        id: UUID = UUID(),
        lastUsed: Date = Date(timeIntervalSince1970: 1_700_000_000)
    ) -> AccountMetadata {
        AccountMetadata(from: Account(
            id: id,
            issuer: "Example",
            label: "user@example.com",
            secret: Data("secret".utf8),
            algorithm: .sha1,
            digits: 6,
            type: .totp,
            lastUsed: lastUsed
        ))
    }
}

final class FakeMetadataKeychain: MetadataKeychainStoring {
    var storage: [String: Data] = [:]
    var candidatesByKey: [String: [Data]] = [:]
    var targetedCandidatesByKey: [String: [Bool: Data]] = [:]
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

    func retrieveCandidates(for key: String) throws -> [KeychainDataCandidate] {
        if let loadError { throw loadError }
        if let candidates = targetedCandidatesByKey[key] {
            return [true, false].map { synchronizable in
                KeychainDataCandidate(
                    synchronizable: synchronizable,
                    data: candidates[synchronizable],
                    isAvailable: true
                )
            }
        }
        if let candidates = candidatesByKey[key] {
            return [
                KeychainDataCandidate(
                    synchronizable: true,
                    data: candidates.first,
                    isAvailable: true
                ),
                KeychainDataCandidate(
                    synchronizable: false,
                    data: candidates.dropFirst().first,
                    isAvailable: true
                ),
            ]
        }
        if let data = storage[key] {
            return [
                KeychainDataCandidate(synchronizable: true, data: data, isAvailable: true),
                KeychainDataCandidate(synchronizable: false, data: data, isAvailable: true),
            ]
        }
        return [
            KeychainDataCandidate(synchronizable: true, data: nil, isAvailable: true),
            KeychainDataCandidate(synchronizable: false, data: nil, isAvailable: true),
        ]
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
