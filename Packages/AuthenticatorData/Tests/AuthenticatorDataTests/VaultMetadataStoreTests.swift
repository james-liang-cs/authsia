import XCTest
@testable import AuthenticatorData
import AuthenticatorCore

final class VaultMetadataStoreTests: XCTestCase {
    func testLoadSSHKeysThrowsKeychainUnavailableInsteadOfReturningLocalFile() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let fileURL = tempDir.appendingPathComponent("vault_sshkeys_metadata.json")
        try metadataEncoder().encode([makeSSHKeyMetadata()]).write(to: fileURL)

        let keychain = StubVaultMetadataKeychain(loadError: KeychainError.unknown(errSecMissingEntitlement))
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)

        XCTAssertThrowsError(try store.loadSSHKeys()) { error in
            guard case MetadataLoadError.keychainUnavailable = error else {
                XCTFail("expected MetadataLoadError.keychainUnavailable, got \(error)")
                return
            }
        }
    }

    func testLoadPasswordsReturnsEmptyOnMissingKeychainItemEvenWhenFileExists() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let fileURL = tempDir.appendingPathComponent("vault_passwords_metadata.json")
        try metadataEncoder().encode([makePasswordMetadata()]).write(to: fileURL)

        let keychain = StubVaultMetadataKeychain()
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)

        let result = try store.loadPasswords()

        XCTAssertEqual(result, [])
    }

    func testSaveSSHKeysOnlyWritesKeychain() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let keychain = StubVaultMetadataKeychain()
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)

        try store.saveSSHKeys([makeSSHKeyMetadata()])

        XCTAssertEqual(keychain.savedKeys, ["vault_sshkeys_metadata"])
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: tempDir.appendingPathComponent("vault_sshkeys_metadata.json").path
        ))
    }

    func testSaveNotesThrowsWhenKeychainSaveFailsAndDoesNotWriteFile() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let keychain = StubVaultMetadataKeychain(saveError: KeychainError.unknown(errSecMissingEntitlement))
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)

        XCTAssertThrowsError(try store.saveNotes([makeNoteMetadata()]))
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: tempDir.appendingPathComponent("vault_notes_metadata.json").path
        ))
    }

    func testSaveFoldersThrowsWhenKeychainSaveFailsAndDoesNotWriteFile() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let keychain = StubVaultMetadataKeychain(saveError: KeychainError.unknown(errSecMissingEntitlement))
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)

        XCTAssertThrowsError(try store.saveFolders([.secureNote: ["Notesia"]]))
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: tempDir.appendingPathComponent("vault_folders.json").path
        ))
    }

    func testSaveAndLoadPreservesPasswordExpiresAt() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let keychain = StubVaultMetadataKeychain()
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)
        let passwordExpiresAt = Date(timeIntervalSince1970: 1_800_000_000)

        try store.savePasswords([makePasswordMetadata(expiresAt: passwordExpiresAt)])

        XCTAssertEqual(try store.loadPasswords().first?.expiresAt, passwordExpiresAt)
    }

    func testSaveAndLoadPreservesPasswordEnvironments() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let keychain = StubVaultMetadataKeychain()
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)

        try store.savePasswords([makePasswordMetadata(environments: ["Production", "Development"])])

        XCTAssertEqual(try store.loadPasswords().first?.environments, ["Development", "Production"])
    }

    func testSavePasswordsMergesWithExistingKeychainMetadataByMostRecentModifiedAt() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let keychain = StubVaultMetadataKeychain()
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)
        let sharedID = UUID()
        let staleExisting = makePasswordMetadata(
            id: sharedID,
            name: "DB_PASSWORD",
            folderPath: "Workspaces/api",
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_001)
        )
        let newerIncoming = makePasswordMetadata(
            id: sharedID,
            name: "DB_PASSWORD",
            folderPath: "Workspaces/web",
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_010)
        )
        let addedElsewhere = makePasswordMetadata(
            id: UUID(),
            name: "WORKSPACE_PASSWORD",
            folderPath: "Workspaces/tmp.xrTsbkl8Ir",
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_020)
        )
        try keychain.seed([staleExisting, addedElsewhere], key: "vault_passwords_metadata")

        try store.savePasswords([newerIncoming])

        let loaded = try store.loadPasswords()
        XCTAssertEqual(Set(loaded.map(\.id)), [sharedID, addedElsewhere.id])
        XCTAssertEqual(loaded.first(where: { $0.id == sharedID })?.folderPath, "Workspaces/web")
        XCTAssertEqual(
            loaded.first(where: { $0.id == addedElsewhere.id })?.folderPath,
            "Workspaces/tmp.xrTsbkl8Ir"
        )
    }

    func testLoadPasswordsMergesStaleSyncAndFreshLocalCandidates() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let keychain = StubVaultMetadataKeychain()
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)
        let oldPassword = makePasswordMetadata(
            name: "OLD_PASSWORD",
            folderPath: "Personal",
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_010)
        )
        let workspacePassword = makePasswordMetadata(
            name: "DB_PASSWORD",
            folderPath: "Workspaces/tmp.A3KrQpuSuG",
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_020)
        )
        try keychain.seedCandidates(
            [
                [oldPassword],
                [oldPassword, workspacePassword],
            ],
            key: "vault_passwords_metadata"
        )

        let loaded = try store.loadPasswords()

        XCTAssertEqual(Set(loaded.map(\.id)), [oldPassword.id, workspacePassword.id])
        XCTAssertEqual(loaded.first(where: { $0.id == workspacePassword.id })?.folderPath, "Workspaces/tmp.A3KrQpuSuG")
    }

    func testLoadPasswordsSuppressesStaleCandidateCoveredBySyncedTombstone() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let keychain = StubVaultMetadataKeychain()
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)
        let password = makePasswordMetadata(
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_010)
        )
        let tombstone = PasswordDeletionTombstone(
            id: password.id,
            deletedAt: Date(timeIntervalSince1970: 1_700_000_020)
        )
        let passwordCandidates: [[PasswordMetadata]] = [[], [password]]
        let tombstoneCandidates: [[PasswordDeletionTombstone]] = [[tombstone], []]
        try keychain.seedCandidates(passwordCandidates, key: "vault_passwords_metadata")
        try keychain.seedCandidates(tombstoneCandidates, key: "vault_password_deletion_tombstones")

        XCTAssertEqual(try store.loadPasswords(), [])
    }

    func testLoadPasswordsKeepsMetadataNewerThanTombstone() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let keychain = StubVaultMetadataKeychain()
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)
        let password = makePasswordMetadata(
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_020)
        )
        let tombstone = PasswordDeletionTombstone(
            id: password.id,
            deletedAt: Date(timeIntervalSince1970: 1_700_000_010)
        )
        let passwordCandidates: [[PasswordMetadata]] = [[], [password]]
        let tombstoneCandidates: [[PasswordDeletionTombstone]] = [[tombstone], []]
        try keychain.seedCandidates(passwordCandidates, key: "vault_passwords_metadata")
        try keychain.seedCandidates(tombstoneCandidates, key: "vault_password_deletion_tombstones")

        XCTAssertEqual(try store.loadPasswords().map(\.id), [password.id])
    }

    func testLoadAPIKeysSuppressesStaleCandidateCoveredBySyncedTombstone() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let keychain = StubVaultMetadataKeychain()
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)
        let apiKey = makeAPIKeyMetadata(modifiedAt: Date(timeIntervalSince1970: 1_700_000_010))
        let tombstone = APIKeyDeletionTombstone(
            id: apiKey.id,
            deletedAt: Date(timeIntervalSince1970: 1_700_000_020)
        )
        let metadataCandidates: [[APIKeyMetadata]] = [[], [apiKey]]
        let tombstoneCandidates: [[APIKeyDeletionTombstone]] = [[tombstone], []]
        try keychain.seedCandidates(metadataCandidates, key: "vault_api_keys_metadata")
        try keychain.seedCandidates(tombstoneCandidates, key: "vault_api_key_deletion_tombstones")

        XCTAssertEqual(try store.loadAPIKeys(), [])
    }

    func testLoadAPIKeysKeepsMetadataNewerThanTombstone() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let keychain = StubVaultMetadataKeychain()
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)
        let apiKey = makeAPIKeyMetadata(modifiedAt: Date(timeIntervalSince1970: 1_700_000_020))
        let tombstone = APIKeyDeletionTombstone(
            id: apiKey.id,
            deletedAt: Date(timeIntervalSince1970: 1_700_000_010)
        )
        let metadataCandidates: [[APIKeyMetadata]] = [[], [apiKey]]
        let tombstoneCandidates: [[APIKeyDeletionTombstone]] = [[tombstone], []]
        try keychain.seedCandidates(metadataCandidates, key: "vault_api_keys_metadata")
        try keychain.seedCandidates(tombstoneCandidates, key: "vault_api_key_deletion_tombstones")

        XCTAssertEqual(try store.loadAPIKeys().map(\.id), [apiKey.id])
    }

    func testLoadFoldersMergesStaleSyncAndFreshLocalCandidates() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let keychain = StubVaultMetadataKeychain()
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)
        try keychain.seedCandidates(
            [
                ["password": ["Personal"]],
                ["password": ["Personal", "Workspaces/tmp.A3KrQpuSuG"]],
            ],
            key: "vault_folders"
        )

        let folders = try store.loadFolders()

        XCTAssertEqual(Set(folders[.password] ?? []), ["Personal", "Workspaces/tmp.A3KrQpuSuG"])
    }

    func testLoadFoldersSuppressesDeletedTypedPathAndDescendants() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let keychain = StubVaultMetadataKeychain()
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)
        let folderCandidates: [[String: [String]]] = [
            ["apiKey": ["AMI/CFT", "AMI/CFT/Nested"]],
            [:],
        ]
        let stateCandidates: [[VaultFolderState]] = [[
            VaultFolderState(
                type: .apiKey,
                path: "AMI/CFT",
                modifiedAt: Date(timeIntervalSince1970: 1_700_000_020),
                isDeleted: true
            ),
        ], []]
        try keychain.seedCandidates(folderCandidates, key: "vault_folders")
        try keychain.seedCandidates(stateCandidates, key: "vault_folder_states")

        XCTAssertNil(try store.loadFolders()[.apiKey])
    }

    func testLoadFoldersScopesDeletionByVaultType() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let keychain = StubVaultMetadataKeychain()
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)
        let folderCandidates: [[String: [String]]] = [[
            "apiKey": ["AMI/CFT"],
            "password": ["AMI/CFT"],
        ]]
        let stateCandidates: [[VaultFolderState]] = [[
            VaultFolderState(
                type: .apiKey,
                path: "AMI/CFT",
                modifiedAt: Date(timeIntervalSince1970: 1_700_000_020),
                isDeleted: true
            ),
        ]]
        try keychain.seedCandidates(folderCandidates, key: "vault_folders")
        try keychain.seedCandidates(stateCandidates, key: "vault_folder_states")

        let folders = try store.loadFolders()

        XCTAssertNil(folders[.apiKey])
        XCTAssertEqual(folders[.password], ["AMI/CFT"])
    }

    func testLoadFoldersKeepsPathRecreatedAfterDeletion() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let keychain = StubVaultMetadataKeychain()
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)
        let deleted = VaultFolderState(
            type: .apiKey,
            path: "AMI/CFT",
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_020),
            isDeleted: true
        )
        let recreated = VaultFolderState(
            type: .apiKey,
            path: "AMI/CFT",
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_030),
            isDeleted: false
        )
        let folderCandidates: [[String: [String]]] = [["apiKey": ["AMI/CFT"]]]
        let stateCandidates: [[VaultFolderState]] = [[deleted], [recreated]]
        try keychain.seedCandidates(folderCandidates, key: "vault_folders")
        try keychain.seedCandidates(stateCandidates, key: "vault_folder_states")

        XCTAssertEqual(try store.loadFolders()[.apiKey], ["AMI/CFT"])
    }

    func testSaveFoldersMergesWithExistingKeychainFolders() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let keychain = StubVaultMetadataKeychain()
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)
        try keychain.seed(["password": ["Workspaces/tmp.xrTsbkl8Ir"]], key: "vault_folders")

        try store.saveFolders([.password: ["Personal"], .secureNote: ["Notes"]])

        let folders = try store.loadFolders()
        XCTAssertEqual(Set(folders[.password] ?? []), ["Personal", "Workspaces/tmp.xrTsbkl8Ir"])
        XCTAssertEqual(folders[.secureNote], ["Notes"])
    }

    func testReplacePasswordsAndFoldersAllowIntentionalRemoval() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let keychain = StubVaultMetadataKeychain()
        let store = VaultMetadataStore(documentsDirectory: tempDir, keychain: keychain)
        let oldPassword = makePasswordMetadata(
            name: "OLD_PASSWORD",
            folderPath: "Workspaces/old",
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_010)
        )
        try keychain.seed([oldPassword], key: "vault_passwords_metadata")
        try keychain.seed(["password": ["Workspaces/old"]], key: "vault_folders")

        try store.replacePasswords([])
        try store.replaceFolders([:])

        XCTAssertEqual(try store.loadPasswords(), [])
        XCTAssertEqual(try store.loadFolders(), [:])
    }

    private func makeTemporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func metadataEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    private func makePasswordMetadata(
        id: UUID = UUID(),
        name: String = "Example",
        folderPath: String? = nil,
        modifiedAt: Date = Date(timeIntervalSince1970: 1_700_000_001),
        expiresAt: Date? = nil,
        environments: [String] = []
    ) -> PasswordMetadata {
        PasswordMetadata(
            id: id,
            name: name,
            username: "user",
            website: nil,
            notes: nil,
            folderPath: folderPath,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: modifiedAt,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            expiresAt: expiresAt,
            environments: environments
        )
    }

    private func makeNoteMetadata() -> SecureNoteMetadata {
        SecureNoteMetadata(
            id: UUID(),
            title: "Scraped Note",
            folderPath: "Notesia",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_001),
            isFavorite: false,
            isCliEnabled: true,
            isScraped: true
        )
    }

    private func makeAPIKeyMetadata(
        id: UUID = UUID(),
        modifiedAt: Date
    ) -> APIKeyMetadata {
        APIKeyMetadata(
            id: id,
            name: "Example",
            website: nil,
            notes: nil,
            folderPath: nil,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: modifiedAt,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            environments: []
        )
    }

    private func makeSSHKeyMetadata() -> SSHKeyMetadata {
        SSHKeyMetadata(
            id: UUID(),
            name: "Work",
            publicKey: "ssh-ed25519 AAAA",
            comment: "laptop",
            fingerprint: "SHA256:abc",
            folderPath: nil,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_001),
            isFavorite: false,
            isCliEnabled: true,
            isScraped: true
        )
    }
}

private final class StubVaultMetadataKeychain: VaultMetadataKeychainStoring, @unchecked Sendable {
    var stored: [String: Data] = [:]
    var storedCandidates: [String: [Data]] = [:]
    var savedKeys: [String] = []
    var loadError: Error?
    var saveError: Error?

    init(loadError: Error? = nil, saveError: Error? = nil) {
        self.loadError = loadError
        self.saveError = saveError
    }

    func seed<T: Encodable>(_ value: T, key: String) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        stored[key] = try encoder.encode(value)
    }

    func seedCandidates<T: Encodable>(_ values: [T], key: String) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        storedCandidates[key] = try values.map { try encoder.encode($0) }
        stored[key] = storedCandidates[key]?.first
    }

    func save(data: Data, key: String) throws {
        if let saveError { throw saveError }
        savedKeys.append(key)
        stored[key] = data
    }

    func load(key: String) throws -> Data? {
        if let loadError { throw loadError }
        return stored[key]
    }

    func loadCandidates(key: String) throws -> [Data] {
        if let loadError { throw loadError }
        return storedCandidates[key] ?? stored[key].map { [$0] } ?? []
    }
}
