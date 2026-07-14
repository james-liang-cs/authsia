import XCTest
@testable import AuthenticatorData
import AuthenticatorCore

@MainActor
final class RepositorySavePathSyncPolicyTests: XCTestCase {
    func testOTPSaveAndUpdateUseLocalOnlyTargetsWhenSyncDisabled() throws {
        try assertOTPSavePath(syncEnabled: false, expectedTargets: [false])
    }

    func testOTPSaveAndUpdateUseDualTargetsWhenSyncEnabled() throws {
        try assertOTPSavePath(syncEnabled: true, expectedTargets: [true, false])
    }

    func testVaultSaveAndUpdateUseLocalOnlyTargetsWhenSyncDisabled() throws {
        try assertVaultSavePath(syncEnabled: false, expectedTargets: [false])
    }

    func testVaultSaveAndUpdateUseDualTargetsWhenSyncEnabled() throws {
        try assertVaultSavePath(syncEnabled: true, expectedTargets: [true, false])
    }

    func testSyncEnableSnapshotCopiesCurrentItemsWithoutDeleting() throws {
        let expectedTargets = [true, false]
        let account = makeAccount(id: UUID(), secret: Data("otp-secret".utf8), label: "Snapshot")
        let accountKeychain = RecordingAccountKeychainStore(writeTargets: expectedTargets)
        accountKeychain.savedSecrets.append((account.id, account.secret, []))
        let accountMetadataKeychain = RecordingMetadataKeychainStore(writeTargets: expectedTargets)
        accountMetadataKeychain.dataByKey["account_metadata"] = try JSONEncoder().encode([AccountMetadata(from: account)])
        accountMetadataKeychain.dataByKey["account_folders"] = try JSONEncoder().encode(["Team/Auth"])
        let accountMetadataStore = MetadataStore(
            fileURL: nil,
            foldersFileURL: nil,
            keychain: accountMetadataKeychain
        )
        let accountRepository = AccountRepository(
            keychainStore: accountKeychain,
            metadataStore: accountMetadataStore
        )

        let password = makePassword(name: "Password", password: Data("pw".utf8))
        let certificate = makeCertificate(name: "Certificate", certificateData: Data("cert".utf8))
        let note = makeNote(title: "Note", content: Data("note".utf8))
        let sshKey = makeSSHKey(name: "SSH", privateKey: Data("priv".utf8))
        let vaultKeychain = RecordingVaultKeychainStore(writeTargets: expectedTargets)
        vaultKeychain.passwords[password.id] = password.password
        vaultKeychain.certificates[certificate.id] = (certificate.certificateData, certificate.privateKeyData)
        vaultKeychain.notes[note.id] = note.content
        vaultKeychain.sshKeys[sshKey.id] = (sshKey.publicKey, sshKey.privateKey)
        let vaultMetadataStore = RecordingVaultMetadataStore(writeTargets: expectedTargets)
        vaultMetadataStore.passwords = [PasswordMetadata(from: password)]
        vaultMetadataStore.certificates = [CertificateMetadata(from: certificate)]
        vaultMetadataStore.notes = [SecureNoteMetadata(from: note)]
        vaultMetadataStore.sshKeys = [SSHKeyMetadata(from: sshKey)]
        vaultMetadataStore.folders = [
            .password: ["Team/Vault"],
            .certificate: ["Team/Certs"],
            .secureNote: ["Team/Notes"],
            .sshKey: ["Team/SSH"],
        ]
        let vaultRepository = VaultRepository(keychainStore: vaultKeychain, metadataStore: vaultMetadataStore)

        let accounts = try accountRepository.collectFullAccountsForCurrentStoragePolicy()
        let vaultSnapshot = try vaultRepository.collectFullItemsForCurrentStoragePolicy()

        accountKeychain.savedSecrets.removeAll()
        accountMetadataKeychain.savedItems.removeAll()
        vaultKeychain.passwordSaveTargets.removeAll()
        vaultKeychain.certificateSaveTargets.removeAll()
        vaultKeychain.noteSaveTargets.removeAll()
        vaultKeychain.sshSaveTargets.removeAll()
        vaultMetadataStore.passwordSaveTargets.removeAll()
        vaultMetadataStore.certificateSaveTargets.removeAll()
        vaultMetadataStore.noteSaveTargets.removeAll()
        vaultMetadataStore.sshSaveTargets.removeAll()

        try accountRepository.saveFullAccountsToCurrentStoragePolicy(accounts)
        try vaultRepository.saveFullItemsToCurrentStoragePolicy(vaultSnapshot)

        XCTAssertEqual(accountKeychain.savedSecrets.map(\.targets), [expectedTargets])
        XCTAssertTrue(accountKeychain.deletedIDs.isEmpty)
        XCTAssertEqual(vaultKeychain.passwordSaveTargets, [expectedTargets])
        XCTAssertEqual(vaultKeychain.certificateSaveTargets, [expectedTargets])
        XCTAssertEqual(vaultKeychain.noteSaveTargets, [expectedTargets])
        XCTAssertEqual(vaultKeychain.sshSaveTargets, [expectedTargets])
        XCTAssertTrue(vaultKeychain.passwordDeleteIDs.isEmpty)
        XCTAssertTrue(vaultKeychain.certificateDeleteIDs.isEmpty)
        XCTAssertTrue(vaultKeychain.noteDeleteIDs.isEmpty)
        XCTAssertTrue(vaultKeychain.sshDeleteIDs.isEmpty)
    }

    func testSyncEnableSnapshotDoesNotReintroducePrunedPasswordMetadata() throws {
        let existing = makePassword(name: "Existing", password: Data("pw".utf8))
        let missing = makePassword(name: "Missing", password: Data("missing".utf8))
        let keychain = RecordingVaultKeychainStore(writeTargets: [true, false])
        keychain.passwords[existing.id] = existing.password
        let metadataKeychain = RecordingVaultMetadataKeychain()
        let metadataStore = VaultMetadataStore(
            documentsDirectory: URL(fileURLWithPath: NSTemporaryDirectory()),
            keychain: metadataKeychain
        )
        try metadataKeychain.seed(
            local: [PasswordMetadata(from: existing)],
            synchronizable: [PasswordMetadata(from: existing), PasswordMetadata(from: missing)],
            key: "vault_passwords_metadata"
        )
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)

        let snapshot = try repository.collectFullItemsForCurrentStoragePolicy()
        try KeychainSyncSettings.withICloudKeychainSyncEnabled(true) {
            try repository.saveFullItemsToCurrentStoragePolicy(snapshot)
        }

        let savedPasswords = try metadataKeychain.decodeSavedPasswords()
        XCTAssertEqual(savedPasswords.map(\.id), [existing.id])
    }

    func testSyncEnableSnapshotDoesNotReintroduceTombstonedAPIKey() throws {
        let createdAt = Date(timeIntervalSince1970: 1_700_000_000)
        let apiKey = APIKeyItem(
            name: "Deleted",
            key: Data("fixture".utf8),
            createdAt: createdAt,
            modifiedAt: createdAt
        )
        let keychain = RecordingVaultKeychainStore(writeTargets: [true, false])
        let metadataStore = RecordingVaultMetadataStore(writeTargets: [true, false])
        metadataStore.apiKeyDeletionTombstones = [
            APIKeyDeletionTombstone(
                id: apiKey.id,
                deletedAt: createdAt.addingTimeInterval(10)
            ),
        ]
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)
        let snapshot = VaultFullItemSnapshot(
            passwords: [],
            apiKeys: [apiKey],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        try repository.saveFullItemsToCurrentStoragePolicy(snapshot)

        XCTAssertTrue(metadataStore.apiKeys.isEmpty)
        XCTAssertNil(keychain.apiKeys[apiKey.id])
    }

    func testSyncEnablePersistsAPIKeyAndFolderDeletionIntentToCurrentPolicy() throws {
        let deletedAt = Date(timeIntervalSince1970: 1_700_000_010)
        let metadataStore = RecordingVaultMetadataStore(writeTargets: [true, false])
        metadataStore.apiKeyDeletionTombstones = [
            APIKeyDeletionTombstone(id: UUID(), deletedAt: deletedAt),
        ]
        metadataStore.folderStates = [
            VaultFolderState(
                type: .apiKey,
                path: "AMI/CFT",
                modifiedAt: deletedAt,
                isDeleted: true
            ),
        ]
        let repository = VaultRepository(
            keychainStore: RecordingVaultKeychainStore(writeTargets: [true, false]),
            metadataStore: metadataStore
        )
        let snapshot = VaultFullItemSnapshot(
            passwords: [],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        try repository.saveFullItemsToCurrentStoragePolicy(snapshot)

        XCTAssertEqual(metadataStore.apiKeyTombstoneSaveTargets, [[true, false]])
        XCTAssertEqual(metadataStore.folderStateSaveTargets, [[true, false]])
    }

    func testSyncEnableSnapshotPreservesPasswordAddedAfterCollect() throws {
        let existing = makePassword(name: "Existing", password: Data("pw".utf8))
        let added = makePassword(name: "Added", password: Data("added".utf8))
        let keychain = RecordingVaultKeychainStore(writeTargets: [true, false])
        keychain.passwords[existing.id] = existing.password
        let metadataStore = RecordingVaultMetadataStore(writeTargets: [true, false])
        metadataStore.passwords = [PasswordMetadata(from: existing)]
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)

        let snapshot = try repository.collectFullItemsForCurrentStoragePolicy()
        keychain.passwords[added.id] = added.password
        metadataStore.passwords = [PasswordMetadata(from: existing), PasswordMetadata(from: added)]
        try KeychainSyncSettings.withICloudKeychainSyncEnabled(true) {
            try repository.saveFullItemsToCurrentStoragePolicy(snapshot)
        }

        XCTAssertEqual(Set(metadataStore.passwords.map(\.id)), [existing.id, added.id])
    }

    func testSyncEnableSnapshotPreservesPasswordEditedAfterCollect() throws {
        let id = UUID()
        let createdAt = Date(timeIntervalSince1970: 1_700_000_000)
        let existing = PasswordItem(
            id: id,
            name: "Original",
            username: "user",
            password: Data("old".utf8),
            folderPath: "Team/Vault",
            createdAt: createdAt,
            modifiedAt: createdAt
        )
        let edited = PasswordItem(
            id: id,
            name: "Edited",
            username: "user",
            password: Data("new".utf8),
            folderPath: "Team/Vault",
            createdAt: createdAt,
            modifiedAt: createdAt.addingTimeInterval(10)
        )
        let keychain = RecordingVaultKeychainStore(writeTargets: [true, false])
        keychain.passwords[existing.id] = existing.password
        let metadataStore = RecordingVaultMetadataStore(writeTargets: [true, false])
        metadataStore.passwords = [PasswordMetadata(from: existing)]
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)

        let snapshot = try repository.collectFullItemsForCurrentStoragePolicy()
        keychain.passwords[edited.id] = edited.password
        metadataStore.passwords = [PasswordMetadata(from: edited)]
        try KeychainSyncSettings.withICloudKeychainSyncEnabled(true) {
            try repository.saveFullItemsToCurrentStoragePolicy(snapshot)
        }

        XCTAssertEqual(metadataStore.passwords.first?.id, id)
        XCTAssertEqual(metadataStore.passwords.first?.name, "Edited")
        XCTAssertEqual(keychain.passwords[id], edited.password)
    }

    func testSyncEnablePersistsMetadataBeforePasswordSecretCopyCanFail() throws {
        let first = makePassword(name: "First", password: Data("first".utf8))
        let second = makePassword(name: "Second", password: Data("second".utf8))
        let keychain = RecordingVaultKeychainStore(writeTargets: [true, false])
        keychain.passwords[first.id] = first.password
        keychain.passwords[second.id] = second.password
        keychain.passwordSaveErrorIDs = [second.id]
        let metadataStore = RecordingVaultMetadataStore(writeTargets: [true, false])
        metadataStore.passwords = [PasswordMetadata(from: first), PasswordMetadata(from: second)]
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)

        let snapshot = try repository.collectFullItemsForCurrentStoragePolicy()
        metadataStore.passwordSaveTargets.removeAll()

        XCTAssertThrowsError(try KeychainSyncSettings.withICloudKeychainSyncEnabled(true) {
            try repository.saveFullItemsToCurrentStoragePolicy(snapshot)
        })
        XCTAssertFalse(metadataStore.passwordSaveTargets.isEmpty)
        XCTAssertEqual(Set(metadataStore.passwords.map(\.id)), [first.id, second.id])
    }

    func testSyncEnableSnapshotPostsVaultPasswordChangeNotification() throws {
        let expected = expectation(description: "vault password change notification")
        let observer = NotificationCenter.default.addObserver(
            forName: .vaultPasswordsDidChange,
            object: nil,
            queue: nil
        ) { _ in
            expected.fulfill()
        }
        defer { NotificationCenter.default.removeObserver(observer) }
        let password = makePassword(name: "Password", password: Data("pw".utf8))
        let keychain = RecordingVaultKeychainStore(writeTargets: [true, false])
        keychain.passwords[password.id] = password.password
        let metadataStore = RecordingVaultMetadataStore(writeTargets: [true, false])
        metadataStore.passwords = [PasswordMetadata(from: password)]
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)

        let snapshot = try repository.collectFullItemsForCurrentStoragePolicy()
        try KeychainSyncSettings.withICloudKeychainSyncEnabled(true) {
            try repository.saveFullItemsToCurrentStoragePolicy(snapshot)
        }

        wait(for: [expected], timeout: 1)
    }

    private func assertOTPSavePath(syncEnabled: Bool, expectedTargets: [Bool]) throws {
        let secretTargets = KeychainStore(syncPolicy: .fixed(syncEnabled)).writeSynchronizableValuesForTesting()
        let metadataTargets = KeychainStore(syncPolicy: .fixed(syncEnabled)).writeSynchronizableValuesForTesting()
        let accountID = UUID()
        let account = makeAccount(id: accountID, secret: Data("otp-secret".utf8), label: "First")
        let updatedAccount = makeAccount(id: accountID, secret: Data("otp-secret-2".utf8), label: "Second")
        let keychain = RecordingAccountKeychainStore(writeTargets: secretTargets)
        let metadataKeychain = RecordingMetadataKeychainStore(writeTargets: metadataTargets)
        let metadataStore = MetadataStore(fileURL: nil, foldersFileURL: nil, keychain: metadataKeychain)
        let repository = AccountRepository(keychainStore: keychain, metadataStore: metadataStore)

        try repository.addAccount(account)
        try repository.saveOrUpdateAccount(updatedAccount)

        XCTAssertEqual(secretTargets, expectedTargets)
        XCTAssertEqual(metadataTargets, expectedTargets)
        XCTAssertEqual(keychain.savedSecrets.map(\.targets), [expectedTargets, expectedTargets])
        XCTAssertTrue(keychain.deletedIDs.isEmpty)
        XCTAssertEqual(metadataKeychain.savedItems.filter { $0.key == "account_metadata" }.map(\.targets), [
            expectedTargets,
            expectedTargets,
        ])
        XCTAssertEqual(repository.accounts.map(\.id), [accountID])
        XCTAssertEqual(repository.accounts.first?.label, "Second")
    }

    private func assertVaultSavePath(syncEnabled: Bool, expectedTargets: [Bool]) throws {
        let secretTargets = VaultKeychainStore(syncPolicy: .fixed(syncEnabled)).writeSynchronizableValuesForTesting()
        let metadataTargets = SecurityVaultMetadataKeychainStore(
            syncPolicy: .fixed(syncEnabled)
        ).writeSynchronizableValuesForTesting()
        let keychain = RecordingVaultKeychainStore(writeTargets: secretTargets)
        let metadataStore = RecordingVaultMetadataStore(writeTargets: metadataTargets)
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)

        let password = makePassword(name: "First Password", password: Data("pw1".utf8))
        let updatedPassword = makePassword(id: password.id, name: "Second Password", password: Data("pw2".utf8))
        try repository.addPassword(password)
        try repository.updatePassword(updatedPassword)

        let certificate = makeCertificate(name: "First Certificate", certificateData: Data("cert1".utf8))
        let updatedCertificate = makeCertificate(
            id: certificate.id,
            name: "Second Certificate",
            certificateData: Data("cert2".utf8)
        )
        try repository.addCertificate(certificate)
        try repository.updateCertificate(updatedCertificate)

        let note = makeNote(title: "First Note", content: Data("note1".utf8))
        let updatedNote = makeNote(id: note.id, title: "Second Note", content: Data("note2".utf8))
        try repository.addNote(note)
        try repository.updateNote(updatedNote)

        let sshKey = makeSSHKey(name: "First SSH", privateKey: Data("priv1".utf8))
        let updatedSSHKey = makeSSHKey(id: sshKey.id, name: "Second SSH", privateKey: Data("priv2".utf8))
        try repository.addSSHKey(sshKey)
        try repository.updateSSHKey(updatedSSHKey)

        XCTAssertEqual(secretTargets, expectedTargets)
        XCTAssertEqual(metadataTargets, expectedTargets)
        XCTAssertEqual(keychain.passwordSaveTargets, [expectedTargets, expectedTargets])
        XCTAssertEqual(keychain.certificateSaveTargets, [expectedTargets, expectedTargets])
        XCTAssertEqual(keychain.noteSaveTargets, [expectedTargets, expectedTargets])
        XCTAssertEqual(keychain.sshSaveTargets, [expectedTargets, expectedTargets])
        XCTAssertTrue(keychain.passwordDeleteIDs.isEmpty)
        XCTAssertTrue(keychain.certificateDeleteIDs.isEmpty)
        XCTAssertTrue(keychain.noteDeleteIDs.isEmpty)
        XCTAssertTrue(keychain.sshDeleteIDs.isEmpty)
        XCTAssertEqual(metadataStore.passwordSaveTargets, [expectedTargets, expectedTargets])
        XCTAssertEqual(metadataStore.certificateSaveTargets, [expectedTargets, expectedTargets])
        XCTAssertEqual(metadataStore.noteSaveTargets, [expectedTargets, expectedTargets])
        XCTAssertEqual(metadataStore.sshSaveTargets, [expectedTargets, expectedTargets])
        XCTAssertEqual(repository.passwords.first?.name, "Second Password")
        XCTAssertEqual(repository.certificates.first?.name, "Second Certificate")
        XCTAssertEqual(repository.notes.first?.title, "Second Note")
        XCTAssertEqual(repository.sshKeys.first?.name, "Second SSH")
    }

    private func makeAccount(id: UUID, secret: Data, label: String) -> Account {
        Account(
            id: id,
            issuer: "Example",
            label: label,
            folderPath: "Team/Auth",
            secret: secret,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            lastUsed: Date(timeIntervalSince1970: 1_700_000_000)
        )
    }

    private func makePassword(
        id: UUID = UUID(),
        name: String,
        password: Data
    ) -> PasswordItem {
        PasswordItem(
            id: id,
            name: name,
            username: "user",
            password: password,
            folderPath: "Team/Vault"
        )
    }

    private func makeCertificate(
        id: UUID = UUID(),
        name: String,
        certificateData: Data
    ) -> CertificateItem {
        CertificateItem(
            id: id,
            name: name,
            certificateData: certificateData,
            privateKeyData: Data("private-key".utf8),
            folderPath: "Team/Certs"
        )
    }

    private func makeNote(
        id: UUID = UUID(),
        title: String,
        content: Data
    ) -> SecureNoteItem {
        SecureNoteItem(
            id: id,
            title: title,
            content: content,
            folderPath: "Team/Notes"
        )
    }

    private func makeSSHKey(
        id: UUID = UUID(),
        name: String,
        privateKey: Data
    ) -> SSHKeyItem {
        SSHKeyItem(
            id: id,
            name: name,
            publicKey: Data("ssh-ed25519 AAAA".utf8),
            privateKey: privateKey,
            comment: "deploy",
            fingerprint: "SHA256:deploy",
            folderPath: "Team/SSH"
        )
    }
}

private final class RecordingAccountKeychainStore: AccountKeychainStoring {
    let writeTargets: [Bool]
    var savedSecrets: [(id: UUID, secret: Data, targets: [Bool])] = []
    var deletedIDs: [UUID] = []

    init(writeTargets: [Bool]) {
        self.writeTargets = writeTargets
    }

    func save(secret: Data, for accountID: UUID) throws {
        savedSecrets.append((accountID, secret, writeTargets))
    }

    func retrieve(for accountID: UUID) throws -> Data {
        guard let secret = savedSecrets.last(where: { $0.id == accountID })?.secret else {
            throw KeychainError.itemNotFound
        }
        return secret
    }

    func delete(for accountID: UUID) throws {
        deletedIDs.append(accountID)
    }
}

private final class RecordingMetadataKeychainStore: MetadataKeychainStoring {
    let writeTargets: [Bool]
    var dataByKey: [String: Data] = [:]
    var savedItems: [(key: String, data: Data, targets: [Bool])] = []

    init(writeTargets: [Bool]) {
        self.writeTargets = writeTargets
    }

    func save(data: Data, for key: String) throws {
        dataByKey[key] = data
        savedItems.append((key, data, writeTargets))
    }

    func retrieve(for key: String) throws -> Data {
        guard let data = dataByKey[key] else { throw KeychainError.itemNotFound }
        return data
    }
}

private final class RecordingVaultMetadataKeychain: VaultMetadataKeychainStoring, @unchecked Sendable {
    var local: [String: Data] = [:]
    var synchronizable: [String: Data] = [:]

    func seed<T: Encodable>(local localValue: T, synchronizable synchronizableValue: T, key: String) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        local[key] = try encoder.encode(localValue)
        synchronizable[key] = try encoder.encode(synchronizableValue)
    }

    func save(data: Data, key: String) throws {
        local[key] = data
        if KeychainSyncSettings.isICloudKeychainSyncEnabled {
            synchronizable[key] = data
        }
    }

    func load(key: String) throws -> Data? {
        try loadCandidates(key: key).first
    }

    func loadCandidates(key: String) throws -> [Data] {
        let candidates = KeychainSyncSettings.isICloudKeychainSyncEnabled
            ? [synchronizable[key], local[key]]
            : [local[key], synchronizable[key]]
        return candidates.compactMap { $0 }
    }

    func decodeSavedPasswords() throws -> [PasswordMetadata] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let data = synchronizable["vault_passwords_metadata"] else { return [] }
        return try decoder.decode([PasswordMetadata].self, from: data)
    }
}

private final class RecordingVaultKeychainStore: VaultKeychainStoring, @unchecked Sendable {
    let writeTargets: [Bool]
    var passwords: [UUID: Data] = [:]
    var apiKeys: [UUID: Data] = [:]
    var certificates: [UUID: (cert: Data, key: Data?)] = [:]
    var notes: [UUID: Data] = [:]
    var sshKeys: [UUID: (publicKey: Data, privateKey: Data)] = [:]
    var passwordSaveTargets: [[Bool]] = []
    var apiKeySaveTargets: [[Bool]] = []
    var certificateSaveTargets: [[Bool]] = []
    var noteSaveTargets: [[Bool]] = []
    var sshSaveTargets: [[Bool]] = []
    var passwordDeleteIDs: [UUID] = []
    var apiKeyDeleteIDs: [UUID] = []
    var certificateDeleteIDs: [UUID] = []
    var noteDeleteIDs: [UUID] = []
    var sshDeleteIDs: [UUID] = []
    var passwordSaveErrorIDs: Set<UUID> = []

    init(writeTargets: [Bool]) {
        self.writeTargets = writeTargets
    }

    func savePassword(_ password: Data, for itemID: UUID) throws {
        if passwordSaveErrorIDs.contains(itemID) {
            throw KeychainError.unknown(errSecAuthFailed)
        }
        passwords[itemID] = password
        passwordSaveTargets.append(writeTargets)
    }

    func containsPassword(for itemID: UUID) throws -> Bool {
        passwords[itemID] != nil
    }

    func retrievePassword(for itemID: UUID) throws -> Data {
        guard let password = passwords[itemID] else { throw KeychainError.itemNotFound }
        return password
    }

    func deletePassword(for itemID: UUID) throws {
        passwordDeleteIDs.append(itemID)
        passwords[itemID] = nil
    }

    func saveAPIKey(_ key: Data, for itemID: UUID) throws {
        apiKeys[itemID] = key
        apiKeySaveTargets.append(writeTargets)
    }

    func containsAPIKey(for itemID: UUID) throws -> Bool {
        apiKeys[itemID] != nil
    }

    func retrieveAPIKey(for itemID: UUID) throws -> Data {
        guard let key = apiKeys[itemID] else { throw KeychainError.itemNotFound }
        return key
    }

    func deleteAPIKey(for itemID: UUID) throws {
        apiKeyDeleteIDs.append(itemID)
        apiKeys[itemID] = nil
    }

    func saveCertificate(_ certData: Data, privateKey: Data?, for itemID: UUID) throws {
        certificates[itemID] = (certData, privateKey)
        certificateSaveTargets.append(writeTargets)
    }

    func containsCertificate(for itemID: UUID) throws -> Bool {
        certificates[itemID] != nil
    }

    func retrieveCertificate(for itemID: UUID) throws -> (cert: Data, key: Data?) {
        guard let certificate = certificates[itemID] else { throw KeychainError.itemNotFound }
        return certificate
    }

    func deleteCertificate(for itemID: UUID) throws {
        certificateDeleteIDs.append(itemID)
        certificates[itemID] = nil
    }

    func deleteCertificatePrivateKey(for itemID: UUID) {
        if let certificate = certificates[itemID] {
            certificates[itemID] = (certificate.cert, nil)
        }
    }

    func saveSSHKey(publicKey: Data, privateKey: Data, for itemID: UUID) throws {
        sshKeys[itemID] = (publicKey, privateKey)
        sshSaveTargets.append(writeTargets)
    }

    func containsSSHKey(for itemID: UUID) throws -> Bool {
        sshKeys[itemID] != nil
    }

    func retrieveSSHKey(for itemID: UUID) throws -> (publicKey: Data, privateKey: Data) {
        guard let sshKey = sshKeys[itemID] else { throw KeychainError.itemNotFound }
        return sshKey
    }

    func deleteSSHKey(for itemID: UUID) throws {
        sshDeleteIDs.append(itemID)
        sshKeys[itemID] = nil
    }

    func saveNoteContent(_ content: Data, for itemID: UUID) throws {
        notes[itemID] = content
        noteSaveTargets.append(writeTargets)
    }

    func containsNoteContent(for itemID: UUID) throws -> Bool {
        notes[itemID] != nil
    }

    func retrieveNoteContent(for itemID: UUID) throws -> Data {
        guard let note = notes[itemID] else { throw KeychainError.itemNotFound }
        return note
    }

    func deleteNoteContent(for itemID: UUID) throws {
        noteDeleteIDs.append(itemID)
        notes[itemID] = nil
    }
}

private final class RecordingVaultMetadataStore: VaultMetadataStoring {
    let writeTargets: [Bool]
    var passwords: [PasswordMetadata] = []
    var passwordDeletionTombstones: [PasswordDeletionTombstone] = []
    var apiKeys: [APIKeyMetadata] = []
    var apiKeyDeletionTombstones: [APIKeyDeletionTombstone] = []
    var certificates: [CertificateMetadata] = []
    var notes: [SecureNoteMetadata] = []
    var sshKeys: [SSHKeyMetadata] = []
    var folders: [VaultItemType: [String]] = [:]
    var folderStates: [VaultFolderState] = []
    var passwordSaveTargets: [[Bool]] = []
    var apiKeySaveTargets: [[Bool]] = []
    var certificateSaveTargets: [[Bool]] = []
    var noteSaveTargets: [[Bool]] = []
    var sshSaveTargets: [[Bool]] = []
    var folderSaveTargets: [[Bool]] = []
    var apiKeyTombstoneSaveTargets: [[Bool]] = []
    var folderStateSaveTargets: [[Bool]] = []

    init(writeTargets: [Bool]) {
        self.writeTargets = writeTargets
    }

    func savePasswords(_ metadata: [PasswordMetadata]) throws {
        passwords = metadata
        passwordSaveTargets.append(writeTargets)
    }

    func replacePasswords(_ metadata: [PasswordMetadata]) throws {
        try savePasswords(metadata)
    }

    func loadPasswords() throws -> [PasswordMetadata] {
        passwords
    }

    func savePasswordDeletionTombstones(_ tombstones: [PasswordDeletionTombstone]) throws {
        passwordDeletionTombstones = tombstones
    }

    func loadPasswordDeletionTombstones() throws -> [PasswordDeletionTombstone] {
        passwordDeletionTombstones
    }

    func saveAPIKeys(_ metadata: [APIKeyMetadata]) throws {
        apiKeys = metadata
        apiKeySaveTargets.append(writeTargets)
    }

    func replaceAPIKeys(_ metadata: [APIKeyMetadata]) throws {
        try saveAPIKeys(metadata)
    }

    func loadAPIKeys() throws -> [APIKeyMetadata] {
        apiKeys
    }

    func saveAPIKeyDeletionTombstones(_ tombstones: [APIKeyDeletionTombstone]) throws {
        apiKeyDeletionTombstones = tombstones
        apiKeyTombstoneSaveTargets.append(writeTargets)
    }

    func loadAPIKeyDeletionTombstones() throws -> [APIKeyDeletionTombstone] {
        apiKeyDeletionTombstones
    }

    func saveCertificates(_ metadata: [CertificateMetadata]) throws {
        certificates = metadata
        certificateSaveTargets.append(writeTargets)
    }

    func replaceCertificates(_ metadata: [CertificateMetadata]) throws {
        try saveCertificates(metadata)
    }

    func loadCertificates() throws -> [CertificateMetadata] {
        certificates
    }

    func saveNotes(_ metadata: [SecureNoteMetadata]) throws {
        notes = metadata
        noteSaveTargets.append(writeTargets)
    }

    func replaceNotes(_ metadata: [SecureNoteMetadata]) throws {
        try saveNotes(metadata)
    }

    func loadNotes() throws -> [SecureNoteMetadata] {
        notes
    }

    func saveSSHKeys(_ metadata: [SSHKeyMetadata]) throws {
        sshKeys = metadata
        sshSaveTargets.append(writeTargets)
    }

    func replaceSSHKeys(_ metadata: [SSHKeyMetadata]) throws {
        try saveSSHKeys(metadata)
    }

    func loadSSHKeys() throws -> [SSHKeyMetadata] {
        sshKeys
    }

    func saveFolders(_ folders: [VaultItemType: [String]]) throws {
        self.folders = folders
        folderSaveTargets.append(writeTargets)
    }

    func replaceFolders(_ folders: [VaultItemType: [String]]) throws {
        try saveFolders(folders)
    }

    func loadFolders() throws -> [VaultItemType: [String]] {
        folders
    }

    func saveFolderStates(_ states: [VaultFolderState]) throws {
        folderStates = states
        folderStateSaveTargets.append(writeTargets)
    }

    func loadFolderStates() throws -> [VaultFolderState] {
        folderStates
    }
}
