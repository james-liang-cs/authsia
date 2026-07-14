import XCTest
@testable import AuthenticatorData
import AuthenticatorCore

@MainActor
final class VaultRepositoryStaleMetadataTests: XCTestCase {
    func testCopyItemDuplicatesEachVaultTypeIntoDestinationWithoutMovingSource() throws {
        let sourceFolder = "Source"
        let destinationFolder = "Archive/Shared"
        let timestamp = Date(timeIntervalSince1970: 1_706_000_000)
        let password = PasswordItem(
            name: "Deploy",
            username: "svc",
            password: Data("password".utf8),
            folderPath: sourceFolder,
            createdAt: timestamp,
            modifiedAt: timestamp,
            isFavorite: true
        )
        let apiKey = APIKeyItem(
            name: "API",
            key: Data("api-key".utf8),
            folderPath: sourceFolder,
            createdAt: timestamp,
            modifiedAt: timestamp
        )
        let certificate = CertificateItem(
            name: "Certificate",
            certificateData: Data("certificate".utf8),
            privateKeyData: Data("private-key".utf8),
            folderPath: sourceFolder,
            createdAt: timestamp,
            modifiedAt: timestamp
        )
        let note = SecureNoteItem(
            title: "Runbook",
            content: Data("note".utf8),
            folderPath: sourceFolder,
            createdAt: timestamp,
            modifiedAt: timestamp
        )
        let sshKey = SSHKeyItem(
            name: "Bastion",
            publicKey: Data("ssh-rsa AAAA".utf8),
            privateKey: Data("ssh-private".utf8),
            comment: "bastion",
            fingerprint: "SHA256:bastion",
            keyType: .rsa4096,
            approvalPolicy: .alwaysPrompt,
            boundHosts: ["bastion.example.com"],
            folderPath: sourceFolder,
            createdAt: timestamp,
            modifiedAt: timestamp
        )
        let metadataStore = FakeVaultMetadataStore(
            passwords: [PasswordMetadata(from: password)],
            apiKeys: [APIKeyMetadata(from: apiKey)],
            certificates: [CertificateMetadata(from: certificate)],
            notes: [SecureNoteMetadata(from: note)],
            sshKeys: [SSHKeyMetadata(from: sshKey)]
        )
        let keychain = FakeVaultKeychainStore()
        keychain.passwords[password.id] = password.password
        keychain.apiKeys[apiKey.id] = apiKey.key
        keychain.certificates[certificate.id] = certificate.certificateData
        keychain.certificateKeys[certificate.id] = certificate.privateKeyData
        keychain.notes[note.id] = note.content
        keychain.sshPublicKeys[sshKey.id] = sshKey.publicKey
        keychain.sshPrivateKeys[sshKey.id] = sshKey.privateKey
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)

        try repository.load()

        let passwordCopyID = try XCTUnwrap(repository.copyItem(id: password.id, toFolderPath: destinationFolder))
        let apiKeyCopyID = try XCTUnwrap(repository.copyItem(id: apiKey.id, toFolderPath: destinationFolder))
        let certificateCopyID = try XCTUnwrap(repository.copyItem(id: certificate.id, toFolderPath: destinationFolder))
        let noteCopyID = try XCTUnwrap(repository.copyItem(id: note.id, toFolderPath: destinationFolder))
        let sshKeyCopyID = try XCTUnwrap(repository.copyItem(id: sshKey.id, toFolderPath: destinationFolder))

        XCTAssertEqual(repository.passwords.first(where: { $0.id == password.id })?.folderPath, sourceFolder)
        XCTAssertEqual(repository.apiKeys.first(where: { $0.id == apiKey.id })?.folderPath, sourceFolder)
        XCTAssertEqual(repository.certificates.first(where: { $0.id == certificate.id })?.folderPath, sourceFolder)
        XCTAssertEqual(repository.notes.first(where: { $0.id == note.id })?.folderPath, sourceFolder)
        XCTAssertEqual(repository.sshKeys.first(where: { $0.id == sshKey.id })?.folderPath, sourceFolder)

        XCTAssertEqual(repository.passwords.first(where: { $0.id == passwordCopyID })?.folderPath, destinationFolder)
        XCTAssertEqual(repository.apiKeys.first(where: { $0.id == apiKeyCopyID })?.folderPath, destinationFolder)
        XCTAssertEqual(repository.certificates.first(where: { $0.id == certificateCopyID })?.folderPath, destinationFolder)
        XCTAssertEqual(repository.notes.first(where: { $0.id == noteCopyID })?.folderPath, destinationFolder)
        let copiedSSHMetadata = try XCTUnwrap(repository.sshKeys.first(where: { $0.id == sshKeyCopyID }))
        XCTAssertEqual(copiedSSHMetadata.folderPath, destinationFolder)
        XCTAssertEqual(copiedSSHMetadata.keyType, sshKey.keyType)
        XCTAssertEqual(copiedSSHMetadata.approvalPolicy, sshKey.approvalPolicy)
        XCTAssertEqual(copiedSSHMetadata.boundHosts, sshKey.boundHosts)

        XCTAssertEqual(keychain.passwords[passwordCopyID], password.password)
        XCTAssertEqual(keychain.apiKeys[apiKeyCopyID], apiKey.key)
        XCTAssertEqual(keychain.certificates[certificateCopyID], certificate.certificateData)
        XCTAssertEqual(keychain.certificateKeys[certificateCopyID], certificate.privateKeyData)
        XCTAssertEqual(keychain.notes[noteCopyID], note.content)
        XCTAssertEqual(keychain.sshPublicKeys[sshKeyCopyID], sshKey.publicKey)
        XCTAssertEqual(keychain.sshPrivateKeys[sshKeyCopyID], sshKey.privateKey)
    }

    func testLoadPrunesVaultMetadataWhoseSecretsAreMissingAndPersistsPrune() throws {
        let passwordID = UUID()
        let certificateID = UUID()
        let noteID = UUID()
        let sshKeyID = UUID()
        let metadataStore = FakeVaultMetadataStore(
            passwords: [makePasswordMetadata(id: passwordID)],
            certificates: [makeCertificateMetadata(id: certificateID)],
            notes: [makeNoteMetadata(id: noteID)],
            sshKeys: [makeSSHKeyMetadata(id: sshKeyID)]
        )
        let repository = VaultRepository(
            keychainStore: FakeVaultKeychainStore(),
            metadataStore: metadataStore
        )

        try repository.load()

        XCTAssertTrue(repository.passwords.isEmpty)
        XCTAssertTrue(repository.certificates.isEmpty)
        XCTAssertTrue(repository.notes.isEmpty)
        XCTAssertTrue(repository.sshKeys.isEmpty)
        XCTAssertEqual(metadataStore.savedPasswords.last?.map(\.id), [])
        XCTAssertEqual(metadataStore.savedCertificates.last?.map(\.id), [])
        XCTAssertEqual(metadataStore.savedNotes.last?.map(\.id), [])
        XCTAssertEqual(metadataStore.savedSSHKeys.last?.map(\.id), [])
    }

    func testImportDoesNotTreatStaleVaultMetadataAsDuplicate() async throws {
        let sshKeyID = UUID()
        let metadataStore = FakeVaultMetadataStore(
            sshKeys: [makeSSHKeyMetadata(id: sshKeyID)]
        )
        let keychain = FakeVaultKeychainStore()
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)
        let importedKey = SSHKeyItem(
            id: sshKeyID,
            name: "Deploy",
            publicKey: Data("ssh-ed25519 AAAA".utf8),
            privateKey: Data("private-key".utf8),
            comment: "deploy",
            fingerprint: "SHA256:deploy"
        )
        let data = try makeSSHExportData(items: [importedKey])

        let importedCount = try await repository.importItems(
            of: .sshKey,
            from: data,
            conflictPolicy: .keepExisting
        )

        XCTAssertEqual(importedCount, 1)
        XCTAssertEqual(keychain.sshPrivateKeys[sshKeyID], Data("private-key".utf8))
        XCTAssertEqual(repository.sshKeys.map(\.id), [sshKeyID])
    }

    func testPreviewImportDoesNotTreatStaleVaultMetadataAsDuplicate() async throws {
        let sshKeyID = UUID()
        let metadataStore = FakeVaultMetadataStore(
            sshKeys: [makeSSHKeyMetadata(id: sshKeyID)]
        )
        let repository = VaultRepository(
            keychainStore: FakeVaultKeychainStore(),
            metadataStore: metadataStore
        )
        let importedKey = SSHKeyItem(
            id: sshKeyID,
            name: "Deploy",
            publicKey: Data("ssh-ed25519 AAAA".utf8),
            privateKey: Data("private-key".utf8),
            comment: "deploy",
            fingerprint: "SHA256:deploy"
        )
        let data = try makeSSHExportData(items: [importedKey])

        let preview = try await repository.previewImportItems(of: .sshKey, from: data)

        XCTAssertEqual(preview.totalItems, 1)
        XCTAssertEqual(preview.duplicateCount, 0)
    }

    func testLoadChecksExistenceWithoutReadingVaultSecrets() throws {
        let passwordID = UUID()
        let certificateID = UUID()
        let noteID = UUID()
        let sshKeyID = UUID()
        let metadataStore = FakeVaultMetadataStore(
            passwords: [makePasswordMetadata(id: passwordID)],
            certificates: [makeCertificateMetadata(id: certificateID)],
            notes: [makeNoteMetadata(id: noteID)],
            sshKeys: [makeSSHKeyMetadata(id: sshKeyID)]
        )
        let keychain = FakeVaultKeychainStore()
        keychain.passwords[passwordID] = Data("password".utf8)
        keychain.certificates[certificateID] = Data("certificate".utf8)
        keychain.notes[noteID] = Data("note".utf8)
        keychain.sshPublicKeys[sshKeyID] = Data("ssh-ed25519 AAAA".utf8)
        keychain.sshPrivateKeys[sshKeyID] = Data("private".utf8)
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)

        try repository.load()

        XCTAssertEqual(keychain.retrieveCallCount, 0)
        XCTAssertEqual(keychain.containsCallCount, 4)
        XCTAssertEqual(repository.totalCount, 4)
    }

    func testRepeatedLoadChecksExistenceWithoutReadingVaultSecrets() throws {
        let passwordID = UUID()
        let metadataStore = FakeVaultMetadataStore(
            passwords: [makePasswordMetadata(id: passwordID)]
        )
        let keychain = FakeVaultKeychainStore()
        keychain.passwords[passwordID] = Data("password".utf8)
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)

        try repository.load()
        try repository.load()

        XCTAssertEqual(keychain.retrieveCallCount, 0)
        XCTAssertEqual(keychain.containsCallCount, 2)
    }

    func testLoadKeepsMetadataWhenKeychainExistenceIsUnavailable() throws {
        let sshKeyID = UUID()
        let metadataStore = FakeVaultMetadataStore(
            sshKeys: [makeSSHKeyMetadata(id: sshKeyID)]
        )
        let keychain = FakeVaultKeychainStore()
        keychain.forcedExistence = .unavailable
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)

        try repository.load()

        XCTAssertEqual(repository.sshKeys.map(\.id), [sshKeyID])
        XCTAssertTrue(
            metadataStore.savedSSHKeys.isEmpty,
            "SSH key metadata must NOT be rewritten when the keychain refused the existence check"
        )
    }

    func testLoadRefusesToBlankNonEmptyMetadataWhenAllExistenceChecksAreUnavailable() throws {
        let passwordID = UUID()
        let certificateID = UUID()
        let noteID = UUID()
        let sshKeyID = UUID()
        let metadataStore = FakeVaultMetadataStore(
            passwords: [makePasswordMetadata(id: passwordID)],
            certificates: [makeCertificateMetadata(id: certificateID)],
            notes: [makeNoteMetadata(id: noteID)],
            sshKeys: [makeSSHKeyMetadata(id: sshKeyID)]
        )
        let keychain = FakeVaultKeychainStore()
        keychain.forcedExistence = .unavailable
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)

        try repository.load()

        XCTAssertEqual(repository.totalCount, 4)
        XCTAssertTrue(metadataStore.savedPasswords.isEmpty)
        XCTAssertTrue(metadataStore.savedCertificates.isEmpty)
        XCTAssertTrue(metadataStore.savedNotes.isEmpty)
        XCTAssertTrue(metadataStore.savedSSHKeys.isEmpty)
    }

    func testRebuildMetadataPersistsCurrentVaultArraysAndFolders() throws {
        let password = makePasswordMetadata(id: UUID())
        let certificate = makeCertificateMetadata(id: UUID())
        let note = makeNoteMetadata(id: UUID())
        let sshKey = makeSSHKeyMetadata(id: UUID())
        let folders: [VaultItemType: [String]] = [.password: ["Team/API"]]
        let metadataStore = FakeVaultMetadataStore()
        let repository = VaultRepository(
            keychainStore: FakeVaultKeychainStore(),
            metadataStore: metadataStore
        )

        let summary = try repository.rebuildMetadata(
            passwords: [password],
            certificates: [certificate],
            notes: [note],
            sshKeys: [sshKey],
            folders: folders
        )

        XCTAssertEqual(summary.passwordCount, 1)
        XCTAssertEqual(summary.certificateCount, 1)
        XCTAssertEqual(summary.noteCount, 1)
        XCTAssertEqual(summary.sshKeyCount, 1)
        XCTAssertEqual(summary.totalCount, 4)
        XCTAssertEqual(metadataStore.savedPasswords.last, [password])
        XCTAssertEqual(metadataStore.savedCertificates.last, [certificate])
        XCTAssertEqual(metadataStore.savedNotes.last, [note])
        XCTAssertEqual(metadataStore.savedSSHKeys.last, [sshKey])
        XCTAssertEqual(metadataStore.savedFolders.last, folders)
        XCTAssertEqual(repository.totalCount, 4)
    }

    func testLoadRefreshesCLIMetadataSnapshotFromLiveMetadata() throws {
        let passwordID = UUID()
        let snapshotStore = RecordingVaultCLIMetadataSnapshotStore()
        let metadataStore = FakeVaultMetadataStore(
            passwords: [makePasswordMetadata(id: passwordID, folderPath: "New")]
        )
        let keychain = FakeVaultKeychainStore()
        keychain.passwords[passwordID] = Data("password".utf8)
        let repository = VaultRepository(
            keychainStore: keychain,
            metadataStore: metadataStore,
            cliMetadataSnapshotStore: snapshotStore
        )

        try repository.load()

        XCTAssertEqual(snapshotStore.savedSnapshots.last?.passwords.first?.folderPath, "New")
    }

    func testAddAPIKeyPersistsDedicatedMetadataSecretFolderAndSnapshot() throws {
        let snapshotStore = RecordingVaultCLIMetadataSnapshotStore()
        let metadataStore = FakeVaultMetadataStore()
        let keychain = FakeVaultKeychainStore()
        let repository = VaultRepository(
            keychainStore: keychain,
            metadataStore: metadataStore,
            cliMetadataSnapshotStore: snapshotStore
        )
        let apiKey = APIKeyItem(
            name: "Stripe",
            key: Data("sk_test_123".utf8),
            website: "https://dashboard.stripe.com",
            notes: "Billing automation",
            folderPath: "Team/API",
            isCliEnabled: true
        )

        try repository.addAPIKey(apiKey)

        XCTAssertEqual(keychain.apiKeys[apiKey.id], apiKey.key)
        XCTAssertEqual(repository.apiKeys.map(\.id), [apiKey.id])
        XCTAssertEqual(metadataStore.savedAPIKeys.last?.map(\.id), [apiKey.id])
        XCTAssertEqual(repository.folders[.apiKey], ["Team/API"])
        XCTAssertEqual(snapshotStore.savedSnapshots.last?.apiKeys.map(\.id), [apiKey.id])
    }

    func testSearchIncludesAPIKeys() throws {
        let repository = VaultRepository(
            keychainStore: FakeVaultKeychainStore(),
            metadataStore: FakeVaultMetadataStore(),
            cliMetadataSnapshotStore: RecordingVaultCLIMetadataSnapshotStore()
        )
        let password = PasswordItem(
            name: "GitHub",
            username: "dev@example.com",
            password: Data("password".utf8)
        )
        let apiKey = APIKeyItem(
            name: "Stripe",
            key: Data("sk_test_123".utf8),
            website: "https://dashboard.stripe.com"
        )

        try repository.addPassword(password)
        try repository.addAPIKey(apiKey)

        let passwordResults = repository.search(query: "github")
        let apiKeyResults = repository.search(query: "stripe")

        XCTAssertEqual(passwordResults.passwords.map(\.id), [password.id])
        XCTAssertTrue(passwordResults.apiKeys.isEmpty)
        XCTAssertEqual(apiKeyResults.apiKeys.map(\.id), [apiKey.id])
        XCTAssertTrue(apiKeyResults.passwords.isEmpty)
    }

    func testConvertPasswordToAPIKeyPreservesSecretAndUsernameInNotes() throws {
        let snapshotStore = RecordingVaultCLIMetadataSnapshotStore()
        let metadataStore = FakeVaultMetadataStore()
        let keychain = FakeVaultKeychainStore()
        let repository = VaultRepository(
            keychainStore: keychain,
            metadataStore: metadataStore,
            cliMetadataSnapshotStore: snapshotStore
        )
        let password = PasswordItem(
            name: "Stripe",
            username: "billing@example.com",
            password: Data("sk_live_123".utf8),
            website: "https://dashboard.stripe.com",
            notes: "Billing automation",
            folderPath: "Team/API",
            isFavorite: true,
            isCliEnabled: true,
            environments: ["Production", "Development"]
        )
        try repository.addPassword(password)

        let convertedAt = Date(timeIntervalSince1970: 1_800_000_000)
        let apiKey = try XCTUnwrap(repository.convertPasswordToAPIKey(id: password.id, modifiedAt: convertedAt))

        XCTAssertNil(keychain.passwords[password.id])
        XCTAssertEqual(keychain.apiKeys[apiKey.id], Data("sk_live_123".utf8))
        XCTAssertTrue(repository.passwords.isEmpty)
        XCTAssertEqual(repository.apiKeys.map(\.id), [apiKey.id])
        XCTAssertEqual(apiKey.name, "Stripe")
        XCTAssertEqual(apiKey.website, "https://dashboard.stripe.com")
        XCTAssertEqual(apiKey.notes, "Billing automation\n\nConverted from password username: billing@example.com")
        XCTAssertEqual(apiKey.folderPath, "Team/API")
        XCTAssertTrue(apiKey.isFavorite)
        XCTAssertTrue(apiKey.isCliEnabled)
        XCTAssertEqual(apiKey.environments, ["Development", "Production"])
        XCTAssertEqual(apiKey.modifiedAt, convertedAt)
        XCTAssertEqual(metadataStore.savedPasswords.last, [])
        XCTAssertEqual(metadataStore.savedAPIKeys.last?.map(\.id), [apiKey.id])
        XCTAssertEqual(
            metadataStore.passwordDeletionTombstones,
            [PasswordDeletionTombstone(id: password.id, deletedAt: convertedAt)]
        )
        XCTAssertEqual(repository.folders[.apiKey], ["Team/API"])
        XCTAssertEqual(snapshotStore.savedSnapshots.last?.passwords, [])
        XCTAssertEqual(snapshotStore.savedSnapshots.last?.apiKeys.map(\.id), [apiKey.id])
    }

    func testDeletePasswordRecordsTombstoneBeforeRemovingSource() throws {
        let deletedAt = Date(timeIntervalSince1970: 1_800_000_000)
        let password = PasswordItem(
            name: "Old",
            username: "",
            password: Data("secret".utf8)
        )
        let metadataStore = FakeVaultMetadataStore()
        let keychain = FakeVaultKeychainStore()
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)
        try repository.addPassword(password)

        try repository.deletePassword(id: password.id, deletedAt: deletedAt)

        XCTAssertEqual(
            metadataStore.passwordDeletionTombstones,
            [PasswordDeletionTombstone(id: password.id, deletedAt: deletedAt)]
        )
        XCTAssertNil(keychain.passwords[password.id])
        XCTAssertTrue(repository.passwords.isEmpty)
    }

    func testDeleteAPIKeyRecordsTombstoneBeforeRemovingSource() throws {
        let deletedAt = Date(timeIntervalSince1970: 1_800_000_000)
        let apiKey = APIKeyItem(name: "Old", key: Data("fixture".utf8))
        let metadataStore = FakeVaultMetadataStore()
        let keychain = FakeVaultKeychainStore()
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)
        try repository.addAPIKey(apiKey)

        try repository.deleteAPIKey(id: apiKey.id, deletedAt: deletedAt)

        XCTAssertEqual(
            metadataStore.apiKeyDeletionTombstones,
            [APIKeyDeletionTombstone(id: apiKey.id, deletedAt: deletedAt)]
        )
        XCTAssertNil(keychain.apiKeys[apiKey.id])
        XCTAssertTrue(repository.apiKeys.isEmpty)
    }

    func testLoadDeletesStaleSecretCoveredByPasswordTombstone() throws {
        let id = UUID()
        let metadataStore = FakeVaultMetadataStore(
            passwordDeletionTombstones: [
                PasswordDeletionTombstone(
                    id: id,
                    deletedAt: Date(timeIntervalSince1970: 1_800_000_000)
                ),
            ]
        )
        let keychain = FakeVaultKeychainStore()
        keychain.passwords[id] = Data("stale".utf8)
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)

        try repository.load()

        XCTAssertNil(keychain.passwords[id])
        XCTAssertTrue(repository.passwords.isEmpty)
    }

    func testLoadDeletesStaleSecretCoveredByAPIKeyTombstone() throws {
        let id = UUID()
        let metadataStore = FakeVaultMetadataStore(
            apiKeyDeletionTombstones: [
                APIKeyDeletionTombstone(
                    id: id,
                    deletedAt: Date(timeIntervalSince1970: 1_800_000_000)
                ),
            ]
        )
        let keychain = FakeVaultKeychainStore()
        keychain.apiKeys[id] = Data("stale".utf8)
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)

        try repository.load()

        XCTAssertNil(keychain.apiKeys[id])
        XCTAssertTrue(repository.apiKeys.isEmpty)
    }

    func testLoadDoesNotDeleteSecretForPasswordNewerThanTombstone() throws {
        let id = UUID()
        let metadataStore = FakeVaultMetadataStore(
            passwords: [
                makePasswordMetadata(
                    id: id,
                    modifiedAt: Date(timeIntervalSince1970: 1_800_000_020)
                ),
            ],
            passwordDeletionTombstones: [
                PasswordDeletionTombstone(
                    id: id,
                    deletedAt: Date(timeIntervalSince1970: 1_800_000_010)
                ),
            ]
        )
        let keychain = FakeVaultKeychainStore()
        keychain.passwords[id] = Data("newer".utf8)
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)

        try repository.load()

        XCTAssertNotNil(keychain.passwords[id])
        XCTAssertEqual(repository.passwords.map(\.id), [id])
    }

    func testDeleteFolderRecordsPasswordTombstones() async throws {
        let password = PasswordItem(
            name: "Folder secret",
            username: "",
            password: Data("secret".utf8),
            folderPath: "Team/Nested"
        )
        let metadataStore = FakeVaultMetadataStore()
        let keychain = FakeVaultKeychainStore()
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)
        try repository.addPassword(password)

        try await repository.deleteFolder(path: "Team", type: .password)

        XCTAssertEqual(Set(metadataStore.passwordDeletionTombstones.map(\.id)), [password.id])
    }

    func testDeleteAPIKeyFolderRecordsItemAndTypedFolderTombstones() async throws {
        let apiKey = APIKeyItem(
            name: "Folder key",
            key: Data("fixture".utf8),
            folderPath: "AMI/CFT"
        )
        let metadataStore = FakeVaultMetadataStore()
        let keychain = FakeVaultKeychainStore()
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)
        try repository.addAPIKey(apiKey)

        try await repository.deleteFolder(path: "AMI/CFT", type: .apiKey)

        XCTAssertEqual(Set(metadataStore.apiKeyDeletionTombstones.map(\.id)), [apiKey.id])
        XCTAssertTrue(metadataStore.folderStates.contains {
            $0.type == .apiKey && $0.path == "AMI/CFT" && $0.isDeleted
        })
    }

    func testDeleteAllRecordsPasswordTombstones() throws {
        let password = PasswordItem(
            name: "Delete all secret",
            username: "",
            password: Data("secret".utf8)
        )
        let metadataStore = FakeVaultMetadataStore()
        let keychain = FakeVaultKeychainStore()
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)
        try repository.addPassword(password)

        try repository.deleteAllItems()

        XCTAssertEqual(Set(metadataStore.passwordDeletionTombstones.map(\.id)), [password.id])
    }

    func testAddPasswordRestoresSameIDWithTimestampNewerThanTombstone() throws {
        let id = UUID()
        let deletedAt = Date(timeIntervalSince1970: 1_800_000_000)
        let metadataStore = FakeVaultMetadataStore(
            passwordDeletionTombstones: [
                PasswordDeletionTombstone(id: id, deletedAt: deletedAt),
            ]
        )
        let keychain = FakeVaultKeychainStore()
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)
        let restored = PasswordItem(
            id: id,
            name: "Restored",
            username: "",
            password: Data("restored".utf8),
            modifiedAt: deletedAt.addingTimeInterval(-60)
        )

        try repository.addPassword(restored)

        let restoredMetadata = try XCTUnwrap(metadataStore.passwords.first(where: { $0.id == id }))
        XCTAssertGreaterThan(restoredMetadata.modifiedAt, deletedAt)
        XCTAssertEqual(keychain.passwords[id], restored.password)
    }

    func testMigratesLegacyBackupManifestNotesIntoRootBackupFolder() throws {
        let rootManifestID = UUID()
        let legacyManifestID = UUID()
        let backupNoteID = UUID()
        let unrelatedNoteID = UUID()
        let legacyFolder = "Team/Security/SecOps/Authsia Backups"
        let rootFolder = "Authsia Backups"
        let backupNoteName = "authsia_backup_team_security_secops_authsia_backups_.env_20260605_143555"
        let now = Date(timeIntervalSince1970: 1_750_000_000)
        let migratedAt = Date(timeIntervalSince1970: 1_760_000_000)
        let entry = TestBackupEntry(
            id: "entry-1",
            originalPath: "/Users/example/project/.env",
            folderPath: legacyFolder,
            backupNoteId: nil,
            backupNoteName: backupNoteName,
            timestamp: now,
            description: "Before authsia scrape",
            kind: "scrape",
            slot: "baseline",
            fileHash: "abc123",
            isRestored: false,
            hostname: "james.local",
            machineId: "machine-1"
        )
        let metadataStore = FakeVaultMetadataStore(
            notes: [
                makeNoteMetadata(
                    id: rootManifestID,
                    title: "authsia_scrape_backups_manifest__authsia_backups",
                    folderPath: rootFolder
                ),
                makeNoteMetadata(
                    id: legacyManifestID,
                    title: "authsia_scrape_backups_manifest__team_security_secops_authsia_backups",
                    folderPath: legacyFolder
                ),
                makeNoteMetadata(id: backupNoteID, title: backupNoteName, folderPath: legacyFolder),
                makeNoteMetadata(id: unrelatedNoteID, title: "Daily note", folderPath: "Team"),
            ],
            folders: [.secureNote: [legacyFolder, "Team"]]
        )
        let keychain = FakeVaultKeychainStore()
        keychain.notes[rootManifestID] = try makeManifestData(backups: [], lastUpdated: now)
        keychain.notes[legacyManifestID] = try makeManifestData(backups: [entry], lastUpdated: now)
        keychain.notes[backupNoteID] = Data("backup content".utf8)
        keychain.notes[unrelatedNoteID] = Data("regular note".utf8)
        let snapshotStore = RecordingVaultCLIMetadataSnapshotStore()
        let repository = VaultRepository(
            keychainStore: keychain,
            metadataStore: metadataStore,
            cliMetadataSnapshotStore: snapshotStore
        )

        let didMigrate = try repository.migrateLegacyBackupNotesIfNeeded(currentDate: migratedAt)

        XCTAssertTrue(didMigrate)
        XCTAssertEqual(metadataStore.notes.first(where: { $0.id == backupNoteID })?.folderPath, rootFolder)
        XCTAssertEqual(metadataStore.notes.first(where: { $0.id == legacyManifestID })?.folderPath, legacyFolder)
        XCTAssertEqual(metadataStore.notes.first(where: { $0.id == unrelatedNoteID })?.folderPath, "Team")
        XCTAssertEqual(metadataStore.folders[.secureNote], [rootFolder, "Team", legacyFolder])
        XCTAssertEqual(snapshotStore.savedSnapshots.last?.notes.first(where: { $0.id == backupNoteID })?.folderPath, rootFolder)

        let migratedManifest = try decodeManifest(from: keychain.notes[rootManifestID])
        XCTAssertEqual(migratedManifest.lastUpdated, migratedAt)
        XCTAssertEqual(migratedManifest.backups.count, 1)
        XCTAssertEqual(migratedManifest.backups[0].id, entry.id)
        XCTAssertEqual(migratedManifest.backups[0].folderPath, rootFolder)
        XCTAssertEqual(migratedManifest.backups[0].backupNoteId, backupNoteID.uuidString)
    }

    func testLoadPurgesExpiredPasswordsButRetainsNotes() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let expiredPasswordID = UUID()
        let activePasswordID = UUID()
        let noteID = UUID()
        let snapshotStore = RecordingVaultCLIMetadataSnapshotStore()
        let metadataStore = FakeVaultMetadataStore(
            passwords: [
                makePasswordMetadata(
                    id: expiredPasswordID,
                    expiresAt: now.addingTimeInterval(-86_400),
                    autoDestroyOnExpiry: true
                ),
                makePasswordMetadata(id: activePasswordID, expiresAt: now.addingTimeInterval(60)),
            ],
            notes: [
                makeNoteMetadata(id: noteID),
            ]
        )
        let keychain = FakeVaultKeychainStore()
        keychain.passwords[expiredPasswordID] = Data("expired".utf8)
        keychain.passwords[activePasswordID] = Data("active".utf8)
        keychain.notes[noteID] = Data("note".utf8)
        let repository = VaultRepository(
            keychainStore: keychain,
            metadataStore: metadataStore,
            cliMetadataSnapshotStore: snapshotStore
        )

        try repository.load(currentDate: now)

        XCTAssertEqual(repository.passwords.map(\.id), [activePasswordID])
        XCTAssertEqual(repository.notes.map(\.id), [noteID])
        XCTAssertNil(keychain.passwords[expiredPasswordID])
        XCTAssertNotNil(keychain.notes[noteID])
        XCTAssertEqual(metadataStore.savedPasswords.last?.map(\.id), [activePasswordID])
        XCTAssertEqual(
            metadataStore.passwordDeletionTombstones,
            [PasswordDeletionTombstone(id: expiredPasswordID, deletedAt: now)]
        )
        XCTAssertEqual(snapshotStore.savedSnapshots.last?.passwords.map(\.id), [activePasswordID])
        XCTAssertEqual(snapshotStore.savedSnapshots.last?.notes.map(\.id), [noteID])
    }

    func testLoadRetainsExpiredPasswordWhenAutoDestroyIsDisabled() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let passwordID = UUID()
        let metadataStore = FakeVaultMetadataStore(passwords: [
            makePasswordMetadata(
                id: passwordID,
                expiresAt: now.addingTimeInterval(-86_400),
                autoDestroyOnExpiry: false
            ),
        ])
        let keychain = FakeVaultKeychainStore()
        keychain.passwords[passwordID] = Data("retained".utf8)
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)

        try repository.load(currentDate: now)

        XCTAssertEqual(repository.passwords.map(\.id), [passwordID])
        XCTAssertNotNil(keychain.passwords[passwordID])
    }

    func testLoadRetainsPasswordExpiringSameCalendarDay() throws {
        // A password whose expiry date is earlier today must survive until the
        // next calendar day; choosing "today" should not delete it immediately.
        let calendar = Calendar.current
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let earlierTodayID = UUID()
        let startOfTodayID = UUID()
        let snapshotStore = RecordingVaultCLIMetadataSnapshotStore()
        let metadataStore = FakeVaultMetadataStore(
            passwords: [
                makePasswordMetadata(id: earlierTodayID, expiresAt: now.addingTimeInterval(-3_600)),
                makePasswordMetadata(id: startOfTodayID, expiresAt: calendar.startOfDay(for: now)),
            ]
        )
        let keychain = FakeVaultKeychainStore()
        keychain.passwords[earlierTodayID] = Data("earlier".utf8)
        keychain.passwords[startOfTodayID] = Data("start".utf8)
        let repository = VaultRepository(
            keychainStore: keychain,
            metadataStore: metadataStore,
            cliMetadataSnapshotStore: snapshotStore
        )

        try repository.load(currentDate: now)

        XCTAssertEqual(Set(repository.passwords.map(\.id)), [earlierTodayID, startOfTodayID])
        XCTAssertNotNil(keychain.passwords[earlierTodayID])
        XCTAssertNotNil(keychain.passwords[startOfTodayID])
    }

    func testEnableCLIAccessForSelectedItemIDsUpdatesOnlyThoseItems() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let passwordID = UUID()
        let noteID = UUID()
        let unrelatedID = UUID()
        let expiresAt = now.addingTimeInterval(300)
        let snapshotStore = RecordingVaultCLIMetadataSnapshotStore()
        let metadataStore = FakeVaultMetadataStore()
        let repository = VaultRepository(
            keychainStore: FakeVaultKeychainStore(),
            metadataStore: metadataStore,
            cliMetadataSnapshotStore: snapshotStore
        )
        try repository.rebuildMetadata(
            passwords: [
                makePasswordMetadata(id: passwordID, isCliEnabled: false, expiresAt: expiresAt),
                makePasswordMetadata(id: unrelatedID, isCliEnabled: false),
            ],
            certificates: [],
            notes: [makeNoteMetadata(id: noteID, isCliEnabled: false)],
            sshKeys: [],
            folders: [:]
        )

        let count = try repository.enableCLIAccess(forItemIDs: [passwordID, noteID])

        XCTAssertEqual(count, 2)
        XCTAssertEqual(repository.passwords.first(where: { $0.id == passwordID })?.isCliEnabled, true)
        XCTAssertEqual(repository.passwords.first(where: { $0.id == passwordID })?.expiresAt, expiresAt)
        XCTAssertEqual(repository.passwords.first(where: { $0.id == unrelatedID })?.isCliEnabled, false)
        XCTAssertEqual(repository.notes.first(where: { $0.id == noteID })?.isCliEnabled, true)
        XCTAssertEqual(metadataStore.savedPasswords.last?.first(where: { $0.id == passwordID })?.isCliEnabled, true)
        XCTAssertEqual(metadataStore.savedNotes.last?.first(where: { $0.id == noteID })?.isCliEnabled, true)
        XCTAssertEqual(snapshotStore.savedSnapshots.last?.passwords.first(where: { $0.id == passwordID })?.isCliEnabled, true)
        XCTAssertEqual(snapshotStore.savedSnapshots.last?.notes.first(where: { $0.id == noteID })?.isCliEnabled, true)
    }

    func testEnableCLIAccessInFolderIncludesNestedFoldersForSelectedType() throws {
        let teamID = UUID()
        let nestedID = UUID()
        let unrelatedID = UUID()
        let snapshotStore = RecordingVaultCLIMetadataSnapshotStore()
        let metadataStore = FakeVaultMetadataStore()
        let repository = VaultRepository(
            keychainStore: FakeVaultKeychainStore(),
            metadataStore: metadataStore,
            cliMetadataSnapshotStore: snapshotStore
        )
        try repository.rebuildMetadata(
            passwords: [
                makePasswordMetadata(id: teamID, folderPath: "Team", isCliEnabled: false),
                makePasswordMetadata(id: nestedID, folderPath: "Team/API", isCliEnabled: false),
                makePasswordMetadata(id: unrelatedID, folderPath: "Other", isCliEnabled: false),
            ],
            certificates: [],
            notes: [],
            sshKeys: [],
            folders: [.password: ["Team/API", "Other"]]
        )

        let count = try repository.enableCLIAccess(inFolder: "Team", type: .password)

        XCTAssertEqual(count, 2)
        XCTAssertEqual(repository.passwords.first(where: { $0.id == teamID })?.isCliEnabled, true)
        XCTAssertEqual(repository.passwords.first(where: { $0.id == nestedID })?.isCliEnabled, true)
        XCTAssertEqual(repository.passwords.first(where: { $0.id == unrelatedID })?.isCliEnabled, false)
        let enabledIDs = snapshotStore.savedSnapshots.last?.passwords
            .filter { $0.isCliEnabled }
            .map(\.id.uuidString)
            .sorted()
        XCTAssertEqual(enabledIDs, [nestedID.uuidString, teamID.uuidString].sorted())
    }

    func testEnableCLIAccessInFolderWithoutTypeIncludesAllVaultItemTypes() throws {
        let passwordID = UUID()
        let certificateID = UUID()
        let noteID = UUID()
        let sshKeyID = UUID()
        let otherID = UUID()
        let snapshotStore = RecordingVaultCLIMetadataSnapshotStore()
        let metadataStore = FakeVaultMetadataStore()
        let repository = VaultRepository(
            keychainStore: FakeVaultKeychainStore(),
            metadataStore: metadataStore,
            cliMetadataSnapshotStore: snapshotStore
        )
        try repository.rebuildMetadata(
            passwords: [
                makePasswordMetadata(id: passwordID, folderPath: "Team/API", isCliEnabled: false),
                makePasswordMetadata(id: otherID, folderPath: "Other", isCliEnabled: false),
            ],
            certificates: [makeCertificateMetadata(id: certificateID, folderPath: "Team/Certs", isCliEnabled: false)],
            notes: [makeNoteMetadata(id: noteID, folderPath: "Team", isCliEnabled: false)],
            sshKeys: [makeSSHKeyMetadata(id: sshKeyID, folderPath: "Team/SSH", isCliEnabled: false)],
            folders: [
                .password: ["Team/API", "Other"],
                .certificate: ["Team/Certs"],
                .secureNote: ["Team"],
                .sshKey: ["Team/SSH"],
            ]
        )

        let count = try repository.enableCLIAccess(inFolder: "Team", type: nil)

        XCTAssertEqual(count, 4)
        XCTAssertEqual(repository.passwords.first(where: { $0.id == passwordID })?.isCliEnabled, true)
        XCTAssertEqual(repository.passwords.first(where: { $0.id == otherID })?.isCliEnabled, false)
        XCTAssertEqual(repository.certificates.first(where: { $0.id == certificateID })?.isCliEnabled, true)
        XCTAssertEqual(repository.notes.first(where: { $0.id == noteID })?.isCliEnabled, true)
        XCTAssertEqual(repository.sshKeys.first(where: { $0.id == sshKeyID })?.isCliEnabled, true)
        XCTAssertEqual(snapshotStore.savedSnapshots.last?.passwords.first(where: { $0.id == otherID })?.isCliEnabled, false)
    }

    func testDisableCLIAccessForSelectedItemIDsUpdatesOnlyThoseItems() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let passwordID = UUID()
        let noteID = UUID()
        let unrelatedID = UUID()
        let expiresAt = now.addingTimeInterval(300)
        let snapshotStore = RecordingVaultCLIMetadataSnapshotStore()
        let metadataStore = FakeVaultMetadataStore()
        let repository = VaultRepository(
            keychainStore: FakeVaultKeychainStore(),
            metadataStore: metadataStore,
            cliMetadataSnapshotStore: snapshotStore
        )
        try repository.rebuildMetadata(
            passwords: [
                makePasswordMetadata(id: passwordID, isCliEnabled: true, expiresAt: expiresAt),
                makePasswordMetadata(id: unrelatedID, isCliEnabled: true),
            ],
            certificates: [],
            notes: [makeNoteMetadata(id: noteID, isCliEnabled: true)],
            sshKeys: [],
            folders: [:]
        )

        let count = try repository.disableCLIAccess(forItemIDs: [passwordID, noteID])

        XCTAssertEqual(count, 2)
        XCTAssertEqual(repository.passwords.first(where: { $0.id == passwordID })?.isCliEnabled, false)
        XCTAssertEqual(repository.passwords.first(where: { $0.id == passwordID })?.expiresAt, expiresAt)
        XCTAssertEqual(repository.passwords.first(where: { $0.id == unrelatedID })?.isCliEnabled, true)
        XCTAssertEqual(repository.notes.first(where: { $0.id == noteID })?.isCliEnabled, false)
        XCTAssertEqual(metadataStore.savedPasswords.last?.first(where: { $0.id == passwordID })?.isCliEnabled, false)
        XCTAssertEqual(metadataStore.savedNotes.last?.first(where: { $0.id == noteID })?.isCliEnabled, false)
        XCTAssertEqual(snapshotStore.savedSnapshots.last?.passwords.first(where: { $0.id == passwordID })?.isCliEnabled, false)
        XCTAssertEqual(snapshotStore.savedSnapshots.last?.notes.first(where: { $0.id == noteID })?.isCliEnabled, false)
    }

    func testDisableCLIAccessInFolderWithoutTypeIncludesNestedFoldersForAllVaultItemTypes() throws {
        let passwordID = UUID()
        let certificateID = UUID()
        let noteID = UUID()
        let sshKeyID = UUID()
        let otherID = UUID()
        let snapshotStore = RecordingVaultCLIMetadataSnapshotStore()
        let metadataStore = FakeVaultMetadataStore()
        let repository = VaultRepository(
            keychainStore: FakeVaultKeychainStore(),
            metadataStore: metadataStore,
            cliMetadataSnapshotStore: snapshotStore
        )
        try repository.rebuildMetadata(
            passwords: [
                makePasswordMetadata(id: passwordID, folderPath: "Team/API", isCliEnabled: true),
                makePasswordMetadata(id: otherID, folderPath: "Other", isCliEnabled: true),
            ],
            certificates: [makeCertificateMetadata(id: certificateID, folderPath: "Team/Certs", isCliEnabled: true)],
            notes: [makeNoteMetadata(id: noteID, folderPath: "Team", isCliEnabled: true)],
            sshKeys: [makeSSHKeyMetadata(id: sshKeyID, folderPath: "Team/SSH", isCliEnabled: true)],
            folders: [
                .password: ["Team/API", "Other"],
                .certificate: ["Team/Certs"],
                .secureNote: ["Team"],
                .sshKey: ["Team/SSH"],
            ]
        )

        let count = try repository.disableCLIAccess(inFolder: "Team", type: nil)

        XCTAssertEqual(count, 4)
        XCTAssertEqual(repository.passwords.first(where: { $0.id == passwordID })?.isCliEnabled, false)
        XCTAssertEqual(repository.passwords.first(where: { $0.id == otherID })?.isCliEnabled, true)
        XCTAssertEqual(repository.certificates.first(where: { $0.id == certificateID })?.isCliEnabled, false)
        XCTAssertEqual(repository.notes.first(where: { $0.id == noteID })?.isCliEnabled, false)
        XCTAssertEqual(repository.sshKeys.first(where: { $0.id == sshKeyID })?.isCliEnabled, false)
        XCTAssertEqual(snapshotStore.savedSnapshots.last?.passwords.first(where: { $0.id == otherID })?.isCliEnabled, true)
    }

    func testPasswordFolderMoveRefreshesCLIMetadataSnapshot() throws {
        let snapshotStore = RecordingVaultCLIMetadataSnapshotStore()
        let repository = VaultRepository(
            keychainStore: FakeVaultKeychainStore(),
            metadataStore: FakeVaultMetadataStore(),
            cliMetadataSnapshotStore: snapshotStore
        )
        let password = PasswordItem(
            name: "GitLab",
            username: "dev@example.com",
            password: Data("old-password".utf8),
            folderPath: "Old"
        )

        try repository.addPassword(password)
        var movedPassword = password
        movedPassword.folderPath = "New"
        movedPassword.modifiedAt = Date(timeIntervalSince1970: 1_700_000_010)

        try repository.updatePassword(movedPassword)

        XCTAssertEqual(snapshotStore.savedSnapshots.last?.passwords.first?.folderPath, "New")
    }

    func testAddPasswordWithoutExplicitLoadPreservesExistingPasswordMetadata() throws {
        let existingID = UUID()
        let metadataStore = FakeVaultMetadataStore(
            passwords: [makePasswordMetadata(id: existingID, folderPath: "Existing")]
        )
        let keychain = FakeVaultKeychainStore()
        keychain.passwords[existingID] = Data("existing-password".utf8)
        let repository = VaultRepository(
            keychainStore: keychain,
            metadataStore: metadataStore
        )
        let newPassword = PasswordItem(
            name: "Starter",
            username: "starter@example.com",
            password: Data("starter-password".utf8),
            folderPath: "Personal/Authsia"
        )

        try repository.addPassword(newPassword)

        XCTAssertEqual(Set(metadataStore.savedPasswords.last?.map(\.id) ?? []), [existingID, newPassword.id])
    }

    func testAddFolderWithoutExplicitLoadPreservesExistingFolders() throws {
        let metadataStore = FakeVaultMetadataStore(
            folders: [.password: ["Existing"]]
        )
        let repository = VaultRepository(
            keychainStore: FakeVaultKeychainStore(),
            metadataStore: metadataStore
        )

        try repository.addFolder("Personal/Authsia", type: .password)

        XCTAssertEqual(metadataStore.savedFolders.last?[.password], ["Existing", "Personal/Authsia"])
    }

    func testAddPasswordPreservesItemAddedByAnotherRepositoryAfterLoad() throws {
        let metadataStore = FakeVaultMetadataStore()
        let keychain = FakeVaultKeychainStore()
        let staleRepository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)
        let otherRepository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)
        try staleRepository.load()

        let addedElsewhere = PasswordItem(
            name: "DB_PASSWORD",
            username: "",
            password: Data("secret".utf8),
            folderPath: "Workspaces/api"
        )
        try otherRepository.addPassword(addedElsewhere)

        let addedLocally = PasswordItem(
            name: "OTHER",
            username: "",
            password: Data("other".utf8)
        )
        try staleRepository.addPassword(addedLocally)

        XCTAssertEqual(
            Set(metadataStore.passwords.map(\.id)),
            [addedElsewhere.id, addedLocally.id]
        )
    }

    func testDeletePasswordPreservesItemAddedByAnotherRepositoryAfterLoad() throws {
        let existingID = UUID()
        let metadataStore = FakeVaultMetadataStore(
            passwords: [makePasswordMetadata(id: existingID)]
        )
        let keychain = FakeVaultKeychainStore()
        keychain.passwords[existingID] = Data("existing".utf8)
        let staleRepository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)
        let otherRepository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)
        try staleRepository.load()

        let addedElsewhere = PasswordItem(
            name: "DB_PASSWORD",
            username: "",
            password: Data("secret".utf8)
        )
        try otherRepository.addPassword(addedElsewhere)

        try staleRepository.deletePassword(id: existingID)

        XCTAssertEqual(metadataStore.passwords.map(\.id), [addedElsewhere.id])
    }

    func testCollectFullItemsPrunesMissingPasswordMetadata() throws {
        let existingID = UUID()
        let missingID = UUID()
        let snapshotStore = RecordingVaultCLIMetadataSnapshotStore()
        let metadataStore = FakeVaultMetadataStore(
            passwords: [
                makePasswordMetadata(id: existingID),
                makePasswordMetadata(id: missingID),
            ]
        )
        let keychain = FakeVaultKeychainStore()
        keychain.passwords[existingID] = Data("existing".utf8)
        let repository = VaultRepository(
            keychainStore: keychain,
            metadataStore: metadataStore,
            cliMetadataSnapshotStore: snapshotStore
        )

        let snapshot = try repository.collectFullItemsForCurrentStoragePolicy()

        let snapshotPasswordIDs: [UUID] = snapshot.passwords.map(\.id)
        let repositoryPasswordIDs: [UUID] = repository.passwords.map(\.id)
        let savedPasswordIDs: [UUID]? = metadataStore.savedPasswords.last?.map(\.id)
        let cliSnapshotPasswordIDs: [UUID]? = snapshotStore.savedSnapshots.last?.passwords.map(\.id)
        XCTAssertEqual(snapshotPasswordIDs, [existingID])
        XCTAssertEqual(repositoryPasswordIDs, [existingID])
        XCTAssertEqual(savedPasswordIDs, [existingID])
        XCTAssertEqual(cliSnapshotPasswordIDs, [existingID])
    }

    func testLoadPrunesMissingVaultMetadataWithoutReadingSecrets() throws {
        let existingPasswordID = UUID()
        let missingPasswordID = UUID()
        let existingCertificateID = UUID()
        let missingCertificateID = UUID()
        let existingNoteID = UUID()
        let missingNoteID = UUID()
        let existingSSHKeyID = UUID()
        let missingSSHKeyID = UUID()
        let snapshotStore = RecordingVaultCLIMetadataSnapshotStore()
        let metadataStore = FakeVaultMetadataStore(
            passwords: [
                makePasswordMetadata(id: existingPasswordID),
                makePasswordMetadata(id: missingPasswordID),
            ],
            certificates: [
                makeCertificateMetadata(id: existingCertificateID),
                makeCertificateMetadata(id: missingCertificateID),
            ],
            notes: [
                makeNoteMetadata(id: existingNoteID),
                makeNoteMetadata(id: missingNoteID),
            ],
            sshKeys: [
                makeSSHKeyMetadata(id: existingSSHKeyID),
                makeSSHKeyMetadata(id: missingSSHKeyID),
            ]
        )
        let keychain = FakeVaultKeychainStore()
        keychain.passwords[existingPasswordID] = Data("password".utf8)
        keychain.certificates[existingCertificateID] = Data("certificate".utf8)
        keychain.notes[existingNoteID] = Data("note".utf8)
        keychain.sshPublicKeys[existingSSHKeyID] = Data("ssh-ed25519 AAAA".utf8)
        keychain.sshPrivateKeys[existingSSHKeyID] = Data("private".utf8)
        let repository = VaultRepository(
            keychainStore: keychain,
            metadataStore: metadataStore,
            cliMetadataSnapshotStore: snapshotStore
        )

        try repository.load()

        XCTAssertEqual(repository.passwords.map(\.id), [existingPasswordID])
        XCTAssertEqual(repository.certificates.map(\.id), [existingCertificateID])
        XCTAssertEqual(repository.notes.map(\.id), [existingNoteID])
        XCTAssertEqual(repository.sshKeys.map(\.id), [existingSSHKeyID])
        XCTAssertEqual(metadataStore.savedPasswords.last?.map(\.id), [existingPasswordID])
        XCTAssertEqual(metadataStore.savedCertificates.last?.map(\.id), [existingCertificateID])
        XCTAssertEqual(metadataStore.savedNotes.last?.map(\.id), [existingNoteID])
        XCTAssertEqual(metadataStore.savedSSHKeys.last?.map(\.id), [existingSSHKeyID])
        XCTAssertEqual(snapshotStore.savedSnapshots.last?.passwords.map(\.id), [existingPasswordID])
        XCTAssertEqual(keychain.retrieveCallCount, 0)
    }

    func testLoadKeepsVaultMetadataWhenSecretExistenceIsUnavailable() throws {
        let passwordID = UUID()
        let metadataStore = FakeVaultMetadataStore(passwords: [makePasswordMetadata(id: passwordID)])
        let keychain = FakeVaultKeychainStore()
        keychain.forcedExistence = .unavailable
        let repository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)

        try repository.load()

        XCTAssertEqual(repository.passwords.map(\.id), [passwordID])
        XCTAssertTrue(metadataStore.savedPasswords.isEmpty)
    }

    func testAddFolderPreservesFolderAddedByAnotherRepositoryAfterLoad() throws {
        let metadataStore = FakeVaultMetadataStore()
        let keychain = FakeVaultKeychainStore()
        let staleRepository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)
        let otherRepository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)
        try staleRepository.load()

        try otherRepository.addFolder("Workspaces/api", type: .password)
        try staleRepository.addFolder("Personal", type: .password)

        XCTAssertEqual(
            Set(metadataStore.folders[.password] ?? []),
            ["Personal", "Workspaces/api"]
        )
    }

    func testSaveFoldersReplacesFolderSnapshot() throws {
        let metadataStore = FakeVaultMetadataStore(
            folders: [.password: ["Personal", "Team/API", "Team/SRE"]],
            mergeFolderSaves: true
        )
        let repository = VaultRepository(
            keychainStore: FakeVaultKeychainStore(),
            metadataStore: metadataStore
        )
        try repository.load()

        try repository.saveFolders([.password: ["Personal", "Platform/API", "Platform/SRE"]])

        XCTAssertEqual(
            metadataStore.folders[.password],
            ["Personal", "Platform/API", "Platform/SRE"]
        )
    }

    func testAddNotePreservesNoteAddedByAnotherRepositoryAfterLoad() throws {
        let metadataStore = FakeVaultMetadataStore()
        let keychain = FakeVaultKeychainStore()
        let staleRepository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)
        let otherRepository = VaultRepository(keychainStore: keychain, metadataStore: metadataStore)
        try staleRepository.load()

        let addedElsewhere = SecureNoteItem(title: "Runbook", content: Data("runbook".utf8))
        try otherRepository.addNote(addedElsewhere)

        let addedLocally = SecureNoteItem(title: "Daily", content: Data("daily".utf8))
        try staleRepository.addNote(addedLocally)

        XCTAssertEqual(
            Set(metadataStore.notes.map(\.id)),
            [addedElsewhere.id, addedLocally.id]
        )
    }

    #if os(macOS)
    func testAddPasswordBroadcastsExternalVaultChangeForOtherProcesses() throws {
        let expected = expectation(description: "external vault change was broadcast")
        let center = DistributedNotificationCenter.default()
        let notificationName = Notification.Name("com.authsia.vault.externalDidChange")
        let observer = center.addObserver(forName: notificationName, object: "app.authsia.vault", queue: .main) { notification in
            if let sourcePID = notification.userInfo?["pid"] as? Int,
               sourcePID == ProcessInfo.processInfo.processIdentifier {
                expected.fulfill()
            }
        }
        defer { center.removeObserver(observer) }
        let repository = VaultRepository(
            keychainStore: FakeVaultKeychainStore(),
            metadataStore: FakeVaultMetadataStore()
        )

        try repository.addPassword(PasswordItem(
            name: "Scraped API Key",
            username: "svc",
            password: Data("secret".utf8),
            isCliEnabled: true,
            isScraped: true
        ))

        wait(for: [expected], timeout: 1)
    }
    #endif

    private func makeSSHExportData(items: [SSHKeyItem]) throws -> Data {
        let container = SSHExportContainer(
            format: "authsia.vault.export",
            version: 1,
            itemType: .sshKey,
            exportedAt: Date(timeIntervalSince1970: 1_700_000_000),
            items: items
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(container)
    }

    private func makePasswordMetadata(
        id: UUID,
        folderPath: String? = nil,
        isCliEnabled: Bool = true,
        expiresAt: Date? = nil,
        autoDestroyOnExpiry: Bool = false,
        modifiedAt: Date = Date(timeIntervalSince1970: 1_700_000_000)
    ) -> PasswordMetadata {
        PasswordMetadata(
            id: id,
            name: "Password",
            username: "user",
            website: nil,
            notes: nil,
            folderPath: folderPath,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: modifiedAt,
            isFavorite: false,
            isCliEnabled: isCliEnabled,
            isScraped: false,
            expiresAt: expiresAt,
            autoDestroyOnExpiry: autoDestroyOnExpiry
        )
    }

    private func makeCertificateMetadata(
        id: UUID,
        folderPath: String? = nil,
        isCliEnabled: Bool = true
    ) -> CertificateMetadata {
        CertificateMetadata(
            id: id,
            name: "Certificate",
            expirationDate: nil,
            issuer: nil,
            subject: nil,
            notes: nil,
            folderPath: folderPath,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_000),
            isFavorite: false,
            isCliEnabled: isCliEnabled,
            isScraped: false
        )
    }

    private func makeNoteMetadata(
        id: UUID,
        title: String = "Note",
        folderPath: String? = nil,
        isCliEnabled: Bool = true
    ) -> SecureNoteMetadata {
        SecureNoteMetadata(
            id: id,
            title: title,
            folderPath: folderPath,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_000),
            isFavorite: false,
            isCliEnabled: isCliEnabled,
            isScraped: false
        )
    }

    private func makeSSHKeyMetadata(
        id: UUID,
        folderPath: String? = nil,
        isCliEnabled: Bool = true
    ) -> SSHKeyMetadata {
        SSHKeyMetadata(
            id: id,
            name: "Deploy",
            publicKey: "ssh-ed25519 AAAA",
            comment: "deploy",
            fingerprint: "SHA256:deploy",
            folderPath: folderPath,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_000),
            isFavorite: false,
            isCliEnabled: isCliEnabled,
            isScraped: false
        )
    }

    private func makeManifestData(backups: [TestBackupEntry], lastUpdated: Date) throws -> Data {
        let manifest = TestBackupManifest(version: "1.0", lastUpdated: lastUpdated, backups: backups)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(manifest)
    }

    private func decodeManifest(from data: Data?) throws -> TestBackupManifest {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(TestBackupManifest.self, from: try XCTUnwrap(data))
    }
}

private struct TestBackupManifest: Codable {
    var version: String
    var lastUpdated: Date
    var backups: [TestBackupEntry]
}

private struct TestBackupEntry: Codable {
    var id: String
    var originalPath: String
    var folderPath: String?
    var backupNoteId: String?
    var backupNoteName: String
    var timestamp: Date
    var description: String
    var kind: String
    var slot: String
    var fileHash: String
    var isRestored: Bool
    var hostname: String?
    var machineId: String?
}

private final class RecordingVaultCLIMetadataSnapshotStore: VaultCLIMetadataSnapshotStoring {
    var savedSnapshots: [VaultCLIMetadataSnapshot] = []

    func save(_ snapshot: VaultCLIMetadataSnapshot) throws {
        savedSnapshots.append(snapshot)
    }
}

private struct SSHExportContainer: Codable {
    let format: String
    let version: Int
    let itemType: VaultItemType
    let exportedAt: Date
    let items: [SSHKeyItem]
}

private final class FakeVaultKeychainStore: VaultKeychainStoring, @unchecked Sendable {
    var passwords: [UUID: Data] = [:]
    var apiKeys: [UUID: Data] = [:]
    var certificates: [UUID: Data] = [:]
    var certificateKeys: [UUID: Data] = [:]
    var notes: [UUID: Data] = [:]
    var sshPublicKeys: [UUID: Data] = [:]
    var sshPrivateKeys: [UUID: Data] = [:]
    var containsCallCount = 0
    var retrieveCallCount = 0
    var forcedExistence: SecretExistence?

    func savePassword(_ password: Data, for itemID: UUID) throws {
        passwords[itemID] = password
    }

    func containsPassword(for itemID: UUID) throws -> Bool {
        containsCallCount += 1
        return passwords[itemID] != nil
    }

    func passwordExistence(for itemID: UUID) -> SecretExistence {
        if let forcedExistence { return forcedExistence }
        return existence { try containsPassword(for: itemID) }
    }

    func retrievePassword(for itemID: UUID) throws -> Data {
        retrieveCallCount += 1
        guard let password = passwords[itemID] else { throw KeychainError.itemNotFound }
        return password
    }

    func deletePassword(for itemID: UUID) throws {
        passwords[itemID] = nil
    }

    func saveAPIKey(_ key: Data, for itemID: UUID) throws {
        apiKeys[itemID] = key
    }

    func containsAPIKey(for itemID: UUID) throws -> Bool {
        containsCallCount += 1
        return apiKeys[itemID] != nil
    }

    func apiKeyExistence(for itemID: UUID) -> SecretExistence {
        if let forcedExistence { return forcedExistence }
        return existence { try containsAPIKey(for: itemID) }
    }

    func retrieveAPIKey(for itemID: UUID) throws -> Data {
        retrieveCallCount += 1
        guard let key = apiKeys[itemID] else { throw KeychainError.itemNotFound }
        return key
    }

    func deleteAPIKey(for itemID: UUID) throws {
        apiKeys[itemID] = nil
    }

    func saveCertificate(_ certData: Data, privateKey: Data?, for itemID: UUID) throws {
        certificates[itemID] = certData
        certificateKeys[itemID] = privateKey
    }

    func deleteCertificatePrivateKey(for itemID: UUID) {
        certificateKeys[itemID] = nil
    }

    func containsCertificate(for itemID: UUID) throws -> Bool {
        containsCallCount += 1
        return certificates[itemID] != nil
    }

    func certificateExistence(for itemID: UUID) -> SecretExistence {
        if let forcedExistence { return forcedExistence }
        return existence { try containsCertificate(for: itemID) }
    }

    func retrieveCertificate(for itemID: UUID) throws -> (cert: Data, key: Data?) {
        retrieveCallCount += 1
        guard let certificate = certificates[itemID] else { throw KeychainError.itemNotFound }
        return (certificate, certificateKeys[itemID])
    }

    func deleteCertificate(for itemID: UUID) throws {
        certificates[itemID] = nil
        certificateKeys[itemID] = nil
    }

    func saveSSHKey(publicKey: Data, privateKey: Data, for itemID: UUID) throws {
        sshPublicKeys[itemID] = publicKey
        sshPrivateKeys[itemID] = privateKey
    }

    func containsSSHKey(for itemID: UUID) throws -> Bool {
        containsCallCount += 1
        return sshPublicKeys[itemID] != nil && sshPrivateKeys[itemID] != nil
    }

    func sshKeyExistence(for itemID: UUID) -> SecretExistence {
        if let forcedExistence { return forcedExistence }
        return existence { try containsSSHKey(for: itemID) }
    }

    func retrieveSSHKey(for itemID: UUID) throws -> (publicKey: Data, privateKey: Data) {
        retrieveCallCount += 1
        guard let publicKey = sshPublicKeys[itemID],
              let privateKey = sshPrivateKeys[itemID] else {
            throw KeychainError.itemNotFound
        }
        return (publicKey, privateKey)
    }

    func deleteSSHKey(for itemID: UUID) throws {
        sshPublicKeys[itemID] = nil
        sshPrivateKeys[itemID] = nil
    }

    func saveNoteContent(_ content: Data, for itemID: UUID) throws {
        notes[itemID] = content
    }

    func containsNoteContent(for itemID: UUID) throws -> Bool {
        containsCallCount += 1
        return notes[itemID] != nil
    }

    func noteExistence(for itemID: UUID) -> SecretExistence {
        if let forcedExistence { return forcedExistence }
        return existence { try containsNoteContent(for: itemID) }
    }

    func retrieveNoteContent(for itemID: UUID) throws -> Data {
        retrieveCallCount += 1
        guard let note = notes[itemID] else { throw KeychainError.itemNotFound }
        return note
    }

    func deleteNoteContent(for itemID: UUID) throws {
        notes[itemID] = nil
    }

    private func existence(_ check: () throws -> Bool) -> SecretExistence {
        do {
            return try check() ? .present : .missing
        } catch {
            return .unavailable
        }
    }
}

private final class FakeVaultMetadataStore: VaultMetadataStoring {
    var passwords: [PasswordMetadata]
    var passwordDeletionTombstones: [PasswordDeletionTombstone]
    var apiKeys: [APIKeyMetadata]
    var apiKeyDeletionTombstones: [APIKeyDeletionTombstone]
    var certificates: [CertificateMetadata]
    var notes: [SecureNoteMetadata]
    var sshKeys: [SSHKeyMetadata]
    var folders: [VaultItemType: [String]]
    var folderStates: [VaultFolderState]
    var mergeFolderSaves: Bool
    var savedPasswords: [[PasswordMetadata]] = []
    var savedAPIKeys: [[APIKeyMetadata]] = []
    var savedCertificates: [[CertificateMetadata]] = []
    var savedNotes: [[SecureNoteMetadata]] = []
    var savedSSHKeys: [[SSHKeyMetadata]] = []
    var savedFolders: [[VaultItemType: [String]]] = []

    init(
        passwords: [PasswordMetadata] = [],
        passwordDeletionTombstones: [PasswordDeletionTombstone] = [],
        apiKeys: [APIKeyMetadata] = [],
        apiKeyDeletionTombstones: [APIKeyDeletionTombstone] = [],
        certificates: [CertificateMetadata] = [],
        notes: [SecureNoteMetadata] = [],
        sshKeys: [SSHKeyMetadata] = [],
        folders: [VaultItemType: [String]] = [:],
        folderStates: [VaultFolderState] = [],
        mergeFolderSaves: Bool = false
    ) {
        self.passwords = passwords
        self.passwordDeletionTombstones = passwordDeletionTombstones
        self.apiKeys = apiKeys
        self.apiKeyDeletionTombstones = apiKeyDeletionTombstones
        self.certificates = certificates
        self.notes = notes
        self.sshKeys = sshKeys
        self.folders = folders
        self.folderStates = folderStates
        self.mergeFolderSaves = mergeFolderSaves
    }

    func savePasswords(_ metadata: [PasswordMetadata]) throws {
        savedPasswords.append(metadata)
        passwords = metadata
    }

    func replacePasswords(_ metadata: [PasswordMetadata]) throws {
        try savePasswords(metadata)
    }

    func loadPasswords() throws -> [PasswordMetadata] {
        passwords
    }

    func savePasswordDeletionTombstones(_ tombstones: [PasswordDeletionTombstone]) throws {
        var byID = Dictionary(uniqueKeysWithValues: passwordDeletionTombstones.map { ($0.id, $0) })
        for tombstone in tombstones {
            if let existing = byID[tombstone.id], existing.deletedAt > tombstone.deletedAt {
                continue
            }
            byID[tombstone.id] = tombstone
        }
        passwordDeletionTombstones = byID.values.sorted { $0.deletedAt < $1.deletedAt }
    }

    func loadPasswordDeletionTombstones() throws -> [PasswordDeletionTombstone] {
        passwordDeletionTombstones
    }

    func saveAPIKeys(_ metadata: [APIKeyMetadata]) throws {
        savedAPIKeys.append(metadata)
        apiKeys = metadata
    }

    func replaceAPIKeys(_ metadata: [APIKeyMetadata]) throws {
        try saveAPIKeys(metadata)
    }

    func loadAPIKeys() throws -> [APIKeyMetadata] {
        apiKeys
    }

    func saveAPIKeyDeletionTombstones(_ tombstones: [APIKeyDeletionTombstone]) throws {
        var byID = Dictionary(uniqueKeysWithValues: apiKeyDeletionTombstones.map { ($0.id, $0) })
        for tombstone in tombstones where byID[tombstone.id].map({ $0.deletedAt <= tombstone.deletedAt }) ?? true {
            byID[tombstone.id] = tombstone
        }
        apiKeyDeletionTombstones = byID.values.sorted { $0.deletedAt < $1.deletedAt }
    }

    func loadAPIKeyDeletionTombstones() throws -> [APIKeyDeletionTombstone] {
        apiKeyDeletionTombstones
    }

    func saveCertificates(_ metadata: [CertificateMetadata]) throws {
        savedCertificates.append(metadata)
        certificates = metadata
    }

    func replaceCertificates(_ metadata: [CertificateMetadata]) throws {
        try saveCertificates(metadata)
    }

    func loadCertificates() throws -> [CertificateMetadata] {
        certificates
    }

    func saveNotes(_ metadata: [SecureNoteMetadata]) throws {
        savedNotes.append(metadata)
        notes = metadata
    }

    func replaceNotes(_ metadata: [SecureNoteMetadata]) throws {
        try saveNotes(metadata)
    }

    func loadNotes() throws -> [SecureNoteMetadata] {
        notes
    }

    func saveSSHKeys(_ metadata: [SSHKeyMetadata]) throws {
        savedSSHKeys.append(metadata)
        sshKeys = metadata
    }

    func replaceSSHKeys(_ metadata: [SSHKeyMetadata]) throws {
        try saveSSHKeys(metadata)
    }

    func loadSSHKeys() throws -> [SSHKeyMetadata] {
        sshKeys
    }

    func saveFolders(_ folders: [VaultItemType: [String]]) throws {
        let persisted: [VaultItemType: [String]]
        if mergeFolderSaves {
            var merged = self.folders
            for (type, paths) in folders {
                merged[type] = Array(Set((merged[type] ?? []) + paths)).sorted {
                    $0.localizedCaseInsensitiveCompare($1) == .orderedAscending
                }
            }
            persisted = merged
        } else {
            persisted = folders
        }
        savedFolders.append(persisted)
        self.folders = persisted
    }

    func replaceFolders(_ folders: [VaultItemType: [String]]) throws {
        savedFolders.append(folders)
        self.folders = folders
    }

    func loadFolders() throws -> [VaultItemType: [String]] {
        folders
    }

    func saveFolderStates(_ states: [VaultFolderState]) throws {
        var byID = Dictionary(uniqueKeysWithValues: folderStates.map { ("\($0.type.rawValue):\($0.path)", $0) })
        for state in states {
            let id = "\(state.type.rawValue):\(state.path)"
            if byID[id].map({ $0.modifiedAt > state.modifiedAt }) ?? false { continue }
            byID[id] = state
        }
        folderStates = Array(byID.values)
    }

    func loadFolderStates() throws -> [VaultFolderState] {
        folderStates
    }
}
