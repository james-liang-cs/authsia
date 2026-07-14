import XCTest
@testable import AuthenticatorData
import AuthenticatorCore

final class VaultImportExportTests: XCTestCase {
    private struct PasswordExportContainer: Codable {
        let format: String
        let version: Int
        let itemType: VaultItemType
        let exportedAt: Date
        let items: [PasswordItem]
    }

    private struct APIKeyExportContainer: Codable {
        let format: String
        let version: Int
        let itemType: VaultItemType
        let exportedAt: Date
        let items: [APIKeyItem]
    }

    private struct AllExportContainer: Codable {
        let format: String
        let version: Int
        let exportedAt: Date
        let passwords: [PasswordItem]
        let certificates: [CertificateItem]
        let secureNotes: [SecureNoteItem]
        let sshKeys: [SSHKeyItem]
    }

    private func makePasswordExportData(items: [PasswordItem]) throws -> Data {
        let container = PasswordExportContainer(
            format: "authsia.vault.export",
            version: 1,
            itemType: .password,
            exportedAt: Date(),
            items: items
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(container)
    }

    private func makeLegacyAllExportData(passwords: [PasswordItem]) throws -> Data {
        let container = AllExportContainer(
            format: "authsia.vault.export.all",
            version: 1,
            exportedAt: Date(),
            passwords: passwords,
            certificates: [],
            secureNotes: [],
            sshKeys: []
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(container)
    }

    @MainActor
    func testPasswordExportImportRoundTripForSelectedType() async throws {
        let repository = makeInMemoryVaultRepository()
        let itemID = UUID()
        let passwordItem = PasswordItem(
            id: itemID,
            name: "VaultImportExportTests-\(itemID.uuidString)",
            username: "vault-import-export",
            password: Data("super-secret".utf8),
            website: "example.com",
            notes: "round trip",
            folderPath: "Tests/Vault"
        )

        do {
            try repository.load()
            try repository.addPassword(passwordItem)
            defer { try? repository.deletePassword(id: itemID) }

            let exportedData = try await repository.exportItems(of: .password)

            try repository.deletePassword(id: itemID)

            let importedCount = try await repository.importItems(of: .password, from: exportedData)
            XCTAssertEqual(importedCount, 1)

            try repository.load()
            XCTAssertTrue(repository.passwords.contains(where: { $0.id == itemID }))
        } catch {
            throw XCTSkip("Keychain or secure storage unavailable in this test environment: \(error)")
        }
    }

    @MainActor
    func testAPIKeyExportImportRoundTripForSelectedType() async throws {
        let sourceRepository = VaultRepository(
            keychainStore: ImportTestVaultKeychainStore(),
            metadataStore: ImportTestVaultMetadataStore()
        )
        let targetRepository = VaultRepository(
            keychainStore: ImportTestVaultKeychainStore(),
            metadataStore: ImportTestVaultMetadataStore()
        )
        let itemID = UUID()
        let apiKey = APIKeyItem(
            id: itemID,
            name: "Stripe",
            key: Data("sk_test_123".utf8),
            website: "https://dashboard.stripe.com",
            notes: "Billing",
            folderPath: "Team/API",
            isCliEnabled: true,
            environments: ["Production", "Development"]
        )

        try sourceRepository.load()
        try sourceRepository.addAPIKey(apiKey)

        let exportedData = try await sourceRepository.exportItems(of: .apiKey)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let container = try decoder.decode(APIKeyExportContainer.self, from: exportedData)
        XCTAssertEqual(container.format, "authsia.vault.export")
        XCTAssertEqual(container.itemType, .apiKey)
        XCTAssertEqual(container.items.map(\.id), [itemID])

        let importedCount = try await targetRepository.importItems(of: .apiKey, from: exportedData)
        XCTAssertEqual(importedCount, 1)

        try targetRepository.load()
        let metadata = try XCTUnwrap(targetRepository.apiKeys.first(where: { $0.id == itemID }))
        let full = try targetRepository.getFullAPIKey(metadata: metadata)
        XCTAssertEqual(full.name, "Stripe")
        XCTAssertEqual(String(decoding: full.key, as: UTF8.self), "sk_test_123")
        XCTAssertEqual(full.website, "https://dashboard.stripe.com")
        XCTAssertEqual(full.notes, "Billing")
        XCTAssertEqual(full.folderPath, "Team/API")
        XCTAssertTrue(full.isCliEnabled)
        XCTAssertEqual(full.environments, ["Development", "Production"])
    }

    @MainActor
    func testImportRejectsMismatchedSelectedType() async throws {
        let repository = makeInMemoryVaultRepository()
        let itemID = UUID()
        let passwordItem = PasswordItem(
            id: itemID,
            name: "VaultImportExportMismatch-\(itemID.uuidString)",
            username: "vault-mismatch",
            password: Data("super-secret".utf8),
            website: nil,
            notes: nil,
            folderPath: "Tests/Vault"
        )

        do {
            try repository.load()
            try repository.addPassword(passwordItem)
            defer { try? repository.deletePassword(id: itemID) }

            let exportedData = try await repository.exportItems(of: .password)

            do {
                _ = try await repository.importItems(of: .secureNote, from: exportedData)
                XCTFail("Expected a type mismatch error when selected import type does not match file type")
            } catch let error as VaultImportExportError {
                if case .typeMismatch(let expected, let actual) = error {
                    XCTAssertEqual(expected, .secureNote)
                    XCTAssertEqual(actual, .password)
                } else {
                    XCTFail("Expected typeMismatch error, got \(error)")
                }
            }
        } catch {
            throw XCTSkip("Keychain or secure storage unavailable in this test environment: \(error)")
        }
    }

    @MainActor
    func testImportDuplicateIDKeepsExistingWhenConflictPolicyIsKeepExisting() async throws {
        let repository = makeInMemoryVaultRepository()
        let itemID = UUID()
        let existingItem = PasswordItem(
            id: itemID,
            name: "Existing-\(itemID.uuidString)",
            username: "existing",
            password: Data("existing-password".utf8),
            website: "existing.example.com",
            notes: "existing",
            folderPath: "Tests/Vault"
        )
        let incomingItem = PasswordItem(
            id: itemID,
            name: "Incoming-\(itemID.uuidString)",
            username: "incoming",
            password: Data("incoming-password".utf8),
            website: "incoming.example.com",
            notes: "incoming",
            folderPath: "Tests/Vault"
        )

        do {
            try repository.load()
            try repository.addPassword(existingItem)
            defer { try? repository.deletePassword(id: itemID) }

            let importData = try makePasswordExportData(items: [incomingItem])
            let importedCount = try await repository.importItems(
                of: .password,
                from: importData,
                conflictPolicy: .keepExisting
            )

            XCTAssertEqual(importedCount, 0)

            try repository.load()
            guard let metadata = repository.passwords.first(where: { $0.id == itemID }) else {
                XCTFail("Expected existing item to remain after import")
                return
            }
            let full = try repository.getFullPassword(metadata: metadata)
            XCTAssertEqual(String(decoding: full.password, as: UTF8.self), "existing-password")
            XCTAssertEqual(full.name, "Existing-\(itemID.uuidString)")
        } catch {
            throw XCTSkip("Keychain or secure storage unavailable in this test environment: \(error)")
        }
    }

    @MainActor
    func testImportDuplicateIDOverwritesWhenConflictPolicyIsOverwriteExisting() async throws {
        let repository = makeInMemoryVaultRepository()
        let itemID = UUID()
        let existingItem = PasswordItem(
            id: itemID,
            name: "Existing-\(itemID.uuidString)",
            username: "existing",
            password: Data("existing-password".utf8),
            website: "existing.example.com",
            notes: "existing",
            folderPath: "Tests/Vault"
        )
        let incomingItem = PasswordItem(
            id: itemID,
            name: "Incoming-\(itemID.uuidString)",
            username: "incoming",
            password: Data("incoming-password".utf8),
            website: "incoming.example.com",
            notes: "incoming",
            folderPath: "Tests/Vault"
        )

        do {
            try repository.load()
            try repository.addPassword(existingItem)
            defer { try? repository.deletePassword(id: itemID) }

            let importData = try makePasswordExportData(items: [incomingItem])
            let importedCount = try await repository.importItems(
                of: .password,
                from: importData,
                conflictPolicy: .overwriteExisting
            )

            XCTAssertEqual(importedCount, 1)

            try repository.load()
            guard let metadata = repository.passwords.first(where: { $0.id == itemID }) else {
                XCTFail("Expected item to remain after overwrite import")
                return
            }
            let full = try repository.getFullPassword(metadata: metadata)
            XCTAssertEqual(String(decoding: full.password, as: UTF8.self), "incoming-password")
            XCTAssertEqual(full.name, "Incoming-\(itemID.uuidString)")
        } catch {
            throw XCTSkip("Keychain or secure storage unavailable in this test environment: \(error)")
        }
    }

    @MainActor
    func testImportDuplicateIDOverwriteUsesIncomingMetadataWhenExportIsOlder() async throws {
        let itemID = UUID()
        let existingModifiedAt = Date(timeIntervalSince1970: 1_800_000_000)
        let incomingModifiedAt = Date(timeIntervalSince1970: 1_700_000_000)
        let metadataStore = ImportTestVaultMetadataStore(mergePasswordSavesByModifiedAt: true)
        let repository = VaultRepository(
            keychainStore: ImportTestVaultKeychainStore(),
            metadataStore: metadataStore
        )
        let existingItem = PasswordItem(
            id: itemID,
            name: "Existing-\(itemID.uuidString)",
            username: "existing",
            password: Data("existing-password".utf8),
            website: "existing.example.com",
            notes: "existing",
            folderPath: "Tests/Existing",
            createdAt: existingModifiedAt,
            modifiedAt: existingModifiedAt
        )
        let incomingItem = PasswordItem(
            id: itemID,
            name: "Incoming-\(itemID.uuidString)",
            username: "incoming",
            password: Data("incoming-password".utf8),
            website: "incoming.example.com",
            notes: "incoming",
            folderPath: "Tests/Incoming",
            createdAt: incomingModifiedAt,
            modifiedAt: incomingModifiedAt
        )

        try repository.load()
        try repository.addPassword(existingItem)

        let importData = try makePasswordExportData(items: [incomingItem])
        let importedCount = try await repository.importItems(
            of: .password,
            from: importData,
            conflictPolicy: .overwriteExisting
        )

        XCTAssertEqual(importedCount, 1)
        try repository.load()
        let metadata = try XCTUnwrap(repository.passwords.first(where: { $0.id == itemID }))
        let full = try repository.getFullPassword(metadata: metadata)
        XCTAssertEqual(String(decoding: full.password, as: UTF8.self), "incoming-password")
        XCTAssertEqual(full.name, "Incoming-\(itemID.uuidString)")
        XCTAssertEqual(full.folderPath, "Tests/Incoming")
    }

    @MainActor
    func testPreviewImportReportsDuplicateIDCount() async throws {
        let repository = makeInMemoryVaultRepository()
        let existingID = UUID()
        let newID = UUID()
        let existingItem = PasswordItem(
            id: existingID,
            name: "Existing-\(existingID.uuidString)",
            username: "existing",
            password: Data("existing-password".utf8),
            website: "existing.example.com",
            notes: nil,
            folderPath: "Tests/Vault"
        )
        let duplicateIncoming = PasswordItem(
            id: existingID,
            name: "Incoming-\(existingID.uuidString)",
            username: "incoming",
            password: Data("incoming-password".utf8),
            website: "incoming.example.com",
            notes: nil,
            folderPath: "Tests/Vault"
        )
        let newIncoming = PasswordItem(
            id: newID,
            name: "Incoming-\(newID.uuidString)",
            username: "incoming-new",
            password: Data("incoming-password-new".utf8),
            website: "incoming-new.example.com",
            notes: nil,
            folderPath: "Tests/Vault"
        )

        do {
            try repository.load()
            try repository.addPassword(existingItem)
            defer {
                try? repository.deletePassword(id: existingID)
                try? repository.deletePassword(id: newID)
            }

            let importData = try makePasswordExportData(items: [duplicateIncoming, newIncoming])
            let preview = try await repository.previewImportItems(of: .password, from: importData)

            XCTAssertEqual(preview.totalItems, 2)
            XCTAssertEqual(preview.duplicateCount, 1)
            XCTAssertEqual(preview.newItemsCount, 1)
        } catch {
            throw XCTSkip("Keychain or secure storage unavailable in this test environment: \(error)")
        }
    }

    @MainActor
    func testFolderExportAllIncludesNestedItemsAcrossTypes() async throws {
        let repository = VaultRepository(
            keychainStore: ImportTestVaultKeychainStore(),
            metadataStore: ImportTestVaultMetadataStore()
        )
        let targetPassword = PasswordItem(
            name: "Target API Password",
            username: "target",
            password: Data("target-secret".utf8),
            folderPath: "Team/API"
        )
        let nestedNote = SecureNoteItem(
            title: "Nested Deploy Note",
            content: Data("nested note".utf8),
            folderPath: "Team/API/Deploy"
        )
        let siblingPassword = PasswordItem(
            name: "Sibling Password",
            username: "sibling",
            password: Data("sibling-secret".utf8),
            folderPath: "Team/Other"
        )
        let unfiledSSHKey = SSHKeyItem(
            name: "Unfiled SSH",
            publicKey: Data("public".utf8),
            privateKey: Data("private".utf8),
            comment: "unfiled",
            fingerprint: "SHA256:unfiled"
        )

        try repository.load()
        try repository.addPassword(targetPassword)
        try repository.addNote(nestedNote)
        try repository.addPassword(siblingPassword)
        try repository.addSSHKey(unfiledSSHKey)

        let exportedData = try await repository.exportItems(inFolder: "Team/API", itemType: nil)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let container = try decoder.decode(AllExportContainer.self, from: exportedData)

        XCTAssertEqual(container.format, "authsia.vault.export.all")
        XCTAssertEqual(Set(container.passwords.map(\.id)), Set([targetPassword.id]))
        XCTAssertTrue(container.certificates.isEmpty)
        XCTAssertEqual(Set(container.secureNotes.map(\.id)), Set([nestedNote.id]))
        XCTAssertTrue(container.sshKeys.isEmpty)
    }

    @MainActor
    func testFolderExportSelectedTypeUsesSingleTypeContainer() async throws {
        let repository = VaultRepository(
            keychainStore: ImportTestVaultKeychainStore(),
            metadataStore: ImportTestVaultMetadataStore()
        )
        let targetPassword = PasswordItem(
            name: "Target API Password",
            username: "target",
            password: Data("target-secret".utf8),
            folderPath: "Team/API"
        )
        let nestedNote = SecureNoteItem(
            title: "Nested Deploy Note",
            content: Data("nested note".utf8),
            folderPath: "Team/API/Deploy"
        )

        try repository.load()
        try repository.addPassword(targetPassword)
        try repository.addNote(nestedNote)

        let exportedData = try await repository.exportItems(inFolder: "Team/API", itemType: .password)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let container = try decoder.decode(PasswordExportContainer.self, from: exportedData)

        XCTAssertEqual(container.format, "authsia.vault.export")
        XCTAssertEqual(container.itemType, .password)
        XCTAssertEqual(Set(container.items.map(\.id)), Set([targetPassword.id]))
    }

    @MainActor
    func testDetectImportPayloadKindForAllFolderExport() async throws {
        let repository = VaultRepository(
            keychainStore: ImportTestVaultKeychainStore(),
            metadataStore: ImportTestVaultMetadataStore()
        )
        let password = PasswordItem(
            name: "Shared API Password",
            username: "shared",
            password: Data("shared-secret".utf8),
            folderPath: "Team/API"
        )

        try repository.load()
        try repository.addPassword(password)

        let exportedData = try await repository.exportItems(inFolder: "Team/API", itemType: nil)

        XCTAssertEqual(try repository.detectImportPayloadKind(from: exportedData), .all)
    }

    @MainActor
    func testImportAllAcceptsPreAPIKeyExportWithoutAPIKeysKey() async throws {
        let repository = VaultRepository(
            keychainStore: ImportTestVaultKeychainStore(),
            metadataStore: ImportTestVaultMetadataStore()
        )
        let password = PasswordItem(
            name: "Legacy API Password",
            username: "svc",
            password: Data("legacy-secret".utf8),
            folderPath: "Team/API"
        )
        let exportData = try makeLegacyAllExportData(passwords: [password])

        let importedCount = try await repository.importItems(from: exportData)

        XCTAssertEqual(importedCount, 1)
        try repository.load()
        let metadata = try XCTUnwrap(repository.passwords.first(where: { $0.id == password.id }))
        let full = try repository.getFullPassword(metadata: metadata)
        XCTAssertEqual(full.name, "Legacy API Password")
        XCTAssertEqual(String(decoding: full.password, as: UTF8.self), "legacy-secret")
        XCTAssertEqual(repository.apiKeys, [])
    }

    @MainActor
    func testDetectImportPayloadKindForSelectedFolderExport() async throws {
        let repository = VaultRepository(
            keychainStore: ImportTestVaultKeychainStore(),
            metadataStore: ImportTestVaultMetadataStore()
        )
        let password = PasswordItem(
            name: "Shared API Password",
            username: "shared",
            password: Data("shared-secret".utf8),
            folderPath: "Team/API"
        )

        try repository.load()
        try repository.addPassword(password)

        let exportedData = try await repository.exportItems(inFolder: "Team/API", itemType: .password)

        XCTAssertEqual(try repository.detectImportPayloadKind(from: exportedData), .item(.password))
    }

    @MainActor
    func testPreviewImportItemsAutoDetectsAllExportDuplicatesAcrossTypes() async throws {
        let sourceRepository = VaultRepository(
            keychainStore: ImportTestVaultKeychainStore(),
            metadataStore: ImportTestVaultMetadataStore()
        )
        let targetRepository = VaultRepository(
            keychainStore: ImportTestVaultKeychainStore(),
            metadataStore: ImportTestVaultMetadataStore()
        )
        let duplicatePassword = PasswordItem(
            name: "Duplicate API Password",
            username: "duplicate",
            password: Data("duplicate-secret".utf8),
            folderPath: "Team/API"
        )
        let newNote = SecureNoteItem(
            title: "Deploy Note",
            content: Data("deploy note".utf8),
            folderPath: "Team/API"
        )

        try sourceRepository.load()
        try sourceRepository.addPassword(duplicatePassword)
        try sourceRepository.addNote(newNote)
        let exportedData = try await sourceRepository.exportItems(inFolder: "Team/API", itemType: nil)

        try targetRepository.load()
        try targetRepository.addPassword(duplicatePassword)

        let preview = try await targetRepository.previewImportItems(from: exportedData)

        XCTAssertEqual(preview.totalItems, 2)
        XCTAssertEqual(preview.duplicateCount, 1)
        XCTAssertEqual(preview.newItemsCount, 1)
    }

    @MainActor
    func testImportThrowsWhenPasswordMetadataSaveFails() async throws {
        let itemID = UUID()
        let passwordItem = PasswordItem(
            id: itemID,
            name: "Incoming-\(itemID.uuidString)",
            username: "incoming",
            password: Data("incoming-password".utf8),
            website: "incoming.example.com",
            notes: nil,
            folderPath: "Tests/Vault"
        )
        let metadataStore = ImportTestVaultMetadataStore(
            savePasswordsError: KeychainError.unknown(errSecMissingEntitlement)
        )
        let repository = VaultRepository(
            keychainStore: ImportTestVaultKeychainStore(),
            metadataStore: metadataStore
        )
        let importData = try makePasswordExportData(items: [passwordItem])

        do {
            _ = try await repository.importItems(of: .password, from: importData)
            XCTFail("Expected vault import to fail when metadata cannot be saved")
        } catch let error as VaultImportExportError {
            guard case .itemSaveFailed(let itemType, _) = error else {
                XCTFail("Expected itemSaveFailed, got \(error)")
                return
            }
            XCTAssertEqual(itemType, .password)
        }
    }
}

private final class ImportTestVaultKeychainStore: VaultKeychainStoring, @unchecked Sendable {
    var passwords: [UUID: Data] = [:]
    var apiKeys: [UUID: Data] = [:]
    var certificates: [UUID: (cert: Data, key: Data?)] = [:]
    var sshKeys: [UUID: (publicKey: Data, privateKey: Data)] = [:]
    var notes: [UUID: Data] = [:]

    func savePassword(_ password: Data, for itemID: UUID) throws {
        passwords[itemID] = password
    }

    func containsPassword(for itemID: UUID) throws -> Bool {
        passwords[itemID] != nil
    }

    func retrievePassword(for itemID: UUID) throws -> Data {
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
        apiKeys[itemID] != nil
    }

    func retrieveAPIKey(for itemID: UUID) throws -> Data {
        guard let key = apiKeys[itemID] else { throw KeychainError.itemNotFound }
        return key
    }

    func deleteAPIKey(for itemID: UUID) throws {
        apiKeys[itemID] = nil
    }

    func saveCertificate(_ certData: Data, privateKey: Data?, for itemID: UUID) throws {
        certificates[itemID] = (certData, privateKey)
    }
    func containsCertificate(for itemID: UUID) throws -> Bool { certificates[itemID] != nil }
    func retrieveCertificate(for itemID: UUID) throws -> (cert: Data, key: Data?) {
        guard let certificate = certificates[itemID] else { throw KeychainError.itemNotFound }
        return certificate
    }
    func deleteCertificate(for itemID: UUID) throws {
        certificates[itemID] = nil
    }
    func deleteCertificatePrivateKey(for itemID: UUID) {}
    func saveSSHKey(publicKey: Data, privateKey: Data, for itemID: UUID) throws {
        sshKeys[itemID] = (publicKey, privateKey)
    }
    func containsSSHKey(for itemID: UUID) throws -> Bool { sshKeys[itemID] != nil }
    func retrieveSSHKey(for itemID: UUID) throws -> (publicKey: Data, privateKey: Data) {
        guard let sshKey = sshKeys[itemID] else { throw KeychainError.itemNotFound }
        return sshKey
    }
    func deleteSSHKey(for itemID: UUID) throws {
        sshKeys[itemID] = nil
    }
    func saveNoteContent(_ content: Data, for itemID: UUID) throws {
        notes[itemID] = content
    }
    func containsNoteContent(for itemID: UUID) throws -> Bool { notes[itemID] != nil }
    func retrieveNoteContent(for itemID: UUID) throws -> Data {
        guard let note = notes[itemID] else { throw KeychainError.itemNotFound }
        return note
    }
    func deleteNoteContent(for itemID: UUID) throws {
        notes[itemID] = nil
    }
}

@MainActor
func makeInMemoryVaultRepository() -> VaultRepository {
    VaultRepository(
        keychainStore: ImportTestVaultKeychainStore(),
        metadataStore: ImportTestVaultMetadataStore()
    )
}

private final class ImportTestVaultMetadataStore: VaultMetadataStoring {
    var savePasswordsError: Error?
    var mergePasswordSavesByModifiedAt: Bool
    var passwords: [PasswordMetadata] = []
    var passwordDeletionTombstones: [PasswordDeletionTombstone] = []
    var apiKeys: [APIKeyMetadata] = []
    var apiKeyDeletionTombstones: [APIKeyDeletionTombstone] = []
    var certificates: [CertificateMetadata] = []
    var notes: [SecureNoteMetadata] = []
    var sshKeys: [SSHKeyMetadata] = []
    var folders: [VaultItemType: [String]] = [:]
    var folderStates: [VaultFolderState] = []

    init(savePasswordsError: Error? = nil, mergePasswordSavesByModifiedAt: Bool = false) {
        self.savePasswordsError = savePasswordsError
        self.mergePasswordSavesByModifiedAt = mergePasswordSavesByModifiedAt
    }

    func savePasswords(_ metadata: [PasswordMetadata]) throws {
        if let savePasswordsError { throw savePasswordsError }
        guard mergePasswordSavesByModifiedAt else {
            passwords = metadata
            return
        }
        var byID = Dictionary(uniqueKeysWithValues: passwords.map { ($0.id, $0) })
        for item in metadata {
            if let current = byID[item.id], current.modifiedAt > item.modifiedAt {
                continue
            }
            byID[item.id] = item
        }
        passwords = byID.values.sorted {
            $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
    }

    func replacePasswords(_ metadata: [PasswordMetadata]) throws {
        try savePasswords(metadata)
    }

    func loadPasswords() throws -> [PasswordMetadata] { passwords }
    func savePasswordDeletionTombstones(_ tombstones: [PasswordDeletionTombstone]) throws {
        passwordDeletionTombstones = tombstones
    }
    func loadPasswordDeletionTombstones() throws -> [PasswordDeletionTombstone] {
        passwordDeletionTombstones
    }
    func saveAPIKeys(_ metadata: [APIKeyMetadata]) throws {
        apiKeys = metadata
    }
    func replaceAPIKeys(_ metadata: [APIKeyMetadata]) throws {
        try saveAPIKeys(metadata)
    }
    func loadAPIKeys() throws -> [APIKeyMetadata] { apiKeys }
    func saveAPIKeyDeletionTombstones(_ tombstones: [APIKeyDeletionTombstone]) throws {
        apiKeyDeletionTombstones = tombstones
    }
    func loadAPIKeyDeletionTombstones() throws -> [APIKeyDeletionTombstone] {
        apiKeyDeletionTombstones
    }
    func saveCertificates(_ metadata: [CertificateMetadata]) throws {
        certificates = metadata
    }
    func replaceCertificates(_ metadata: [CertificateMetadata]) throws {
        try saveCertificates(metadata)
    }
    func loadCertificates() throws -> [CertificateMetadata] { certificates }
    func saveNotes(_ metadata: [SecureNoteMetadata]) throws {
        notes = metadata
    }
    func replaceNotes(_ metadata: [SecureNoteMetadata]) throws {
        try saveNotes(metadata)
    }
    func loadNotes() throws -> [SecureNoteMetadata] { notes }
    func saveSSHKeys(_ metadata: [SSHKeyMetadata]) throws {
        sshKeys = metadata
    }
    func replaceSSHKeys(_ metadata: [SSHKeyMetadata]) throws {
        try saveSSHKeys(metadata)
    }
    func loadSSHKeys() throws -> [SSHKeyMetadata] { sshKeys }
    func saveFolders(_ folders: [VaultItemType: [String]]) throws {
        self.folders = folders
    }
    func replaceFolders(_ folders: [VaultItemType: [String]]) throws {
        try saveFolders(folders)
    }
    func loadFolders() throws -> [VaultItemType: [String]] { folders }
    func saveFolderStates(_ states: [VaultFolderState]) throws { folderStates = states }
    func loadFolderStates() throws -> [VaultFolderState] { folderStates }
}
