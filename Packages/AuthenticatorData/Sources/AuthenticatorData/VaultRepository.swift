import Foundation
import Security
import AuthenticatorCore

/// Tri-state result of an existence probe against the vault keychain.
///
/// `errSecMissingEntitlement`, `errSecInteractionNotAllowed`, and `errSecAuthFailed`
/// can all be returned by `SecItemCopyMatching` on hardened or MDM-managed Macs
/// when the calling process is not in the item's ACL. They look identical to
/// "user deleted the secret" if we collapse to `Bool`. Treating those as
/// `.unavailable` lets callers refuse to take destructive action.
enum SecretExistence: Equatable {
    case present
    case missing
    case unavailable
}

protocol VaultKeychainStoring: AnyObject, Sendable {
    func savePassword(_ password: Data, for itemID: UUID) throws
    func containsPassword(for itemID: UUID) throws -> Bool
    func passwordExistence(for itemID: UUID) -> SecretExistence
    func retrievePassword(for itemID: UUID) throws -> Data
    func deletePassword(for itemID: UUID) throws
    func saveAPIKey(_ key: Data, for itemID: UUID) throws
    func containsAPIKey(for itemID: UUID) throws -> Bool
    func apiKeyExistence(for itemID: UUID) -> SecretExistence
    func retrieveAPIKey(for itemID: UUID) throws -> Data
    func deleteAPIKey(for itemID: UUID) throws
    func saveCertificate(_ certData: Data, privateKey: Data?, for itemID: UUID) throws
    func containsCertificate(for itemID: UUID) throws -> Bool
    func certificateExistence(for itemID: UUID) -> SecretExistence
    func retrieveCertificate(for itemID: UUID) throws -> (cert: Data, key: Data?)
    func deleteCertificate(for itemID: UUID) throws
    func deleteCertificatePrivateKey(for itemID: UUID)
    func saveSSHKey(publicKey: Data, privateKey: Data, for itemID: UUID) throws
    func containsSSHKey(for itemID: UUID) throws -> Bool
    func sshKeyExistence(for itemID: UUID) -> SecretExistence
    func retrieveSSHKey(for itemID: UUID) throws -> (publicKey: Data, privateKey: Data)
    func deleteSSHKey(for itemID: UUID) throws
    func saveNoteContent(_ content: Data, for itemID: UUID) throws
    func containsNoteContent(for itemID: UUID) throws -> Bool
    func noteExistence(for itemID: UUID) -> SecretExistence
    func retrieveNoteContent(for itemID: UUID) throws -> Data
    func deleteNoteContent(for itemID: UUID) throws
}

extension VaultKeychainStoring {
    func passwordExistence(for itemID: UUID) -> SecretExistence {
        Self.existence { try self.containsPassword(for: itemID) }
    }

    func apiKeyExistence(for itemID: UUID) -> SecretExistence {
        Self.existence { try self.containsAPIKey(for: itemID) }
    }

    func certificateExistence(for itemID: UUID) -> SecretExistence {
        Self.existence { try self.containsCertificate(for: itemID) }
    }

    func sshKeyExistence(for itemID: UUID) -> SecretExistence {
        Self.existence { try self.containsSSHKey(for: itemID) }
    }

    func noteExistence(for itemID: UUID) -> SecretExistence {
        Self.existence { try self.containsNoteContent(for: itemID) }
    }

    /// Maps a throwing `Bool` existence probe into a `SecretExistence`. Errors
    /// that are known to mean "denied / not allowed to read" become
    /// `.unavailable` rather than collapsing to a missing item.
    fileprivate static func existence(_ check: () throws -> Bool) -> SecretExistence {
        do {
            return try check() ? .present : .missing
        } catch let KeychainError.unknown(status) where Self.isUnavailable(status) {
            return .unavailable
        } catch {
            return .unavailable
        }
    }

    fileprivate static func isUnavailable(_ status: OSStatus) -> Bool {
        switch status {
        case errSecMissingEntitlement,
             errSecInteractionNotAllowed,
             errSecAuthFailed,
             errSecUserCanceled:
            return true
        default:
            return false
        }
    }
}

extension VaultKeychainStore: VaultKeychainStoring {}

protocol VaultMetadataStoring: AnyObject {
    func savePasswords(_ metadata: [PasswordMetadata]) throws
    func replacePasswords(_ metadata: [PasswordMetadata]) throws
    func loadPasswords() throws -> [PasswordMetadata]
    func savePasswordDeletionTombstones(_ tombstones: [PasswordDeletionTombstone]) throws
    func loadPasswordDeletionTombstones() throws -> [PasswordDeletionTombstone]
    func saveAPIKeys(_ metadata: [APIKeyMetadata]) throws
    func replaceAPIKeys(_ metadata: [APIKeyMetadata]) throws
    func loadAPIKeys() throws -> [APIKeyMetadata]
    func saveAPIKeyDeletionTombstones(_ tombstones: [APIKeyDeletionTombstone]) throws
    func loadAPIKeyDeletionTombstones() throws -> [APIKeyDeletionTombstone]
    func saveCertificates(_ metadata: [CertificateMetadata]) throws
    func replaceCertificates(_ metadata: [CertificateMetadata]) throws
    func loadCertificates() throws -> [CertificateMetadata]
    func saveNotes(_ metadata: [SecureNoteMetadata]) throws
    func replaceNotes(_ metadata: [SecureNoteMetadata]) throws
    func loadNotes() throws -> [SecureNoteMetadata]
    func saveSSHKeys(_ metadata: [SSHKeyMetadata]) throws
    func replaceSSHKeys(_ metadata: [SSHKeyMetadata]) throws
    func loadSSHKeys() throws -> [SSHKeyMetadata]
    func saveFolders(_ folders: [VaultItemType: [String]]) throws
    func replaceFolders(_ folders: [VaultItemType: [String]]) throws
    func loadFolders() throws -> [VaultItemType: [String]]
    func saveFolderStates(_ states: [VaultFolderState]) throws
    func loadFolderStates() throws -> [VaultFolderState]
}

extension VaultMetadataStore: VaultMetadataStoring {}

public struct VaultMetadataRebuildSummary: Equatable, Sendable {
    public let passwordCount: Int
    public let apiKeyCount: Int
    public let certificateCount: Int
    public let noteCount: Int
    public let sshKeyCount: Int

    public var totalCount: Int {
        passwordCount + apiKeyCount + certificateCount + noteCount + sshKeyCount
    }

    public init(
        passwordCount: Int,
        apiKeyCount: Int = 0,
        certificateCount: Int,
        noteCount: Int,
        sshKeyCount: Int
    ) {
        self.passwordCount = passwordCount
        self.apiKeyCount = apiKeyCount
        self.certificateCount = certificateCount
        self.noteCount = noteCount
        self.sshKeyCount = sshKeyCount
    }
}

public struct VaultFullItemSnapshot {
    public let passwords: [PasswordItem]
    public let apiKeys: [APIKeyItem]
    public let certificates: [CertificateItem]
    public let notes: [SecureNoteItem]
    public let sshKeys: [SSHKeyItem]

    public init(
        passwords: [PasswordItem],
        apiKeys: [APIKeyItem] = [],
        certificates: [CertificateItem],
        notes: [SecureNoteItem],
        sshKeys: [SSHKeyItem]
    ) {
        self.passwords = passwords
        self.apiKeys = apiKeys
        self.certificates = certificates
        self.notes = notes
        self.sshKeys = sshKeys
    }
}

@MainActor
public class VaultRepository {
    public static let shared = VaultRepository()

    private let keychain: any VaultKeychainStoring
    private let metadataStore: any VaultMetadataStoring
    private let cliMetadataSnapshotStore: (any VaultCLIMetadataSnapshotStoring)?

    public private(set) var passwords: [PasswordMetadata] = []
    public private(set) var apiKeys: [APIKeyMetadata] = []
    public private(set) var certificates: [CertificateMetadata] = []
    public private(set) var notes: [SecureNoteMetadata] = []
    public private(set) var sshKeys: [SSHKeyMetadata] = []
    public private(set) var folders: [VaultItemType: [String]] = [:]
    public private(set) var hasLoadedVaultState = false
    private static let backupManifestBaseNoteName = "authsia_scrape_backups_manifest"
    private static let backupManifestNoteName = "authsia_scrape_backups_manifest__authsia_backups"
    private static let backupFolderPath = "Authsia Backups"

    public init(
        keychain: VaultKeychainStore = .shared,
        metadataStore: VaultMetadataStore = .shared,
        cliMetadataSnapshotStore: VaultCLIMetadataSnapshotStore = .shared
    ) {
        self.keychain = keychain
        self.metadataStore = metadataStore
        self.cliMetadataSnapshotStore = cliMetadataSnapshotStore
    }

    init(
        keychainStore: any VaultKeychainStoring,
        metadataStore: any VaultMetadataStoring,
        cliMetadataSnapshotStore: (any VaultCLIMetadataSnapshotStoring)? = nil
    ) {
        self.keychain = keychainStore
        self.metadataStore = metadataStore
        self.cliMetadataSnapshotStore = cliMetadataSnapshotStore
    }

    // MARK: - Load All

    public func load() throws {
        try load(currentDate: Date())
    }

    public func load(currentDate: Date) throws {
        let loadedPasswords = try metadataStore.loadPasswords()
        let passwordDeletionTombstones = try metadataStore.loadPasswordDeletionTombstones()
        let loadedAPIKeys = try metadataStore.loadAPIKeys()
        let apiKeyDeletionTombstones = try metadataStore.loadAPIKeyDeletionTombstones()
        let loadedCertificates = try metadataStore.loadCertificates()
        let loadedNotes = try metadataStore.loadNotes()
        let loadedSSHKeys = try metadataStore.loadSSHKeys()

        let expiredPasswordIDs = Set(loadedPasswords.filter {
            $0.autoDestroyOnExpiry && Self.isExpired($0.expiresAt, currentDate: currentDate)
        }.map(\.id))
        let expiredAPIKeyIDs = Set(loadedAPIKeys.filter {
            $0.autoDestroyOnExpiry && Self.isExpired($0.expiresAt, currentDate: currentDate)
        }.map(\.id))

        let visiblePasswordsByID = Dictionary(uniqueKeysWithValues: loadedPasswords.map { ($0.id, $0) })
        for tombstone in passwordDeletionTombstones {
            if let visible = visiblePasswordsByID[tombstone.id], visible.modifiedAt > tombstone.deletedAt {
                continue
            }
            try? keychain.deletePassword(for: tombstone.id)
        }
        let visibleAPIKeysByID = Dictionary(uniqueKeysWithValues: loadedAPIKeys.map { ($0.id, $0) })
        for tombstone in apiKeyDeletionTombstones {
            if let visible = visibleAPIKeysByID[tombstone.id], visible.modifiedAt > tombstone.deletedAt {
                continue
            }
            try? keychain.deleteAPIKey(for: tombstone.id)
        }

        let unexpiredPasswords = loadedPasswords.filter { !expiredPasswordIDs.contains($0.id) }
        let unexpiredAPIKeys = loadedAPIKeys.filter { !expiredAPIKeyIDs.contains($0.id) }
        let prunedPasswords = pruneMissingMetadata(unexpiredPasswords, existence: keychain.passwordExistence)
        let prunedAPIKeys = pruneMissingMetadata(unexpiredAPIKeys, existence: keychain.apiKeyExistence)
        let prunedCertificates = pruneMissingMetadata(loadedCertificates, existence: keychain.certificateExistence)
        let prunedNotes = pruneMissingMetadata(loadedNotes, existence: keychain.noteExistence)
        let prunedSSHKeys = pruneMissingMetadata(loadedSSHKeys, existence: keychain.sshKeyExistence)
        var changedNames: [Notification.Name] = []

        passwords = prunedPasswords.metadata
        apiKeys = prunedAPIKeys.metadata
        certificates = prunedCertificates.metadata
        notes = prunedNotes.metadata
        sshKeys = prunedSSHKeys.metadata

        if !expiredPasswordIDs.isEmpty {
            try recordPasswordDeletions(expiredPasswordIDs, deletedAt: currentDate)
        }
        if !expiredPasswordIDs.isEmpty || prunedPasswords.didPrune {
            try metadataStore.replacePasswords(passwords)
            changedNames.append(.vaultPasswordsDidChange)
        }
        if !expiredAPIKeyIDs.isEmpty || prunedAPIKeys.didPrune {
            try metadataStore.replaceAPIKeys(apiKeys)
            changedNames.append(.vaultAPIKeysDidChange)
        }
        if prunedCertificates.didPrune {
            try metadataStore.replaceCertificates(certificates)
            changedNames.append(.vaultCertificatesDidChange)
        }
        if prunedNotes.didPrune {
            try metadataStore.replaceNotes(notes)
            changedNames.append(.vaultNotesDidChange)
        }
        if prunedSSHKeys.didPrune {
            try metadataStore.replaceSSHKeys(sshKeys)
            changedNames.append(.vaultSSHKeysDidChange)
        }
        try deleteExpiredSecrets(passwordIDs: expiredPasswordIDs, apiKeyIDs: expiredAPIKeyIDs)

        folders = try metadataStore.loadFolders()
        mergeFoldersFromMetadata()
        try? saveCLIMetadataSnapshot()
        hasLoadedVaultState = true
        postVaultChanges(changedNames)
    }

    private func pruneMissingMetadata<Metadata: Identifiable>(
        _ metadata: [Metadata],
        existence: (UUID) -> SecretExistence
    ) -> (metadata: [Metadata], didPrune: Bool) where Metadata.ID == UUID {
        var retained: [Metadata] = []
        var didPrune = false

        for item in metadata {
            switch existence(item.id) {
            case .present, .unavailable:
                retained.append(item)
            case .missing:
                didPrune = true
            }
        }

        return (retained, didPrune)
    }

    @discardableResult
    public func migrateLegacyBackupNotesIfNeeded(currentDate: Date = Date()) throws -> Bool {
        try loadIfNeeded()

        let legacyManifestNotes = notes.filter {
            isBackupManifestNote($0) && !isCurrentBackupManifestNote($0)
        }
        guard !legacyManifestNotes.isEmpty else { return false }

        let existingRootManifestNote = notes.first(where: isCurrentBackupManifestNote)
        var rootManifest = try existingRootManifestNote.map {
            try decodeBackupManifest($0, defaultEntryFolderPath: Self.backupFolderPath)
        } ?? BackupManifest(lastUpdated: currentDate)
        var seenEntryIDs = Set(rootManifest.backups.map(\.id))
        var backupNoteIDsToMove = Set<UUID>()
        var didMigrate = false

        for manifestNote in legacyManifestNotes {
            let legacyManifest = try decodeBackupManifest(
                manifestNote,
                defaultEntryFolderPath: manifestNote.folderPath
            )
            for var entry in legacyManifest.backups where seenEntryIDs.insert(entry.id).inserted {
                if let backupNoteID = resolveBackupNoteID(for: entry, legacyManifestFolderPath: manifestNote.folderPath) {
                    backupNoteIDsToMove.insert(backupNoteID)
                    entry.backupNoteId = backupNoteID.uuidString
                    entry.folderPath = Self.backupFolderPath
                }
                rootManifest.backups.append(entry)
                didMigrate = true
            }
        }

        guard didMigrate else { return false }

        let rootManifestID: UUID
        if let existingRootManifestNote {
            rootManifestID = existingRootManifestNote.id
        } else {
            rootManifestID = UUID()
            notes.append(SecureNoteMetadata(
                id: rootManifestID,
                title: Self.backupManifestNoteName,
                folderPath: Self.backupFolderPath,
                createdAt: currentDate,
                modifiedAt: currentDate,
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false
            ))
        }

        rootManifest.lastUpdated = currentDate
        try keychain.saveNoteContent(try Self.encodeBackupManifest(rootManifest), for: rootManifestID)

        for index in notes.indices {
            if notes[index].id == rootManifestID || backupNoteIDsToMove.contains(notes[index].id) {
                notes[index].folderPath = Self.backupFolderPath
                notes[index].modifiedAt = currentDate
            }
        }
        notes.sort { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        try metadataStore.saveNotes(notes)
        try registerFolderIfNeeded(Self.backupFolderPath, type: .secureNote)
        try saveCLIMetadataSnapshot()
        postVaultChange(.vaultNotesDidChange)
        return true
    }

    private func loadIfNeeded() throws {
        guard !hasLoadedVaultState else { return }
        try load()
    }

    /// Mutations must apply to the latest persisted state, not this process's
    /// cached copy. The GUI app and the headless bridge each hold their own
    /// long-lived VaultRepository; metadata is stored as whole arrays, so
    /// saving from a stale cache silently erases items the other process
    /// added since our last load.
    private func prepareForMutation() throws {
        guard hasLoadedVaultState else {
            try load()
            return
        }
        passwords = try metadataStore.loadPasswords()
        apiKeys = try metadataStore.loadAPIKeys()
        certificates = try metadataStore.loadCertificates()
        notes = try metadataStore.loadNotes()
        sshKeys = try metadataStore.loadSSHKeys()
        folders = try metadataStore.loadFolders()
    }

    public func collectFullItemsForCurrentStoragePolicy() throws -> VaultFullItemSnapshot {
        passwords = try metadataStore.loadPasswords()
        apiKeys = try metadataStore.loadAPIKeys()
        certificates = try metadataStore.loadCertificates()
        notes = try metadataStore.loadNotes()
        sshKeys = try metadataStore.loadSSHKeys()
        folders = try metadataStore.loadFolders()
        mergeFoldersFromMetadata()

        let passwordSnapshot = try collectAvailableFullItems(passwords, load: getFullPassword)
        let apiKeySnapshot = try collectAvailableFullItems(apiKeys, load: getFullAPIKey)
        let certificateSnapshot = try collectAvailableFullItems(certificates, load: getFullCertificate)
        let noteSnapshot = try collectAvailableFullItems(notes, load: getFullNote)
        let sshKeySnapshot = try collectAvailableFullItems(sshKeys, load: getFullSSHKey)
        var changedNames: [Notification.Name] = []

        if passwordSnapshot.metadata.count != passwords.count {
            passwords = passwordSnapshot.metadata
            try metadataStore.replacePasswords(passwords)
            changedNames.append(.vaultPasswordsDidChange)
        }
        if apiKeySnapshot.metadata.count != apiKeys.count {
            apiKeys = apiKeySnapshot.metadata
            try metadataStore.replaceAPIKeys(apiKeys)
            changedNames.append(.vaultAPIKeysDidChange)
        }
        if certificateSnapshot.metadata.count != certificates.count {
            certificates = certificateSnapshot.metadata
            try metadataStore.replaceCertificates(certificates)
            changedNames.append(.vaultCertificatesDidChange)
        }
        if noteSnapshot.metadata.count != notes.count {
            notes = noteSnapshot.metadata
            try metadataStore.replaceNotes(notes)
            changedNames.append(.vaultNotesDidChange)
        }
        if sshKeySnapshot.metadata.count != sshKeys.count {
            sshKeys = sshKeySnapshot.metadata
            try metadataStore.replaceSSHKeys(sshKeys)
            changedNames.append(.vaultSSHKeysDidChange)
        }

        if !changedNames.isEmpty {
            try saveCLIMetadataSnapshot()
            postVaultChanges(changedNames)
        }

        return VaultFullItemSnapshot(
            passwords: passwordSnapshot.items,
            apiKeys: apiKeySnapshot.items,
            certificates: certificateSnapshot.items,
            notes: noteSnapshot.items,
            sshKeys: sshKeySnapshot.items
        )
    }

    private func collectAvailableFullItems<Metadata, Item>(
        _ metadataItems: [Metadata],
        load: (Metadata) throws -> Item
    ) throws -> (items: [Item], metadata: [Metadata]) {
        var items: [Item] = []
        var retainedMetadata: [Metadata] = []

        for metadata in metadataItems {
            do {
                items.append(try load(metadata))
                retainedMetadata.append(metadata)
            } catch KeychainError.itemNotFound {
                continue
            }
        }

        return (items, retainedMetadata)
    }

    private func mergeAvailableFullItems<Metadata, Item>(
        snapshotItems: [Item],
        currentMetadata: [Metadata],
        load: (Metadata) throws -> Item,
        id: (Item) -> UUID,
        modifiedAt: (Item) -> Date,
        sort: (Item, Item) -> Bool
    ) throws -> [Item] where Metadata: Identifiable, Metadata.ID == UUID {
        var itemsByID: [UUID: Item] = [:]
        var missingCurrentIDs = Set<UUID>()

        for metadata in currentMetadata {
            do {
                let currentItem = try load(metadata)
                itemsByID[id(currentItem)] = currentItem
            } catch KeychainError.itemNotFound {
                missingCurrentIDs.insert(metadata.id)
            }
        }

        for snapshotItem in snapshotItems {
            let snapshotID = id(snapshotItem)
            guard !missingCurrentIDs.contains(snapshotID) else { continue }
            if let currentItem = itemsByID[snapshotID],
               modifiedAt(currentItem) > modifiedAt(snapshotItem) {
                continue
            }
            itemsByID[snapshotID] = snapshotItem
        }

        return itemsByID.values.sorted(by: sort)
    }

    public func saveFullItemsToCurrentStoragePolicy(_ snapshot: VaultFullItemSnapshot) throws {
        let currentPasswords = try metadataStore.loadPasswords()
        let currentAPIKeys = try metadataStore.loadAPIKeys()
        let currentAPIKeyDeletionTombstones = try metadataStore.loadAPIKeyDeletionTombstones()
        let currentCertificates = try metadataStore.loadCertificates()
        let currentNotes = try metadataStore.loadNotes()
        let currentSSHKeys = try metadataStore.loadSSHKeys()
        let currentFolders = try metadataStore.loadFolders()
        let currentFolderStates = try metadataStore.loadFolderStates()

        let mergedPasswords = try mergeAvailableFullItems(
            snapshotItems: snapshot.passwords,
            currentMetadata: currentPasswords,
            load: getFullPassword,
            id: \.id,
            modifiedAt: \.modifiedAt,
            sort: { Self.localizedAscending($0.name, $1.name) }
        )
        let apiKeyTombstonesByID = Dictionary(
            uniqueKeysWithValues: currentAPIKeyDeletionTombstones.map { ($0.id, $0) }
        )
        let visibleSnapshotAPIKeys = snapshot.apiKeys.filter { item in
            guard let tombstone = apiKeyTombstonesByID[item.id] else { return true }
            return item.modifiedAt > tombstone.deletedAt
        }
        let mergedAPIKeys = try mergeAvailableFullItems(
            snapshotItems: visibleSnapshotAPIKeys,
            currentMetadata: currentAPIKeys,
            load: getFullAPIKey,
            id: \.id,
            modifiedAt: \.modifiedAt,
            sort: { Self.localizedAscending($0.name, $1.name) }
        )
        let mergedCertificates = try mergeAvailableFullItems(
            snapshotItems: snapshot.certificates,
            currentMetadata: currentCertificates,
            load: getFullCertificate,
            id: \.id,
            modifiedAt: \.modifiedAt,
            sort: { Self.localizedAscending($0.name, $1.name) }
        )
        let mergedNotes = try mergeAvailableFullItems(
            snapshotItems: snapshot.notes,
            currentMetadata: currentNotes,
            load: getFullNote,
            id: \.id,
            modifiedAt: \.modifiedAt,
            sort: { Self.localizedAscending($0.title, $1.title) }
        )
        let mergedSSHKeys = try mergeAvailableFullItems(
            snapshotItems: snapshot.sshKeys,
            currentMetadata: currentSSHKeys,
            load: getFullSSHKey,
            id: \.id,
            modifiedAt: \.modifiedAt,
            sort: { Self.localizedAscending($0.name, $1.name) }
        )

        passwords = mergedPasswords.map { PasswordMetadata(from: $0) }
        apiKeys = mergedAPIKeys.map { APIKeyMetadata(from: $0) }
        certificates = mergedCertificates.map { CertificateMetadata(from: $0) }
        notes = mergedNotes.map { SecureNoteMetadata(from: $0) }
        sshKeys = mergedSSHKeys.map { SSHKeyMetadata(from: $0) }
        folders = currentFolders
        mergeFoldersFromMetadata()

        if !currentAPIKeyDeletionTombstones.isEmpty {
            try metadataStore.saveAPIKeyDeletionTombstones(currentAPIKeyDeletionTombstones)
        }
        if !currentFolderStates.isEmpty {
            try metadataStore.saveFolderStates(currentFolderStates)
        }
        try metadataStore.replacePasswords(passwords)
        try metadataStore.replaceAPIKeys(apiKeys)
        try metadataStore.replaceCertificates(certificates)
        try metadataStore.replaceNotes(notes)
        try metadataStore.replaceSSHKeys(sshKeys)
        try metadataStore.saveFolders(folders)

        for password in mergedPasswords {
            try keychain.savePassword(password.password, for: password.id)
        }
        for apiKey in mergedAPIKeys {
            try keychain.saveAPIKey(apiKey.key, for: apiKey.id)
        }
        for certificate in mergedCertificates {
            try keychain.saveCertificate(
                certificate.certificateData,
                privateKey: certificate.privateKeyData,
                for: certificate.id
            )
        }
        for note in mergedNotes {
            try keychain.saveNoteContent(note.content, for: note.id)
        }
        for sshKey in mergedSSHKeys {
            try keychain.saveSSHKey(publicKey: sshKey.publicKey, privateKey: sshKey.privateKey, for: sshKey.id)
        }

        hasLoadedVaultState = true
        try saveCLIMetadataSnapshot()

        var changedNames: [Notification.Name] = []
        if !snapshot.passwords.isEmpty || passwords != currentPasswords {
            changedNames.append(.vaultPasswordsDidChange)
        }
        if !snapshot.apiKeys.isEmpty || apiKeys != currentAPIKeys {
            changedNames.append(.vaultAPIKeysDidChange)
        }
        if !snapshot.certificates.isEmpty || certificates != currentCertificates {
            changedNames.append(.vaultCertificatesDidChange)
        }
        if !snapshot.notes.isEmpty || notes != currentNotes {
            changedNames.append(.vaultNotesDidChange)
        }
        if !snapshot.sshKeys.isEmpty || sshKeys != currentSSHKeys {
            changedNames.append(.vaultSSHKeysDidChange)
        }
        if folders != currentFolders {
            changedNames.append(.vaultFoldersDidChange)
        }
        postVaultChanges(changedNames)
    }

    private static func localizedAscending(_ lhs: String, _ rhs: String) -> Bool {
        lhs.localizedCaseInsensitiveCompare(rhs) == .orderedAscending
    }

    private static func notesPreservingUsername(existingNotes: String?, username: String) -> String? {
        let trimmedUsername = username.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedUsername.isEmpty else { return existingNotes }
        let preservedUsername = "Converted from password username: \(trimmedUsername)"
        guard let existingNotes, !existingNotes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return preservedUsername
        }
        return "\(existingNotes)\n\n\(preservedUsername)"
    }

    @discardableResult
    public func rebuildMetadata(
        passwords rebuiltPasswords: [PasswordMetadata],
        apiKeys rebuiltAPIKeys: [APIKeyMetadata] = [],
        certificates rebuiltCertificates: [CertificateMetadata],
        notes rebuiltNotes: [SecureNoteMetadata],
        sshKeys rebuiltSSHKeys: [SSHKeyMetadata],
        folders rebuiltFolders: [VaultItemType: [String]]
    ) throws -> VaultMetadataRebuildSummary {
        try metadataStore.replacePasswords(rebuiltPasswords)
        try metadataStore.replaceAPIKeys(rebuiltAPIKeys)
        try metadataStore.replaceCertificates(rebuiltCertificates)
        try metadataStore.replaceNotes(rebuiltNotes)
        try metadataStore.replaceSSHKeys(rebuiltSSHKeys)
        try metadataStore.replaceFolders(rebuiltFolders)

        passwords = rebuiltPasswords
        apiKeys = rebuiltAPIKeys
        certificates = rebuiltCertificates
        notes = rebuiltNotes
        sshKeys = rebuiltSSHKeys
        folders = rebuiltFolders
        hasLoadedVaultState = true
        try saveCLIMetadataSnapshot()

        return VaultMetadataRebuildSummary(
            passwordCount: rebuiltPasswords.count,
            apiKeyCount: rebuiltAPIKeys.count,
            certificateCount: rebuiltCertificates.count,
            noteCount: rebuiltNotes.count,
            sshKeyCount: rebuiltSSHKeys.count
        )
    }

    public var isEmpty: Bool {
        passwords.isEmpty && apiKeys.isEmpty && certificates.isEmpty && notes.isEmpty && sshKeys.isEmpty
    }

    public var totalCount: Int {
        passwords.count + apiKeys.count + certificates.count + notes.count + sshKeys.count
    }

    // MARK: - Password Operations

    public func addPassword(_ item: PasswordItem) throws {
        try prepareForMutation()
        var item = item
        if let tombstone = try metadataStore.loadPasswordDeletionTombstones().first(where: { $0.id == item.id }),
           item.modifiedAt <= tombstone.deletedAt {
            item.modifiedAt = max(Date(), tombstone.deletedAt.addingTimeInterval(1))
        }
        try keychain.savePassword(item.password, for: item.id)

        let metadata = PasswordMetadata(from: item)
        passwords.append(metadata)
        passwords.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        try metadataStore.savePasswords(passwords)
        try registerFolderIfNeeded(metadata.folderPath, type: .password)
        try saveCLIMetadataSnapshot()

        postVaultChange(.vaultPasswordsDidChange)
    }

    public func updatePassword(_ item: PasswordItem) throws {
        try prepareForMutation()
        try keychain.savePassword(item.password, for: item.id)

        if let index = passwords.firstIndex(where: { $0.id == item.id }) {
            passwords[index] = PasswordMetadata(from: item)
            try metadataStore.savePasswords(passwords)
            try registerFolderIfNeeded(passwords[index].folderPath, type: .password)
            try saveCLIMetadataSnapshot()
        }

        postVaultChange(.vaultPasswordsDidChange)
    }

    public func deletePassword(id: UUID) throws {
        try deletePassword(id: id, deletedAt: Date())
    }

    public func deletePassword(id: UUID, deletedAt: Date) throws {
        try prepareForMutation()
        try recordPasswordDeletions([id], deletedAt: deletedAt)
        try keychain.deletePassword(for: id)
        passwords.removeAll { $0.id == id }
        try metadataStore.replacePasswords(passwords)
        try saveCLIMetadataSnapshot()

        postVaultChange(.vaultPasswordsDidChange)
    }

    public func getFullPassword(metadata: PasswordMetadata) throws -> PasswordItem {
        let passwordData = try keychain.retrievePassword(for: metadata.id)
        return metadata.toPasswordItem(password: passwordData)
    }

    // MARK: - API Key Operations

    public func addAPIKey(_ item: APIKeyItem) throws {
        try prepareForMutation()
        var item = item
        if let tombstone = try metadataStore.loadAPIKeyDeletionTombstones().first(where: { $0.id == item.id }),
           item.modifiedAt <= tombstone.deletedAt {
            item.modifiedAt = max(Date(), tombstone.deletedAt.addingTimeInterval(1))
        }
        try keychain.saveAPIKey(item.key, for: item.id)

        let metadata = APIKeyMetadata(from: item)
        apiKeys.append(metadata)
        apiKeys.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        try metadataStore.saveAPIKeys(apiKeys)
        try registerFolderIfNeeded(metadata.folderPath, type: .apiKey)
        try saveCLIMetadataSnapshot()

        postVaultChange(.vaultAPIKeysDidChange)
    }

    public func updateAPIKey(_ item: APIKeyItem) throws {
        try prepareForMutation()
        try keychain.saveAPIKey(item.key, for: item.id)

        if let index = apiKeys.firstIndex(where: { $0.id == item.id }) {
            apiKeys[index] = APIKeyMetadata(from: item)
            try metadataStore.saveAPIKeys(apiKeys)
            try registerFolderIfNeeded(apiKeys[index].folderPath, type: .apiKey)
            try saveCLIMetadataSnapshot()
        }

        postVaultChange(.vaultAPIKeysDidChange)
    }

    public func deleteAPIKey(id: UUID) throws {
        try deleteAPIKey(id: id, deletedAt: Date())
    }

    public func deleteAPIKey(id: UUID, deletedAt: Date) throws {
        try prepareForMutation()
        try recordAPIKeyDeletions([id], deletedAt: deletedAt)
        try keychain.deleteAPIKey(for: id)
        apiKeys.removeAll { $0.id == id }
        try metadataStore.replaceAPIKeys(apiKeys)
        try saveCLIMetadataSnapshot()

        postVaultChange(.vaultAPIKeysDidChange)
    }

    public func getFullAPIKey(metadata: APIKeyMetadata) throws -> APIKeyItem {
        let keyData = try keychain.retrieveAPIKey(for: metadata.id)
        return metadata.toAPIKeyItem(key: keyData)
    }

    public func convertPasswordToAPIKey(id: UUID, modifiedAt: Date = Date()) throws -> APIKeyItem? {
        try prepareForMutation()
        guard let metadata = passwords.first(where: { $0.id == id }) else { return nil }
        let password = try getFullPassword(metadata: metadata)
        let notes = Self.notesPreservingUsername(existingNotes: password.notes, username: password.username)
        let apiKey = APIKeyItem(
            name: password.name,
            key: password.password,
            website: password.website,
            notes: notes,
            folderPath: password.folderPath,
            createdAt: password.createdAt,
            modifiedAt: modifiedAt,
            isFavorite: password.isFavorite,
            isCliEnabled: password.isCliEnabled,
            isScraped: password.isScraped,
            scrapeMachineName: password.scrapeMachineName,
            scrapeMachineId: password.scrapeMachineId,
            expiresAt: password.expiresAt,
            autoDestroyOnExpiry: password.autoDestroyOnExpiry,
            environments: password.environments
        )

        try keychain.saveAPIKey(apiKey.key, for: apiKey.id)
        apiKeys.append(APIKeyMetadata(from: apiKey))
        apiKeys.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        try metadataStore.saveAPIKeys(apiKeys)
        try registerFolderIfNeeded(apiKey.folderPath, type: .apiKey)

        try recordPasswordDeletions([password.id], deletedAt: modifiedAt)
        try keychain.deletePassword(for: password.id)
        passwords.removeAll { $0.id == password.id }
        try metadataStore.replacePasswords(passwords)
        try saveCLIMetadataSnapshot()
        postVaultChanges([.vaultAPIKeysDidChange, .vaultPasswordsDidChange])
        return apiKey
    }

    // MARK: - Certificate Operations

    public func addCertificate(_ item: CertificateItem) throws {
        try prepareForMutation()
        try keychain.saveCertificate(item.certificateData, privateKey: item.privateKeyData, for: item.id)

        let metadata = CertificateMetadata(from: item)
        certificates.append(metadata)
        certificates.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        try metadataStore.saveCertificates(certificates)
        try registerFolderIfNeeded(metadata.folderPath, type: .certificate)
        try saveCLIMetadataSnapshot()

        postVaultChange(.vaultCertificatesDidChange)
    }

    public func updateCertificate(_ item: CertificateItem) throws {
        try prepareForMutation()
        try keychain.saveCertificate(item.certificateData, privateKey: item.privateKeyData, for: item.id)

        if let index = certificates.firstIndex(where: { $0.id == item.id }) {
            certificates[index] = CertificateMetadata(from: item)
            try metadataStore.saveCertificates(certificates)
            try registerFolderIfNeeded(certificates[index].folderPath, type: .certificate)
            try saveCLIMetadataSnapshot()
        }

        postVaultChange(.vaultCertificatesDidChange)
    }

    public func deleteCertificatePrivateKey(id: UUID) {
        keychain.deleteCertificatePrivateKey(for: id)
    }

    public func deleteCertificate(id: UUID) throws {
        try prepareForMutation()
        try keychain.deleteCertificate(for: id)
        certificates.removeAll { $0.id == id }
        try metadataStore.replaceCertificates(certificates)
        try saveCLIMetadataSnapshot()

        postVaultChange(.vaultCertificatesDidChange)
    }

    public func getFullCertificate(metadata: CertificateMetadata) throws -> CertificateItem {
        let (certData, keyData) = try keychain.retrieveCertificate(for: metadata.id)
        return CertificateItem(
            id: metadata.id,
            name: metadata.name,
            certificateData: certData,
            privateKeyData: keyData,
            expirationDate: metadata.expirationDate,
            issuer: metadata.issuer,
            subject: metadata.subject,
            notes: metadata.notes,
            folderPath: metadata.folderPath,
            createdAt: metadata.createdAt,
            modifiedAt: metadata.modifiedAt,
            isFavorite: metadata.isFavorite,
            isCliEnabled: metadata.isCliEnabled,
            isScraped: metadata.isScraped,
            scrapeMachineName: metadata.scrapeMachineName,
            scrapeMachineId: metadata.scrapeMachineId,
            environments: metadata.environments
        )
    }

    // MARK: - Secure Note Operations

    public func addNote(_ item: SecureNoteItem) throws {
        try prepareForMutation()
        try keychain.saveNoteContent(item.content, for: item.id)

        let metadata = SecureNoteMetadata(from: item)
        notes.append(metadata)
        notes.sort { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        try metadataStore.saveNotes(notes)
        try registerFolderIfNeeded(metadata.folderPath, type: .secureNote)
        try saveCLIMetadataSnapshot()

        postVaultChange(.vaultNotesDidChange)
    }

    public func updateNote(_ item: SecureNoteItem) throws {
        try prepareForMutation()
        try keychain.saveNoteContent(item.content, for: item.id)

        if let index = notes.firstIndex(where: { $0.id == item.id }) {
            notes[index] = SecureNoteMetadata(from: item)
            try metadataStore.saveNotes(notes)
            try registerFolderIfNeeded(notes[index].folderPath, type: .secureNote)
            try saveCLIMetadataSnapshot()
        }

        postVaultChange(.vaultNotesDidChange)
    }

    public func deleteNote(id: UUID) throws {
        try prepareForMutation()
        try keychain.deleteNoteContent(for: id)
        notes.removeAll { $0.id == id }
        try metadataStore.replaceNotes(notes)
        try saveCLIMetadataSnapshot()

        postVaultChange(.vaultNotesDidChange)
    }

    public func getFullNote(metadata: SecureNoteMetadata) throws -> SecureNoteItem {
        let content = try keychain.retrieveNoteContent(for: metadata.id)
        return SecureNoteItem(
            id: metadata.id,
            title: metadata.title,
            content: content,
            folderPath: metadata.folderPath,
            createdAt: metadata.createdAt,
            modifiedAt: metadata.modifiedAt,
            isFavorite: metadata.isFavorite,
            isCliEnabled: metadata.isCliEnabled,
            isScraped: metadata.isScraped,
            scrapeMachineName: metadata.scrapeMachineName,
            scrapeMachineId: metadata.scrapeMachineId,
            environments: metadata.environments
        )
    }

    // MARK: - SSH Key Operations

    public func addSSHKey(_ item: SSHKeyItem) throws {
        try prepareForMutation()
        try keychain.saveSSHKey(publicKey: item.publicKey, privateKey: item.privateKey, for: item.id)

        let metadata = SSHKeyMetadata(from: item)
        sshKeys.append(metadata)
        sshKeys.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        try metadataStore.saveSSHKeys(sshKeys)
        try registerFolderIfNeeded(metadata.folderPath, type: .sshKey)
        try saveCLIMetadataSnapshot()

        postVaultChange(.vaultSSHKeysDidChange)
    }

    public func updateSSHKey(_ item: SSHKeyItem) throws {
        try prepareForMutation()
        try keychain.saveSSHKey(publicKey: item.publicKey, privateKey: item.privateKey, for: item.id)

        if let index = sshKeys.firstIndex(where: { $0.id == item.id }) {
            sshKeys[index] = SSHKeyMetadata(from: item)
            try metadataStore.saveSSHKeys(sshKeys)
            try registerFolderIfNeeded(sshKeys[index].folderPath, type: .sshKey)
            try saveCLIMetadataSnapshot()
        }

        postVaultChange(.vaultSSHKeysDidChange)
    }

    public func deleteSSHKey(id: UUID) throws {
        try prepareForMutation()
        try keychain.deleteSSHKey(for: id)
        sshKeys.removeAll { $0.id == id }
        try metadataStore.replaceSSHKeys(sshKeys)
        try saveCLIMetadataSnapshot()

        postVaultChange(.vaultSSHKeysDidChange)
    }

    public func deleteFolder(path: String, type: VaultItemType) async throws {
        guard let normalizedPath = normalizeFolderPath(path) else { return }
        try prepareForMutation()

        var passwordIDs: Set<UUID> = []
        var apiKeyIDs: Set<UUID> = []
        var certificateIDs: Set<UUID> = []
        var noteIDs: Set<UUID> = []
        var sshKeyIDs: Set<UUID> = []
        switch type {
        case .password:
            passwordIDs = Set(passwords.filter { isPath($0.folderPath, withinFolder: normalizedPath) }.map(\.id))
        case .apiKey:
            apiKeyIDs = Set(apiKeys.filter { isPath($0.folderPath, withinFolder: normalizedPath) }.map(\.id))
        case .certificate:
            certificateIDs = Set(certificates.filter { isPath($0.folderPath, withinFolder: normalizedPath) }.map(\.id))
        case .secureNote:
            noteIDs = Set(notes.filter { isPath($0.folderPath, withinFolder: normalizedPath) }.map(\.id))
        case .sshKey:
            sshKeyIDs = Set(sshKeys.filter { isPath($0.folderPath, withinFolder: normalizedPath) }.map(\.id))
        }
        let keychainStore = keychain

        let deletedAt = Date()
        try recordPasswordDeletions(passwordIDs, deletedAt: deletedAt)
        try recordAPIKeyDeletions(apiKeyIDs, deletedAt: deletedAt)
        try metadataStore.saveFolderStates([
            VaultFolderState(type: type, path: normalizedPath, modifiedAt: deletedAt, isDeleted: true),
        ])

        try await Self.deleteSecrets(
            keychain: keychainStore,
            passwordIDs: passwordIDs,
            apiKeyIDs: apiKeyIDs,
            certificateIDs: certificateIDs,
            noteIDs: noteIDs,
            sshKeyIDs: sshKeyIDs
        )

        switch type {
        case .password:
            passwords.removeAll { isPath($0.folderPath, withinFolder: normalizedPath) }
            try metadataStore.replacePasswords(passwords)
        case .apiKey:
            apiKeys.removeAll { isPath($0.folderPath, withinFolder: normalizedPath) }
            try metadataStore.replaceAPIKeys(apiKeys)
        case .certificate:
            certificates.removeAll { isPath($0.folderPath, withinFolder: normalizedPath) }
            try metadataStore.replaceCertificates(certificates)
        case .secureNote:
            notes.removeAll { isPath($0.folderPath, withinFolder: normalizedPath) }
            try metadataStore.replaceNotes(notes)
        case .sshKey:
            sshKeys.removeAll { isPath($0.folderPath, withinFolder: normalizedPath) }
            try metadataStore.replaceSSHKeys(sshKeys)
        }

        let remaining = normalizeFolders((folders[type] ?? []).filter { !isPath($0, withinFolder: normalizedPath) })
        folders[type] = remaining.isEmpty ? nil : remaining
        try metadataStore.replaceFolders(folders)
        try saveCLIMetadataSnapshot()

        var changeNames: [Notification.Name] = []
        if !passwordIDs.isEmpty {
            changeNames.append(.vaultPasswordsDidChange)
        }
        if !apiKeyIDs.isEmpty {
            changeNames.append(.vaultAPIKeysDidChange)
        }
        if !certificateIDs.isEmpty {
            changeNames.append(.vaultCertificatesDidChange)
        }
        if !noteIDs.isEmpty {
            changeNames.append(.vaultNotesDidChange)
        }
        if !sshKeyIDs.isEmpty {
            changeNames.append(.vaultSSHKeysDidChange)
        }
        changeNames.append(.vaultFoldersDidChange)
        postVaultChanges(changeNames)
    }

    public func getFullSSHKey(metadata: SSHKeyMetadata) throws -> SSHKeyItem {
        let (publicKey, privateKey) = try keychain.retrieveSSHKey(for: metadata.id)
        return SSHKeyItem(
            id: metadata.id,
            name: metadata.name,
            publicKey: publicKey,
            privateKey: privateKey,
            comment: metadata.comment,
            fingerprint: metadata.fingerprint,
            keyType: metadata.keyType,
            approvalPolicy: metadata.approvalPolicy,
            boundHosts: metadata.boundHosts,
            folderPath: metadata.folderPath,
            createdAt: metadata.createdAt,
            modifiedAt: metadata.modifiedAt,
            isFavorite: metadata.isFavorite,
            isCliEnabled: metadata.isCliEnabled,
            isScraped: metadata.isScraped,
            scrapeMachineName: metadata.scrapeMachineName,
            scrapeMachineId: metadata.scrapeMachineId,
            environments: metadata.environments
        )
    }

    public func copyItem(id: UUID, toFolderPath folderPath: String?) throws -> UUID? {
        try prepareForMutation()
        let destination = normalizeFolderPath(folderPath)
        let copiedAt = Date()

        if let metadata = passwords.first(where: { $0.id == id }) {
            let source = try getFullPassword(metadata: metadata)
            let copy = PasswordItem(
                name: source.name,
                username: source.username,
                password: source.password,
                website: source.website,
                notes: source.notes,
                folderPath: destination,
                createdAt: copiedAt,
                modifiedAt: copiedAt,
                isFavorite: source.isFavorite,
                isCliEnabled: source.isCliEnabled,
                isScraped: source.isScraped,
                scrapeMachineName: source.scrapeMachineName,
                scrapeMachineId: source.scrapeMachineId,
                expiresAt: source.expiresAt,
                autoDestroyOnExpiry: source.autoDestroyOnExpiry,
                environments: source.environments
            )
            try addPassword(copy)
            return copy.id
        }

        if let metadata = apiKeys.first(where: { $0.id == id }) {
            let source = try getFullAPIKey(metadata: metadata)
            let copy = APIKeyItem(
                name: source.name,
                key: source.key,
                website: source.website,
                notes: source.notes,
                folderPath: destination,
                createdAt: copiedAt,
                modifiedAt: copiedAt,
                isFavorite: source.isFavorite,
                isCliEnabled: source.isCliEnabled,
                isScraped: source.isScraped,
                scrapeMachineName: source.scrapeMachineName,
                scrapeMachineId: source.scrapeMachineId,
                expiresAt: source.expiresAt,
                autoDestroyOnExpiry: source.autoDestroyOnExpiry,
                environments: source.environments
            )
            try addAPIKey(copy)
            return copy.id
        }

        if let metadata = certificates.first(where: { $0.id == id }) {
            let source = try getFullCertificate(metadata: metadata)
            let copy = CertificateItem(
                name: source.name,
                certificateData: source.certificateData,
                privateKeyData: source.privateKeyData,
                expirationDate: source.expirationDate,
                issuer: source.issuer,
                subject: source.subject,
                notes: source.notes,
                folderPath: destination,
                createdAt: copiedAt,
                modifiedAt: copiedAt,
                isFavorite: source.isFavorite,
                isCliEnabled: source.isCliEnabled,
                isScraped: source.isScraped,
                scrapeMachineName: source.scrapeMachineName,
                scrapeMachineId: source.scrapeMachineId,
                environments: source.environments
            )
            try addCertificate(copy)
            return copy.id
        }

        if let metadata = notes.first(where: { $0.id == id }) {
            let source = try getFullNote(metadata: metadata)
            let copy = SecureNoteItem(
                title: source.title,
                content: source.content,
                folderPath: destination,
                createdAt: copiedAt,
                modifiedAt: copiedAt,
                isFavorite: source.isFavorite,
                isCliEnabled: source.isCliEnabled,
                isScraped: source.isScraped,
                scrapeMachineName: source.scrapeMachineName,
                scrapeMachineId: source.scrapeMachineId,
                environments: source.environments
            )
            try addNote(copy)
            return copy.id
        }

        if let metadata = sshKeys.first(where: { $0.id == id }) {
            let source = try getFullSSHKey(metadata: metadata)
            let copy = SSHKeyItem(
                name: source.name,
                publicKey: source.publicKey,
                privateKey: source.privateKey,
                comment: source.comment,
                fingerprint: source.fingerprint,
                keyType: source.keyType,
                approvalPolicy: source.approvalPolicy,
                boundHosts: source.boundHosts,
                folderPath: destination,
                createdAt: copiedAt,
                modifiedAt: copiedAt,
                isFavorite: source.isFavorite,
                isCliEnabled: source.isCliEnabled,
                isScraped: source.isScraped,
                scrapeMachineName: source.scrapeMachineName,
                scrapeMachineId: source.scrapeMachineId,
                environments: source.environments
            )
            try addSSHKey(copy)
            return copy.id
        }

        return nil
    }

    // MARK: - CLI Access

    @discardableResult
    public func enableCLIAccess(forItemIDs ids: Set<UUID>) throws -> Int {
        guard !ids.isEmpty else { return 0 }
        try prepareForMutation()

        let passwordCount = setPasswordCLIAccess(true) { ids.contains($0.id) }
        let apiKeyCount = setAPIKeyCLIAccess(true) { ids.contains($0.id) }
        let certificateCount = setCertificateCLIAccess(true) { ids.contains($0.id) }
        let noteCount = setNoteCLIAccess(true) { ids.contains($0.id) }
        let sshKeyCount = setSSHKeyCLIAccess(true) { ids.contains($0.id) }

        return try persistCLIAccessChanges(
            passwordCount: passwordCount,
            apiKeyCount: apiKeyCount,
            certificateCount: certificateCount,
            noteCount: noteCount,
            sshKeyCount: sshKeyCount
        )
    }

    @discardableResult
    public func disableCLIAccess(forItemIDs ids: Set<UUID>) throws -> Int {
        guard !ids.isEmpty else { return 0 }
        try prepareForMutation()

        let passwordCount = setPasswordCLIAccess(false) { ids.contains($0.id) }
        let apiKeyCount = setAPIKeyCLIAccess(false) { ids.contains($0.id) }
        let certificateCount = setCertificateCLIAccess(false) { ids.contains($0.id) }
        let noteCount = setNoteCLIAccess(false) { ids.contains($0.id) }
        let sshKeyCount = setSSHKeyCLIAccess(false) { ids.contains($0.id) }

        return try persistCLIAccessChanges(
            passwordCount: passwordCount,
            apiKeyCount: apiKeyCount,
            certificateCount: certificateCount,
            noteCount: noteCount,
            sshKeyCount: sshKeyCount
        )
    }

    @discardableResult
    public func enableCLIAccess(inFolder folderPath: String, type: VaultItemType?) throws -> Int {
        guard let normalizedPath = normalizeFolderPath(folderPath) else { return 0 }
        try prepareForMutation()
        let targetTypes = type.map { [$0] } ?? VaultItemType.allCases

        let passwordCount = targetTypes.contains(.password)
            ? setPasswordCLIAccess(true) { isPath($0.folderPath, withinFolder: normalizedPath) }
            : 0
        let apiKeyCount = targetTypes.contains(.apiKey)
            ? setAPIKeyCLIAccess(true) { isPath($0.folderPath, withinFolder: normalizedPath) }
            : 0
        let certificateCount = targetTypes.contains(.certificate)
            ? setCertificateCLIAccess(true) { isPath($0.folderPath, withinFolder: normalizedPath) }
            : 0
        let noteCount = targetTypes.contains(.secureNote)
            ? setNoteCLIAccess(true) { isPath($0.folderPath, withinFolder: normalizedPath) }
            : 0
        let sshKeyCount = targetTypes.contains(.sshKey)
            ? setSSHKeyCLIAccess(true) { isPath($0.folderPath, withinFolder: normalizedPath) }
            : 0

        return try persistCLIAccessChanges(
            passwordCount: passwordCount,
            apiKeyCount: apiKeyCount,
            certificateCount: certificateCount,
            noteCount: noteCount,
            sshKeyCount: sshKeyCount
        )
    }

    @discardableResult
    public func disableCLIAccess(inFolder folderPath: String, type: VaultItemType?) throws -> Int {
        guard let normalizedPath = normalizeFolderPath(folderPath) else { return 0 }
        try prepareForMutation()
        let targetTypes = type.map { [$0] } ?? VaultItemType.allCases

        let passwordCount = targetTypes.contains(.password)
            ? setPasswordCLIAccess(false) { isPath($0.folderPath, withinFolder: normalizedPath) }
            : 0
        let apiKeyCount = targetTypes.contains(.apiKey)
            ? setAPIKeyCLIAccess(false) { isPath($0.folderPath, withinFolder: normalizedPath) }
            : 0
        let certificateCount = targetTypes.contains(.certificate)
            ? setCertificateCLIAccess(false) { isPath($0.folderPath, withinFolder: normalizedPath) }
            : 0
        let noteCount = targetTypes.contains(.secureNote)
            ? setNoteCLIAccess(false) { isPath($0.folderPath, withinFolder: normalizedPath) }
            : 0
        let sshKeyCount = targetTypes.contains(.sshKey)
            ? setSSHKeyCLIAccess(false) { isPath($0.folderPath, withinFolder: normalizedPath) }
            : 0

        return try persistCLIAccessChanges(
            passwordCount: passwordCount,
            apiKeyCount: apiKeyCount,
            certificateCount: certificateCount,
            noteCount: noteCount,
            sshKeyCount: sshKeyCount
        )
    }

    // MARK: - Delete All

    /// Permanently deletes all vault items and folders.
    /// Removes secrets from Keychain and clears all metadata.
    public func deleteAllItems() throws {
        try prepareForMutation()
        try recordPasswordDeletions(Set(passwords.map(\.id)), deletedAt: Date())

        // 1. Delete all secrets from Keychain
        for password in passwords {
            try? keychain.deletePassword(for: password.id)
        }
        for apiKey in apiKeys {
            try? keychain.deleteAPIKey(for: apiKey.id)
        }
        for certificate in certificates {
            try? keychain.deleteCertificate(for: certificate.id)
        }
        for note in notes {
            try? keychain.deleteNoteContent(for: note.id)
        }
        for sshKey in sshKeys {
            try? keychain.deleteSSHKey(for: sshKey.id)
        }

        // 2. Clear all metadata
        try metadataStore.replacePasswords([])
        try metadataStore.replaceAPIKeys([])
        try metadataStore.replaceCertificates([])
        try metadataStore.replaceNotes([])
        try metadataStore.replaceSSHKeys([])
        self.passwords = []
        self.apiKeys = []
        self.certificates = []
        self.notes = []
        self.sshKeys = []

        // 3. Clear folders
        try metadataStore.replaceFolders([:])
        self.folders = [:]
        try saveCLIMetadataSnapshot()

        // 4. Notify observers
        postVaultChanges([
            .vaultPasswordsDidChange,
            .vaultAPIKeysDidChange,
            .vaultCertificatesDidChange,
            .vaultNotesDidChange,
            .vaultSSHKeysDidChange,
            .vaultFoldersDidChange,
        ])
    }

    // MARK: - Toggle Favorite

    public func togglePasswordFavorite(id: UUID) throws {
        try prepareForMutation()
        guard let index = passwords.firstIndex(where: { $0.id == id }) else { return }
        var metadata = passwords[index]
        metadata = PasswordMetadata(
            id: metadata.id,
            name: metadata.name,
            username: metadata.username,
            website: metadata.website,
            notes: metadata.notes,
            folderPath: metadata.folderPath,
            createdAt: metadata.createdAt,
            modifiedAt: Date(),
            isFavorite: !metadata.isFavorite,
            isCliEnabled: metadata.isCliEnabled,
            isScraped: metadata.isScraped,
            scrapeMachineName: metadata.scrapeMachineName,
            scrapeMachineId: metadata.scrapeMachineId,
            expiresAt: metadata.expiresAt,
            autoDestroyOnExpiry: metadata.autoDestroyOnExpiry
        )
        passwords[index] = metadata
        try metadataStore.savePasswords(passwords)
        try saveCLIMetadataSnapshot()
        postVaultChange(.vaultPasswordsDidChange)
    }

    public func toggleAPIKeyFavorite(id: UUID) throws {
        try prepareForMutation()
        guard let index = apiKeys.firstIndex(where: { $0.id == id }) else { return }
        var metadata = apiKeys[index]
        metadata = APIKeyMetadata(
            id: metadata.id,
            name: metadata.name,
            website: metadata.website,
            notes: metadata.notes,
            folderPath: metadata.folderPath,
            createdAt: metadata.createdAt,
            modifiedAt: Date(),
            isFavorite: !metadata.isFavorite,
            isCliEnabled: metadata.isCliEnabled,
            isScraped: metadata.isScraped,
            scrapeMachineName: metadata.scrapeMachineName,
            scrapeMachineId: metadata.scrapeMachineId,
            expiresAt: metadata.expiresAt,
            autoDestroyOnExpiry: metadata.autoDestroyOnExpiry
        )
        apiKeys[index] = metadata
        try metadataStore.saveAPIKeys(apiKeys)
        try saveCLIMetadataSnapshot()
        postVaultChange(.vaultAPIKeysDidChange)
    }

    public func toggleCertificateFavorite(id: UUID) throws {
        try prepareForMutation()
        guard let index = certificates.firstIndex(where: { $0.id == id }) else { return }
        var metadata = certificates[index]
        metadata = CertificateMetadata(
            id: metadata.id,
            name: metadata.name,
            expirationDate: metadata.expirationDate,
            issuer: metadata.issuer,
            subject: metadata.subject,
            notes: metadata.notes,
            folderPath: metadata.folderPath,
            createdAt: metadata.createdAt,
            modifiedAt: Date(),
            isFavorite: !metadata.isFavorite,
            isCliEnabled: metadata.isCliEnabled,
            isScraped: metadata.isScraped,
            scrapeMachineName: metadata.scrapeMachineName,
            scrapeMachineId: metadata.scrapeMachineId
        )
        certificates[index] = metadata
        try metadataStore.saveCertificates(certificates)
        try saveCLIMetadataSnapshot()
        postVaultChange(.vaultCertificatesDidChange)
    }

    public func toggleNoteFavorite(id: UUID) throws {
        try prepareForMutation()
        guard let index = notes.firstIndex(where: { $0.id == id }) else { return }
        var metadata = notes[index]
        metadata = SecureNoteMetadata(
            id: metadata.id,
            title: metadata.title,
            folderPath: metadata.folderPath,
            createdAt: metadata.createdAt,
            modifiedAt: Date(),
            isFavorite: !metadata.isFavorite,
            isCliEnabled: metadata.isCliEnabled,
            isScraped: metadata.isScraped,
            scrapeMachineName: metadata.scrapeMachineName,
            scrapeMachineId: metadata.scrapeMachineId
        )
        notes[index] = metadata
        try metadataStore.saveNotes(notes)
        try saveCLIMetadataSnapshot()
        postVaultChange(.vaultNotesDidChange)
    }

    public func toggleSSHKeyFavorite(id: UUID) throws {
        try prepareForMutation()
        guard let index = sshKeys.firstIndex(where: { $0.id == id }) else { return }
        var metadata = sshKeys[index]
        metadata = SSHKeyMetadata(
            id: metadata.id,
            name: metadata.name,
            publicKey: metadata.publicKey,
            comment: metadata.comment,
            fingerprint: metadata.fingerprint,
            folderPath: metadata.folderPath,
            createdAt: metadata.createdAt,
            modifiedAt: Date(),
            isFavorite: !metadata.isFavorite,
            isCliEnabled: metadata.isCliEnabled,
            isScraped: metadata.isScraped,
            scrapeMachineName: metadata.scrapeMachineName,
            scrapeMachineId: metadata.scrapeMachineId
        )
        sshKeys[index] = metadata
        try metadataStore.saveSSHKeys(sshKeys)
        try saveCLIMetadataSnapshot()
        postVaultChange(.vaultSSHKeysDidChange)
    }

    // MARK: - Folder Operations

    public func saveFolders(_ folders: [VaultItemType: [String]]) throws {
        var normalized: [VaultItemType: [String]] = [:]
        for (type, paths) in folders {
            let n = normalizeFolders(paths)
            if !n.isEmpty { normalized[type] = n }
        }
        try metadataStore.replaceFolders(normalized)
        self.folders = normalized
        try saveCLIMetadataSnapshot()
        postVaultChange(.vaultFoldersDidChange)
    }

    public func addFolder(_ path: String, type: VaultItemType) throws {
        try prepareForMutation()
        guard let normalizedPath = normalizeFolderPath(path) else { return }
        var updatedFolders = folders
        updatedFolders[type] = normalizeFolders((updatedFolders[type] ?? []) + [normalizedPath])
        try metadataStore.saveFolderStates([
            VaultFolderState(type: type, path: normalizedPath, modifiedAt: Date(), isDeleted: false),
        ])
        try saveFolders(updatedFolders)
    }

    public func loadFolders() throws -> [VaultItemType: [String]] {
        let loaded = try metadataStore.loadFolders()
        self.folders = loaded
        return loaded
    }

    // MARK: - Search

    public func search(query: String) -> (
        passwords: [PasswordMetadata],
        apiKeys: [APIKeyMetadata],
        certificates: [CertificateMetadata],
        notes: [SecureNoteMetadata]
    ) {
        let lowercased = query.lowercased()

        let matchedPasswords = passwords.filter {
            $0.name.lowercased().contains(lowercased) ||
            $0.username.lowercased().contains(lowercased) ||
            ($0.website?.lowercased().contains(lowercased) ?? false)
        }

        let matchedAPIKeys = apiKeys.filter {
            $0.name.lowercased().contains(lowercased) ||
            ($0.website?.lowercased().contains(lowercased) ?? false)
        }

        let matchedCertificates = certificates.filter {
            $0.name.lowercased().contains(lowercased) ||
            ($0.issuer?.lowercased().contains(lowercased) ?? false) ||
            ($0.subject?.lowercased().contains(lowercased) ?? false)
        }

        let matchedNotes = notes.filter {
            $0.title.lowercased().contains(lowercased)
        }
        return (matchedPasswords, matchedAPIKeys, matchedCertificates, matchedNotes)
    }

    // MARK: - Import/Export

    public func exportItems(of itemType: VaultItemType) async throws -> Data {
        try await VaultImportExportService.shared.exportItems(of: itemType, from: self)
    }

    public func exportAllItems() async throws -> Data {
        try await VaultImportExportService.shared.exportAllItems(from: self)
    }

    public func exportItems(inFolder folderPath: String, itemType: VaultItemType?) async throws -> Data {
        try await VaultImportExportService.shared.exportItems(inFolder: folderPath, itemType: itemType, from: self)
    }

    public func importAllItems(
        from data: Data,
        conflictPolicy: VaultImportConflictPolicy = .keepExisting
    ) async throws -> Int {
        try await VaultImportExportService.shared.importAllItems(
            from: data,
            into: self,
            conflictPolicy: conflictPolicy
        )
    }

    public func detectImportPayloadKind(from data: Data) throws -> VaultImportPayloadKind {
        try VaultImportExportService.shared.detectImportPayloadKind(from: data)
    }

    public func importItems(
        from data: Data,
        conflictPolicy: VaultImportConflictPolicy = .keepExisting
    ) async throws -> Int {
        try await VaultImportExportService.shared.importItems(
            from: data,
            into: self,
            conflictPolicy: conflictPolicy
        )
    }

    public func importItems(
        of itemType: VaultItemType,
        from data: Data,
        conflictPolicy: VaultImportConflictPolicy = .keepExisting
    ) async throws -> Int {
        try await VaultImportExportService.shared.importItems(
            of: itemType,
            from: data,
            into: self,
            conflictPolicy: conflictPolicy
        )
    }

    public func exportToFile(url: URL, itemType: VaultItemType) async throws {
        try await VaultImportExportService.shared.exportToFile(url: url, itemType: itemType, from: self)
    }

    public func importFromFile(
        url: URL,
        itemType: VaultItemType,
        conflictPolicy: VaultImportConflictPolicy = .keepExisting
    ) async throws -> Int {
        try await VaultImportExportService.shared.importFromFile(
            url: url,
            itemType: itemType,
            into: self,
            conflictPolicy: conflictPolicy
        )
    }

    public func previewImportItems(from data: Data) async throws -> VaultImportPreview {
        try await VaultImportExportService.shared.previewImportItems(from: data, into: self)
    }

    public func previewImportItems(of itemType: VaultItemType, from data: Data) async throws -> VaultImportPreview {
        try await VaultImportExportService.shared.previewImportItems(of: itemType, from: data, into: self)
    }

    public func previewImportFromFile(url: URL, itemType: VaultItemType) async throws -> VaultImportPreview {
        try await VaultImportExportService.shared.previewImportFromFile(url: url, itemType: itemType, into: self)
    }

    private func saveCLIMetadataSnapshot() throws {
        guard let cliMetadataSnapshotStore else { return }
        try cliMetadataSnapshotStore.save(VaultCLIMetadataSnapshot(
            passwords: passwords,
            apiKeys: apiKeys,
            certificates: certificates,
            notes: notes,
            sshKeys: sshKeys,
            folders: folders
        ))
    }

    private func postVaultChange(_ name: Notification.Name) {
        postVaultChanges([name])
    }

    private func postVaultChanges(_ names: [Notification.Name]) {
        for name in names {
            NotificationCenter.default.post(name: name, object: nil)
        }
        #if os(macOS)
        if !names.isEmpty {
            VaultExternalChangeNotifier.post()
        }
        #endif
    }

    private func registerFolderIfNeeded(_ folderPath: String?, type: VaultItemType) throws {
        guard let normalizedPath = normalizeFolderPath(folderPath) else { return }
        var paths = folders[type] ?? []
        if paths.contains(normalizedPath) {
            return
        }
        paths.append(normalizedPath)
        folders[type] = normalizeFolders(paths)
        try metadataStore.saveFolderStates([
            VaultFolderState(type: type, path: normalizedPath, modifiedAt: Date(), isDeleted: false),
        ])
        try metadataStore.saveFolders(folders)
    }

    private func mergeFoldersFromMetadata() {
        let before = folders
        func merge(_ type: VaultItemType, _ paths: [String?]) {
            let existing = folders[type] ?? []
            let merged = normalizeFolders(existing + paths.compactMap { normalizeFolderPath($0) })
            if merged != existing { folders[type] = merged }
        }
        merge(.password, passwords.map { $0.folderPath })
        merge(.apiKey, apiKeys.map { $0.folderPath })
        merge(.certificate, certificates.map { $0.folderPath })
        merge(.secureNote, notes.map { $0.folderPath })
        merge(.sshKey, sshKeys.map { $0.folderPath })
        guard folders != before else { return }
        try? metadataStore.saveFolders(folders)
    }

    private static func isExpired(
        _ expiresAt: Date?,
        currentDate: Date,
        calendar: Calendar = .current
    ) -> Bool {
        guard let expiresAt else { return false }
        // "Auto-destroy on date X" means keep the item through all of X and
        // remove it only once we're on a later calendar day. The picker stores
        // only a date, but the Date carries a time-of-day, so compare by day to
        // avoid deleting a password the same day the user chose it.
        return calendar.startOfDay(for: currentDate) > calendar.startOfDay(for: expiresAt)
    }

    private func decodeBackupManifest(
        _ note: SecureNoteMetadata,
        defaultEntryFolderPath: String?
    ) throws -> BackupManifest {
        let data = try keychain.retrieveNoteContent(for: note.id)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        var manifest = try decoder.decode(BackupManifest.self, from: data)
        let normalizedDefaultFolderPath = normalizeFolderPath(defaultEntryFolderPath)
        manifest.backups = manifest.backups.map { entry in
            var updatedEntry = entry
            if updatedEntry.folderPath == nil {
                updatedEntry.folderPath = normalizedDefaultFolderPath
            }
            return updatedEntry
        }
        return manifest
    }

    private static func encodeBackupManifest(_ manifest: BackupManifest) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(manifest)
    }

    private func resolveBackupNoteID(
        for entry: BackupManifestEntry,
        legacyManifestFolderPath: String?
    ) -> UUID? {
        if let backupNoteId = entry.backupNoteId,
           let id = UUID(uuidString: backupNoteId),
           notes.contains(where: { $0.id == id }) {
            return id
        }

        let matches = notes.filter { $0.title == entry.backupNoteName }
        let targetFolderPath = normalizeFolderPath(entry.folderPath)
            ?? normalizeFolderPath(legacyManifestFolderPath)
        if let targetFolderPath,
           let exactFolderMatch = matches.first(where: {
               normalizeFolderPath($0.folderPath) == targetFolderPath
           }) {
            return exactFolderMatch.id
        }

        guard matches.count == 1 else {
            return nil
        }
        return matches[0].id
    }

    private func isBackupManifestNote(_ note: SecureNoteMetadata) -> Bool {
        note.title == Self.backupManifestBaseNoteName ||
            note.title.hasPrefix("\(Self.backupManifestBaseNoteName)__")
    }

    private func isCurrentBackupManifestNote(_ note: SecureNoteMetadata) -> Bool {
        note.title == Self.backupManifestNoteName &&
            normalizeFolderPath(note.folderPath) == normalizeFolderPath(Self.backupFolderPath)
    }

    private struct BackupManifest: Codable {
        var version: String
        var lastUpdated: Date
        var backups: [BackupManifestEntry]

        init(version: String = "1.0", lastUpdated: Date = Date(), backups: [BackupManifestEntry] = []) {
            self.version = version
            self.lastUpdated = lastUpdated
            self.backups = backups
        }
    }

    private struct BackupManifestEntry: Codable {
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

        private enum CodingKeys: String, CodingKey {
            case id
            case originalPath
            case folderPath
            case backupNoteId
            case backupNoteName
            case timestamp
            case description
            case kind
            case slot
            case fileHash
            case isRestored
            case hostname
            case machineId
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            id = try container.decode(String.self, forKey: .id)
            originalPath = try container.decode(String.self, forKey: .originalPath)
            folderPath = try container.decodeIfPresent(String.self, forKey: .folderPath)
            backupNoteId = try container.decodeIfPresent(String.self, forKey: .backupNoteId)
            backupNoteName = try container.decode(String.self, forKey: .backupNoteName)
            timestamp = try container.decode(Date.self, forKey: .timestamp)
            description = try container.decode(String.self, forKey: .description)
            kind = try container.decodeIfPresent(String.self, forKey: .kind) ?? Self.inferredKind(from: description)
            slot = try container.decodeIfPresent(String.self, forKey: .slot) ?? (kind == "scrape" ? "baseline" : "latest")
            fileHash = try container.decode(String.self, forKey: .fileHash)
            isRestored = try container.decode(Bool.self, forKey: .isRestored)
            hostname = try container.decodeIfPresent(String.self, forKey: .hostname)
            machineId = try container.decodeIfPresent(String.self, forKey: .machineId)
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(id, forKey: .id)
            try container.encode(originalPath, forKey: .originalPath)
            try container.encodeIfPresent(folderPath, forKey: .folderPath)
            try container.encodeIfPresent(backupNoteId, forKey: .backupNoteId)
            try container.encode(backupNoteName, forKey: .backupNoteName)
            try container.encode(timestamp, forKey: .timestamp)
            try container.encode(description, forKey: .description)
            try container.encode(kind, forKey: .kind)
            try container.encode(slot, forKey: .slot)
            try container.encode(fileHash, forKey: .fileHash)
            try container.encode(isRestored, forKey: .isRestored)
            try container.encodeIfPresent(hostname, forKey: .hostname)
            try container.encodeIfPresent(machineId, forKey: .machineId)
        }

        private static func inferredKind(from description: String) -> String {
            description.localizedCaseInsensitiveContains("ssh adopt") ? "sshAdoption" : "scrape"
        }
    }

    private func deleteExpiredSecrets(passwordIDs: Set<UUID>, apiKeyIDs: Set<UUID>) throws {
        for id in passwordIDs {
            try keychain.deletePassword(for: id)
        }
        for id in apiKeyIDs {
            try keychain.deleteAPIKey(for: id)
        }
    }

    private func recordPasswordDeletions(_ ids: Set<UUID>, deletedAt: Date) throws {
        guard !ids.isEmpty else { return }
        try metadataStore.savePasswordDeletionTombstones(
            ids.map { PasswordDeletionTombstone(id: $0, deletedAt: deletedAt) }
        )
    }

    private func recordAPIKeyDeletions(_ ids: Set<UUID>, deletedAt: Date) throws {
        guard !ids.isEmpty else { return }
        try metadataStore.saveAPIKeyDeletionTombstones(
            ids.map { APIKeyDeletionTombstone(id: $0, deletedAt: deletedAt) }
        )
    }

    private func setPasswordCLIAccess(
        _ isEnabled: Bool,
        matching shouldUpdate: (PasswordMetadata) -> Bool
    ) -> Int {
        var count = 0
        for index in passwords.indices where shouldUpdate(passwords[index]) && passwords[index].isCliEnabled != isEnabled {
            passwords[index].isCliEnabled = isEnabled
            count += 1
        }
        return count
    }

    private func setAPIKeyCLIAccess(
        _ isEnabled: Bool,
        matching shouldUpdate: (APIKeyMetadata) -> Bool
    ) -> Int {
        var count = 0
        for index in apiKeys.indices where shouldUpdate(apiKeys[index]) && apiKeys[index].isCliEnabled != isEnabled {
            apiKeys[index].isCliEnabled = isEnabled
            count += 1
        }
        return count
    }

    private func setCertificateCLIAccess(
        _ isEnabled: Bool,
        matching shouldUpdate: (CertificateMetadata) -> Bool
    ) -> Int {
        var count = 0
        for index in certificates.indices where shouldUpdate(certificates[index]) &&
            certificates[index].isCliEnabled != isEnabled {
            certificates[index].isCliEnabled = isEnabled
            count += 1
        }
        return count
    }

    private func setNoteCLIAccess(
        _ isEnabled: Bool,
        matching shouldUpdate: (SecureNoteMetadata) -> Bool
    ) -> Int {
        var count = 0
        for index in notes.indices where shouldUpdate(notes[index]) && notes[index].isCliEnabled != isEnabled {
            notes[index].isCliEnabled = isEnabled
            count += 1
        }
        return count
    }

    private func setSSHKeyCLIAccess(
        _ isEnabled: Bool,
        matching shouldUpdate: (SSHKeyMetadata) -> Bool
    ) -> Int {
        var count = 0
        for index in sshKeys.indices where shouldUpdate(sshKeys[index]) && sshKeys[index].isCliEnabled != isEnabled {
            sshKeys[index].isCliEnabled = isEnabled
            count += 1
        }
        return count
    }

    private func persistCLIAccessChanges(
        passwordCount: Int,
        apiKeyCount: Int,
        certificateCount: Int,
        noteCount: Int,
        sshKeyCount: Int
    ) throws -> Int {
        let total = passwordCount + apiKeyCount + certificateCount + noteCount + sshKeyCount
        guard total > 0 else { return 0 }

        var changeNames: [Notification.Name] = []
        if passwordCount > 0 {
            try metadataStore.savePasswords(passwords)
            changeNames.append(.vaultPasswordsDidChange)
        }
        if apiKeyCount > 0 {
            try metadataStore.saveAPIKeys(apiKeys)
            changeNames.append(.vaultAPIKeysDidChange)
        }
        if certificateCount > 0 {
            try metadataStore.saveCertificates(certificates)
            changeNames.append(.vaultCertificatesDidChange)
        }
        if noteCount > 0 {
            try metadataStore.saveNotes(notes)
            changeNames.append(.vaultNotesDidChange)
        }
        if sshKeyCount > 0 {
            try metadataStore.saveSSHKeys(sshKeys)
            changeNames.append(.vaultSSHKeysDidChange)
        }

        try saveCLIMetadataSnapshot()
        postVaultChanges(changeNames)
        return total
    }

    func passwordSecretExistence(_ metadata: PasswordMetadata) -> SecretExistence {
        keychain.passwordExistence(for: metadata.id)
    }

    func apiKeySecretExistence(_ metadata: APIKeyMetadata) -> SecretExistence {
        keychain.apiKeyExistence(for: metadata.id)
    }

    func certificateSecretExistence(_ metadata: CertificateMetadata) -> SecretExistence {
        keychain.certificateExistence(for: metadata.id)
    }

    func noteSecretExistence(_ metadata: SecureNoteMetadata) -> SecretExistence {
        keychain.noteExistence(for: metadata.id)
    }

    func sshKeySecretExistence(_ metadata: SSHKeyMetadata) -> SecretExistence {
        keychain.sshKeyExistence(for: metadata.id)
    }

    private func normalizeFolderPath(_ folderPath: String?) -> String? {
        guard let folderPath else { return nil }
        let segments = folderPath
            .split(separator: "/")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard !segments.isEmpty else { return nil }
        return segments.joined(separator: "/")
    }

    private func normalizeFolders(_ folders: [String]) -> [String] {
        let normalized = folders.compactMap { normalizeFolderPath($0) }
        return Array(Set(normalized))
            .sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    }

    private func isPath(_ folderPath: String?, withinFolder target: String) -> Bool {
        guard let normalized = normalizeFolderPath(folderPath) else { return false }
        return normalized == target || normalized.hasPrefix("\(target)/")
    }

    private nonisolated static func deleteSecrets(
        keychain: any VaultKeychainStoring,
        passwordIDs: Set<UUID>,
        apiKeyIDs: Set<UUID>,
        certificateIDs: Set<UUID>,
        noteIDs: Set<UUID>,
        sshKeyIDs: Set<UUID>
    ) async throws {
        try await Task.detached(priority: .userInitiated) {
            for id in passwordIDs {
                try keychain.deletePassword(for: id)
            }
            for id in apiKeyIDs {
                try keychain.deleteAPIKey(for: id)
            }
            for id in certificateIDs {
                try keychain.deleteCertificate(for: id)
            }
            for id in noteIDs {
                try keychain.deleteNoteContent(for: id)
            }
            for id in sshKeyIDs {
                try keychain.deleteSSHKey(for: id)
            }
        }.value
    }
}
