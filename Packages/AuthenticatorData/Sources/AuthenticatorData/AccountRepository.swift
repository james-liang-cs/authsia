import Foundation
import AuthenticatorCore

/// Result of attempting to recover secrets after an Apple ID switch.
public struct RecoveryResult {
    public let totalCount: Int
    public let recoveredCount: Int
    public let lostCount: Int
    public let lostAccounts: [AccountMetadata]

    public init(totalCount: Int, recoveredCount: Int, lostCount: Int, lostAccounts: [AccountMetadata]) {
        self.totalCount = totalCount
        self.recoveredCount = recoveredCount
        self.lostCount = lostCount
        self.lostAccounts = lostAccounts
    }
}

protocol AccountKeychainStoring: AnyObject {
    func save(secret: Data, for accountID: UUID) throws
    func retrieve(for accountID: UUID) throws -> Data
    func delete(for accountID: UUID) throws
}

extension KeychainStore: AccountKeychainStoring {}

@MainActor
public class AccountRepository {
    public static let shared = AccountRepository()
    
    private let keychain: any AccountKeychainStoring
    private let metadataStore: MetadataStore
    
    // In-memory cache of metadata
    public private(set) var accounts: [AccountMetadata] = []
    public private(set) var folders: [String] = []
    
    public convenience init(keychain: KeychainStore = .shared, metadataStore: MetadataStore = .shared) {
        self.init(keychainStore: keychain, metadataStore: metadataStore)
    }

    init(keychainStore: any AccountKeychainStoring, metadataStore: MetadataStore) {
        self.keychain = keychainStore
        self.metadataStore = metadataStore
    }
    
    public func load() throws {
        self.accounts = try metadataStore.loadAll()
        self.folders = try metadataStore.loadFolders()
        mergeAccountFoldersFromMetadata()
    }

    public func collectFullAccountsForCurrentStoragePolicy() throws -> [Account] {
        self.accounts = try metadataStore.loadAll()
        self.folders = try metadataStore.loadFolders()
        mergeAccountFoldersFromMetadata()

        return try accounts.map { metadata in
            try getFullAccount(metadata: metadata)
        }
    }

    public func saveFullAccountsToCurrentStoragePolicy(_ fullAccounts: [Account]) throws {
        for account in fullAccounts {
            try saveOrUpdateAccount(account)
        }
        try metadataStore.saveFolders(folders)
    }

    /// Attempts to recover secrets from local Keychain after an Apple ID switch.
    public func performRecovery() -> RecoveryResult {
        // Metadata lives in local JSON — it survives Apple ID switches.
        let metadata = self.accounts.isEmpty ? (try? metadataStore.loadAll()) ?? [] : self.accounts
        guard !metadata.isEmpty else {
            return RecoveryResult(totalCount: 0, recoveredCount: 0, lostCount: 0, lostAccounts: [])
        }

        var recoveredCount = 0
        var lostAccounts: [AccountMetadata] = []

        for meta in metadata {
            // retrieve(for:) tries synced first, then legacy, and backfills both directions internally.
            if (try? keychain.retrieve(for: meta.id)) != nil {
                recoveredCount += 1
            } else {
                lostAccounts.append(meta)
            }
        }

        CoreLogger.shared.info("Apple ID recovery: \(recoveredCount)/\(metadata.count) accounts recovered")

        return RecoveryResult(
            totalCount: metadata.count,
            recoveredCount: recoveredCount,
            lostCount: lostAccounts.count,
            lostAccounts: lostAccounts
        )
    }

    public func addAccount(_ account: Account) throws {
        // 1. Save Secret to Keychain
        try keychain.save(secret: account.secret, for: account.id)
        
        // 2. Save Metadata
        let metadata = AccountMetadata(from: account)
        var newAccounts = self.accounts
        newAccounts.append(metadata)
        
        try metadataStore.saveAll(newAccounts)
        self.accounts = newAccounts
        try registerFolderIfNeeded(metadata.folderPath)
    }
    
    /// Adds multiple accounts efficiently by saving metadata only once.
    public func addAccounts(_ accounts: [Account]) throws {
        if accounts.isEmpty { return }
        
        // 1. Save Secrets to Keychain (Iterative)
        // We do this first so if it fails, we haven't updated metadata yet
        // However, secrets are individual items so failures might be partial.
        // We'll trust the individual saves.
        for account in accounts {
            try keychain.save(secret: account.secret, for: account.id)
        }
        
        // 2. Save Metadata (Batch)
        let newMetadata = accounts.map { AccountMetadata(from: $0) }
        var currentAccounts = self.accounts
        currentAccounts.append(contentsOf: newMetadata)
        
        try metadataStore.saveAll(currentAccounts)
        self.accounts = currentAccounts
        mergeAccountFoldersFromMetadata()
    }
    
    public func deleteAccount(id: UUID) throws {
        // 1. Delete from Keychain
        // We attempt to delete, but if it fails (not found), we proceed to clean metadata
        try? keychain.delete(for: id)
        
        // 2. Remove from Metadata
        var newAccounts = self.accounts
        newAccounts.removeAll { $0.id == id }
        
        try metadataStore.saveAll(newAccounts)
        self.accounts = newAccounts
    }
    
    public func updateAccountMetadata(_ metadata: AccountMetadata) throws {
        var newAccounts = self.accounts
        if let index = newAccounts.firstIndex(where: { $0.id == metadata.id }) {
            newAccounts[index] = metadata
            try metadataStore.saveAll(newAccounts)
            self.accounts = newAccounts
            try registerFolderIfNeeded(metadata.folderPath)
        }
    }

    public func saveOrUpdateAccount(_ account: Account) throws {
        try keychain.save(secret: account.secret, for: account.id)

        let metadata = AccountMetadata(from: account)
        var newAccounts = self.accounts
        if let index = newAccounts.firstIndex(where: { $0.id == account.id }) {
            newAccounts[index] = metadata
        } else {
            newAccounts.append(metadata)
        }

        try metadataStore.saveAll(newAccounts)
        self.accounts = newAccounts
        mergeAccountFoldersFromMetadata()
    }
    
    public func getFullAccount(metadata: AccountMetadata) throws -> Account {
        let secret = try keychain.retrieve(for: metadata.id)
        return metadata.toAccount(secret: secret)
    }
    /// Checks if an account already exists (by Secret or Issuer+Label).
    public func findDuplicate(_ newAccount: Account) -> AccountMetadata? {
        // 1. Check Metadata (Fast)
        if let match = accounts.first(where: {
            $0.issuer.caseInsensitiveCompare(newAccount.issuer) == .orderedSame &&
            $0.label.caseInsensitiveCompare(newAccount.label) == .orderedSame
        }) {
            return match
        }
        
        // 2. Check Secrets (Slower, involves Keychain access)
        // We iterate through all accounts to check if the secret is identical.
        for metadata in accounts {
            if let existingSecret = try? keychain.retrieve(for: metadata.id),
               existingSecret == newAccount.secret {
                return metadata
            }
        }
        
        return nil
    }

    public func saveFolders(_ folders: [String]) throws {
        try metadataStore.saveFolders(folders)
        self.folders = normalizeFolders(folders)
    }

    public func loadFolders() throws -> [String] {
        let loadedFolders = try metadataStore.loadFolders()
        self.folders = normalizeFolders(loadedFolders)
        return self.folders
    }

    private func registerFolderIfNeeded(_ folderPath: String?) throws {
        guard let normalizedPath = normalizeFolderPath(folderPath) else { return }
        if folders.contains(normalizedPath) {
            return
        }
        folders.append(normalizedPath)
        folders = normalizeFolders(folders)
        try metadataStore.saveFolders(folders)
    }

    private func mergeAccountFoldersFromMetadata() {
        let metadataFolders = accounts.compactMap { normalizeFolderPath($0.folderPath) }
        let mergedFolders = normalizeFolders(folders + metadataFolders)
        guard mergedFolders != folders else { return }
        folders = mergedFolders
        try? metadataStore.saveFolders(mergedFolders)
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

    private func normalizeFolders(_ folderPaths: [String]) -> [String] {
        let normalized = folderPaths.compactMap { normalizeFolderPath($0) }
        return Array(Set(normalized))
            .sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    }
    
    // MARK: - Delete All

    /// Permanently deletes all accounts and folders.
    /// Removes secrets from Keychain and clears all metadata.
    public func deleteAllAccounts() throws {
        // 1. Delete all secrets from Keychain
        for account in accounts {
            try? keychain.delete(for: account.id)
        }

        // 2. Clear metadata
        try metadataStore.saveAll([])
        self.accounts = []

        // 3. Clear folders
        try metadataStore.saveFolders([])
        self.folders = []
    }

    // MARK: - Import/Export

    /// Export all accounts to JSON data
    public func exportAccounts() async throws -> Data {
        return try await ImportExportService.shared.exportAccounts(from: self)
    }
    
    /// Import accounts from JSON data
    /// - Returns: Number of successfully imported accounts
    public func importAccounts(
        from data: Data,
        conflictPolicy: AccountImportConflictPolicy = .keepExisting
    ) async throws -> Int {
        return try await ImportExportService.shared.importAccounts(
            from: data,
            into: self,
            conflictPolicy: conflictPolicy
        )
    }
    
    /// Export accounts to a file
    public func exportToFile(url: URL) async throws {
        try await ImportExportService.shared.exportToFile(url: url, from: self)
    }
    
    /// Import accounts from a file
    /// - Returns: Number of successfully imported accounts
    public func importFromFile(
        url: URL,
        conflictPolicy: AccountImportConflictPolicy = .keepExisting
    ) async throws -> Int {
        return try await ImportExportService.shared.importFromFile(
            url: url,
            into: self,
            conflictPolicy: conflictPolicy
        )
    }

    public func previewImportAccounts(from data: Data) async throws -> AccountImportPreview {
        try await ImportExportService.shared.previewImportAccounts(from: data, into: self)
    }

    public func previewImportFromFile(url: URL) async throws -> AccountImportPreview {
        try await ImportExportService.shared.previewImportFromFile(url: url, into: self)
    }
}
