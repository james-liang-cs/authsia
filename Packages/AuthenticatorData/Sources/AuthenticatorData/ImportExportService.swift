import Foundation
import AuthenticatorCore

public enum AccountImportConflictPolicy: Sendable {
    case keepExisting
    case overwriteExisting
}

public struct AccountImportPreview: Sendable {
    public let totalItems: Int
    public let duplicateIDCount: Int

    public var newItemsCount: Int {
        max(0, totalItems - duplicateIDCount)
    }

    public init(totalItems: Int, duplicateIDCount: Int) {
        self.totalItems = totalItems
        self.duplicateIDCount = duplicateIDCount
    }
}

/// Service for importing and exporting accounts in JSON format
@MainActor
public final class ImportExportService {
    public static let shared = ImportExportService()
    
    private init() {}
    
    // MARK: - Export
    
    /// Exports all accounts to JSON Data
    /// - Parameter repository: The AccountRepository containing accounts to export
    /// - Returns: JSON data ready to be written to file
    public func exportAccounts(from repository: AccountRepository) async throws -> Data {
        var exportableAccounts: [ExportableAccount] = []
        
        // Get all metadata
        let allMetadata = repository.accounts
        
        // Convert each account to exportable format
        for metadata in allMetadata {
            do {
                let account = try repository.getFullAccount(metadata: metadata)
                let exportable = ExportableAccount(from: metadata, secret: account.secret)
                exportableAccounts.append(exportable)
            } catch {
                CoreLogger.shared.error("Failed to export account \(metadata.id): \(error)")
                // Continue with other accounts even if one fails
            }
        }
        
        // Create container
        let container = ExportContainer(items: exportableAccounts)
        
        // Encode to JSON
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        
        do {
            return try encoder.encode(container)
        } catch {
            throw ImportExportError.invalidJSON
        }
    }
    
    // MARK: - Import
    
    /// Imports accounts from JSON Data
    /// - Parameters:
    ///   - data: JSON data to import
    ///   - repository: The AccountRepository to import into
    /// - Returns: Number of successfully imported accounts
    public func importAccounts(
        from data: Data,
        into repository: AccountRepository,
        conflictPolicy: AccountImportConflictPolicy = .keepExisting
    ) async throws -> Int {
        // Refresh in-memory state before checking for duplicates
        try repository.load()

        // Decode JSON
        let container = try decodeExportContainer(from: data)
        
        var importedCount = 0
        var skippedDuplicates = 0
        var failedImports: [(ExportableAccount, Error)] = []
        var accountsToOverwrite: [Account] = []
        
        // Collect accounts for batch import
        var accountsToImport: [Account] = []
        var existingIDs = Set(repository.accounts.map(\.id))
        
        // Import each account
        for exportable in container.items {
            do {
                let account = try exportable.toAccount()
                
                if existingIDs.contains(account.id) {
                    switch conflictPolicy {
                    case .keepExisting:
                        CoreLogger.shared.info("Skipping duplicate account ID: \(account.id)")
                        skippedDuplicates += 1
                    case .overwriteExisting:
                        accountsToOverwrite.append(account)
                    }
                    continue
                }

                // Check for non-ID duplicates
                if repository.findDuplicate(account) != nil {
                    CoreLogger.shared.info("Skipping duplicate account: \(account.issuer) - \(account.label)")
                    skippedDuplicates += 1
                    continue
                }
                
                accountsToImport.append(account)
                existingIDs.insert(account.id)
                
            } catch {
                CoreLogger.shared.error("Failed to import account \(exportable.issuer) - \(exportable.account): \(error)")
                failedImports.append((exportable, error))
            }
        }

        for account in accountsToOverwrite {
            do {
                try repository.saveOrUpdateAccount(account)
                importedCount += 1
            } catch {
                CoreLogger.shared.error("Failed to overwrite account \(account.id): \(error)")
            }
        }
        
        // Batch add accounts (Persists metadata ONCE)
        if !accountsToImport.isEmpty {
            do {
                try repository.addAccounts(accountsToImport)
                importedCount += accountsToImport.count
            } catch {
                CoreLogger.shared.error("Failed to save batch accounts: \(error)")
                // If batch save fails, we assume all failed for this batch
                // We should probably report this better, but for now log it.
                // Re-calculate imported count or throw?
                // Let's assume partial failure isn't handled by addAccounts (it throws on first error).
                throw error
            }
        }
        
        // Log summary
        CoreLogger.shared.info("""
        Import summary:
        - Imported: \(importedCount)
        - Skipped (duplicates): \(skippedDuplicates)
        - Failed: \(failedImports.count)
        """)
        
        // Notify observers that accounts have changed (if any were imported)
        if importedCount > 0 {
            NotificationCenter.default.post(name: .accountsDidChange, object: nil)
        }
        
        return importedCount
    }

    public func previewImportAccounts(from data: Data, into repository: AccountRepository) async throws -> AccountImportPreview {
        let container = try decodeExportContainer(from: data)
        let existingIDs = Set(repository.accounts.map(\.id))
        let duplicateIDCount = container.items.reduce(into: 0) { count, exportable in
            if let uuid = UUID(uuidString: exportable.primary), existingIDs.contains(uuid) {
                count += 1
            }
        }
        return AccountImportPreview(totalItems: container.items.count, duplicateIDCount: duplicateIDCount)
    }
    
    // MARK: - File I/O
    
    /// Export accounts to a file URL
    /// - Parameters:
    ///   - url: Destination file URL
    ///   - repository: The AccountRepository to export from
    public func exportToFile(url: URL, from repository: AccountRepository) async throws {
        let data = try await exportAccounts(from: repository)
        
        // Start accessing security-scoped resource (required for file saver on iOS/macOS)
        let didStartAccessing = url.startAccessingSecurityScopedResource()
        defer {
            if didStartAccessing {
                url.stopAccessingSecurityScopedResource()
            }
        }
        
        do {
            try data.write(to: url, options: .atomic)
            CoreLogger.shared.info("Exported accounts to \(url.path)")
        } catch {
            throw ImportExportError.fileWriteError(error)
        }
    }
    
    /// Import accounts from a file URL
    /// - Parameters:
    ///   - url: Source file URL
    ///   - repository: The AccountRepository to import into
    /// - Returns: Number of successfully imported accounts
    public func importFromFile(
        url: URL,
        into repository: AccountRepository,
        conflictPolicy: AccountImportConflictPolicy = .keepExisting
    ) async throws -> Int {
        // Start accessing security-scoped resource (required for file picker on iOS/macOS)
        let didStartAccessing = url.startAccessingSecurityScopedResource()
        defer {
            if didStartAccessing {
                url.stopAccessingSecurityScopedResource()
            }
        }
        
        let data: Data
        
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw ImportExportError.fileReadError(error)
        }
        
        CoreLogger.shared.info("Importing accounts from \(url.path)")
        return try await importAccounts(from: data, into: repository, conflictPolicy: conflictPolicy)
    }

    public func previewImportFromFile(url: URL, into repository: AccountRepository) async throws -> AccountImportPreview {
        let didStartAccessing = url.startAccessingSecurityScopedResource()
        defer {
            if didStartAccessing {
                url.stopAccessingSecurityScopedResource()
            }
        }

        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw ImportExportError.fileReadError(error)
        }

        return try await previewImportAccounts(from: data, into: repository)
    }

    private func decodeExportContainer(from data: Data) throws -> ExportContainer {
        let decoder = JSONDecoder()

        do {
            return try decoder.decode(ExportContainer.self, from: data)
        } catch {
            CoreLogger.shared.error("Failed to decode JSON: \(error)")
            throw ImportExportError.invalidJSON
        }
    }
}
