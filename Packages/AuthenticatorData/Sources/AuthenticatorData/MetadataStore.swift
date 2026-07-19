import Foundation
import AuthenticatorCore

/// Represents the data stored locally (non-secret).
/// The Secret is stored in Keychain and linked by ID.
public struct AccountMetadata: Identifiable, Equatable {
    public let id: UUID
    public var issuer: String
    public var label: String
    public var folderPath: String?
    public var algorithm: OTPAlgorithm
    public var digits: Int
    public var type: OTPType
    public var period: TimeInterval
    public var counter: UInt64
    public var createdAt: Date
    public var lastUsed: Date
    
    // UI Metadata
    public var colorHex: String?
    public var isFavorite: Bool
    public var isCliEnabled: Bool
    public var isScraped: Bool
    
    // Import/Export Metadata (with defaults for backward compatibility)
    public var icon: String?
    public var hosts: [String]?
    public var isExcludedFromWatch: Bool
    
    public init(from account: Account) {
        self.id = account.id
        self.issuer = account.issuer
        self.label = account.label
        self.folderPath = account.folderPath
        self.algorithm = account.algorithm
        self.digits = account.digits
        self.type = account.type
        self.period = account.period
        self.counter = account.counter
        self.createdAt = account.createdAt
        self.lastUsed = account.lastUsed
        self.colorHex = nil
        self.isFavorite = account.isFavorite
        self.isCliEnabled = account.isCliEnabled
        self.isScraped = account.isScraped
        self.icon = account.icon
        self.hosts = account.hosts
        self.isExcludedFromWatch = account.isExcludedFromWatch
    }
    
    /// Reconstructs the full Account object by combining metadata with the secret.
    public func toAccount(secret: Data) -> Account {
        return Account(
            id: id,
            issuer: issuer,
            label: label,
            folderPath: folderPath,
            secret: secret,
            algorithm: algorithm,
            digits: digits,
            type: type,
            period: period,
            counter: counter,
            createdAt: createdAt,
            lastUsed: lastUsed,
            isFavorite: isFavorite,
            isCliEnabled: isCliEnabled,
            isScraped: isScraped,
            icon: icon,
            hosts: hosts,
            isExcludedFromWatch: isExcludedFromWatch
        )
    }
}

// MARK: - Codable Implementation with Backward Compatibility

extension AccountMetadata: Codable {
    enum CodingKeys: String, CodingKey {
        case id, issuer, label, folderPath, algorithm, digits, type, period, counter
        case createdAt, lastUsed, colorHex, isFavorite, isCliEnabled, isScraped
        case icon, hosts, isExcludedFromWatch
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        // Required fields
        id = try container.decode(UUID.self, forKey: .id)
        issuer = try container.decode(String.self, forKey: .issuer)
        label = try container.decode(String.self, forKey: .label)
        folderPath = try container.decodeIfPresent(String.self, forKey: .folderPath)
        algorithm = try container.decode(OTPAlgorithm.self, forKey: .algorithm)
        digits = try container.decode(Int.self, forKey: .digits)
        type = try container.decode(OTPType.self, forKey: .type)
        period = try container.decode(TimeInterval.self, forKey: .period)
        counter = try container.decode(UInt64.self, forKey: .counter)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        lastUsed = try container.decode(Date.self, forKey: .lastUsed)
        
        // Optional fields with defaults
        colorHex = try container.decodeIfPresent(String.self, forKey: .colorHex)
        isFavorite = try container.decodeIfPresent(Bool.self, forKey: .isFavorite) ?? false
        isCliEnabled = try container.decodeIfPresent(Bool.self, forKey: .isCliEnabled) ?? true
        isScraped = try container.decodeIfPresent(Bool.self, forKey: .isScraped) ?? false
        
        // NEW fields with defaults for backward compatibility
        icon = try container.decodeIfPresent(String.self, forKey: .icon)
        hosts = try container.decodeIfPresent([String].self, forKey: .hosts)
        isExcludedFromWatch = try container.decodeIfPresent(Bool.self, forKey: .isExcludedFromWatch) ?? false
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(id, forKey: .id)
        try container.encode(issuer, forKey: .issuer)
        try container.encode(label, forKey: .label)
        try container.encodeIfPresent(folderPath, forKey: .folderPath)
        try container.encode(algorithm, forKey: .algorithm)
        try container.encode(digits, forKey: .digits)
        try container.encode(type, forKey: .type)
        try container.encode(period, forKey: .period)
        try container.encode(counter, forKey: .counter)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(lastUsed, forKey: .lastUsed)
        try container.encodeIfPresent(colorHex, forKey: .colorHex)
        try container.encode(isFavorite, forKey: .isFavorite)
        try container.encode(isCliEnabled, forKey: .isCliEnabled)
        try container.encode(isScraped, forKey: .isScraped)
        try container.encodeIfPresent(icon, forKey: .icon)
        try container.encodeIfPresent(hosts, forKey: .hosts)
        try container.encode(isExcludedFromWatch, forKey: .isExcludedFromWatch)
    }
}

protocol MetadataKeychainStoring {
    func save(data: Data, for key: String) throws
    func retrieve(for key: String) throws -> Data
    func retrieveCandidates(for key: String) throws -> [KeychainDataCandidate]
}

struct AccountDeletionTombstone: Identifiable, Codable, Equatable, Sendable {
    let id: UUID
    let deletedAt: Date
}

extension KeychainStore: MetadataKeychainStoring {}

public final class MetadataStore: @unchecked Sendable {
    public static let shared = MetadataStore()

    private let fileURL: URL?
    private let foldersFileURL: URL?
    private let keychain: MetadataKeychainStoring

    private static func documentsFileURL(named fileName: String) -> URL? {
        do {
            let documents = try FileManager.default.url(
                for: .documentDirectory,
                in: .userDomainMask,
                appropriateFor: nil,
                create: true
            )
            return documents.appendingPathComponent(fileName)
        } catch {
            #if DEBUG
            print("⚠️ Failed to get documents directory: \(error)")
            #endif
            return nil
        }
    }

    private convenience init() {
        self.init(
            fileURL: Self.documentsFileURL(named: "accounts_metadata.json"),
            foldersFileURL: Self.documentsFileURL(named: "accounts_folders.json"),
            keychain: KeychainStore.shared
        )
    }

    init(
        fileURL: URL?,
        foldersFileURL: URL?,
        keychain: MetadataKeychainStoring
    ) {
        self.fileURL = fileURL
        self.foldersFileURL = foldersFileURL
        self.keychain = keychain
    }
    
    public func saveAll(_ metadata: [AccountMetadata]) throws {
        // Merge with the current candidates so a writer holding a stale cache
        // cannot silently erase accounts another process or device added, then
        // drop anything covered by a deletion tombstone so stale candidates
        // cannot reintroduce deleted accounts.
        var mergedByID: [UUID: AccountMetadata] = [:]
        var order: [UUID] = []
        for item in try loadAll() where mergedByID[item.id] == nil {
            mergedByID[item.id] = item
            order.append(item.id)
        }
        for item in metadata {
            if mergedByID[item.id] == nil {
                order.append(item.id)
            }
            mergedByID[item.id] = item
        }
        let merged = try filterTombstonedAccounts(order.compactMap { mergedByID[$0] })
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(merged)
        try keychain.save(data: data, for: "account_metadata")
        CoreLogger.shared.info("Saved metadata to Keychain")
    }

    public func loadAll() throws -> [AccountMetadata] {
        do {
            let candidates = try keychain.retrieveCandidates(for: "account_metadata")
            let tombstonesByID = Dictionary(
                uniqueKeysWithValues: try loadAccountDeletionTombstones().map { ($0.id, $0) }
            )
            var merged: [AccountMetadata] = []
            var seenIDs = Set<UUID>()
            for candidate in candidates {
                guard let data = candidate.data else { continue }
                let decoded: [AccountMetadata]
                do {
                    decoded = try JSONDecoder().decode([AccountMetadata].self, from: data)
                } catch {
                    throw MetadataLoadError.decodeFailed(String(describing: error))
                }
                for item in decoded
                    where isVisible(item, tombstonesByID: tombstonesByID) && seenIDs.insert(item.id).inserted {
                    merged.append(item)
                }
            }
            if candidates.contains(where: \.needsHealing),
               candidates.contains(where: { $0.data != nil }),
               let data = try? JSONEncoder().encode(merged) {
                try? keychain.save(data: data, for: "account_metadata")
            }
            CoreLogger.shared.info("Loaded metadata from Keychain")
            return merged
        } catch let metadataError as MetadataLoadError {
            throw metadataError
        } catch let KeychainError.unknown(status) {
            throw MetadataLoadError.keychainUnavailable(status)
        } catch {
            throw MetadataLoadError.keychainUnavailable(nil)
        }
    }

    private func filterTombstonedAccounts(_ metadata: [AccountMetadata]) throws -> [AccountMetadata] {
        let tombstonesByID = Dictionary(
            uniqueKeysWithValues: try loadAccountDeletionTombstones().map { ($0.id, $0) }
        )
        return metadata.filter { isVisible($0, tombstonesByID: tombstonesByID) }
    }

    private func isVisible(
        _ item: AccountMetadata,
        tombstonesByID: [UUID: AccountDeletionTombstone]
    ) -> Bool {
        guard let tombstone = tombstonesByID[item.id] else { return true }
        return item.lastUsed > tombstone.deletedAt
    }

    func saveAccountDeletionTombstones(_ tombstones: [AccountDeletionTombstone]) throws {
        let merged = mergeTombstones(tombstones, with: try loadAccountDeletionTombstones())
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(merged)
        try keychain.save(data: data, for: "account_deletion_tombstones")
    }

    func loadAccountDeletionTombstones() throws -> [AccountDeletionTombstone] {
        do {
            let candidates = try keychain.retrieveCandidates(for: "account_deletion_tombstones")
            var merged: [AccountDeletionTombstone] = []
            var writeTargetFingerprints: [[UUID: Date]] = []
            for candidate in candidates {
                guard let data = candidate.data else { continue }
                let decoded: [AccountDeletionTombstone]
                do {
                    decoded = try JSONDecoder().decode([AccountDeletionTombstone].self, from: data)
                } catch {
                    throw MetadataLoadError.decodeFailed(String(describing: error))
                }
                if candidate.isWriteTarget {
                    writeTargetFingerprints.append(
                        Dictionary(decoded.map { ($0.id, $0.deletedAt) }, uniquingKeysWith: { max($0, $1) })
                    )
                }
                merged = mergeTombstones(decoded, with: merged)
            }
            // Re-save the union when any candidate is missing entries (for
            // example after iCloud last-writer-wins clobbered a fresher blob on
            // another device) so deletion intent stays monotonic. Best effort.
            let mergedFingerprint = Dictionary(
                merged.map { ($0.id, $0.deletedAt) },
                uniquingKeysWith: { max($0, $1) }
            )
            if (candidates.contains(where: \.needsHealing)
                || writeTargetFingerprints.contains(where: { $0 != mergedFingerprint })),
               candidates.contains(where: { $0.data != nil }),
               let data = try? JSONEncoder().encode(merged) {
                try? keychain.save(data: data, for: "account_deletion_tombstones")
            }
            return merged
        } catch let metadataError as MetadataLoadError {
            throw metadataError
        } catch let KeychainError.unknown(status) {
            throw MetadataLoadError.keychainUnavailable(status)
        } catch {
            throw MetadataLoadError.keychainUnavailable(nil)
        }
    }

    private func mergeTombstones(
        _ incoming: [AccountDeletionTombstone],
        with existing: [AccountDeletionTombstone]
    ) -> [AccountDeletionTombstone] {
        var byID = Dictionary(uniqueKeysWithValues: existing.map { ($0.id, $0) })
        for tombstone in incoming {
            if let current = byID[tombstone.id], current.deletedAt > tombstone.deletedAt {
                continue
            }
            byID[tombstone.id] = tombstone
        }
        return byID.values.sorted { $0.deletedAt < $1.deletedAt }
    }

    public func saveFolders(_ folders: [String]) throws {
        let normalizedFolders = normalizeFolderPaths(folders)
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(normalizedFolders)
        try keychain.save(data: data, for: "account_folders")
        CoreLogger.shared.info("Saved account folders to Keychain")
    }

    public func loadFolders() throws -> [String] {
        do {
            let data = try keychain.retrieve(for: "account_folders")
            let decoder = JSONDecoder()
            do {
                let folders = try decoder.decode([String].self, from: data)
                let normalizedFolders = normalizeFolderPaths(folders)
                CoreLogger.shared.info("Loaded account folders from Keychain")
                return normalizedFolders
            } catch {
                throw MetadataLoadError.decodeFailed(String(describing: error))
            }
        } catch let metadataError as MetadataLoadError {
            throw metadataError
        } catch KeychainError.itemNotFound {
            return []
        } catch let KeychainError.unknown(status) {
            throw MetadataLoadError.keychainUnavailable(status)
        } catch {
            throw MetadataLoadError.keychainUnavailable(nil)
        }
    }

    private func normalizeFolderPaths(_ folders: [String]) -> [String] {
        let normalized = folders.compactMap { path -> String? in
            let segments = path
                .split(separator: "/")
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            guard !segments.isEmpty else { return nil }
            return segments.joined(separator: "/")
        }
        return Array(Set(normalized))
            .sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    }
}
