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
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(metadata)
        try keychain.save(data: data, for: "account_metadata")
        CoreLogger.shared.info("Saved metadata to Keychain")
    }
    
    public func loadAll() throws -> [AccountMetadata] {
        do {
            let data = try keychain.retrieve(for: "account_metadata")
            let decoder = JSONDecoder()
            do {
                let metadata = try decoder.decode([AccountMetadata].self, from: data)
                CoreLogger.shared.info("Loaded metadata from Keychain")
                return metadata
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
