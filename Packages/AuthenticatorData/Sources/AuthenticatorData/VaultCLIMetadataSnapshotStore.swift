import Foundation
import AuthenticatorCore

public struct VaultCLIMetadataSnapshot: Codable, Equatable, Sendable {
    public struct Password: Identifiable, Codable, Equatable, Sendable {
        public let id: UUID
        public let name: String
        public let username: String
        public let website: String?
        public let folderPath: String?
        public let createdAt: Date
        public let modifiedAt: Date
        public let isFavorite: Bool
        public let isCliEnabled: Bool
        public let isScraped: Bool
        public let scrapeMachineName: String?
        public let scrapeMachineId: String?
        public let expiresAt: Date?
        @VaultEnvironmentTagList public var environments: [String] = []

        public init(from metadata: PasswordMetadata) {
            id = metadata.id
            name = metadata.name
            username = metadata.username
            website = metadata.website
            folderPath = metadata.folderPath
            createdAt = metadata.createdAt
            modifiedAt = metadata.modifiedAt
            isFavorite = metadata.isFavorite
            isCliEnabled = metadata.isCliEnabled
            isScraped = metadata.isScraped
            scrapeMachineName = metadata.scrapeMachineName
            scrapeMachineId = metadata.scrapeMachineId
            expiresAt = metadata.expiresAt
            environments = metadata.environments
        }
    }

    public struct APIKey: Identifiable, Codable, Equatable, Sendable {
        public let id: UUID
        public let name: String
        public let website: String?
        public let folderPath: String?
        public let createdAt: Date
        public let modifiedAt: Date
        public let isFavorite: Bool
        public let isCliEnabled: Bool
        public let isScraped: Bool
        public let scrapeMachineName: String?
        public let scrapeMachineId: String?
        public let expiresAt: Date?
        @VaultEnvironmentTagList public var environments: [String] = []

        public init(from metadata: APIKeyMetadata) {
            id = metadata.id
            name = metadata.name
            website = metadata.website
            folderPath = metadata.folderPath
            createdAt = metadata.createdAt
            modifiedAt = metadata.modifiedAt
            isFavorite = metadata.isFavorite
            isCliEnabled = metadata.isCliEnabled
            isScraped = metadata.isScraped
            scrapeMachineName = metadata.scrapeMachineName
            scrapeMachineId = metadata.scrapeMachineId
            expiresAt = metadata.expiresAt
            environments = metadata.environments
        }
    }

    public struct Certificate: Identifiable, Codable, Equatable, Sendable {
        public let id: UUID
        public let name: String
        public let issuer: String?
        public let subject: String?
        public let expirationDate: Date?
        public let folderPath: String?
        public let createdAt: Date
        public let modifiedAt: Date
        public let isFavorite: Bool
        public let isCliEnabled: Bool
        public let isScraped: Bool
        public let scrapeMachineName: String?
        public let scrapeMachineId: String?
        @VaultEnvironmentTagList public var environments: [String] = []

        public init(from metadata: CertificateMetadata) {
            id = metadata.id
            name = metadata.name
            issuer = metadata.issuer
            subject = metadata.subject
            expirationDate = metadata.expirationDate
            folderPath = metadata.folderPath
            createdAt = metadata.createdAt
            modifiedAt = metadata.modifiedAt
            isFavorite = metadata.isFavorite
            isCliEnabled = metadata.isCliEnabled
            isScraped = metadata.isScraped
            scrapeMachineName = metadata.scrapeMachineName
            scrapeMachineId = metadata.scrapeMachineId
            environments = metadata.environments
        }
    }

    public struct Note: Identifiable, Codable, Equatable, Sendable {
        public let id: UUID
        public let title: String
        public let folderPath: String?
        public let createdAt: Date
        public let modifiedAt: Date
        public let isFavorite: Bool
        public let isCliEnabled: Bool
        public let isScraped: Bool
        public let scrapeMachineName: String?
        public let scrapeMachineId: String?
        @VaultEnvironmentTagList public var environments: [String] = []

        public init(from metadata: SecureNoteMetadata) {
            id = metadata.id
            title = metadata.title
            folderPath = metadata.folderPath
            createdAt = metadata.createdAt
            modifiedAt = metadata.modifiedAt
            isFavorite = metadata.isFavorite
            isCliEnabled = metadata.isCliEnabled
            isScraped = metadata.isScraped
            scrapeMachineName = metadata.scrapeMachineName
            scrapeMachineId = metadata.scrapeMachineId
            environments = metadata.environments
        }
    }

    public struct SSHKey: Identifiable, Codable, Equatable, Sendable {
        public let id: UUID
        public let name: String
        public let publicKey: String
        public let comment: String
        public let fingerprint: String
        public let folderPath: String?
        public let createdAt: Date
        public let modifiedAt: Date
        public let isFavorite: Bool
        public let isCliEnabled: Bool
        public let isScraped: Bool
        public let scrapeMachineName: String?
        public let scrapeMachineId: String?
        public let keyType: SSHKeyType
        public let approvalPolicy: SSHKeyApprovalPolicy
        public let boundHosts: [String]
        @VaultEnvironmentTagList public var environments: [String] = []

        public init(from metadata: SSHKeyMetadata) {
            id = metadata.id
            name = metadata.name
            publicKey = metadata.publicKey
            comment = metadata.comment
            fingerprint = metadata.fingerprint
            folderPath = metadata.folderPath
            createdAt = metadata.createdAt
            modifiedAt = metadata.modifiedAt
            isFavorite = metadata.isFavorite
            isCliEnabled = metadata.isCliEnabled
            isScraped = metadata.isScraped
            scrapeMachineName = metadata.scrapeMachineName
            scrapeMachineId = metadata.scrapeMachineId
            keyType = metadata.keyType
            approvalPolicy = metadata.approvalPolicy
            boundHosts = metadata.boundHosts
            environments = metadata.environments
        }
    }

    public let savedAt: Date
    public let passwords: [Password]
    public let apiKeys: [APIKey]
    public let certificates: [Certificate]
    public let notes: [Note]
    public let sshKeys: [SSHKey]
    public let folders: [VaultItemType: [String]]

    private enum CodingKeys: String, CodingKey {
        case savedAt
        case passwords
        case apiKeys
        case certificates
        case notes
        case sshKeys
        case folders
    }

    public init(
        savedAt: Date = Date(),
        passwords: [Password],
        apiKeys: [APIKey] = [],
        certificates: [Certificate],
        notes: [Note],
        sshKeys: [SSHKey],
        folders: [VaultItemType: [String]]
    ) {
        self.savedAt = savedAt
        self.passwords = passwords
        self.apiKeys = apiKeys
        self.certificates = certificates
        self.notes = notes
        self.sshKeys = sshKeys
        self.folders = folders
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        savedAt = try container.decode(Date.self, forKey: .savedAt)
        passwords = try container.decode([Password].self, forKey: .passwords)
        apiKeys = try container.decodeIfPresent([APIKey].self, forKey: .apiKeys) ?? []
        certificates = try container.decode([Certificate].self, forKey: .certificates)
        notes = try container.decode([Note].self, forKey: .notes)
        sshKeys = try container.decode([SSHKey].self, forKey: .sshKeys)
        folders = try Self.decodeFolders(from: container)
    }

    public init(
        savedAt: Date = Date(),
        passwords: [PasswordMetadata],
        apiKeys: [APIKeyMetadata] = [],
        certificates: [CertificateMetadata],
        notes: [SecureNoteMetadata],
        sshKeys: [SSHKeyMetadata],
        folders: [VaultItemType: [String]]
    ) {
        self.init(
            savedAt: savedAt,
            passwords: passwords.map(Password.init),
            apiKeys: apiKeys.map(APIKey.init),
            certificates: certificates.map(Certificate.init),
            notes: notes.map(Note.init),
            sshKeys: sshKeys.map(SSHKey.init),
            folders: folders
        )
    }

    private static func decodeFolders(from container: KeyedDecodingContainer<CodingKeys>) throws -> [VaultItemType: [String]] {
        if let folders = try? container.decode([VaultItemType: [String]].self, forKey: .folders) {
            return folders
        }
        let rawFolders = try container.decode([String: [String]].self, forKey: .folders)
        return Dictionary(uniqueKeysWithValues: rawFolders.compactMap { rawType, paths in
            guard let type = VaultItemType(rawValue: rawType) else { return nil }
            return (type, paths)
        })
    }
}

protocol VaultCLIMetadataSnapshotStoring: AnyObject {
    func save(_ snapshot: VaultCLIMetadataSnapshot) throws
}

public final class VaultCLIMetadataSnapshotStore: VaultCLIMetadataSnapshotStoring, @unchecked Sendable {
    public static let shared = VaultCLIMetadataSnapshotStore()

    private let fileManager: FileManager
    private let applicationSupportDirectory: URL
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public convenience init() {
        self.init(
            applicationSupportDirectory: FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            )[0],
            fileManager: .default
        )
    }

    init(applicationSupportDirectory: URL, fileManager: FileManager = .default) {
        self.applicationSupportDirectory = applicationSupportDirectory
        self.fileManager = fileManager
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
    }

    public func save(_ snapshot: VaultCLIMetadataSnapshot) throws {
        let directory = snapshotURL.deletingLastPathComponent()
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        #if os(macOS)
        try? fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        #endif

        let data = try encoder.encode(snapshot)
        try data.write(to: snapshotURL, options: .atomic)
        #if os(macOS)
        try? fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: snapshotURL.path)
        #endif
    }

    public func load() throws -> VaultCLIMetadataSnapshot? {
        guard fileManager.fileExists(atPath: snapshotURL.path) else {
            return nil
        }
        let data = try Data(contentsOf: snapshotURL)
        return try decoder.decode(VaultCLIMetadataSnapshot.self, from: data)
    }

    private var snapshotURL: URL {
        applicationSupportDirectory
            .appendingPathComponent("Authsia", isDirectory: true)
            .appendingPathComponent("CLI", isDirectory: true)
            .appendingPathComponent("vault_metadata_snapshot.json")
    }
}
