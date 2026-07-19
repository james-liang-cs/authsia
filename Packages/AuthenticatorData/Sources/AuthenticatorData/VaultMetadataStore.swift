import Foundation
import AuthenticatorCore
import Security

// MARK: - Password Metadata (non-secret parts)

public struct PasswordMetadata: Identifiable, Codable, Equatable, Sendable {
    public let id: UUID
    public var name: String
    public var username: String
    public var website: String?
    public var notes: String?
    public var folderPath: String?
    public var createdAt: Date
    public var modifiedAt: Date
    public var isFavorite: Bool
    public var isCliEnabled: Bool
    public var isScraped: Bool
    public var scrapeMachineName: String?
    public var scrapeMachineId: String?
    public var expiresAt: Date?
    public var autoDestroyOnExpiry: Bool
    public var environments: [String]

    public init(from item: PasswordItem) {
        self.id = item.id
        self.name = item.name
        self.username = item.username
        self.website = item.website
        self.notes = item.notes
        self.folderPath = item.folderPath
        self.createdAt = item.createdAt
        self.modifiedAt = item.modifiedAt
        self.isFavorite = item.isFavorite
        self.isCliEnabled = item.isCliEnabled
        self.isScraped = item.isScraped
        self.scrapeMachineName = item.scrapeMachineName
        self.scrapeMachineId = item.scrapeMachineId
        self.expiresAt = item.expiresAt
        self.autoDestroyOnExpiry = item.autoDestroyOnExpiry
        self.environments = item.environments
    }

    public init(
        id: UUID,
        name: String,
        username: String,
        website: String?,
        notes: String?,
        folderPath: String? = nil,
        createdAt: Date,
        modifiedAt: Date,
        isFavorite: Bool,
        isCliEnabled: Bool,
        isScraped: Bool,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        expiresAt: Date? = nil,
        autoDestroyOnExpiry: Bool = false,
        environments: [String] = []
    ) {
        self.id = id
        self.name = name
        self.username = username
        self.website = website
        self.notes = notes
        self.folderPath = folderPath
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.isFavorite = isFavorite
        self.isCliEnabled = isCliEnabled
        self.isScraped = isScraped
        self.scrapeMachineName = scrapeMachineName
        self.scrapeMachineId = scrapeMachineId
        self.expiresAt = expiresAt
        self.autoDestroyOnExpiry = autoDestroyOnExpiry
        self.environments = VaultEnvironmentTags.normalize(environments)
    }

    public func toPasswordItem(password: Data) -> PasswordItem {
        PasswordItem(
            id: id,
            name: name,
            username: username,
            password: password,
            website: website,
            notes: notes,
            folderPath: folderPath,
            createdAt: createdAt,
            modifiedAt: modifiedAt,
            isFavorite: isFavorite,
            isCliEnabled: isCliEnabled,
            isScraped: isScraped,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            expiresAt: expiresAt,
            autoDestroyOnExpiry: autoDestroyOnExpiry,
            environments: environments
        )
    }
}

struct PasswordDeletionTombstone: Identifiable, Codable, Equatable, Sendable {
    let id: UUID
    let deletedAt: Date
}

struct APIKeyDeletionTombstone: Identifiable, Codable, Equatable, Sendable {
    let id: UUID
    let deletedAt: Date
}

struct CertificateDeletionTombstone: Identifiable, Codable, Equatable, Sendable {
    let id: UUID
    let deletedAt: Date
}

struct NoteDeletionTombstone: Identifiable, Codable, Equatable, Sendable {
    let id: UUID
    let deletedAt: Date
}

struct SSHKeyDeletionTombstone: Identifiable, Codable, Equatable, Sendable {
    let id: UUID
    let deletedAt: Date
}

struct VaultFolderState: Codable, Equatable, Sendable {
    let type: VaultItemType
    let path: String
    let modifiedAt: Date
    let isDeleted: Bool
}

// MARK: - API Key Metadata (non-secret parts)

public struct APIKeyMetadata: Identifiable, Codable, Equatable, Sendable {
    public let id: UUID
    public var name: String
    public var website: String?
    public var notes: String?
    public var folderPath: String?
    public var createdAt: Date
    public var modifiedAt: Date
    public var isFavorite: Bool
    public var isCliEnabled: Bool
    public var isScraped: Bool
    public var scrapeMachineName: String?
    public var scrapeMachineId: String?
    public var expiresAt: Date?
    public var autoDestroyOnExpiry: Bool
    public var environments: [String]

    public init(from item: APIKeyItem) {
        self.id = item.id
        self.name = item.name
        self.website = item.website
        self.notes = item.notes
        self.folderPath = item.folderPath
        self.createdAt = item.createdAt
        self.modifiedAt = item.modifiedAt
        self.isFavorite = item.isFavorite
        self.isCliEnabled = item.isCliEnabled
        self.isScraped = item.isScraped
        self.scrapeMachineName = item.scrapeMachineName
        self.scrapeMachineId = item.scrapeMachineId
        self.expiresAt = item.expiresAt
        self.autoDestroyOnExpiry = item.autoDestroyOnExpiry
        self.environments = item.environments
    }

    public init(
        id: UUID,
        name: String,
        website: String?,
        notes: String?,
        folderPath: String? = nil,
        createdAt: Date,
        modifiedAt: Date,
        isFavorite: Bool,
        isCliEnabled: Bool,
        isScraped: Bool,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        expiresAt: Date? = nil,
        autoDestroyOnExpiry: Bool = false,
        environments: [String] = []
    ) {
        self.id = id
        self.name = name
        self.website = website
        self.notes = notes
        self.folderPath = folderPath
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.isFavorite = isFavorite
        self.isCliEnabled = isCliEnabled
        self.isScraped = isScraped
        self.scrapeMachineName = scrapeMachineName
        self.scrapeMachineId = scrapeMachineId
        self.expiresAt = expiresAt
        self.autoDestroyOnExpiry = autoDestroyOnExpiry
        self.environments = VaultEnvironmentTags.normalize(environments)
    }

    public func toAPIKeyItem(key: Data) -> APIKeyItem {
        APIKeyItem(
            id: id,
            name: name,
            key: key,
            website: website,
            notes: notes,
            folderPath: folderPath,
            createdAt: createdAt,
            modifiedAt: modifiedAt,
            isFavorite: isFavorite,
            isCliEnabled: isCliEnabled,
            isScraped: isScraped,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            expiresAt: expiresAt,
            autoDestroyOnExpiry: autoDestroyOnExpiry,
            environments: environments
        )
    }
}

// MARK: - Certificate Metadata

public struct CertificateMetadata: Identifiable, Codable, Equatable, Sendable {
    public let id: UUID
    public var name: String
    public var expirationDate: Date?
    public var issuer: String?
    public var subject: String?
    public var notes: String?
    public var folderPath: String?
    public var createdAt: Date
    public var modifiedAt: Date
    public var isFavorite: Bool
    public var isCliEnabled: Bool
    public var isScraped: Bool
    public var scrapeMachineName: String?
    public var scrapeMachineId: String?
    public var environments: [String]

    public init(from item: CertificateItem) {
        self.id = item.id
        self.name = item.name
        self.expirationDate = item.expirationDate
        self.issuer = item.issuer
        self.subject = item.subject
        self.notes = item.notes
        self.folderPath = item.folderPath
        self.createdAt = item.createdAt
        self.modifiedAt = item.modifiedAt
        self.isFavorite = item.isFavorite
        self.isCliEnabled = item.isCliEnabled
        self.isScraped = item.isScraped
        self.scrapeMachineName = item.scrapeMachineName
        self.scrapeMachineId = item.scrapeMachineId
        self.environments = item.environments
    }

    public init(
        id: UUID,
        name: String,
        expirationDate: Date?,
        issuer: String?,
        subject: String?,
        notes: String?,
        folderPath: String? = nil,
        createdAt: Date,
        modifiedAt: Date,
        isFavorite: Bool,
        isCliEnabled: Bool,
        isScraped: Bool,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        environments: [String] = []
    ) {
        self.id = id
        self.name = name
        self.expirationDate = expirationDate
        self.issuer = issuer
        self.subject = subject
        self.notes = notes
        self.folderPath = folderPath
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.isFavorite = isFavorite
        self.isCliEnabled = isCliEnabled
        self.isScraped = isScraped
        self.scrapeMachineName = scrapeMachineName
        self.scrapeMachineId = scrapeMachineId
        self.environments = VaultEnvironmentTags.normalize(environments)
    }
}

// MARK: - Secure Note Metadata

public struct SecureNoteMetadata: Identifiable, Codable, Equatable, Sendable {
    public let id: UUID
    public var title: String
    public var folderPath: String?
    public var createdAt: Date
    public var modifiedAt: Date
    public var isFavorite: Bool
    public var isCliEnabled: Bool
    public var isScraped: Bool
    public var scrapeMachineName: String?
    public var scrapeMachineId: String?
    public var environments: [String]

    public init(from item: SecureNoteItem) {
        self.id = item.id
        self.title = item.title
        self.folderPath = item.folderPath
        self.createdAt = item.createdAt
        self.modifiedAt = item.modifiedAt
        self.isFavorite = item.isFavorite
        self.isCliEnabled = item.isCliEnabled
        self.isScraped = item.isScraped
        self.scrapeMachineName = item.scrapeMachineName
        self.scrapeMachineId = item.scrapeMachineId
        self.environments = item.environments
    }

    public init(
        id: UUID,
        title: String,
        folderPath: String? = nil,
        createdAt: Date,
        modifiedAt: Date,
        isFavorite: Bool,
        isCliEnabled: Bool,
        isScraped: Bool,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        environments: [String] = []
    ) {
        self.id = id
        self.title = title
        self.folderPath = folderPath
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.isFavorite = isFavorite
        self.isCliEnabled = isCliEnabled
        self.isScraped = isScraped
        self.scrapeMachineName = scrapeMachineName
        self.scrapeMachineId = scrapeMachineId
        self.environments = VaultEnvironmentTags.normalize(environments)
    }
}

// MARK: - SSH Key Metadata

public struct SSHKeyMetadata: Identifiable, Codable, Equatable, Sendable {
    public let id: UUID
    public var name: String
    public var publicKey: String
    public var comment: String
    public var fingerprint: String
    public var folderPath: String?
    public var createdAt: Date
    public var modifiedAt: Date
    public var isFavorite: Bool
    public var isCliEnabled: Bool
    public var isScraped: Bool
    public var scrapeMachineName: String?
    public var scrapeMachineId: String?
    public var keyType: SSHKeyType
    public var approvalPolicy: SSHKeyApprovalPolicy
    public var boundHosts: [String]
    public var environments: [String]

    public init(from item: SSHKeyItem) {
        self.id = item.id
        self.name = item.name
        self.publicKey = String(decoding: item.publicKey, as: UTF8.self)
        self.comment = item.comment
        self.fingerprint = item.fingerprint
        self.folderPath = item.folderPath
        self.createdAt = item.createdAt
        self.modifiedAt = item.modifiedAt
        self.isFavorite = item.isFavorite
        self.isCliEnabled = item.isCliEnabled
        self.isScraped = item.isScraped
        self.scrapeMachineName = item.scrapeMachineName
        self.scrapeMachineId = item.scrapeMachineId
        self.keyType = item.keyType
        self.approvalPolicy = item.approvalPolicy
        self.boundHosts = item.boundHosts
        self.environments = item.environments
    }

    public init(
        id: UUID,
        name: String,
        publicKey: String,
        comment: String,
        fingerprint: String,
        folderPath: String? = nil,
        createdAt: Date,
        modifiedAt: Date,
        isFavorite: Bool,
        isCliEnabled: Bool,
        isScraped: Bool,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        keyType: SSHKeyType = .ed25519,
        approvalPolicy: SSHKeyApprovalPolicy = .sessionBased,
        boundHosts: [String] = [],
        environments: [String] = []
    ) {
        self.id = id
        self.name = name
        self.publicKey = publicKey
        self.comment = comment
        self.fingerprint = fingerprint
        self.folderPath = folderPath
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.isFavorite = isFavorite
        self.isCliEnabled = isCliEnabled
        self.isScraped = isScraped
        self.scrapeMachineName = scrapeMachineName
        self.scrapeMachineId = scrapeMachineId
        self.keyType = keyType
        self.approvalPolicy = approvalPolicy
        self.boundHosts = boundHosts
        self.environments = VaultEnvironmentTags.normalize(environments)
    }
}

extension PasswordMetadata {
    enum CodingKeys: String, CodingKey {
        case id, name, username, website, notes, folderPath, createdAt, modifiedAt, isFavorite, isCliEnabled
        case isScraped, scrapeMachineName, scrapeMachineId, expiresAt, autoDestroyOnExpiry, environments
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        username = try container.decode(String.self, forKey: .username)
        website = try container.decodeIfPresent(String.self, forKey: .website)
        notes = try container.decodeIfPresent(String.self, forKey: .notes)
        folderPath = try container.decodeIfPresent(String.self, forKey: .folderPath)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        modifiedAt = try container.decode(Date.self, forKey: .modifiedAt)
        isFavorite = try container.decodeIfPresent(Bool.self, forKey: .isFavorite) ?? false
        isCliEnabled = try container.decodeIfPresent(Bool.self, forKey: .isCliEnabled) ?? true
        isScraped = try container.decodeIfPresent(Bool.self, forKey: .isScraped) ?? false
        scrapeMachineName = try container.decodeIfPresent(String.self, forKey: .scrapeMachineName)
        scrapeMachineId = try container.decodeIfPresent(String.self, forKey: .scrapeMachineId)
        expiresAt = try container.decodeIfPresent(Date.self, forKey: .expiresAt)
        autoDestroyOnExpiry = try container.decodeIfPresent(Bool.self, forKey: .autoDestroyOnExpiry) ?? (expiresAt != nil)
        environments = VaultEnvironmentTags.normalize(
            try container.decodeIfPresent([String].self, forKey: .environments) ?? []
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(username, forKey: .username)
        try container.encodeIfPresent(website, forKey: .website)
        try container.encodeIfPresent(notes, forKey: .notes)
        try container.encodeIfPresent(folderPath, forKey: .folderPath)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(modifiedAt, forKey: .modifiedAt)
        try container.encode(isFavorite, forKey: .isFavorite)
        try container.encode(isCliEnabled, forKey: .isCliEnabled)
        try container.encode(isScraped, forKey: .isScraped)
        try container.encodeIfPresent(scrapeMachineName, forKey: .scrapeMachineName)
        try container.encodeIfPresent(scrapeMachineId, forKey: .scrapeMachineId)
        try container.encodeIfPresent(expiresAt, forKey: .expiresAt)
        try container.encode(autoDestroyOnExpiry, forKey: .autoDestroyOnExpiry)
        try container.encode(environments, forKey: .environments)
    }
}

extension APIKeyMetadata {
    enum CodingKeys: String, CodingKey {
        case id, name, website, notes, folderPath, createdAt, modifiedAt, isFavorite, isCliEnabled
        case isScraped, scrapeMachineName, scrapeMachineId, expiresAt, autoDestroyOnExpiry, environments
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        website = try container.decodeIfPresent(String.self, forKey: .website)
        notes = try container.decodeIfPresent(String.self, forKey: .notes)
        folderPath = try container.decodeIfPresent(String.self, forKey: .folderPath)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        modifiedAt = try container.decode(Date.self, forKey: .modifiedAt)
        isFavorite = try container.decodeIfPresent(Bool.self, forKey: .isFavorite) ?? false
        isCliEnabled = try container.decodeIfPresent(Bool.self, forKey: .isCliEnabled) ?? true
        isScraped = try container.decodeIfPresent(Bool.self, forKey: .isScraped) ?? false
        scrapeMachineName = try container.decodeIfPresent(String.self, forKey: .scrapeMachineName)
        scrapeMachineId = try container.decodeIfPresent(String.self, forKey: .scrapeMachineId)
        expiresAt = try container.decodeIfPresent(Date.self, forKey: .expiresAt)
        autoDestroyOnExpiry = try container.decodeIfPresent(Bool.self, forKey: .autoDestroyOnExpiry) ?? (expiresAt != nil)
        environments = VaultEnvironmentTags.normalize(
            try container.decodeIfPresent([String].self, forKey: .environments) ?? []
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encodeIfPresent(website, forKey: .website)
        try container.encodeIfPresent(notes, forKey: .notes)
        try container.encodeIfPresent(folderPath, forKey: .folderPath)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(modifiedAt, forKey: .modifiedAt)
        try container.encode(isFavorite, forKey: .isFavorite)
        try container.encode(isCliEnabled, forKey: .isCliEnabled)
        try container.encode(isScraped, forKey: .isScraped)
        try container.encodeIfPresent(scrapeMachineName, forKey: .scrapeMachineName)
        try container.encodeIfPresent(scrapeMachineId, forKey: .scrapeMachineId)
        try container.encodeIfPresent(expiresAt, forKey: .expiresAt)
        try container.encode(autoDestroyOnExpiry, forKey: .autoDestroyOnExpiry)
        try container.encode(environments, forKey: .environments)
    }
}

extension CertificateMetadata {
    enum CodingKeys: String, CodingKey {
        case id, name, expirationDate, issuer, subject, notes, folderPath, createdAt, modifiedAt, isFavorite, isCliEnabled
        case isScraped, scrapeMachineName, scrapeMachineId, environments
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        expirationDate = try container.decodeIfPresent(Date.self, forKey: .expirationDate)
        issuer = try container.decodeIfPresent(String.self, forKey: .issuer)
        subject = try container.decodeIfPresent(String.self, forKey: .subject)
        notes = try container.decodeIfPresent(String.self, forKey: .notes)
        folderPath = try container.decodeIfPresent(String.self, forKey: .folderPath)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        modifiedAt = try container.decode(Date.self, forKey: .modifiedAt)
        isFavorite = try container.decodeIfPresent(Bool.self, forKey: .isFavorite) ?? false
        isCliEnabled = try container.decodeIfPresent(Bool.self, forKey: .isCliEnabled) ?? true
        isScraped = try container.decodeIfPresent(Bool.self, forKey: .isScraped) ?? false
        scrapeMachineName = try container.decodeIfPresent(String.self, forKey: .scrapeMachineName)
        scrapeMachineId = try container.decodeIfPresent(String.self, forKey: .scrapeMachineId)
        environments = VaultEnvironmentTags.normalize(
            try container.decodeIfPresent([String].self, forKey: .environments) ?? []
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encodeIfPresent(expirationDate, forKey: .expirationDate)
        try container.encodeIfPresent(issuer, forKey: .issuer)
        try container.encodeIfPresent(subject, forKey: .subject)
        try container.encodeIfPresent(notes, forKey: .notes)
        try container.encodeIfPresent(folderPath, forKey: .folderPath)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(modifiedAt, forKey: .modifiedAt)
        try container.encode(isFavorite, forKey: .isFavorite)
        try container.encode(isCliEnabled, forKey: .isCliEnabled)
        try container.encode(isScraped, forKey: .isScraped)
        try container.encodeIfPresent(scrapeMachineName, forKey: .scrapeMachineName)
        try container.encodeIfPresent(scrapeMachineId, forKey: .scrapeMachineId)
        try container.encode(environments, forKey: .environments)
    }
}

extension SecureNoteMetadata {
    enum CodingKeys: String, CodingKey {
        case id, title, folderPath, createdAt, modifiedAt, isFavorite, isCliEnabled, isScraped
        case scrapeMachineName, scrapeMachineId, environments
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        title = try container.decode(String.self, forKey: .title)
        folderPath = try container.decodeIfPresent(String.self, forKey: .folderPath)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        modifiedAt = try container.decode(Date.self, forKey: .modifiedAt)
        isFavorite = try container.decodeIfPresent(Bool.self, forKey: .isFavorite) ?? false
        isCliEnabled = try container.decodeIfPresent(Bool.self, forKey: .isCliEnabled) ?? true
        isScraped = try container.decodeIfPresent(Bool.self, forKey: .isScraped) ?? false
        scrapeMachineName = try container.decodeIfPresent(String.self, forKey: .scrapeMachineName)
        scrapeMachineId = try container.decodeIfPresent(String.self, forKey: .scrapeMachineId)
        environments = VaultEnvironmentTags.normalize(
            try container.decodeIfPresent([String].self, forKey: .environments) ?? []
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(title, forKey: .title)
        try container.encodeIfPresent(folderPath, forKey: .folderPath)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(modifiedAt, forKey: .modifiedAt)
        try container.encode(isFavorite, forKey: .isFavorite)
        try container.encode(isCliEnabled, forKey: .isCliEnabled)
        try container.encode(isScraped, forKey: .isScraped)
        try container.encodeIfPresent(scrapeMachineName, forKey: .scrapeMachineName)
        try container.encodeIfPresent(scrapeMachineId, forKey: .scrapeMachineId)
        try container.encode(environments, forKey: .environments)
    }
}

extension SSHKeyMetadata {
    enum CodingKeys: String, CodingKey {
        case id, name, publicKey, comment, fingerprint, folderPath, createdAt, modifiedAt, isFavorite, isCliEnabled
        case isScraped, scrapeMachineName, scrapeMachineId
        case keyType, approvalPolicy, boundHosts, environments
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        publicKey = try container.decode(String.self, forKey: .publicKey)
        comment = try container.decode(String.self, forKey: .comment)
        fingerprint = try container.decode(String.self, forKey: .fingerprint)
        folderPath = try container.decodeIfPresent(String.self, forKey: .folderPath)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        modifiedAt = try container.decode(Date.self, forKey: .modifiedAt)
        isFavorite = try container.decodeIfPresent(Bool.self, forKey: .isFavorite) ?? false
        isCliEnabled = try container.decodeIfPresent(Bool.self, forKey: .isCliEnabled) ?? true
        isScraped = try container.decodeIfPresent(Bool.self, forKey: .isScraped) ?? false
        scrapeMachineName = try container.decodeIfPresent(String.self, forKey: .scrapeMachineName)
        scrapeMachineId = try container.decodeIfPresent(String.self, forKey: .scrapeMachineId)
        keyType = try container.decodeIfPresent(SSHKeyType.self, forKey: .keyType) ?? .ed25519
        approvalPolicy = try container.decodeIfPresent(SSHKeyApprovalPolicy.self, forKey: .approvalPolicy) ?? .sessionBased
        boundHosts = try container.decodeIfPresent([String].self, forKey: .boundHosts) ?? []
        environments = VaultEnvironmentTags.normalize(
            try container.decodeIfPresent([String].self, forKey: .environments) ?? []
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(publicKey, forKey: .publicKey)
        try container.encode(comment, forKey: .comment)
        try container.encode(fingerprint, forKey: .fingerprint)
        try container.encodeIfPresent(folderPath, forKey: .folderPath)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(modifiedAt, forKey: .modifiedAt)
        try container.encode(isFavorite, forKey: .isFavorite)
        try container.encode(isCliEnabled, forKey: .isCliEnabled)
        try container.encode(isScraped, forKey: .isScraped)
        try container.encodeIfPresent(scrapeMachineName, forKey: .scrapeMachineName)
        try container.encodeIfPresent(scrapeMachineId, forKey: .scrapeMachineId)
        try container.encode(keyType, forKey: .keyType)
        try container.encode(approvalPolicy, forKey: .approvalPolicy)
        try container.encode(boundHosts, forKey: .boundHosts)
        try container.encode(environments, forKey: .environments)
    }
}

// MARK: - Vault Metadata Store

protocol VaultMetadataKeychainStoring: Sendable {
    func save(data: Data, key: String) throws
    func load(key: String) throws -> Data?
    func loadCandidates(key: String) throws -> [KeychainDataCandidate]
}

struct SecurityVaultMetadataKeychainStore: VaultMetadataKeychainStoring {
    private static let metadataService = "com.authsia.vault.metadata"
    private static let localMetadataService = "com.authsia.vault.metadata.local"
    private static let preferredSynchronizableValues: [Bool] = [true, false]
    private static let unavailableStoreStatuses: Set<OSStatus> = [errSecMissingEntitlement]
    private let syncPolicy: KeychainSyncPolicy

    private var syncEnabled: Bool {
        syncPolicy.isICloudKeychainSyncEnabled()
    }

    private var writeSynchronizableValues: [Bool] {
        syncEnabled ? Self.preferredSynchronizableValues : [false]
    }

    private var readSynchronizableValues: [Bool] {
        syncEnabled ? Self.preferredSynchronizableValues : [false, true]
    }

    init(syncPolicy: KeychainSyncPolicy = .live) {
        self.syncPolicy = syncPolicy
    }

    func save(data: Data, key: String) throws {
        var statuses: [(synchronizable: Bool, status: OSStatus)] = []
        for synchronizable in writeSynchronizableValues {
            let status = upsert(data: data, key: key, synchronizable: synchronizable)
            statuses.append((synchronizable: synchronizable, status: status))
        }

        if let status = KeychainSyncSettings.writeFailureStatus(statuses: statuses) {
            throw KeychainError.unknown(status)
        }
    }

    func load(key: String) throws -> Data? {
        try loadCandidates(key: key).first(where: { $0.data != nil })?.data
    }

    func loadCandidates(key: String) throws -> [KeychainDataCandidate] {
        var unavailableStatus: OSStatus?
        var candidates: [KeychainDataCandidate] = []
        let writeTargets = Set(writeSynchronizableValues)
        for synchronizable in readSynchronizableValues {
            do {
                candidates.append(KeychainDataCandidate(
                    synchronizable: synchronizable,
                    data: try load(key: key, synchronizable: synchronizable),
                    isAvailable: true,
                    isWriteTarget: writeTargets.contains(synchronizable)
                ))
            } catch KeychainError.unknown(let status) where Self.isStoreUnavailable(status) {
                unavailableStatus = unavailableStatus ?? status
                candidates.append(KeychainDataCandidate(
                    synchronizable: synchronizable,
                    data: nil,
                    isAvailable: false,
                    isWriteTarget: writeTargets.contains(synchronizable)
                ))
            }
        }

        if candidates.contains(where: { $0.data != nil }) {
            return candidates
        }
        if let unavailableStatus {
            throw KeychainError.unknown(unavailableStatus)
        }
        return candidates
    }

    private func load(key: String, synchronizable: Bool) throws -> Data? {
        var firstError: OSStatus?
        let queries = readQueries(key: key, synchronizable: synchronizable)
        for var query in queries {
            query[kSecReturnData as String] = true

            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            if status == errSecItemNotFound {
                continue
            }
            guard status == errSecSuccess else {
                if !Self.isStoreUnavailable(status) || queries.count == 1 {
                    firstError = firstError ?? status
                }
                continue
            }
            guard let data = result as? Data else {
                throw KeychainError.unexpectedData
            }
            return data
        }
        if let firstError {
            throw KeychainError.unknown(firstError)
        }
        return nil
    }

    private func makeBaseQuery(key: String, synchronizable: Bool) -> [String: Any] {
        Self.makeBaseQuery(key: key, synchronizable: synchronizable, useDataProtectionFallback: true)
    }

    private func readQueries(key: String, synchronizable: Bool) -> [[String: Any]] {
        var queries = [makeBaseQuery(key: key, synchronizable: synchronizable)]
        #if os(macOS)
        if !synchronizable {
            queries.append(Self.makeBaseQuery(
                key: key,
                synchronizable: synchronizable,
                useDataProtectionFallback: false
            ))
            queries.append(Self.makeBaseQuery(
                key: key,
                synchronizable: synchronizable,
                useDataProtectionFallback: true,
                service: Self.metadataService
            ))
            queries.append(Self.makeBaseQuery(
                key: key,
                synchronizable: synchronizable,
                useDataProtectionFallback: false,
                service: Self.metadataService
            ))
        }
        #endif
        return queries
    }

    static func baseQueryForTesting(
        key: String,
        synchronizable: Bool,
        accessGroup: String? = SharedKeychainAccessGroup.current()
    ) -> [String: Any] {
        makeBaseQuery(
            key: key,
            synchronizable: synchronizable,
            useDataProtectionFallback: true,
            accessGroup: accessGroup
        )
    }

    func writeSynchronizableValuesForTesting() -> [Bool] {
        writeSynchronizableValues
    }

    func readSynchronizableValuesForTesting() -> [Bool] {
        readSynchronizableValues
    }

    private static func isStoreUnavailable(_ status: OSStatus) -> Bool {
        unavailableStoreStatuses.contains(status)
    }

    private static func service(for synchronizable: Bool) -> String {
        synchronizable ? metadataService : localMetadataService
    }

    private static func makeBaseQuery(
        key: String,
        synchronizable: Bool,
        useDataProtectionFallback: Bool,
        service: String? = nil,
        accessGroup: String? = SharedKeychainAccessGroup.current()
    ) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: service ?? Self.service(for: synchronizable),
            kSecAttrSynchronizable as String: synchronizable,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        #if os(macOS)
        if !synchronizable && useDataProtectionFallback {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        #endif
        return query
    }

    @discardableResult
    private func upsert(data: Data, key: String, synchronizable: Bool) -> OSStatus {
        let status = upsert(data: data, key: key, synchronizable: synchronizable, useDataProtectionFallback: true)
        #if os(macOS)
        if !synchronizable, Self.isStoreUnavailable(status) {
            return upsert(data: data, key: key, synchronizable: synchronizable, useDataProtectionFallback: false)
        }
        #endif
        return status
    }

    @discardableResult
    private func upsert(
        data: Data,
        key: String,
        synchronizable: Bool,
        useDataProtectionFallback: Bool
    ) -> OSStatus {
        let baseQuery = Self.makeBaseQuery(
            key: key,
            synchronizable: synchronizable,
            useDataProtectionFallback: useDataProtectionFallback
        )

        var addQuery = baseQuery
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus == errSecSuccess {
            return errSecSuccess
        }

        if addStatus == errSecDuplicateItem {
            let update: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
            ]
            let updateStatus = SecItemUpdate(baseQuery as CFDictionary, update as CFDictionary)

            #if os(macOS)
            if updateStatus == errSecItemNotFound {
                if synchronizable {
                    for conflictingLocalQuery in [
                        Self.makeBaseQuery(
                            key: key,
                            synchronizable: false,
                            useDataProtectionFallback: true,
                            service: Self.metadataService
                        ),
                        Self.makeBaseQuery(
                            key: key,
                            synchronizable: false,
                            useDataProtectionFallback: false,
                            service: Self.metadataService
                        ),
                    ] {
                        SecItemDelete(conflictingLocalQuery as CFDictionary)
                    }
                    return SecItemAdd(addQuery as CFDictionary, nil)
                } else {
                    let conflictingLocalQuery = Self.makeBaseQuery(
                        key: key,
                        synchronizable: false,
                        useDataProtectionFallback: false
                    )
                    SecItemDelete(conflictingLocalQuery as CFDictionary)
                    let retryStatus = SecItemAdd(addQuery as CFDictionary, nil)
                    return retryStatus == errSecDuplicateItem ? errSecSuccess : retryStatus
                }
            }
            #endif

            return updateStatus
        }

        return addStatus
    }
}

public final class VaultMetadataStore: @unchecked Sendable {
    public static let shared = VaultMetadataStore()

    private let passwordsFileName = "vault_passwords_metadata.json"
    private let certificatesFileName = "vault_certificates_metadata.json"
    private let notesFileName = "vault_notes_metadata.json"
    private let sshKeysFileName = "vault_sshkeys_metadata.json"
    private let foldersFileName = "vault_folders.json"

    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private let documentsDirectoryOverride: URL?
    private let keychain: any VaultMetadataKeychainStoring

    private var documentsDirectory: URL {
        if let documentsDirectoryOverride { return documentsDirectoryOverride }
        return FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    private convenience init() {
        self.init(documentsDirectory: nil, keychain: SecurityVaultMetadataKeychainStore())
    }

    convenience init(documentsDirectory: URL, keychain: any VaultMetadataKeychainStoring) {
        self.init(documentsDirectory: Optional(documentsDirectory), keychain: keychain)
    }

    private init(documentsDirectory: URL?, keychain: any VaultMetadataKeychainStoring) {
        self.documentsDirectoryOverride = documentsDirectory
        self.keychain = keychain
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
    }

    // MARK: - Passwords

    public func savePasswords(_ metadata: [PasswordMetadata]) throws {
        let merged = mergeMetadata(
            incoming: metadata,
            existing: try loadPasswords(),
            modifiedAt: \.modifiedAt,
            sort: { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        )
        try replacePasswords(merged)
    }

    func replacePasswords(_ metadata: [PasswordMetadata]) throws {
        try saveMetadata(metadata, key: "vault_passwords_metadata")
    }

    public func loadPasswords() throws -> [PasswordMetadata] {
        let metadata: [PasswordMetadata] = try loadMetadataArrays(
            key: "vault_passwords_metadata",
            modifiedAt: \.modifiedAt,
            sort: { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        )
        let tombstonesByID = Dictionary(
            uniqueKeysWithValues: try loadPasswordDeletionTombstones().map { ($0.id, $0) }
        )
        return metadata.filter { item in
            guard let tombstone = tombstonesByID[item.id] else { return true }
            return item.modifiedAt > tombstone.deletedAt
        }
    }

    func savePasswordDeletionTombstones(_ tombstones: [PasswordDeletionTombstone]) throws {
        let merged = mergeMetadata(
            incoming: tombstones,
            existing: try loadPasswordDeletionTombstones(),
            modifiedAt: \.deletedAt,
            sort: { $0.deletedAt < $1.deletedAt }
        )
        try saveMetadata(merged, key: "vault_password_deletion_tombstones")
    }

    func loadPasswordDeletionTombstones() throws -> [PasswordDeletionTombstone] {
        try loadTombstoneArrays(
            key: "vault_password_deletion_tombstones",
            modifiedAt: \.deletedAt,
            sort: { $0.deletedAt < $1.deletedAt }
        )
    }

    // MARK: - API Keys

    public func saveAPIKeys(_ metadata: [APIKeyMetadata]) throws {
        let merged = mergeMetadata(
            incoming: metadata,
            existing: try loadAPIKeys(),
            modifiedAt: \.modifiedAt,
            sort: { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        )
        try replaceAPIKeys(merged)
    }

    func replaceAPIKeys(_ metadata: [APIKeyMetadata]) throws {
        try saveMetadata(metadata, key: "vault_api_keys_metadata")
    }

    public func loadAPIKeys() throws -> [APIKeyMetadata] {
        let metadata: [APIKeyMetadata] = try loadMetadataArrays(
            key: "vault_api_keys_metadata",
            modifiedAt: \.modifiedAt,
            sort: { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        )
        let tombstonesByID = Dictionary(
            uniqueKeysWithValues: try loadAPIKeyDeletionTombstones().map { ($0.id, $0) }
        )
        return metadata.filter { item in
            guard let tombstone = tombstonesByID[item.id] else { return true }
            return item.modifiedAt > tombstone.deletedAt
        }
    }

    func saveAPIKeyDeletionTombstones(_ tombstones: [APIKeyDeletionTombstone]) throws {
        let merged = mergeMetadata(
            incoming: tombstones,
            existing: try loadAPIKeyDeletionTombstones(),
            modifiedAt: \.deletedAt,
            sort: { $0.deletedAt < $1.deletedAt }
        )
        try saveMetadata(merged, key: "vault_api_key_deletion_tombstones")
    }

    func loadAPIKeyDeletionTombstones() throws -> [APIKeyDeletionTombstone] {
        try loadTombstoneArrays(
            key: "vault_api_key_deletion_tombstones",
            modifiedAt: \.deletedAt,
            sort: { $0.deletedAt < $1.deletedAt }
        )
    }

    // MARK: - Certificates

    public func saveCertificates(_ metadata: [CertificateMetadata]) throws {
        let merged = mergeMetadata(
            incoming: metadata,
            existing: try loadCertificates(),
            modifiedAt: \.modifiedAt,
            sort: { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        )
        try replaceCertificates(merged)
    }

    func replaceCertificates(_ metadata: [CertificateMetadata]) throws {
        try saveMetadata(metadata, key: "vault_certificates_metadata")
    }

    public func loadCertificates() throws -> [CertificateMetadata] {
        let metadata: [CertificateMetadata] = try loadMetadataArrays(
            key: "vault_certificates_metadata",
            modifiedAt: \.modifiedAt,
            sort: { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        )
        let tombstonesByID = Dictionary(
            uniqueKeysWithValues: try loadCertificateDeletionTombstones().map { ($0.id, $0) }
        )
        return metadata.filter { item in
            guard let tombstone = tombstonesByID[item.id] else { return true }
            return item.modifiedAt > tombstone.deletedAt
        }
    }

    func saveCertificateDeletionTombstones(_ tombstones: [CertificateDeletionTombstone]) throws {
        let merged = mergeMetadata(
            incoming: tombstones,
            existing: try loadCertificateDeletionTombstones(),
            modifiedAt: \.deletedAt,
            sort: { $0.deletedAt < $1.deletedAt }
        )
        try saveMetadata(merged, key: "vault_certificate_deletion_tombstones")
    }

    func loadCertificateDeletionTombstones() throws -> [CertificateDeletionTombstone] {
        try loadTombstoneArrays(
            key: "vault_certificate_deletion_tombstones",
            modifiedAt: \.deletedAt,
            sort: { $0.deletedAt < $1.deletedAt }
        )
    }

    // MARK: - Secure Notes

    public func saveNotes(_ metadata: [SecureNoteMetadata]) throws {
        let merged = mergeMetadata(
            incoming: metadata,
            existing: try loadNotes(),
            modifiedAt: \.modifiedAt,
            sort: { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        )
        try replaceNotes(merged)
    }

    func replaceNotes(_ metadata: [SecureNoteMetadata]) throws {
        try saveMetadata(metadata, key: "vault_notes_metadata")
    }

    public func loadNotes() throws -> [SecureNoteMetadata] {
        let metadata: [SecureNoteMetadata] = try loadMetadataArrays(
            key: "vault_notes_metadata",
            modifiedAt: \.modifiedAt,
            sort: { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        )
        let tombstonesByID = Dictionary(
            uniqueKeysWithValues: try loadNoteDeletionTombstones().map { ($0.id, $0) }
        )
        return metadata.filter { item in
            guard let tombstone = tombstonesByID[item.id] else { return true }
            return item.modifiedAt > tombstone.deletedAt
        }
    }

    func saveNoteDeletionTombstones(_ tombstones: [NoteDeletionTombstone]) throws {
        let merged = mergeMetadata(
            incoming: tombstones,
            existing: try loadNoteDeletionTombstones(),
            modifiedAt: \.deletedAt,
            sort: { $0.deletedAt < $1.deletedAt }
        )
        try saveMetadata(merged, key: "vault_note_deletion_tombstones")
    }

    func loadNoteDeletionTombstones() throws -> [NoteDeletionTombstone] {
        try loadTombstoneArrays(
            key: "vault_note_deletion_tombstones",
            modifiedAt: \.deletedAt,
            sort: { $0.deletedAt < $1.deletedAt }
        )
    }

    // MARK: - SSH Keys

    public func saveSSHKeys(_ metadata: [SSHKeyMetadata]) throws {
        let merged = mergeMetadata(
            incoming: metadata,
            existing: try loadSSHKeys(),
            modifiedAt: \.modifiedAt,
            sort: { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        )
        try replaceSSHKeys(merged)
    }

    func replaceSSHKeys(_ metadata: [SSHKeyMetadata]) throws {
        try saveMetadata(metadata, key: "vault_sshkeys_metadata")
    }

    public func loadSSHKeys() throws -> [SSHKeyMetadata] {
        let metadata: [SSHKeyMetadata] = try loadMetadataArrays(
            key: "vault_sshkeys_metadata",
            modifiedAt: \.modifiedAt,
            sort: { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        )
        let tombstonesByID = Dictionary(
            uniqueKeysWithValues: try loadSSHKeyDeletionTombstones().map { ($0.id, $0) }
        )
        return metadata.filter { item in
            guard let tombstone = tombstonesByID[item.id] else { return true }
            return item.modifiedAt > tombstone.deletedAt
        }
    }

    func saveSSHKeyDeletionTombstones(_ tombstones: [SSHKeyDeletionTombstone]) throws {
        let merged = mergeMetadata(
            incoming: tombstones,
            existing: try loadSSHKeyDeletionTombstones(),
            modifiedAt: \.deletedAt,
            sort: { $0.deletedAt < $1.deletedAt }
        )
        try saveMetadata(merged, key: "vault_ssh_key_deletion_tombstones")
    }

    func loadSSHKeyDeletionTombstones() throws -> [SSHKeyDeletionTombstone] {
        try loadTombstoneArrays(
            key: "vault_ssh_key_deletion_tombstones",
            modifiedAt: \.deletedAt,
            sort: { $0.deletedAt < $1.deletedAt }
        )
    }

    // MARK: - Folders

    public func saveFolders(_ folders: [VaultItemType: [String]]) throws {
        try replaceFolders(mergeFolderMaps(incoming: folders, existing: try loadFolders()))
    }

    func replaceFolders(_ folders: [VaultItemType: [String]]) throws {
        let normalized = normalizeFolderMap(folders)
        let rawFolders = Dictionary(uniqueKeysWithValues: normalized.map { ($0.key.rawValue, $0.value) })
        try saveMetadata(rawFolders, key: "vault_folders")
    }

    public func loadFolders() throws -> [VaultItemType: [String]] {
        func decode(_ data: Data) -> [VaultItemType: [String]]? {
            // New format: { "password": ["Work"], ... }
            if let raw = try? decoder.decode([String: [String]].self, from: data) {
                var result: [VaultItemType: [String]] = [:]
                for (key, paths) in raw {
                    guard let type = VaultItemType(rawValue: key) else { continue }
                    let normalized = normalizeFolderPaths(paths)
                    if !normalized.isEmpty { result[type] = normalized }
                }
                return result
            }
            // Legacy format: ["Work", "Personal"] — drop it; items rebuild per-category.
            if (try? decoder.decode([String].self, from: data)) != nil {
                return [:]
            }
            return nil
        }

        do {
            let candidates = try keychain.loadCandidates(key: "vault_folders")
            let storedCandidates = candidates.compactMap(\.data)
            guard !storedCandidates.isEmpty else {
                return [:]
            }
            var merged: [VaultItemType: [String]] = [:]
            for data in storedCandidates {
                guard let map = decode(data) else {
                    throw MetadataLoadError.decodeFailed("Unable to decode vault folders")
                }
                merged = mergeFolderMaps(incoming: map, existing: merged)
            }
            return try filterFolders(merged, using: loadFolderStates())
        } catch let metadataError as MetadataLoadError {
            throw metadataError
        } catch let KeychainError.unknown(status) {
            throw MetadataLoadError.keychainUnavailable(status)
        } catch {
            throw MetadataLoadError.keychainUnavailable(nil)
        }
    }

    func saveFolderStates(_ states: [VaultFolderState]) throws {
        var merged = Dictionary(uniqueKeysWithValues: try loadFolderStates().map { (folderStateID($0), $0) })
        for state in normalizeFolderStates(states) {
            let id = folderStateID(state)
            if let existing = merged[id], existing.modifiedAt > state.modifiedAt {
                continue
            }
            merged[id] = state
        }
        let sorted = merged.values.sorted(by: folderStateAscending)
        try saveMetadata(sorted, key: "vault_folder_states")
    }

    func loadFolderStates() throws -> [VaultFolderState] {
        do {
            let candidates = try keychain.loadCandidates(key: "vault_folder_states")
            var merged: [String: VaultFolderState] = [:]
            for data in candidates.compactMap(\.data) {
                let decoded: [VaultFolderState]
                do {
                    decoded = try decoder.decode([VaultFolderState].self, from: data)
                } catch {
                    throw MetadataLoadError.decodeFailed(String(describing: error))
                }
                for state in normalizeFolderStates(decoded) {
                    let id = folderStateID(state)
                    if let existing = merged[id], existing.modifiedAt > state.modifiedAt {
                        continue
                    }
                    merged[id] = state
                }
            }
            return merged.values.sorted(by: folderStateAscending)
        } catch let metadataError as MetadataLoadError {
            throw metadataError
        } catch let KeychainError.unknown(status) {
            throw MetadataLoadError.keychainUnavailable(status)
        } catch {
            throw MetadataLoadError.keychainUnavailable(nil)
        }
    }

    private func normalizeFolderMap(_ folders: [VaultItemType: [String]]) -> [VaultItemType: [String]] {
        var result: [VaultItemType: [String]] = [:]
        for (type, paths) in folders {
            let normalized = normalizeFolderPaths(paths)
            if !normalized.isEmpty { result[type] = normalized }
        }
        return result
    }

    private func mergeMetadata<T: Identifiable>(
        incoming: [T],
        existing: [T],
        modifiedAt: KeyPath<T, Date>,
        sort: (T, T) -> Bool
    ) -> [T] where T.ID == UUID {
        var byID = Dictionary(uniqueKeysWithValues: existing.map { ($0.id, $0) })
        for item in incoming {
            if let current = byID[item.id], current[keyPath: modifiedAt] > item[keyPath: modifiedAt] {
                continue
            }
            byID[item.id] = item
        }
        return byID.values.sorted(by: sort)
    }

    private func mergeFolderMaps(
        incoming: [VaultItemType: [String]],
        existing: [VaultItemType: [String]]
    ) -> [VaultItemType: [String]] {
        var merged = existing
        for (type, paths) in incoming {
            merged[type] = normalizeFolderPaths((merged[type] ?? []) + paths)
        }
        return normalizeFolderMap(merged)
    }

    private func filterFolders(
        _ folders: [VaultItemType: [String]],
        using states: [VaultFolderState]
    ) -> [VaultItemType: [String]] {
        let statesByType = Dictionary(grouping: states, by: \.type)
        var filtered: [VaultItemType: [String]] = [:]
        for (type, paths) in folders {
            let typeStates = statesByType[type] ?? []
            let retained = paths.filter { path in
                let newestDeletion = typeStates
                    .filter { $0.isDeleted && Self.isFolderPath(path, within: $0.path) }
                    .map(\.modifiedAt)
                    .max()
                guard let newestDeletion else { return true }
                let liveState = typeStates.first { !$0.isDeleted && $0.path == path }
                return liveState.map { $0.modifiedAt > newestDeletion } ?? false
            }
            if !retained.isEmpty {
                filtered[type] = retained
            }
        }
        return filtered
    }

    private func normalizeFolderStates(_ states: [VaultFolderState]) -> [VaultFolderState] {
        states.compactMap { state in
            guard let path = normalizeFolderPaths([state.path]).first else { return nil }
            return VaultFolderState(
                type: state.type,
                path: path,
                modifiedAt: state.modifiedAt,
                isDeleted: state.isDeleted
            )
        }
    }

    private func folderStateID(_ state: VaultFolderState) -> String {
        "\(state.type.rawValue):\(state.path)"
    }

    private func folderStateAscending(_ lhs: VaultFolderState, _ rhs: VaultFolderState) -> Bool {
        if lhs.type.rawValue != rhs.type.rawValue {
            return lhs.type.rawValue < rhs.type.rawValue
        }
        return lhs.path.localizedCaseInsensitiveCompare(rhs.path) == .orderedAscending
    }

    private static func isFolderPath(_ path: String, within folder: String) -> Bool {
        path == folder || path.hasPrefix(folder + "/")
    }

    // MARK: - Keychain Helpers (iCloud Sync)

    private func saveMetadata<T: Encodable>(_ metadata: T, key: String) throws {
        let data = try encoder.encode(metadata)
        try keychain.save(data: data, key: key)
    }

    private func loadMetadataArrays<T: Codable & Identifiable>(
        key: String,
        modifiedAt: KeyPath<T, Date>,
        sort: (T, T) -> Bool
    ) throws -> [T] where T.ID == UUID {
        do {
            let candidates = try keychain.loadCandidates(key: key)
            let storedCandidates = candidates.compactMap(\.data)
            guard !storedCandidates.isEmpty else {
                return []
            }
            var merged: [T] = []
            let decoder = decoder
            for candidate in candidates {
                guard let data = candidate.data else { continue }
                let decoded: [T]
                do {
                    decoded = try decoder.decode([T].self, from: data)
                } catch {
                    throw MetadataLoadError.decodeFailed(String(describing: error))
                }
                merged = mergeMetadata(incoming: decoded, existing: merged, modifiedAt: modifiedAt, sort: sort)
            }
            if candidates.contains(where: \.needsHealing) {
                try? saveMetadata(merged, key: key)
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

    /// Loads a tombstone array like `loadMetadataArrays`, but when any stored
    /// candidate is missing entries the merged union has — for example after
    /// iCloud Keychain last-writer-wins clobbered a fresher blob on another
    /// device — the union is re-saved so deletion intent stays monotonic
    /// across the sync circle. The re-save is best effort and never fails the
    /// load.
    private func loadTombstoneArrays<T: Codable & Identifiable>(
        key: String,
        modifiedAt: KeyPath<T, Date>,
        sort: (T, T) -> Bool
    ) throws -> [T] where T.ID == UUID {
        do {
            let candidates = try keychain.loadCandidates(key: key)
            let storedCandidates = candidates.compactMap(\.data)
            guard !storedCandidates.isEmpty else {
                return []
            }
            var merged: [T] = []
            var writeTargetFingerprints: [[UUID: Date]] = []
            let decoder = decoder
            for candidate in candidates {
                guard let data = candidate.data else { continue }
                let decoded: [T]
                do {
                    decoded = try decoder.decode([T].self, from: data)
                } catch {
                    throw MetadataLoadError.decodeFailed(String(describing: error))
                }
                if candidate.isWriteTarget {
                    writeTargetFingerprints.append(
                        Dictionary(decoded.map { ($0.id, $0[keyPath: modifiedAt]) }, uniquingKeysWith: { max($0, $1) })
                    )
                }
                merged = mergeMetadata(incoming: decoded, existing: merged, modifiedAt: modifiedAt, sort: sort)
            }
            let mergedFingerprint = Dictionary(
                merged.map { ($0.id, $0[keyPath: modifiedAt]) },
                uniquingKeysWith: { max($0, $1) }
            )
            if candidates.contains(where: \.needsHealing)
                || writeTargetFingerprints.contains(where: { $0 != mergedFingerprint }) {
                try? saveMetadata(merged, key: key)
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
