import Foundation

public enum VaultEnvironmentTags {
    public static let all = "All"

    private static let comparisonLocale = Locale(identifier: "en_US_POSIX")

    private static func folded(_ value: String) -> String {
        value.folding(options: [.caseInsensitive], locale: comparisonLocale)
    }

    public static func normalize(_ values: [String]) -> [String] {
        var displayByFoldedName: [String: String] = [:]
        for value in values {
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            let display = folded(trimmed) == folded(all) ? all : trimmed
            let key = folded(display)
            if displayByFoldedName[key] == nil {
                displayByFoldedName[key] = display
            }
        }
        return displayByFoldedName.sorted { $0.key < $1.key }.map(\.value)
    }

    public static func contains(_ name: String, in values: [String]) -> Bool {
        let needle = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty else { return false }
        return values.contains { folded($0) == folded(needle) }
    }

    public static func containsAll(in values: [String]) -> Bool {
        contains(all, in: values)
    }

    public static func selectableEnvironments(_ values: [String]) -> [String] {
        normalize(values).filter { !contains(all, in: [$0]) }
    }
}

@propertyWrapper
public struct VaultEnvironmentTagList: Codable, Equatable, Sendable {
    private var value: [String]

    public var wrappedValue: [String] {
        get { value }
        set { value = VaultEnvironmentTags.normalize(newValue) }
    }

    public init(wrappedValue: [String]) {
        value = VaultEnvironmentTags.normalize(wrappedValue)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        value = VaultEnvironmentTags.normalize(try container.decode([String].self))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(value)
    }
}

public extension KeyedDecodingContainer {
    func decode(_ type: VaultEnvironmentTagList.Type, forKey key: Key) throws -> VaultEnvironmentTagList {
        try decodeIfPresent(type, forKey: key) ?? VaultEnvironmentTagList(wrappedValue: [])
    }
}

// MARK: - Vault Item Types

public enum VaultItemType: String, Codable, CaseIterable, Sendable {
    case password
    case apiKey
    case certificate
    case secureNote
    case sshKey

    public var displayName: String {
        switch self {
        case .password: return "Passwords"
        case .apiKey: return "API Keys"
        case .certificate: return "Certificates"
        case .secureNote: return "Notes"
        case .sshKey: return "SSH Keys"
        }
    }

    public var iconName: String {
        switch self {
        case .password: return "key.fill"
        case .apiKey: return "key.horizontal.fill"
        case .certificate: return "checkmark.seal.fill"
        case .secureNote: return "note.text"
        case .sshKey: return "terminal"
        }
    }
}

// MARK: - Password Item

public struct PasswordItem: Identifiable, Codable, Equatable, Sendable {
    public let id: UUID
    public var name: String
    public var username: String
    public var password: Data
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

    public init(
        id: UUID = UUID(),
        name: String,
        username: String,
        password: Data,
        website: String? = nil,
        notes: String? = nil,
        folderPath: String? = nil,
        createdAt: Date = Date(),
        modifiedAt: Date = Date(),
        isFavorite: Bool = false,
        isCliEnabled: Bool = true,
        isScraped: Bool = false,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        expiresAt: Date? = nil,
        autoDestroyOnExpiry: Bool = false,
        environments: [String] = []
    ) {
        self.id = id
        self.name = name
        self.username = username
        self.password = password
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
}

// MARK: - API Key Item

public struct APIKeyItem: Identifiable, Codable, Equatable, Sendable {
    public let id: UUID
    public var name: String
    public var key: Data
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

    public init(
        id: UUID = UUID(),
        name: String,
        key: Data,
        website: String? = nil,
        notes: String? = nil,
        folderPath: String? = nil,
        createdAt: Date = Date(),
        modifiedAt: Date = Date(),
        isFavorite: Bool = false,
        isCliEnabled: Bool = true,
        isScraped: Bool = false,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        expiresAt: Date? = nil,
        autoDestroyOnExpiry: Bool = false,
        environments: [String] = []
    ) {
        self.id = id
        self.name = name
        self.key = key
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
}

// MARK: - Certificate Item

public struct CertificateItem: Identifiable, Codable, Equatable, Sendable {
    public let id: UUID
    public var name: String
    public var certificateData: Data
    public var privateKeyData: Data?
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

    public init(
        id: UUID = UUID(),
        name: String,
        certificateData: Data,
        privateKeyData: Data? = nil,
        expirationDate: Date? = nil,
        issuer: String? = nil,
        subject: String? = nil,
        notes: String? = nil,
        folderPath: String? = nil,
        createdAt: Date = Date(),
        modifiedAt: Date = Date(),
        isFavorite: Bool = false,
        isCliEnabled: Bool = true,
        isScraped: Bool = false,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        environments: [String] = []
    ) {
        self.id = id
        self.name = name
        self.certificateData = certificateData
        self.privateKeyData = privateKeyData
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

// MARK: - Secure Note Item

public struct SecureNoteItem: Identifiable, Codable, Equatable, Sendable {
    public let id: UUID
    public var title: String
    public var content: Data
    public var folderPath: String?
    public var createdAt: Date
    public var modifiedAt: Date
    public var isFavorite: Bool
    public var isCliEnabled: Bool
    public var isScraped: Bool
    public var scrapeMachineName: String?
    public var scrapeMachineId: String?
    public var environments: [String]

    public init(
        id: UUID = UUID(),
        title: String,
        content: Data,
        folderPath: String? = nil,
        createdAt: Date = Date(),
        modifiedAt: Date = Date(),
        isFavorite: Bool = false,
        isCliEnabled: Bool = true,
        isScraped: Bool = false,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        environments: [String] = []
    ) {
        self.id = id
        self.title = title
        self.content = content
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

// MARK: - SSH Key Type

public enum SSHKeyType: String, Codable, CaseIterable, Sendable {
    case ed25519
    case rsa2048
    case rsa3072
    case rsa4096
}

// MARK: - SSH Key Approval Policy

public enum SSHKeyApprovalPolicy: String, Codable, CaseIterable, Sendable {
    case alwaysPrompt
    case sessionBased
    case autoApprove
}

// MARK: - SSH Key Item

public struct SSHKeyItem: Identifiable, Codable, Equatable, Sendable {
    public let id: UUID
    public var name: String
    public var publicKey: Data
    public var privateKey: Data
    public var comment: String
    public var fingerprint: String
    public var keyType: SSHKeyType
    public var approvalPolicy: SSHKeyApprovalPolicy
    public var boundHosts: [String]
    public var folderPath: String?
    public var createdAt: Date
    public var modifiedAt: Date
    public var isFavorite: Bool
    public var isCliEnabled: Bool
    public var isScraped: Bool
    public var scrapeMachineName: String?
    public var scrapeMachineId: String?
    public var environments: [String]

    public init(
        id: UUID = UUID(),
        name: String,
        publicKey: Data,
        privateKey: Data,
        comment: String,
        fingerprint: String,
        keyType: SSHKeyType = .ed25519,
        approvalPolicy: SSHKeyApprovalPolicy = .sessionBased,
        boundHosts: [String] = [],
        folderPath: String? = nil,
        createdAt: Date = Date(),
        modifiedAt: Date = Date(),
        isFavorite: Bool = false,
        isCliEnabled: Bool = true,
        isScraped: Bool = false,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        environments: [String] = []
    ) {
        self.id = id
        self.name = name
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.comment = comment
        self.fingerprint = fingerprint
        self.keyType = keyType
        self.approvalPolicy = approvalPolicy
        self.boundHosts = boundHosts
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

extension PasswordItem {
    enum CodingKeys: String, CodingKey {
        case id, name, username, password, website, notes, folderPath, createdAt, modifiedAt, isFavorite, isCliEnabled
        case isScraped, scrapeMachineName, scrapeMachineId, expiresAt, autoDestroyOnExpiry, environments
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        username = try container.decode(String.self, forKey: .username)
        password = try container.decode(Data.self, forKey: .password)
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
        try container.encode(password, forKey: .password)
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

extension APIKeyItem {
    enum CodingKeys: String, CodingKey {
        case id, name, key, website, notes, folderPath, createdAt, modifiedAt, isFavorite, isCliEnabled
        case isScraped, scrapeMachineName, scrapeMachineId, expiresAt, autoDestroyOnExpiry, environments
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        key = try container.decode(Data.self, forKey: .key)
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
        try container.encode(key, forKey: .key)
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

extension CertificateItem {
    enum CodingKeys: String, CodingKey {
        case id, name, certificateData, privateKeyData, expirationDate, issuer, subject, notes, folderPath
        case createdAt, modifiedAt, isFavorite, isCliEnabled, isScraped, scrapeMachineName, scrapeMachineId
        case environments
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        certificateData = try container.decode(Data.self, forKey: .certificateData)
        privateKeyData = try container.decodeIfPresent(Data.self, forKey: .privateKeyData)
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
        try container.encode(certificateData, forKey: .certificateData)
        try container.encodeIfPresent(privateKeyData, forKey: .privateKeyData)
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

extension SecureNoteItem {
    enum CodingKeys: String, CodingKey {
        case id, title, content, folderPath, createdAt, modifiedAt, isFavorite, isCliEnabled
        case isScraped, scrapeMachineName, scrapeMachineId, environments
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        title = try container.decode(String.self, forKey: .title)
        content = try container.decode(Data.self, forKey: .content)
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
        try container.encode(content, forKey: .content)
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

extension SSHKeyItem {
    enum CodingKeys: String, CodingKey {
        case id, name, publicKey, privateKey, comment, fingerprint, keyType, approvalPolicy, boundHosts, folderPath, createdAt, modifiedAt
        case isFavorite, isCliEnabled, isScraped, scrapeMachineName, scrapeMachineId, environments
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        publicKey = try container.decode(Data.self, forKey: .publicKey)
        privateKey = try container.decode(Data.self, forKey: .privateKey)
        comment = try container.decode(String.self, forKey: .comment)
        fingerprint = try container.decode(String.self, forKey: .fingerprint)
        keyType = try container.decodeIfPresent(SSHKeyType.self, forKey: .keyType) ?? .ed25519
        approvalPolicy = try container.decodeIfPresent(SSHKeyApprovalPolicy.self, forKey: .approvalPolicy) ?? .sessionBased
        boundHosts = try container.decodeIfPresent([String].self, forKey: .boundHosts) ?? []
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
        try container.encode(publicKey, forKey: .publicKey)
        try container.encode(privateKey, forKey: .privateKey)
        try container.encode(comment, forKey: .comment)
        try container.encode(fingerprint, forKey: .fingerprint)
        try container.encode(keyType, forKey: .keyType)
        try container.encode(approvalPolicy, forKey: .approvalPolicy)
        try container.encode(boundHosts, forKey: .boundHosts)
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
