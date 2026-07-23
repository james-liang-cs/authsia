import Foundation
import AuthenticatorCore

public enum EnvironmentAccessScope: Codable, Equatable, Sendable {
    case defaultOnly
    case named(String)

    public func allows(itemEnvironments: [String]) -> Bool {
        switch self {
        case .defaultOnly:
            return itemEnvironments.isEmpty
                || VaultEnvironmentTags.containsAll(in: itemEnvironments)
        case .named(let name):
            return VaultEnvironmentTags.contains(name, in: itemEnvironments)
                || VaultEnvironmentTags.containsAll(in: itemEnvironments)
        }
    }
}

public enum BridgeRequestType: String, Codable {
    case ping
    case status
    case unlock
    case lock
    case getOTP
    case getPassword
    case getAPIKey
    case getCertificate
    case getNote
    case getSSH
    case list
    case workspaceMetadata
    case auditVerify
    case exportAccounts
    case addPassword
    case updatePassword
    case deletePassword
    case convertPasswordToAPIKey
    case addAPIKey
    case updateAPIKey
    case deleteAPIKey
    case addCertificate
    case updateCertificate
    case deleteCertificate
    case addNote
    case updateNote
    case deleteNote
    case addSSH
    case updateSSH
    case deleteSSH
    case ensureVaultFolder
    case deleteVaultFolder
    case sshAgentSign
    case createAccess
    case agentJITPreflight
    case agentJITSnapshot
    case agentJITRevoke
    case agentJITRevokeAll
}

public struct BridgeRequest: Codable, Equatable {
    public let id: UUID
    public let type: BridgeRequestType
    public let query: String
    public let options: BridgeOptions
    public let context: BridgeContext
    public let body: Data?
    /// Session token for anti-replay protection (required for authenticated requests)
    public let sessionToken: String?

    public init(
        id: UUID,
        type: BridgeRequestType,
        query: String,
        options: BridgeOptions,
        context: BridgeContext,
        body: Data? = nil,
        sessionToken: String? = nil
    ) {
        self.id = id
        self.type = type
        self.query = query
        self.options = options
        self.context = context
        self.body = body
        self.sessionToken = sessionToken
    }
}

public struct BridgeOptions: Codable, Equatable {
    public let field: String?
    public let copy: Bool

    public init(field: String?, copy: Bool) {
        self.field = field
        self.copy = copy
    }
}

public struct BridgeContext: Codable, Equatable {
    public static let chromeNativeHostRequestedCommand = "chromeNativeHost"
    public static let chromeNativeHostProcessName = "AuthsiaNativeHost"
    /// Stable Bridge session scope for Chrome autofill CLI invocations.
    /// Chrome native-host has no TTY, so without this each short-lived `authsia`
    /// process would re-prompt for approval on every list/get.
    public static let chromeNativeHostSessionScope = "chrome-native-host"
    public static let workspaceStatusRequestedCommand = "workspace status"
    public static let workspaceSyncPreviewRequestedCommand = "workspace sync preview"
    public static let workspaceEnvValidateRequestedCommand = "workspace env validate"
    public static let workspaceRunRequestedCommand = "workspace run"

    public static func isChromeNativeHostProcessName(_ processName: String?) -> Bool {
        processName == chromeNativeHostProcessName
    }

    public static func isChromeNativeHostAncestry(_ processAncestry: [AgenticProcessReference]) -> Bool {
        processAncestry.contains { isChromeNativeHostProcessName($0.processName) }
    }

    public let isTTY: Bool
    public let isPiped: Bool
    public let isSSH: Bool
    public let isCI: Bool
    public let timestamp: Date
    public let automationCredentialID: String?
    public let automationScope: String?
    public let requestedCommand: String?
    public let fullCommand: String?
    public let sessionScope: String?
    public let workingDirectory: String?
    public let agentRuntimeContext: AgentRuntimeContext?
    public let workspaceContext: WorkspaceRuntimeContext?

    public init(
        isTTY: Bool,
        isPiped: Bool,
        isSSH: Bool,
        isCI: Bool,
        timestamp: Date,
        automationCredentialID: String? = nil,
        automationScope: String? = nil,
        requestedCommand: String? = nil,
        fullCommand: String? = nil,
        sessionScope: String? = nil,
        workingDirectory: String? = nil,
        agentRuntimeContext: AgentRuntimeContext? = nil,
        workspaceContext: WorkspaceRuntimeContext? = nil
    ) {
        self.isTTY = isTTY
        self.isPiped = isPiped
        self.isSSH = isSSH
        self.isCI = isCI
        self.timestamp = timestamp
        self.automationCredentialID = automationCredentialID
        self.automationScope = automationScope
        self.requestedCommand = requestedCommand
        self.fullCommand = fullCommand
        self.sessionScope = sessionScope
        self.workingDirectory = workingDirectory
        self.agentRuntimeContext = agentRuntimeContext
        self.workspaceContext = workspaceContext
    }
}

public enum WorkspaceMetadataMode: String, Codable, Equatable, Sendable {
    case status
    case syncPreview
    case validate
}

public enum WorkspaceMetadataItemType: String, Codable, Equatable, Hashable, Sendable {
    case password
    case apiKey = "api-key"
    case certificate = "cert"
    case note
    case ssh
}

public struct WorkspaceMetadataReference: Codable, Equatable, Hashable, Sendable {
    public let itemType: WorkspaceMetadataItemType
    public let itemName: String
    public let folderPath: String?

    public init(itemType: WorkspaceMetadataItemType, itemName: String, folderPath: String?) {
        self.itemType = itemType
        self.itemName = itemName
        self.folderPath = folderPath
    }
}

public struct WorkspaceMetadataRequestPayload: Codable, Equatable, Sendable {
    public let workspaceFolder: String
    public let mode: WorkspaceMetadataMode
    public let references: [WorkspaceMetadataReference]

    public init(
        workspaceFolder: String,
        mode: WorkspaceMetadataMode,
        references: [WorkspaceMetadataReference]
    ) {
        self.workspaceFolder = workspaceFolder
        self.mode = mode
        self.references = references
    }
}

public struct WorkspaceRuntimeContext: Codable, Equatable, Sendable {
    public let name: String
    public let rootLabel: String
    public let authsiaFolder: String?

    public var displayName: String {
        name == rootLabel ? name : "\(name) (\(rootLabel))"
    }

    public init(name: String, rootLabel: String, authsiaFolder: String? = nil) {
        let sanitizedName = Self.sanitize(name, maxLength: 128) ?? "Workspace"
        self.name = sanitizedName
        self.rootLabel = Self.sanitize(rootLabel, maxLength: 128) ?? sanitizedName
        self.authsiaFolder = Self.sanitize(authsiaFolder, maxLength: 256)
    }

    private static func sanitize(_ value: String?, maxLength: Int) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty else {
            return nil
        }
        guard trimmed.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            return nil
        }
        return String(trimmed.prefix(maxLength))
    }
}

public enum BridgeErrorCode: String, Codable, Sendable {
    case notAuthorized
    case requiresApproval
    case policyDenied
    case notFound
    case multipleMatches
    case invalidRequest
    case appUnavailable
}

public struct BridgeErrorPayload: Codable, Equatable {
    public let code: BridgeErrorCode
    public let message: String

    public init(code: BridgeErrorCode, message: String) {
        self.code = code
        self.message = message
    }
}

public struct BridgeResponse<T: Codable & Equatable>: Codable, Equatable {
    public let id: UUID
    public let payload: T?
    public let error: BridgeErrorPayload?
    /// Session token returned after biometric approval, allowing CLI to cache it for subsequent requests
    public let sessionToken: String?
    /// The actual expiration date of the server-side session, so the CLI can cache with the correct TTL
    public let sessionExpiresAt: Date?

    public init(id: UUID, payload: T?, error: BridgeErrorPayload?, sessionToken: String? = nil, sessionExpiresAt: Date? = nil) {
        self.id = id
        self.payload = payload
        self.error = error
        self.sessionToken = sessionToken
        self.sessionExpiresAt = sessionExpiresAt
    }
}

// MARK: - Ping

public struct BridgePingPayload: Codable, Equatable, Sendable {
    /// XPC protocol version. Bumped only when the wire format changes.
    public let protocolVersion: String
    /// CFBundleShortVersionString of the running Authsia.app, e.g. "1.0.2".
    public let appVersion: String?
    /// Absolute path to the bundled CLI helper inside the running app, used by
    /// `authsia doctor` to detect a stale `~/.local/bin/authsia` symlink.
    public let bundledCLIPath: String?
    /// Authoritative bridge-owned CLI session state. Nil means the bridge is an older build
    /// that does not report session state, so the CLI should fall back to its local cache.
    public let sessionActive: Bool?
    /// Expiry for the current bridge-owned CLI session when one is active.
    public let sessionExpiresAt: Date?

    public init(
        protocolVersion: String,
        appVersion: String? = nil,
        bundledCLIPath: String? = nil,
        sessionActive: Bool? = nil,
        sessionExpiresAt: Date? = nil
    ) {
        self.protocolVersion = protocolVersion
        self.appVersion = appVersion
        self.bundledCLIPath = bundledCLIPath
        self.sessionActive = sessionActive
        self.sessionExpiresAt = sessionExpiresAt
    }
}

// MARK: - Access Approval

public struct AccessCreateApprovalPayload: Codable, Equatable, Sendable {
    public let name: String
    public let scope: String?
    public let ttlSeconds: Int
    public let expiresAt: Date
    public let machineId: String
    public let machineName: String
    public let allowedCommands: [String]
    public let environmentScope: EnvironmentAccessScope?

    public init(
        name: String,
        scope: String?,
        ttlSeconds: Int,
        expiresAt: Date,
        machineId: String,
        machineName: String,
        allowedCommands: [String],
        environmentScope: EnvironmentAccessScope? = nil
    ) {
        self.name = name
        self.scope = scope
        self.ttlSeconds = ttlSeconds
        self.expiresAt = expiresAt
        self.machineId = machineId
        self.machineName = machineName
        self.allowedCommands = allowedCommands
        self.environmentScope = environmentScope
    }
}

public struct AgentJITPreflightReference: Codable, Equatable, Sendable {
    public let type: String
    public let query: String
    public let folderPath: String?
    public let isFolderScoped: Bool

    public init(type: String, query: String, folderPath: String?, isFolderScoped: Bool = true) {
        self.type = type
        self.query = query
        self.folderPath = folderPath
        self.isFolderScoped = isFolderScoped
    }

    private enum CodingKeys: String, CodingKey {
        case type
        case query
        case folderPath
        case isFolderScoped
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.type = try container.decode(String.self, forKey: .type)
        self.query = try container.decode(String.self, forKey: .query)
        self.folderPath = try container.decodeIfPresent(String.self, forKey: .folderPath)
        self.isFolderScoped = try container.decodeIfPresent(Bool.self, forKey: .isFolderScoped) ?? true
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(query, forKey: .query)
        try container.encodeIfPresent(folderPath, forKey: .folderPath)
        try container.encode(isFolderScoped, forKey: .isFolderScoped)
    }
}

public struct AgentJITPreflightPayload: Codable, Equatable, Sendable {
    public let requestedCommand: String
    public let references: [AgentJITPreflightReference]
    public let environmentScope: EnvironmentAccessScope?

    public init(
        requestedCommand: String,
        references: [AgentJITPreflightReference],
        environmentScope: EnvironmentAccessScope? = nil
    ) {
        self.requestedCommand = requestedCommand
        self.references = references
        self.environmentScope = environmentScope
    }
}

public struct AgentJITPreflightResultPayload: Codable, Equatable, Sendable {
    public let grantIDs: [UUID]

    public init(grantIDs: [UUID]) {
        self.grantIDs = grantIDs
    }
}

// MARK: - Shared DTOs

public struct BridgeAccount: Identifiable, Codable, Equatable {
    public let id: UUID
    public let issuer: String
    public let label: String
    public let hosts: [String]?
    public let isFavorite: Bool
    public let isCliEnabled: Bool
    public let isScraped: Bool
    public let createdAt: Date
    public let updatedAt: Date

    public init(
        id: UUID,
        issuer: String,
        label: String,
        hosts: [String]? = nil,
        isFavorite: Bool,
        isCliEnabled: Bool,
        isScraped: Bool,
        createdAt: Date,
        updatedAt: Date
    ) {
        self.id = id
        self.issuer = issuer
        self.label = label
        self.hosts = hosts
        self.isFavorite = isFavorite
        self.isCliEnabled = isCliEnabled
        self.isScraped = isScraped
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

public struct BridgePassword: Identifiable, Codable, Equatable {
    public let id: UUID
    public let name: String
    public let username: String
    public let website: String?
    public let folderPath: String?
    public let isFavorite: Bool
    public let isCliEnabled: Bool
    public let isScraped: Bool
    public let createdAt: Date
    public let updatedAt: Date
    public let expiresAt: Date?
    public let scrapeMachineName: String?
    public let scrapeMachineId: String?
    public let hasSecret: Bool?
    @VaultEnvironmentTagList public var environments: [String] = []

    public init(
        id: UUID,
        name: String,
        username: String,
        website: String?,
        folderPath: String? = nil,
        isFavorite: Bool,
        isCliEnabled: Bool,
        isScraped: Bool,
        createdAt: Date,
        updatedAt: Date,
        expiresAt: Date? = nil,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        hasSecret: Bool? = nil,
        environments: [String] = []
    ) {
        self.id = id
        self.name = name
        self.username = username
        self.website = website
        self.folderPath = folderPath
        self.isFavorite = isFavorite
        self.isCliEnabled = isCliEnabled
        self.isScraped = isScraped
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.expiresAt = expiresAt
        self.scrapeMachineName = scrapeMachineName
        self.scrapeMachineId = scrapeMachineId
        self.hasSecret = hasSecret
        self.environments = VaultEnvironmentTags.normalize(environments)
    }
}

public struct BridgeAPIKey: Identifiable, Codable, Equatable {
    public let id: UUID
    public let name: String
    public let website: String?
    public let folderPath: String?
    public let isFavorite: Bool
    public let isCliEnabled: Bool
    public let isScraped: Bool
    public let createdAt: Date
    public let updatedAt: Date
    public let expiresAt: Date?
    public let scrapeMachineName: String?
    public let scrapeMachineId: String?
    public let hasSecret: Bool?
    @VaultEnvironmentTagList public var environments: [String] = []

    public init(
        id: UUID,
        name: String,
        website: String?,
        folderPath: String? = nil,
        isFavorite: Bool,
        isCliEnabled: Bool,
        isScraped: Bool,
        createdAt: Date,
        updatedAt: Date,
        expiresAt: Date? = nil,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        hasSecret: Bool? = nil,
        environments: [String] = []
    ) {
        self.id = id
        self.name = name
        self.website = website
        self.folderPath = folderPath
        self.isFavorite = isFavorite
        self.isCliEnabled = isCliEnabled
        self.isScraped = isScraped
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.expiresAt = expiresAt
        self.scrapeMachineName = scrapeMachineName
        self.scrapeMachineId = scrapeMachineId
        self.hasSecret = hasSecret
        self.environments = VaultEnvironmentTags.normalize(environments)
    }
}

public struct BridgeCertificate: Identifiable, Codable, Equatable {
    public let id: UUID
    public let name: String
    public let issuer: String?
    public let subject: String?
    public let expirationDate: Date?
    public let folderPath: String?
    public let isFavorite: Bool
    public let isCliEnabled: Bool
    public let isScraped: Bool
    public let createdAt: Date
    public let updatedAt: Date
    public let scrapeMachineName: String?
    public let scrapeMachineId: String?
    @VaultEnvironmentTagList public var environments: [String] = []

    public init(
        id: UUID,
        name: String,
        issuer: String?,
        subject: String?,
        expirationDate: Date?,
        folderPath: String? = nil,
        isFavorite: Bool,
        isCliEnabled: Bool,
        isScraped: Bool,
        createdAt: Date,
        updatedAt: Date,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        environments: [String] = []
    ) {
        self.id = id
        self.name = name
        self.issuer = issuer
        self.subject = subject
        self.expirationDate = expirationDate
        self.folderPath = folderPath
        self.isFavorite = isFavorite
        self.isCliEnabled = isCliEnabled
        self.isScraped = isScraped
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.scrapeMachineName = scrapeMachineName
        self.scrapeMachineId = scrapeMachineId
        self.environments = VaultEnvironmentTags.normalize(environments)
    }
}

public struct BridgeNote: Identifiable, Codable, Equatable {
    public let id: UUID
    public let title: String
    public let folderPath: String?
    public let isFavorite: Bool
    public let isCliEnabled: Bool
    public let isScraped: Bool
    public let createdAt: Date
    public let updatedAt: Date
    public let scrapeMachineName: String?
    public let scrapeMachineId: String?
    @VaultEnvironmentTagList public var environments: [String] = []

    public init(
        id: UUID,
        title: String,
        folderPath: String? = nil,
        isFavorite: Bool,
        isCliEnabled: Bool,
        isScraped: Bool,
        createdAt: Date,
        updatedAt: Date,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        environments: [String] = []
    ) {
        self.id = id
        self.title = title
        self.folderPath = folderPath
        self.isFavorite = isFavorite
        self.isCliEnabled = isCliEnabled
        self.isScraped = isScraped
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.scrapeMachineName = scrapeMachineName
        self.scrapeMachineId = scrapeMachineId
        self.environments = VaultEnvironmentTags.normalize(environments)
    }
}

public struct BridgeSSHKey: Identifiable, Codable, Equatable {
    public let id: UUID
    public let name: String
    public let comment: String
    public let fingerprint: String
    public let publicKey: String
    public let folderPath: String?
    public let isFavorite: Bool
    public let isCliEnabled: Bool
    public let isScraped: Bool
    public let createdAt: Date
    public let updatedAt: Date
    public let scrapeMachineName: String?
    public let scrapeMachineId: String?
    public let keyType: SSHKeyType
    public let approvalPolicy: SSHKeyApprovalPolicy
    public let boundHosts: [String]
    @VaultEnvironmentTagList public var environments: [String] = []

    public init(
        id: UUID,
        name: String,
        comment: String,
        fingerprint: String,
        publicKey: String,
        folderPath: String? = nil,
        isFavorite: Bool,
        isCliEnabled: Bool,
        isScraped: Bool,
        createdAt: Date,
        updatedAt: Date,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        keyType: SSHKeyType = .ed25519,
        approvalPolicy: SSHKeyApprovalPolicy = .sessionBased,
        boundHosts: [String] = [],
        environments: [String] = []
    ) {
        self.id = id
        self.name = name
        self.comment = comment
        self.fingerprint = fingerprint
        self.publicKey = publicKey
        self.folderPath = folderPath
        self.isFavorite = isFavorite
        self.isCliEnabled = isCliEnabled
        self.isScraped = isScraped
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.scrapeMachineName = scrapeMachineName
        self.scrapeMachineId = scrapeMachineId
        self.keyType = keyType
        self.approvalPolicy = approvalPolicy
        self.boundHosts = boundHosts
        self.environments = VaultEnvironmentTags.normalize(environments)
    }
}

public struct BridgeListPayload: Codable, Equatable {
    public let accounts: [BridgeAccount]
    public let passwords: [BridgePassword]
    public let apiKeys: [BridgeAPIKey]
    public let certificates: [BridgeCertificate]
    public let notes: [BridgeNote]
    public let sshKeys: [BridgeSSHKey]
    
    public init(
        accounts: [BridgeAccount],
        passwords: [BridgePassword],
        apiKeys: [BridgeAPIKey] = [],
        certificates: [BridgeCertificate],
        notes: [BridgeNote],
        sshKeys: [BridgeSSHKey]
    ) {
        self.accounts = accounts
        self.passwords = passwords
        self.apiKeys = apiKeys
        self.certificates = certificates
        self.notes = notes
        self.sshKeys = sshKeys
    }
}

extension BridgeListPayload {
    private enum CodingKeys: String, CodingKey {
        case accounts
        case passwords
        case apiKeys
        case certificates
        case notes
        case sshKeys
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        accounts = try container.decode([BridgeAccount].self, forKey: .accounts)
        passwords = try container.decode([BridgePassword].self, forKey: .passwords)
        apiKeys = try container.decodeIfPresent([BridgeAPIKey].self, forKey: .apiKeys) ?? []
        certificates = try container.decode([BridgeCertificate].self, forKey: .certificates)
        notes = try container.decode([BridgeNote].self, forKey: .notes)
        sshKeys = try container.decode([BridgeSSHKey].self, forKey: .sshKeys)
    }
}

// MARK: - Write Payloads

public struct PasswordWritePayload: Codable, Equatable {
    public let name: String?
    public let username: String?
    public let password: String?
    public let website: String?
    public let notes: String?
    public let isScraped: Bool?
    public let folderPath: String?
    public let scrapeMachineName: String?
    public let scrapeMachineId: String?
    public let expiresAt: Date?
    public let clearExpiresAt: Bool?
    public let environments: [String]?

    public init(
        name: String?,
        username: String?,
        password: String?,
        website: String?,
        notes: String?,
        isScraped: Bool? = nil,
        folderPath: String? = nil,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        expiresAt: Date? = nil,
        clearExpiresAt: Bool? = nil,
        environments: [String]? = nil
    ) {
        self.name = name
        self.username = username
        self.password = password
        self.website = website
        self.notes = notes
        self.isScraped = isScraped
        self.folderPath = folderPath
        self.scrapeMachineName = scrapeMachineName
        self.scrapeMachineId = scrapeMachineId
        self.expiresAt = expiresAt
        self.clearExpiresAt = clearExpiresAt
        self.environments = environments.map(VaultEnvironmentTags.normalize)
    }
}

public struct APIKeyWritePayload: Codable, Equatable {
    public let name: String?
    public let key: String?
    public let website: String?
    public let notes: String?
    public let isScraped: Bool?
    public let folderPath: String?
    public let scrapeMachineName: String?
    public let scrapeMachineId: String?
    public let expiresAt: Date?
    public let clearExpiresAt: Bool?
    public let environments: [String]?

    public init(
        name: String?,
        key: String?,
        website: String?,
        notes: String?,
        isScraped: Bool? = nil,
        folderPath: String? = nil,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        expiresAt: Date? = nil,
        clearExpiresAt: Bool? = nil,
        environments: [String]? = nil
    ) {
        self.name = name
        self.key = key
        self.website = website
        self.notes = notes
        self.isScraped = isScraped
        self.folderPath = folderPath
        self.scrapeMachineName = scrapeMachineName
        self.scrapeMachineId = scrapeMachineId
        self.expiresAt = expiresAt
        self.clearExpiresAt = clearExpiresAt
        self.environments = environments.map(VaultEnvironmentTags.normalize)
    }
}

public struct PasswordConversionPayload: Codable, Equatable {
    public let targetType: String

    public init(targetType: String) {
        self.targetType = targetType
    }
}

public struct CertificateWritePayload: Codable, Equatable {
    public let name: String?
    public let certificate: String?
    public let privateKey: String?
    public let clearPrivateKey: Bool?
    public let notes: String?
    public let isScraped: Bool?
    public let folderPath: String?
    public let scrapeMachineName: String?
    public let scrapeMachineId: String?
    public let environments: [String]?

    public init(
        name: String?,
        certificate: String?,
        privateKey: String?,
        clearPrivateKey: Bool? = nil,
        notes: String?,
        isScraped: Bool? = nil,
        folderPath: String? = nil,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        environments: [String]? = nil
    ) {
        self.name = name
        self.certificate = certificate
        self.privateKey = privateKey
        self.clearPrivateKey = clearPrivateKey
        self.notes = notes
        self.isScraped = isScraped
        self.folderPath = folderPath
        self.scrapeMachineName = scrapeMachineName
        self.scrapeMachineId = scrapeMachineId
        self.environments = environments.map(VaultEnvironmentTags.normalize)
    }
}

public struct NoteWritePayload: Codable, Equatable {
    public let title: String?
    public let content: String?
    public let isScraped: Bool?
    public let folderPath: String?
    public let scrapeMachineName: String?
    public let scrapeMachineId: String?
    public let environments: [String]?

    public init(
        title: String?,
        content: String?,
        isScraped: Bool? = nil,
        folderPath: String? = nil,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        environments: [String]? = nil
    ) {
        self.title = title
        self.content = content
        self.isScraped = isScraped
        self.folderPath = folderPath
        self.scrapeMachineName = scrapeMachineName
        self.scrapeMachineId = scrapeMachineId
        self.environments = environments.map(VaultEnvironmentTags.normalize)
    }
}

public struct SSHKeyWritePayload: Codable, Equatable {
    public let name: String?
    public let publicKey: String?
    public let privateKey: String?
    public let comment: String?
    public let fingerprint: String?
    public let passphrase: String?
    public let isScraped: Bool?
    public let folderPath: String?
    public let scrapeMachineName: String?
    public let scrapeMachineId: String?
    public let keyType: SSHKeyType?
    public let approvalPolicy: SSHKeyApprovalPolicy?
    public let boundHosts: [String]?
    public let environments: [String]?

    public init(
        name: String?,
        publicKey: String?,
        privateKey: String?,
        comment: String?,
        fingerprint: String?,
        passphrase: String? = nil,
        isScraped: Bool? = nil,
        folderPath: String? = nil,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil,
        keyType: SSHKeyType? = nil,
        approvalPolicy: SSHKeyApprovalPolicy? = nil,
        boundHosts: [String]? = nil,
        environments: [String]? = nil
    ) {
        self.name = name
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.comment = comment
        self.fingerprint = fingerprint
        self.passphrase = passphrase
        self.isScraped = isScraped
        self.folderPath = folderPath
        self.scrapeMachineName = scrapeMachineName
        self.scrapeMachineId = scrapeMachineId
        self.keyType = keyType
        self.approvalPolicy = approvalPolicy
        self.boundHosts = boundHosts
        self.environments = environments.map(VaultEnvironmentTags.normalize)
    }
}

public struct VaultFolderWritePayload: Codable, Equatable {
    public let path: String

    public init(path: String) {
        self.path = path
    }
}

public struct WriteResultPayload: Codable, Equatable {
    public let id: String
    public let message: String

    public init(id: String, message: String) {
        self.id = id
        self.message = message
    }
}

public struct AuditVerifyPayload: Codable, Equatable {
    public let valid: Bool

    public init(valid: Bool) {
        self.valid = valid
    }
}

public struct ExportAccountsRequestPayload: Codable, Equatable {
    /// If non-nil, the app encrypts the export with this password before returning it.
    public let password: String?

    public init(password: String?) {
        self.password = password
    }
}

public struct ExportAccountsPayload: Codable, Equatable {
    /// The export bytes, base64-encoded. May be raw JSON or an encrypted envelope.
    public let data: String
    /// True when the data field contains an encrypted envelope.
    public let encrypted: Bool
    /// Suggested filename (e.g. "authenticator-backup-2026-04-03.json").
    public let suggestedFilename: String

    public init(data: String, encrypted: Bool, suggestedFilename: String) {
        self.data = data
        self.encrypted = encrypted
        self.suggestedFilename = suggestedFilename
    }
}
