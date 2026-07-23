import Foundation

public enum AgentJITCapability: String, Codable, CaseIterable, Sendable {
    case exec
    case list
}

public enum AgentJITGrantStatus: String, Codable, Sendable {
    case active
    case expired
    case revoked
}

public enum AgentJITFolderScope: Codable, Equatable, Hashable, Sendable {
    case root
    case folder(String)

    private enum CodingKeys: String, CodingKey {
        case kind
        case path
    }

    private enum Kind: String, Codable {
        case root
        case folder
    }

    public init(folderPath: String?) {
        if let normalized = normalizeFolderPath(folderPath) {
            self = .folder(normalized)
        } else {
            self = .root
        }
    }

    public var storageValue: String? {
        switch self {
        case .root:
            return nil
        case .folder(let path):
            return normalizeFolderPath(path)
        }
    }

    public var displayName: String {
        switch self {
        case .root:
            return "Root"
        case .folder(let path):
            return normalizeFolderPath(path) ?? ""
        }
    }

    public func matches(itemFolderPath: String?) -> Bool {
        switch self {
        case .root:
            return normalizeFolderPath(itemFolderPath) == nil
        case .folder(let path):
            guard let normalizedPath = normalizeFolderPath(path),
                  let normalizedItemPath = normalizeFolderPath(itemFolderPath) else {
                return false
            }
            return normalizedItemPath == normalizedPath
                || normalizedItemPath.hasPrefix(normalizedPath + "/")
        }
    }

    public static func == (lhs: AgentJITFolderScope, rhs: AgentJITFolderScope) -> Bool {
        switch (lhs, rhs) {
        case (.root, .root):
            return true
        case (.folder(let lhsPath), .folder(let rhsPath)):
            return normalizeFolderPath(lhsPath) == normalizeFolderPath(rhsPath)
        default:
            return false
        }
    }

    public func hash(into hasher: inout Hasher) {
        switch self {
        case .root:
            hasher.combine("root")
        case .folder(let path):
            hasher.combine("folder")
            hasher.combine(normalizeFolderPath(path))
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try container.decode(Kind.self, forKey: .kind)
        switch kind {
        case .root:
            self = .root
        case .folder:
            let path = try container.decode(String.self, forKey: .path)
            guard let normalized = normalizeFolderPath(path) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .path,
                    in: container,
                    debugDescription: "Folder path is empty."
                )
            }
            self = .folder(normalized)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .root:
            try container.encode(Kind.root, forKey: .kind)
        case .folder(let path):
            guard let normalizedPath = normalizeFolderPath(path) else {
                throw EncodingError.invalidValue(
                    path,
                    EncodingError.Context(
                        codingPath: encoder.codingPath,
                        debugDescription: "Folder path is empty."
                    )
                )
            }
            try container.encode(Kind.folder, forKey: .kind)
            try container.encode(normalizedPath, forKey: .path)
        }
    }
}

public struct AgentJITItemIdentity: Codable, Equatable, Hashable, Sendable {
    public let type: String
    public let id: UUID

    public init(type: String, id: UUID) {
        self.type = Self.normalizedType(type)
        self.id = id
    }

    private static func normalizedType(_ type: String) -> String {
        switch type.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "apikey", "api-key": return "api-key"
        case "cert", "certificate": return "certificate"
        case "ssh", "sshkey", "ssh-key": return "ssh"
        default: return type.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        }
    }
}

public enum AgentJITResourceScope: Codable, Equatable, Sendable {
    case items(Set<AgentJITItemIdentity>)
    case folder(AgentJITFolderScope)

    public func matches(
        itemIdentity: AgentJITItemIdentity?,
        itemFolderPath: String?
    ) -> Bool {
        switch self {
        case .items(let identities):
            guard let itemIdentity else { return false }
            return identities.contains(itemIdentity)
        case .folder(let folderScope):
            return folderScope.matches(itemFolderPath: itemFolderPath)
        }
    }

    public func covers(
        itemIdentities: Set<AgentJITItemIdentity>,
        itemFolderPath: String?
    ) -> Bool {
        switch self {
        case .items(let approvedIdentities):
            return !itemIdentities.isEmpty
                && approvedIdentities.isSuperset(of: itemIdentities)
        case .folder(let folderScope):
            return folderScope.matches(itemFolderPath: itemFolderPath)
        }
    }
}

public struct AgentJITApprovalItem: Equatable, Sendable {
    public let id: UUID
    public let type: String
    public let name: String
    public let folderPath: String?

    init?(reference: AgentJITGrantItemReference) {
        guard let identity = reference.itemIdentity else { return nil }
        id = identity.id
        type = Self.displayType(identity.type)
        name = Self.safeDisplayText(reference.name, fallback: "Unnamed item")
        folderPath = reference.folderPath.map {
            Self.safeDisplayText($0, fallback: "Root")
        }
    }

    private static func displayType(_ type: String) -> String {
        switch type {
        case "api-key": return "API key"
        case "certificate": return "Certificate"
        case "note": return "Note"
        case "password": return "Password"
        case "ssh": return "SSH key"
        default: return "Vault item"
        }
    }

    private static func safeDisplayText(_ value: String, fallback: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              trimmed.unicodeScalars.allSatisfy({
                  !CharacterSet.controlCharacters.contains($0)
              }) else {
            return fallback
        }
        return String(trimmed.prefix(256))
    }
}

public struct AgentJITApprovalDescriptor: Equatable, Sendable {
    public let callerFingerprint: AgentJITCallerFingerprint
    public let capabilities: [AgentJITCapability]
    public let resourceScope: AgentJITResourceScope
    public let environmentScope: EnvironmentAccessScope?
    public let requestedItems: [AgentJITApprovalItem]
    public let requestIssuedAtMilliseconds: Int64
    public let grantExpiresAtMilliseconds: Int64

    public init(
        callerFingerprint: AgentJITCallerFingerprint,
        capabilities: [AgentJITCapability],
        resourceScope: AgentJITResourceScope,
        environmentScope: EnvironmentAccessScope?,
        requestedItems: [AgentJITGrantItemReference],
        requestIssuedAtMilliseconds: Int64,
        grantExpiresAtMilliseconds: Int64
    ) {
        self.callerFingerprint = callerFingerprint
        self.capabilities = Array(Set(capabilities)).sorted { $0.rawValue < $1.rawValue }
        self.resourceScope = resourceScope
        self.environmentScope = environmentScope
        self.requestedItems = requestedItems.compactMap(AgentJITApprovalItem.init(reference:))
        self.requestIssuedAtMilliseconds = requestIssuedAtMilliseconds
        self.grantExpiresAtMilliseconds = grantExpiresAtMilliseconds
    }

    public var callerDisplayName: String {
        callerFingerprint.displayName
    }

    public var workspaceLabel: String {
        guard let path = callerFingerprint.workingDirectory, path != "/" else {
            return "/"
        }
        return String(path.split(separator: "/").last ?? "/")
    }

    public var durationSeconds: Int {
        max(0, Int((grantExpiresAtMilliseconds - requestIssuedAtMilliseconds) / 1_000))
    }

    public var reuseDescription: String {
        switch resourceScope {
        case .items:
            return "Exact items only"
        case .folder(let folderScope):
            return "Folder reuse: \(folderScope.displayName)"
        }
    }
}

public struct AgentJITCallerFingerprint: Codable, Equatable, Sendable {
    public let processName: String
    public let bundleIdentifier: String?
    public let signingTeamId: String?
    public let signingIdentity: String?
    public let parentProcessName: String?
    public let parentBundleIdentifier: String?
    public let hostProcessName: String?
    public let hostBundleIdentifier: String?
    public let sessionScope: String?
    public let workingDirectory: String?

    public init(
        processName: String,
        bundleIdentifier: String?,
        signingTeamId: String?,
        signingIdentity: String?,
        parentProcessName: String?,
        parentBundleIdentifier: String?,
        hostProcessName: String? = nil,
        hostBundleIdentifier: String? = nil,
        sessionScope: String?,
        workingDirectory: String?
    ) {
        self.processName = processName
        self.bundleIdentifier = bundleIdentifier
        self.signingTeamId = signingTeamId
        self.signingIdentity = signingIdentity
        self.parentProcessName = parentProcessName
        self.parentBundleIdentifier = parentBundleIdentifier
        self.hostProcessName = hostProcessName
        self.hostBundleIdentifier = hostBundleIdentifier
        self.sessionScope = sessionScope
        self.workingDirectory = workingDirectory
    }

    public func matches(_ current: AgentJITCallerFingerprint) -> Bool {
        processName == current.processName
            && optionalMatch(bundleIdentifier, current.bundleIdentifier)
            && optionalMatch(signingTeamId, current.signingTeamId)
            && optionalMatch(signingIdentity, current.signingIdentity)
            && optionalMatch(parentProcessName, current.parentProcessName)
            && optionalMatch(parentBundleIdentifier, current.parentBundleIdentifier)
            && optionalMatch(hostProcessName, current.hostProcessName)
            && optionalMatch(hostBundleIdentifier, current.hostBundleIdentifier)
            && requiredMatch(sessionScope, current.sessionScope)
            && requiredMatch(workingDirectory, current.workingDirectory)
    }

    public var displayName: String {
        let agent = Self.displayLabel(
            processName: parentProcessName ?? processName,
            bundleIdentifier: parentBundleIdentifier ?? bundleIdentifier
        )
        guard let hostProcessName else {
            return agent
        }
        let host = Self.displayLabel(processName: hostProcessName, bundleIdentifier: hostBundleIdentifier)
        return host == agent ? agent : "\(agent) via \(host)"
    }

    private static func displayLabel(processName: String, bundleIdentifier: String?) -> String {
        let normalizedBundle = bundleIdentifier?.lowercased() ?? ""
        if normalizedBundle.contains("com.microsoft.vscode") {
            return "Visual Studio Code"
        }
        if normalizedBundle.contains("com.todesktop.230313mzl4w4u92")
            || normalizedBundle.contains("com.cursor") {
            return "Cursor"
        }
        if normalizedBundle.contains("windsurf") {
            return "Windsurf"
        }
        if normalizedBundle.contains("dev.zed.zed") {
            return "Zed"
        }
        if normalizedBundle.contains("com.anthropic.claude") {
            return "Claude"
        }
        if normalizedBundle.contains("codex") {
            return "Codex"
        }

        return processName
            .replacingOccurrences(of: "_", with: " ")
            .replacingOccurrences(of: "-", with: " ")
            .split(separator: " ")
            .map { word in
                let lowercased = word.lowercased()
                return lowercased.prefix(1).uppercased() + String(lowercased.dropFirst())
            }
            .joined(separator: " ")
    }

    private func optionalMatch(_ stored: String?, _ current: String?) -> Bool {
        guard let stored else { return true }
        return stored == current
    }

    private func requiredMatch(_ stored: String?, _ current: String?) -> Bool {
        switch (stored, current) {
        case (nil, nil):
            return true
        case let (stored?, current?):
            return stored == current
        default:
            return false
        }
    }
}

public struct AgentJITGrantItemReference: Codable, Equatable, Sendable {
    public let type: String
    public let id: String
    public let name: String
    public let folderPath: String?

    public init(type: String, id: String, name: String, folderPath: String?) {
        self.type = type
        self.id = id
        self.name = name
        self.folderPath = folderPath
    }

    public var itemIdentity: AgentJITItemIdentity? {
        UUID(uuidString: id).map { AgentJITItemIdentity(type: type, id: $0) }
    }
}

public struct AgentJITGrant: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let agentName: String
    public let callerFingerprint: AgentJITCallerFingerprint
    public let folderScope: AgentJITFolderScope
    public let resourceScope: AgentJITResourceScope
    public let capabilities: Set<AgentJITCapability>
    public let createdAt: Date
    public let expiresAt: Date
    public let revokedAt: Date?
    public let lastUsedAt: Date?
    public let requestedItems: [AgentJITGrantItemReference]
    public let agentRuntimeContext: AgentRuntimeContext?
    public let approvedBy: String
    public let environmentScope: EnvironmentAccessScope?

    private enum CodingKeys: String, CodingKey {
        case id
        case agentName
        case callerFingerprint
        case folderScope
        case resourceScope
        case capabilities
        case createdAt
        case expiresAt
        case revokedAt
        case lastUsedAt
        case requestedItems
        case agentRuntimeContext
        case approvedBy
        case environmentScope
    }

    public init(
        id: UUID,
        agentName: String,
        callerFingerprint: AgentJITCallerFingerprint,
        folderScope: AgentJITFolderScope,
        resourceScope: AgentJITResourceScope? = nil,
        capabilities: Set<AgentJITCapability>,
        createdAt: Date,
        expiresAt: Date,
        revokedAt: Date?,
        lastUsedAt: Date?,
        requestedItems: [AgentJITGrantItemReference] = [],
        agentRuntimeContext: AgentRuntimeContext? = nil,
        approvedBy: String,
        environmentScope: EnvironmentAccessScope? = nil
    ) {
        self.id = id
        self.agentName = agentName
        self.callerFingerprint = callerFingerprint
        self.folderScope = folderScope
        let itemIdentities = Set(requestedItems.compactMap(\.itemIdentity))
        self.resourceScope = resourceScope
            ?? (requestedItems.isEmpty ? .folder(folderScope) : .items(itemIdentities))
        self.capabilities = capabilities
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.revokedAt = revokedAt
        self.lastUsedAt = lastUsedAt
        self.requestedItems = requestedItems
        self.agentRuntimeContext = agentRuntimeContext
        self.approvedBy = approvedBy
        self.environmentScope = environmentScope
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try container.decode(UUID.self, forKey: .id)
        self.agentName = try container.decode(String.self, forKey: .agentName)
        self.callerFingerprint = try container.decode(AgentJITCallerFingerprint.self, forKey: .callerFingerprint)
        self.folderScope = try container.decode(AgentJITFolderScope.self, forKey: .folderScope)
        let decodedItems = try container.decodeIfPresent(
            [AgentJITGrantItemReference].self,
            forKey: .requestedItems
        ) ?? []
        let itemIdentities = Set(decodedItems.compactMap(\.itemIdentity))
        self.resourceScope = try container.decodeIfPresent(
            AgentJITResourceScope.self,
            forKey: .resourceScope
        ) ?? (decodedItems.isEmpty ? .folder(folderScope) : .items(itemIdentities))
        self.capabilities = try container.decode(Set<AgentJITCapability>.self, forKey: .capabilities)
        self.createdAt = try container.decode(Date.self, forKey: .createdAt)
        self.expiresAt = try container.decode(Date.self, forKey: .expiresAt)
        self.revokedAt = try container.decodeIfPresent(Date.self, forKey: .revokedAt)
        self.lastUsedAt = try container.decodeIfPresent(Date.self, forKey: .lastUsedAt)
        self.requestedItems = decodedItems
        self.agentRuntimeContext = try container.decodeIfPresent(
            AgentRuntimeContext.self,
            forKey: .agentRuntimeContext
        )
        self.approvedBy = try container.decode(String.self, forKey: .approvedBy)
        self.environmentScope = try container.decodeIfPresent(EnvironmentAccessScope.self, forKey: .environmentScope)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(agentName, forKey: .agentName)
        try container.encode(callerFingerprint, forKey: .callerFingerprint)
        try container.encode(folderScope, forKey: .folderScope)
        try container.encode(resourceScope, forKey: .resourceScope)
        try container.encode(capabilities, forKey: .capabilities)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(expiresAt, forKey: .expiresAt)
        try container.encodeIfPresent(revokedAt, forKey: .revokedAt)
        try container.encodeIfPresent(lastUsedAt, forKey: .lastUsedAt)
        try container.encode(requestedItems, forKey: .requestedItems)
        try container.encodeIfPresent(agentRuntimeContext, forKey: .agentRuntimeContext)
        try container.encode(approvedBy, forKey: .approvedBy)
        try container.encodeIfPresent(environmentScope, forKey: .environmentScope)
    }

    public func status(asOf date: Date) -> AgentJITGrantStatus {
        if revokedAt != nil { return .revoked }
        return expiresAt > date ? .active : .expired
    }

    public func allows(
        capability: AgentJITCapability,
        itemIdentity: AgentJITItemIdentity? = nil,
        itemFolderPath: String?,
        itemEnvironments: [String] = [],
        caller: AgentJITCallerFingerprint,
        now: Date
    ) -> Bool {
        status(asOf: now) == .active
            && capabilities.contains(capability)
            && resourceScope.matches(
                itemIdentity: itemIdentity,
                itemFolderPath: itemFolderPath
            )
            && (environmentScope?.allows(itemEnvironments: itemEnvironments) ?? true)
            && callerFingerprint.matches(caller)
    }
}

public struct AgentJITGrantSnapshotPayload: Codable, Equatable, Sendable {
    public let active: [AgentJITGrant]
    public let history: [AgentJITGrant]

    public init(active: [AgentJITGrant], history: [AgentJITGrant]) {
        self.active = active
        self.history = history
    }
}

public struct AgentJITGrantRevokePayload: Codable, Equatable, Sendable {
    public let id: UUID

    public init(id: UUID) {
        self.id = id
    }
}

public struct AgentJITGrantMutationPayload: Codable, Equatable, Sendable {
    public let revokedGrantIDs: [UUID]

    public init(revokedGrantIDs: [UUID]) {
        self.revokedGrantIDs = revokedGrantIDs
    }
}
