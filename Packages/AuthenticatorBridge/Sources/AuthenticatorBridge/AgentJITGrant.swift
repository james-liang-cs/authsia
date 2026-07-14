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
}

public struct AgentJITGrant: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let agentName: String
    public let callerFingerprint: AgentJITCallerFingerprint
    public let folderScope: AgentJITFolderScope
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
        self.capabilities = try container.decode(Set<AgentJITCapability>.self, forKey: .capabilities)
        self.createdAt = try container.decode(Date.self, forKey: .createdAt)
        self.expiresAt = try container.decode(Date.self, forKey: .expiresAt)
        self.revokedAt = try container.decodeIfPresent(Date.self, forKey: .revokedAt)
        self.lastUsedAt = try container.decodeIfPresent(Date.self, forKey: .lastUsedAt)
        self.requestedItems = try container.decodeIfPresent(
            [AgentJITGrantItemReference].self,
            forKey: .requestedItems
        ) ?? []
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
        itemFolderPath: String?,
        itemEnvironments: [String] = [],
        caller: AgentJITCallerFingerprint,
        now: Date
    ) -> Bool {
        status(asOf: now) == .active
            && capabilities.contains(capability)
            && folderScope.matches(itemFolderPath: itemFolderPath)
            && (environmentScope?.allows(itemEnvironments: itemEnvironments) ?? true)
            && callerFingerprint.matches(caller)
    }
}
