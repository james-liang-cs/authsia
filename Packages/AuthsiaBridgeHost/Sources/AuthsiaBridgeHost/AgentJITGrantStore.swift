#if os(macOS)
import CryptoKit
import Foundation
import AuthenticatorBridge

public enum AgentJITGrantStoreError: LocalizedError, Equatable {
    case notFound(UUID)
    case corruptedStore

    public var errorDescription: String? {
        switch self {
        case .notFound(let id):
            return "JIT grant '\(id.uuidString)' was not found."
        case .corruptedStore:
            return "The JIT grant store is corrupted."
        }
    }
}

public nonisolated protocol AgentJITGrantStoring {
    func loadAll() throws -> [AgentJITGrant]
    func save(_ grant: AgentJITGrant) throws
    func saveAll(_ grants: [AgentJITGrant]) throws
    func markUsed(id: UUID, at date: Date) throws -> AgentJITGrant
    func revoke(id: UUID, revokedAt date: Date) throws -> AgentJITGrant
    func revokeAll(revokedAt date: Date) throws -> [AgentJITGrant]
    func revokeClosedTerminalGrants(now: Date) throws -> [AgentJITGrant]
    func markUsedIfAllowed(
        capability: AgentJITCapability,
        itemFolderPath: String?,
        itemEnvironments: [String],
        caller: AgentJITCallerFingerprint,
        now: Date
    ) throws -> AgentJITGrant?
    func markUsedScopes(
        capability: AgentJITCapability,
        caller: AgentJITCallerFingerprint,
        now: Date
    ) throws -> [AgentJITFolderScope]
}

public extension AgentJITGrantStoring {
    func revokeAll(revokedAt date: Date) throws -> [AgentJITGrant] {
        try loadAll()
            .filter { $0.status(asOf: date) == .active }
            .map { try revoke(id: $0.id, revokedAt: date) }
    }
}

/// Bridge-owned JIT authority. The former JSON path is retained only so an
/// upgraded installation can quarantine it without trusting its contents.
public nonisolated final class AgentJITGrantStore: AgentJITGrantStoring {
    private static let mutationLock = NSLock()

    private let authorityStore: AuthorityStoring
    private let legacyFileURL: URL
    private let fileManager: FileManager
    private let terminalSessionLiveness: (String?) -> TerminalSessionLiveness

    public init(
        authorityStore: AuthorityStoring = KeychainAuthorityStore(),
        legacyFileURL: URL = AgentJITGrantStore.defaultFileURL(),
        fileManager: FileManager = .default,
        terminalSessionLiveness: @escaping (String?) -> TerminalSessionLiveness = {
            TerminalSessionScope.liveness(for: $0)
        }
    ) {
        self.authorityStore = authorityStore
        self.legacyFileURL = legacyFileURL
        self.fileManager = fileManager
        self.terminalSessionLiveness = terminalSessionLiveness
        try? locked {
            try migrateLegacyFileUnlocked()
        }
    }

    public func loadAll() throws -> [AgentJITGrant] {
        try locked {
            try loadAllUnlocked()
        }
    }

    public func loadAllRevokingClosedTerminalGrants(now: Date = Date()) throws -> [AgentJITGrant] {
        try locked {
            var grants = try loadAllUnlocked()
            let revoked = try revokeClosedTerminalGrantsUnlocked(&grants, now: now)
            if !revoked.isEmpty {
                try persistUnlocked(grants)
            }
            return grants
        }
    }

    public func save(_ grant: AgentJITGrant) throws {
        try saveAll([grant])
    }

    public func saveAll(_ newGrants: [AgentJITGrant]) throws {
        guard !newGrants.isEmpty else { return }
        try locked {
            try migrateLegacyFileUnlocked()
            try persistUnlocked(newGrants)
        }
    }

    public func markUsed(id: UUID, at date: Date) throws -> AgentJITGrant {
        try locked {
            try updateUnlocked(id: id) { grant in
                grant.copy(lastUsedAt: date)
            }
        }
    }

    public func revoke(id: UUID, revokedAt date: Date) throws -> AgentJITGrant {
        try locked {
            try updateUnlocked(id: id) { grant in
                grant.copy(revokedAt: date)
            }
        }
    }

    public func revokeAll(revokedAt date: Date) throws -> [AgentJITGrant] {
        try locked {
            let grants = try loadAllUnlocked()
            let revoked = grants
                .filter { $0.status(asOf: date) == .active }
                .map { $0.copy(revokedAt: date) }
            try persistUnlocked(revoked)
            return revoked
        }
    }

    public func revokeClosedTerminalGrants(now: Date = Date()) throws -> [AgentJITGrant] {
        try locked {
            var grants = try loadAllUnlocked()
            let revoked = try revokeClosedTerminalGrantsUnlocked(&grants, now: now)
            if !revoked.isEmpty {
                try persistUnlocked(grants)
            }
            return revoked
        }
    }

    public func markUsedIfAllowed(
        capability: AgentJITCapability,
        itemFolderPath: String?,
        itemEnvironments: [String],
        caller: AgentJITCallerFingerprint,
        now: Date
    ) throws -> AgentJITGrant? {
        try locked {
            var grants = try loadAllUnlocked()
            let revoked = try revokeClosedTerminalGrantsUnlocked(&grants, now: now)
            guard let index = grants.firstIndex(where: {
                $0.allows(
                    capability: capability,
                    itemFolderPath: itemFolderPath,
                    itemEnvironments: itemEnvironments,
                    caller: caller,
                    now: now
                )
            }) else {
                if !revoked.isEmpty {
                    try persistUnlocked(grants)
                }
                return nil
            }

            let updated = grants[index].copy(lastUsedAt: now)
            try persistUnlocked([updated])
            return updated
        }
    }

    public func markUsedScopes(
        capability: AgentJITCapability,
        caller: AgentJITCallerFingerprint,
        now: Date
    ) throws -> [AgentJITFolderScope] {
        try locked {
            var grants = try loadAllUnlocked()
            let revoked = try revokeClosedTerminalGrantsUnlocked(&grants, now: now)
            let matchingIndices = grants.indices.filter {
                grants[$0].status(asOf: now) == .active
                    && grants[$0].capabilities.contains(capability)
                    && grants[$0].callerFingerprint.matches(caller)
            }
            guard !matchingIndices.isEmpty else {
                if !revoked.isEmpty {
                    try persistUnlocked(grants)
                }
                return []
            }

            let scopes = matchingIndices.map { grants[$0].folderScope }
            let updated = matchingIndices.map { index in
                grants[index].copy(lastUsedAt: now)
            }
            try persistUnlocked(updated)
            return scopes
        }
    }

    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        Self.mutationLock.lock()
        defer { Self.mutationLock.unlock() }
        return try body()
    }

    private func revokeClosedTerminalGrantsUnlocked(
        _ grants: inout [AgentJITGrant],
        now: Date
    ) throws -> [AgentJITGrant] {
        var revoked: [AgentJITGrant] = []
        for index in grants.indices where grants[index].status(asOf: now) == .active {
            guard terminalSessionLiveness(grants[index].callerFingerprint.sessionScope) == .closed else {
                continue
            }
            let updated = grants[index].copy(revokedAt: now)
            grants[index] = updated
            revoked.append(updated)
        }
        return revoked
    }

    private func loadAllUnlocked() throws -> [AgentJITGrant] {
        try migrateLegacyFileUnlocked()
        do {
            return try authorityStore.allRecords()
                .filter { $0.type == .agentJITGrant }
                .map(Self.grant(from:))
        } catch let error as AgentJITGrantStoreError {
            throw error
        } catch {
            throw AgentJITGrantStoreError.corruptedStore
        }
    }

    private func updateUnlocked(
        id: UUID,
        transform: (AgentJITGrant) -> AgentJITGrant
    ) throws -> AgentJITGrant {
        let grants = try loadAllUnlocked()
        guard let grant = grants.first(where: { $0.id == id }) else {
            throw AgentJITGrantStoreError.notFound(id)
        }
        let updated = transform(grant)
        try persistUnlocked([updated])
        return updated
    }

    private func persistUnlocked(_ grants: [AgentJITGrant]) throws {
        try authorityStore.upsert(try grants.map(Self.record(from:)))
    }

    private func migrateLegacyFileUnlocked() throws {
        guard fileManager.fileExists(atPath: legacyFileURL.path) else { return }
        let quarantinedURL = legacyFileURL.appendingPathExtension("legacy")
        if fileManager.fileExists(atPath: quarantinedURL.path) {
            try fileManager.removeItem(at: legacyFileURL)
        } else {
            try fileManager.moveItem(at: legacyFileURL, to: quarantinedURL)
        }
    }

    private static func record(from grant: AgentJITGrant) throws -> AuthorityRecord {
        let payload = try encoder.encode(grant)
        return AuthorityRecord(
            type: .agentJITGrant,
            id: grant.id,
            createdAt: grant.createdAt,
            expiresAt: grant.expiresAt,
            revokedAt: grant.revokedAt,
            maximumUses: .max,
            consumedUses: 0,
            bindingDigest: Data(SHA256.hash(data: payload)),
            displayMetadata: [
                "agent": grant.agentName,
                "scope": grant.folderScope.displayName,
            ],
            payload: payload
        )
    }

    private static func grant(from record: AuthorityRecord) throws -> AgentJITGrant {
        guard let payload = record.payload,
              Data(SHA256.hash(data: payload)) == record.bindingDigest,
              let grant = try? decoder.decode(AgentJITGrant.self, from: payload),
              grant.id == record.id,
              grant.createdAt == record.createdAt,
              grant.expiresAt == record.expiresAt,
              grant.revokedAt == record.revokedAt else {
            throw AgentJITGrantStoreError.corruptedStore
        }
        return grant
    }

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    public static func defaultFileURL() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Application Support", isDirectory: true)
        return base
            .appendingPathComponent("Authsia", isDirectory: true)
            .appendingPathComponent("agent-jit-grants.json")
    }
}

private extension AgentJITGrant {
    nonisolated func copy(revokedAt: Date? = nil, lastUsedAt: Date? = nil) -> AgentJITGrant {
        AgentJITGrant(
            id: id,
            agentName: agentName,
            callerFingerprint: callerFingerprint,
            folderScope: folderScope,
            capabilities: capabilities,
            createdAt: createdAt,
            expiresAt: expiresAt,
            revokedAt: revokedAt ?? self.revokedAt,
            lastUsedAt: lastUsedAt ?? self.lastUsedAt,
            requestedItems: requestedItems,
            agentRuntimeContext: agentRuntimeContext,
            approvedBy: approvedBy,
            environmentScope: environmentScope
        )
    }
}
#endif
