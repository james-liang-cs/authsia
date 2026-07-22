#if os(macOS)
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

// nonisolated so the workspace refresh can load grants off the main thread; all
// mutable state is the store file itself, serialized by the shared mutationLock.
public nonisolated final class AgentJITGrantStore: AgentJITGrantStoring {
    private static let directoryPermissions: NSNumber = 0o700
    private static let filePermissions: NSNumber = 0o600
    private static let mutationLock = NSLock()

    private let fileURL: URL
    private let fileManager: FileManager
    private let terminalSessionLiveness: (String?) -> TerminalSessionLiveness
    private let atomicWriter: (Data) throws -> Void

    public init(
        fileURL: URL = AgentJITGrantStore.defaultFileURL(),
        fileManager: FileManager = .default,
        terminalSessionLiveness: @escaping (String?) -> TerminalSessionLiveness = {
            TerminalSessionScope.liveness(for: $0)
        }
    ) {
        self.fileURL = fileURL
        self.fileManager = fileManager
        self.terminalSessionLiveness = terminalSessionLiveness
        self.atomicWriter = { data in
            try Self.writeAtomically(data, to: fileURL, fileManager: fileManager)
        }
    }

    init(
        fileURL: URL,
        fileManager: FileManager = .default,
        terminalSessionLiveness: @escaping (String?) -> TerminalSessionLiveness = {
            TerminalSessionScope.liveness(for: $0)
        },
        atomicWriter: @escaping (Data) throws -> Void
    ) {
        self.fileURL = fileURL
        self.fileManager = fileManager
        self.terminalSessionLiveness = terminalSessionLiveness
        self.atomicWriter = atomicWriter
    }

    public func loadAll() throws -> [AgentJITGrant] {
        try locked {
            try loadAllUnlocked()
        }
    }

    public func loadAllRevokingClosedTerminalGrants(now: Date = Date()) throws -> [AgentJITGrant] {
        try locked {
            var grants = try loadAllUnlocked()
            let revoked = revokeClosedTerminalGrantsUnlocked(&grants, now: now)
            if !revoked.isEmpty {
                try writeUnlocked(grants)
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
            var grants = try loadAllUnlocked()
            for grant in newGrants {
                if let index = grants.firstIndex(where: { $0.id == grant.id }) {
                    grants[index] = grant
                } else {
                    grants.append(grant)
                }
            }
            try writeUnlocked(grants)
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

    public func revokeClosedTerminalGrants(now: Date = Date()) throws -> [AgentJITGrant] {
        try locked {
            var grants = try loadAllUnlocked()
            let revoked = revokeClosedTerminalGrantsUnlocked(&grants, now: now)
            if !revoked.isEmpty {
                try writeUnlocked(grants)
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
            let revoked = revokeClosedTerminalGrantsUnlocked(&grants, now: now)
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
                    try writeUnlocked(grants)
                }
                return nil
            }

            let updated = grants[index].copy(lastUsedAt: now)
            grants[index] = updated
            try writeUnlocked(grants)
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
            let revoked = revokeClosedTerminalGrantsUnlocked(&grants, now: now)
            let matchingIndices = grants.indices.filter {
                grants[$0].status(asOf: now) == .active
                    && grants[$0].capabilities.contains(capability)
                    && grants[$0].callerFingerprint.matches(caller)
            }
            guard !matchingIndices.isEmpty else {
                if !revoked.isEmpty {
                    try writeUnlocked(grants)
                }
                return []
            }

            let scopes = matchingIndices.map { grants[$0].folderScope }
            for index in matchingIndices {
                grants[index] = grants[index].copy(lastUsedAt: now)
            }
            try writeUnlocked(grants)
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
    ) -> [AgentJITGrant] {
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
        try ensureDirectory()
        guard fileManager.fileExists(atPath: fileURL.path) else { return [] }
        try enforceFilePermissions()

        let data = try Data(contentsOf: fileURL)
        guard !data.isEmpty else { return [] }

        do {
            return try Self.decoder.decode([AgentJITGrant].self, from: data)
        } catch {
            throw AgentJITGrantStoreError.corruptedStore
        }
    }

    private func updateUnlocked(
        id: UUID,
        transform: (AgentJITGrant) -> AgentJITGrant
    ) throws -> AgentJITGrant {
        var grants = try loadAllUnlocked()
        guard let index = grants.firstIndex(where: { $0.id == id }) else {
            throw AgentJITGrantStoreError.notFound(id)
        }
        let updated = transform(grants[index])
        grants[index] = updated
        try writeUnlocked(grants)
        return updated
    }

    private func writeUnlocked(_ grants: [AgentJITGrant]) throws {
        try ensureDirectory()
        let data = try Self.encoder.encode(grants)
        try atomicWriter(data)
    }

    private func ensureDirectory() throws {
        let directory = fileURL.deletingLastPathComponent()
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: Self.directoryPermissions]
        )
        try fileManager.setAttributes([.posixPermissions: Self.directoryPermissions], ofItemAtPath: directory.path)
    }

    private func enforceFilePermissions() throws {
        try fileManager.setAttributes([.posixPermissions: Self.filePermissions], ofItemAtPath: fileURL.path)
    }

    private static func writeAtomically(
        _ data: Data,
        to fileURL: URL,
        fileManager: FileManager
    ) throws {
        let directory = fileURL.deletingLastPathComponent()
        let temporaryURL = directory.appendingPathComponent(
            ".\(fileURL.lastPathComponent).\(UUID().uuidString).tmp"
        )
        defer { try? fileManager.removeItem(at: temporaryURL) }

        try data.write(to: temporaryURL)
        try fileManager.setAttributes(
            [.posixPermissions: filePermissions],
            ofItemAtPath: temporaryURL.path
        )
        if fileManager.fileExists(atPath: fileURL.path) {
            _ = try fileManager.replaceItemAt(
                fileURL,
                withItemAt: temporaryURL,
                backupItemName: nil,
                options: .usingNewMetadataOnly
            )
        } else {
            try fileManager.moveItem(at: temporaryURL, to: fileURL)
        }
    }

    private static var encoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }

    private static var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

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
