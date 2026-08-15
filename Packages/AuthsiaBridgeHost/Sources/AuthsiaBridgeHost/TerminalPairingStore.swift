#if os(macOS)
import CryptoKit
import Foundation
import AuthenticatorBridge

public enum TerminalPairingStoreError: LocalizedError, Equatable {
    case notFound(UUID)
    case corruptedStore

    public var errorDescription: String? {
        switch self {
        case .notFound(let id):
            return "Terminal pairing '\(id.uuidString)' was not found."
        case .corruptedStore:
            return "The terminal pairing store is corrupted."
        }
    }
}

/// Reports what a prune dropped alongside what survived, so the caller can audit
/// the drop without a second read that another request could race.
public struct TerminalPairingPruneResult: Equatable, Sendable {
    public let valid: [TerminalPairing]
    public let pruned: [TerminalPairing]

    public init(valid: [TerminalPairing], pruned: [TerminalPairing]) {
        self.valid = valid
        self.pruned = pruned
    }
}

public nonisolated protocol TerminalPairingStoring: Sendable {
    func loadAll() throws -> [TerminalPairing]
    func loadAllPruningInvalid(now: Date) throws -> TerminalPairingPruneResult
    func save(_ pairing: TerminalPairing) throws
    func saveAll(_ pairings: [TerminalPairing]) throws
    func revoke(id: UUID) throws -> TerminalPairing
    func revokeAll() throws -> [TerminalPairing]
}

/// A pairing is a human-attestation grant, so it is held in the same
/// Keychain-backed authority store as Agent JIT grants rather than a plain
/// file. A same-user process must not be able to forge `paired-human` trust by
/// writing JSON it can fully observe about itself.
public nonisolated final class TerminalPairingStore: TerminalPairingStoring, @unchecked Sendable {
    private static let mutationLock = NSLock()

    private let authorityStore: AuthorityStoring
    private let legacyFileURL: URL
    private let fileManager: FileManager
    private let processStartTime: @Sendable (Int32) -> UInt64?

    public init(
        authorityStore: AuthorityStoring = KeychainAuthorityStore(),
        legacyFileURL: URL = TerminalPairingStore.defaultLegacyFileURL(),
        fileManager: FileManager = .default,
        processStartTime: @escaping @Sendable (Int32) -> UInt64? = {
            TerminalSessionScope.startTimeSeconds(pid: $0)
        }
    ) {
        self.authorityStore = authorityStore
        self.legacyFileURL = legacyFileURL
        self.fileManager = fileManager
        self.processStartTime = processStartTime
        try? locked {
            try quarantineLegacyFileUnlocked()
        }
    }

    public func loadAll() throws -> [TerminalPairing] {
        try locked { try loadAllUnlocked() }
    }

    public func loadAllPruningInvalid(now: Date = Date()) throws -> TerminalPairingPruneResult {
        try locked {
            let stored = try loadAllUnlocked()
            let valid = stored.filter {
                $0.expiresAt > now
                    && processStartTime($0.anchorShellPID) == $0.anchorShellStartTime
            }
            let validIDs = Set(valid.map(\.id))
            let pruned = stored.filter { !validIDs.contains($0.id) }
            for pairing in pruned {
                try authorityStore.removeRecord(id: pairing.id, ofType: .terminalPairing)
            }
            return TerminalPairingPruneResult(valid: valid, pruned: pruned)
        }
    }

    public func save(_ pairing: TerminalPairing) throws {
        try saveAll([pairing])
    }

    public func saveAll(_ pairings: [TerminalPairing]) throws {
        guard !pairings.isEmpty else { return }
        try locked {
            try authorityStore.upsert(try pairings.map(Self.record(from:)))
        }
    }

    public func revoke(id: UUID) throws -> TerminalPairing {
        try locked {
            guard let pairing = try loadAllUnlocked().first(where: { $0.id == id }) else {
                throw TerminalPairingStoreError.notFound(id)
            }
            try authorityStore.removeRecord(id: id, ofType: .terminalPairing)
            return pairing
        }
    }

    public func revokeAll() throws -> [TerminalPairing] {
        try locked {
            let stored = try loadAllUnlocked()
            for pairing in stored {
                try authorityStore.removeRecord(id: pairing.id, ofType: .terminalPairing)
            }
            return stored
        }
    }

    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        Self.mutationLock.lock()
        defer { Self.mutationLock.unlock() }
        return try body()
    }

    private func loadAllUnlocked() throws -> [TerminalPairing] {
        do {
            return try authorityStore.allRecords()
                .filter { $0.type == .terminalPairing }
                .map(Self.pairing(from:))
        } catch let error as TerminalPairingStoreError {
            throw error
        } catch {
            throw TerminalPairingStoreError.corruptedStore
        }
    }

    /// Pairings predating the authority store lived in a world-readable file that
    /// any same-user process could rewrite, so they are quarantined rather than
    /// migrated. Those terminals pair again.
    private func quarantineLegacyFileUnlocked() throws {
        guard fileManager.fileExists(atPath: legacyFileURL.path) else { return }
        let quarantinedURL = legacyFileURL.appendingPathExtension("legacy")
        if fileManager.fileExists(atPath: quarantinedURL.path) {
            try fileManager.removeItem(at: legacyFileURL)
        } else {
            try fileManager.moveItem(at: legacyFileURL, to: quarantinedURL)
        }
    }

    private static func record(from pairing: TerminalPairing) throws -> AuthorityRecord {
        let payload = try encoder.encode(pairing)
        // The record dates must equal what `pairing(from:)` decodes back, and the
        // ISO-8601 payload encoding drops sub-second precision.
        let stored = try decoder.decode(TerminalPairing.self, from: payload)
        return AuthorityRecord(
            type: .terminalPairing,
            id: stored.id,
            createdAt: stored.createdAt,
            expiresAt: stored.expiresAt,
            revokedAt: nil,
            maximumUses: .max,
            consumedUses: 0,
            bindingDigest: Data(SHA256.hash(data: payload)),
            displayMetadata: [
                "terminal": stored.controllingTerminal,
                "workspaceRoot": stored.workspaceRoot,
            ],
            payload: payload
        )
    }

    /// The digest covers the payload, so the record fields are cross-checked to
    /// stop an envelope-level edit from extending a pairing's lifetime.
    private static func pairing(from record: AuthorityRecord) throws -> TerminalPairing {
        guard let payload = record.payload,
              Data(SHA256.hash(data: payload)) == record.bindingDigest,
              let pairing = try? decoder.decode(TerminalPairing.self, from: payload),
              pairing.id == record.id,
              pairing.createdAt == record.createdAt,
              pairing.expiresAt == record.expiresAt,
              record.revokedAt == nil else {
            throw TerminalPairingStoreError.corruptedStore
        }
        return pairing
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

    public static func defaultLegacyFileURL() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Application Support", isDirectory: true)
        return base
            .appendingPathComponent("Authsia", isDirectory: true)
            .appendingPathComponent("terminal-pairings.json")
    }
}
#endif
