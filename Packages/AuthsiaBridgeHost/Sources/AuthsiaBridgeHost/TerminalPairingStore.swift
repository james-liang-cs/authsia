#if os(macOS)
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

public nonisolated protocol TerminalPairingStoring: Sendable {
    func loadAll() throws -> [TerminalPairing]
    func loadAllPruningInvalid(now: Date) throws -> [TerminalPairing]
    func save(_ pairing: TerminalPairing) throws
    func saveAll(_ pairings: [TerminalPairing]) throws
    func revoke(id: UUID) throws -> TerminalPairing
    func revokeAll() throws -> [TerminalPairing]
}

public nonisolated final class TerminalPairingStore: TerminalPairingStoring, @unchecked Sendable {
    private static let mutationLock = NSLock()

    private let fileURL: URL
    private let fileManager: FileManager
    private let processStartTime: @Sendable (Int32) -> UInt64?

    public init(
        fileURL: URL = TerminalPairingStore.defaultFileURL(),
        fileManager: FileManager = .default,
        processStartTime: @escaping @Sendable (Int32) -> UInt64? = {
            TerminalSessionScope.startTimeSeconds(pid: $0)
        }
    ) {
        self.fileURL = fileURL
        self.fileManager = fileManager
        self.processStartTime = processStartTime
    }

    public func loadAll() throws -> [TerminalPairing] {
        try locked { try loadAllUnlocked() }
    }

    public func loadAllPruningInvalid(now: Date = Date()) throws -> [TerminalPairing] {
        try locked {
            let stored = try loadAllUnlocked()
            let valid = stored.filter {
                $0.expiresAt > now
                    && processStartTime($0.anchorShellPID) == $0.anchorShellStartTime
            }
            if valid != stored {
                try persistUnlocked(valid)
            }
            return valid
        }
    }

    public func save(_ pairing: TerminalPairing) throws {
        try saveAll([pairing])
    }

    public func saveAll(_ pairings: [TerminalPairing]) throws {
        guard !pairings.isEmpty else { return }
        try locked {
            var stored = try loadAllUnlocked()
            for pairing in pairings {
                stored.removeAll { $0.id == pairing.id }
                stored.append(pairing)
            }
            try persistUnlocked(stored)
        }
    }

    public func revoke(id: UUID) throws -> TerminalPairing {
        try locked {
            var stored = try loadAllUnlocked()
            guard let index = stored.firstIndex(where: { $0.id == id }) else {
                throw TerminalPairingStoreError.notFound(id)
            }
            let pairing = stored.remove(at: index)
            try persistUnlocked(stored)
            return pairing
        }
    }

    public func revokeAll() throws -> [TerminalPairing] {
        try locked {
            let stored = try loadAllUnlocked()
            try persistUnlocked([])
            return stored
        }
    }

    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        Self.mutationLock.lock()
        defer { Self.mutationLock.unlock() }
        return try body()
    }

    private func loadAllUnlocked() throws -> [TerminalPairing] {
        guard fileManager.fileExists(atPath: fileURL.path) else { return [] }
        do {
            return try Self.decoder.decode([TerminalPairing].self, from: Data(contentsOf: fileURL))
        } catch {
            throw TerminalPairingStoreError.corruptedStore
        }
    }

    private func persistUnlocked(_ pairings: [TerminalPairing]) throws {
        try fileManager.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Self.encoder.encode(pairings).write(to: fileURL, options: .atomic)
    }

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }()

    private static let decoder = JSONDecoder()

    public static func defaultFileURL() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Application Support", isDirectory: true)
        return base
            .appendingPathComponent("Authsia", isDirectory: true)
            .appendingPathComponent("terminal-pairings.json")
    }
}
#endif
