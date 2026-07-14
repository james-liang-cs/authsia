import Foundation

public struct WorkspaceKnownRootsSnapshot: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let roots: [String]

    public init(schemaVersion: Int = 1, roots: [String]) {
        self.schemaVersion = schemaVersion
        self.roots = roots
    }
}

public final class WorkspaceKnownRootsStore: @unchecked Sendable {
    public static let shared = WorkspaceKnownRootsStore()
    public static let currentSchemaVersion = 1

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

    public init(applicationSupportDirectory: URL, fileManager: FileManager = .default) {
        self.applicationSupportDirectory = applicationSupportDirectory
        self.fileManager = fileManager
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    }

    public func load() throws -> [String] {
        guard fileManager.fileExists(atPath: knownRootsURL.path) else {
            return []
        }
        let data = try Data(contentsOf: knownRootsURL)
        let snapshot = try decoder.decode(WorkspaceKnownRootsSnapshot.self, from: data)
        guard snapshot.schemaVersion <= Self.currentSchemaVersion else {
            throw WorkspaceKnownRootsStoreError.unsupportedSchema(snapshot.schemaVersion)
        }
        return Self.normalizedUnique(snapshot.roots)
    }

    public func record(_ path: String) throws {
        let current = try load()
        let normalized = Self.normalizedPath(path)
        guard !normalized.isEmpty else { return }
        let updated = [normalized] + current.filter { $0 != normalized }
        guard updated != current else { return }
        try save(updated)
    }

    public func record(_ paths: [String]) throws {
        let current = try load()
        var seen = Set(current)
        var updated = current
        for path in Self.normalizedUnique(paths) where seen.insert(path).inserted {
            updated.append(path)
        }
        // The workspace view records known roots on every refresh tick; skip the
        // rewrite when nothing changed so idle refreshes don't touch the disk.
        guard updated != current else { return }
        try save(updated)
    }

    public func forget(_ path: String) throws {
        let normalized = Self.normalizedPath(path)
        try save(try load().filter { $0 != normalized })
    }

    private func save(_ roots: [String]) throws {
        let directory = knownRootsURL.deletingLastPathComponent()
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        #if os(macOS)
        try? fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        #endif

        let snapshot = WorkspaceKnownRootsSnapshot(roots: roots)
        let data = try encoder.encode(snapshot)
        try data.write(to: knownRootsURL, options: .atomic)
        #if os(macOS)
        try? fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: knownRootsURL.path)
        #endif
    }

    private var knownRootsURL: URL {
        applicationSupportDirectory
            .appendingPathComponent("Authsia", isDirectory: true)
            .appendingPathComponent("Workspace", isDirectory: true)
            .appendingPathComponent("known_roots.json")
    }

    private static func normalizedUnique(_ paths: [String]) -> [String] {
        var seen = Set<String>()
        return paths.compactMap { path in
            let normalized = normalizedPath(path)
            guard !normalized.isEmpty, seen.insert(normalized).inserted else { return nil }
            return normalized
        }
    }

    private static func normalizedPath(_ path: String) -> String {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "" }
        return URL(fileURLWithPath: trimmed, isDirectory: true).standardizedFileURL.path
    }
}

private enum WorkspaceKnownRootsStoreError: Error {
    case unsupportedSchema(Int)
}
