import Foundation

enum EnvironmentProfileStoreError: LocalizedError {
    case notFound(String)
    case corruptedStore

    var errorDescription: String? {
        switch self {
        case .notFound(let name):
            return "No environment profile named '\(name)' was found. Run `authsia env list`, or create it with `authsia env add`."
        case .corruptedStore:
            return "The environment profile store is corrupted and could not be decoded. Recreate profiles with `authsia env add`."
        }
    }
}

final class EnvironmentProfileStore {
    struct State: Codable {
        var profiles: [EnvironmentProfile]
        var activeProfileName: String?
    }

    let fileURL: URL
    private let fileManager: FileManager
    private static let directoryPermissions = 0o700
    private static let filePermissions = 0o600

    init(fileURL: URL, fileManager: FileManager = .default) {
        self.fileURL = fileURL
        self.fileManager = fileManager
    }

    convenience init(fileManager: FileManager = .default) {
        self.init(fileURL: Self.defaultFileURL(), fileManager: fileManager)
    }

    func loadAll() throws -> [EnvironmentProfile] {
        try loadState().profiles
    }

    func load(named name: String) throws -> EnvironmentProfile? {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        return try loadAll().first(where: { $0.name == trimmed })
    }

    func loadActiveProfileName() throws -> String? {
        try loadState().activeProfileName
    }

    func loadActiveProfile() throws -> EnvironmentProfile? {
        guard let activeName = try loadActiveProfileName() else { return nil }
        return try load(named: activeName)
    }

    func save(_ profile: EnvironmentProfile) throws {
        var state = try loadState()
        if let index = state.profiles.firstIndex(where: { $0.name == profile.name }) {
            state.profiles[index] = profile
        } else {
            state.profiles.append(profile)
        }
        try saveState(state)
    }

    func setActive(name: String) throws -> EnvironmentProfile {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw EnvironmentProfileStoreError.notFound(name)
        }

        var state = try loadState()
        guard let profile = state.profiles.first(where: { $0.name == trimmed }) else {
            throw EnvironmentProfileStoreError.notFound(trimmed)
        }
        state.activeProfileName = profile.name
        try saveState(state)
        return profile
    }

    func clearActive() throws -> Bool {
        var state = try loadState()
        guard state.activeProfileName != nil else {
            return false
        }
        state.activeProfileName = nil
        try saveState(state)
        return true
    }

    // MARK: - Persistence

    private func loadState() throws -> State {
        guard fileManager.fileExists(atPath: fileURL.path) else {
            return State(profiles: [], activeProfileName: nil)
        }

        let data = try Data(contentsOf: fileURL)
        guard !data.isEmpty else {
            return State(profiles: [], activeProfileName: nil)
        }

        let decoder = JSONDecoder()
        do {
            let state = try decoder.decode(State.self, from: data)
            try? fileManager.setAttributes([.posixPermissions: Self.filePermissions], ofItemAtPath: fileURL.path)
            return state
        } catch {
            throw EnvironmentProfileStoreError.corruptedStore
        }
    }

    private func saveState(_ state: State) throws {
        let directory = fileURL.deletingLastPathComponent()
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        try? fileManager.setAttributes([.posixPermissions: Self.directoryPermissions], ofItemAtPath: directory.path)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(state)
        try data.write(to: fileURL, options: .atomic)
        try? fileManager.setAttributes([.posixPermissions: Self.filePermissions], ofItemAtPath: fileURL.path)
    }

    private static func defaultFileURL() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".authsia", isDirectory: true)
            .appendingPathComponent("environment-profiles.json")
    }
}
