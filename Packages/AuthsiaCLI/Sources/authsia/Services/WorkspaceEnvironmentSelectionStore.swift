import AuthenticatorCore
import Foundation

enum WorkspaceEnvironmentSelectionStoreError: LocalizedError {
    case invalidEnvironment
    case corruptedStore
    case unsupportedSchema(Int)

    var errorDescription: String? {
        switch self {
        case .invalidEnvironment:
            return "Environment names cannot be empty."
        case .corruptedStore:
            return "The workspace environment selection store is corrupted."
        case .unsupportedSchema(let version):
            return "Workspace environment selection schema \(version) is not supported."
        }
    }
}

final class WorkspaceEnvironmentSelectionStore {
    struct State: Codable, Equatable {
        var schemaVersion = 1
        var activeEnvironmentByWorkspace: [String: String] = [:]
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
        self.init(fileURL: Self.defaultFileURL(fileManager: fileManager), fileManager: fileManager)
    }

    func activeEnvironment(for workspaceRoot: URL) throws -> String? {
        try loadState().activeEnvironmentByWorkspace[canonicalPath(workspaceRoot)]
    }

    func setActiveEnvironment(_ environment: String, for workspaceRoot: URL) throws {
        guard let normalized = VaultEnvironmentTags.normalize([environment]).first else {
            throw WorkspaceEnvironmentSelectionStoreError.invalidEnvironment
        }
        var state = try loadState()
        state.activeEnvironmentByWorkspace[canonicalPath(workspaceRoot)] = normalized
        try saveState(state)
    }

    @discardableResult
    func clearActiveEnvironment(for workspaceRoot: URL) throws -> Bool {
        var state = try loadState()
        guard state.activeEnvironmentByWorkspace.removeValue(forKey: canonicalPath(workspaceRoot)) != nil else {
            return false
        }
        try saveState(state)
        return true
    }

    private func loadState() throws -> State {
        guard fileManager.fileExists(atPath: fileURL.path) else { return State() }
        let data = try Data(contentsOf: fileURL)
        guard !data.isEmpty else { return State() }
        do {
            let state = try JSONDecoder().decode(State.self, from: data)
            guard state.schemaVersion == 1 else {
                throw WorkspaceEnvironmentSelectionStoreError.unsupportedSchema(state.schemaVersion)
            }
            try? fileManager.setAttributes([.posixPermissions: Self.filePermissions], ofItemAtPath: fileURL.path)
            return state
        } catch let error as WorkspaceEnvironmentSelectionStoreError {
            throw error
        } catch {
            throw WorkspaceEnvironmentSelectionStoreError.corruptedStore
        }
    }

    private func saveState(_ state: State) throws {
        let directory = fileURL.deletingLastPathComponent()
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        try fileManager.setAttributes([.posixPermissions: Self.directoryPermissions], ofItemAtPath: directory.path)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(state).write(to: fileURL, options: .atomic)
        try fileManager.setAttributes([.posixPermissions: Self.filePermissions], ofItemAtPath: fileURL.path)
    }

    private func canonicalPath(_ workspaceRoot: URL) -> String {
        workspaceRoot.resolvingSymlinksInPath().standardizedFileURL.path
    }

    private static func defaultFileURL(fileManager: FileManager) -> URL {
        fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent(".authsia", isDirectory: true)
            .appendingPathComponent("workspace-environments.json")
    }
}
