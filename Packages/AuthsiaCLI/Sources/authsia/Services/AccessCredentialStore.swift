import Foundation

enum AccessCredentialStoreError: LocalizedError {
    case notFound(UUID)
    case corruptedStore

    var errorDescription: String? {
        switch self {
        case .notFound(let id):
            return "No access credential found with id \(id.uuidString). Run `authsia access list --all` and copy an ID."
        case .corruptedStore:
            return "The access credential store is corrupted and could not be decoded. Recreate credentials with `authsia access create`."
        }
    }
}

final class AccessCredentialStore {
    let fileURL: URL
    let legacyFileURL: URL?
    private let fileManager: FileManager
    private static let directoryPermissions = 0o700
    private static let filePermissions = 0o600

    init(
        fileURL: URL,
        legacyFileURL: URL? = nil,
        fileManager: FileManager = .default
    ) {
        self.fileURL = fileURL
        self.legacyFileURL = legacyFileURL
        self.fileManager = fileManager
    }

    convenience init(fileManager: FileManager = .default) {
        self.init(
            fileURL: Self.defaultFileURL(),
            legacyFileURL: Self.defaultLegacyFileURL(),
            fileManager: fileManager
        )
    }

    func loadAll() throws -> [AccessCredential] {
        guard fileManager.fileExists(atPath: fileURL.path) else { return [] }
        let data = try Data(contentsOf: fileURL)
        guard !data.isEmpty else { return [] }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            let credentials = try decoder.decode([AccessCredential].self, from: data)
            try? fileManager.setAttributes([.posixPermissions: Self.filePermissions], ofItemAtPath: fileURL.path)
            return credentials
        } catch {
            throw AccessCredentialStoreError.corruptedStore
        }
    }

    func save(_ credential: AccessCredential) throws {
        var credentials = try loadAll()
        if let index = credentials.firstIndex(where: { $0.id == credential.id }) {
            credentials[index] = credential
        } else {
            credentials.append(credential)
        }
        try saveAll(credentials)
    }

    func load(id: UUID) throws -> AccessCredential? {
        try loadAll().first(where: { $0.id == id })
    }

    func loadDisabledLegacy() throws -> [AccessCredential] {
        guard let legacyFileURL,
              fileManager.fileExists(atPath: legacyFileURL.path) else {
            return []
        }
        let data = try Data(contentsOf: legacyFileURL)
        guard !data.isEmpty else { return [] }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return try decoder.decode([AccessCredential].self, from: data)
        } catch {
            throw AccessCredentialStoreError.corruptedStore
        }
    }

    func replaceAll(with credentials: [AccessCredential]) throws {
        try saveAll(credentials)
    }

    func revoke(id: UUID, revokedAt: Date = Date()) throws -> AccessCredential {
        var credentials = try loadAll()
        guard let index = credentials.firstIndex(where: { $0.id == id }) else {
            throw AccessCredentialStoreError.notFound(id)
        }

        let existing = credentials[index]
        let updated = AccessCredential(
            id: existing.id,
            name: existing.name,
            scope: existing.scope,
            createdAt: existing.createdAt,
            expiresAt: existing.expiresAt,
            revokedAt: existing.revokedAt ?? revokedAt,
            machineId: existing.machineId,
            machineName: existing.machineName,
            allowedCommands: existing.allowedCommands,
            environmentScope: existing.environmentScope,
            bearerToken: nil
        )
        credentials[index] = updated
        try saveAll(credentials)
        return updated
    }

    private func saveAll(_ credentials: [AccessCredential]) throws {
        let directory = fileURL.deletingLastPathComponent()
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        try? fileManager.setAttributes([.posixPermissions: Self.directoryPermissions], ofItemAtPath: directory.path)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(credentials)
        try data.write(to: fileURL, options: .atomic)
        try? fileManager.setAttributes([.posixPermissions: Self.filePermissions], ofItemAtPath: fileURL.path)
    }

    private static func defaultFileURL() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".authsia", isDirectory: true)
            .appendingPathComponent("access-credential-metadata.json")
    }

    private static func defaultLegacyFileURL() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".authsia", isDirectory: true)
            .appendingPathComponent("access-credentials.json")
    }
}
