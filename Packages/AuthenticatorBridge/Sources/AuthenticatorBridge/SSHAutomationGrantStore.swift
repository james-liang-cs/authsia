import Foundation

public struct SSHAutomationGrantRecord: Codable, Equatable, Sendable {
    public let id: UUID
    public let credentialID: UUID
    public let sessionScope: String?
    public let rootProcessID: Int32?
    public let createdAt: Date
    public let expiresAt: Date

    public init(
        id: UUID = UUID(),
        credentialID: UUID,
        sessionScope: String?,
        rootProcessID: Int32?,
        createdAt: Date,
        expiresAt: Date
    ) {
        self.id = id
        self.credentialID = credentialID
        self.sessionScope = sessionScope
        self.rootProcessID = rootProcessID
        self.createdAt = createdAt
        self.expiresAt = expiresAt
    }
}

public enum SSHAutomationGrantStore {
    private static let directoryPermissions = 0o700
    private static let filePermissions = 0o600

    public static var defaultFileURL: URL {
        #if os(macOS)
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".authsia", isDirectory: true)
            .appendingPathComponent("ssh-automation-grants.json")
        #else
        FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia", isDirectory: true)
            .appendingPathComponent("ssh-automation-grants.json")
        #endif
    }

    public static func load(fileURL: URL = defaultFileURL) -> [SSHAutomationGrantRecord] {
        guard let data = try? Data(contentsOf: fileURL), !data.isEmpty else {
            return []
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let records = try? decoder.decode([SSHAutomationGrantRecord].self, from: data) else {
            return []
        }
        try? FileManager.default.setAttributes([.posixPermissions: filePermissions], ofItemAtPath: fileURL.path)
        return records
    }

    @discardableResult
    public static func saveGrant(
        credentialID: UUID,
        sessionScope: String?,
        rootProcessID: Int32?,
        expiresAt: Date,
        fileURL: URL = defaultFileURL,
        currentDate: Date = Date()
    ) throws -> SSHAutomationGrantRecord {
        let record = SSHAutomationGrantRecord(
            credentialID: credentialID,
            sessionScope: normalized(sessionScope),
            rootProcessID: rootProcessID,
            createdAt: currentDate,
            expiresAt: expiresAt
        )
        let active = load(fileURL: fileURL).filter { $0.expiresAt > currentDate }
        let remaining = active.filter { !sameBinding($0, record) }
        try save(remaining + [record], fileURL: fileURL)
        return record
    }

    public static func activeCredentialID(
        sessionScope: String?,
        ancestryPIDs: [Int32],
        currentDate: Date = Date(),
        fileURL: URL = defaultFileURL
    ) -> UUID? {
        let records = load(fileURL: fileURL)
        let active = records.filter { $0.expiresAt > currentDate }
        if active.count != records.count {
            if active.isEmpty {
                clear(fileURL: fileURL)
            } else {
                try? save(active, fileURL: fileURL)
            }
        }

        let normalizedScope = normalized(sessionScope)
        let ancestrySet = Set(ancestryPIDs)
        return active.first { record in
            if let recordScope = record.sessionScope,
               let normalizedScope,
               recordScope == normalizedScope {
                return true
            }
            if let rootProcessID = record.rootProcessID,
               ancestrySet.contains(rootProcessID) {
                return true
            }
            return false
        }?.credentialID
    }

    public static func clearGrant(id: UUID, fileURL: URL = defaultFileURL) {
        let remaining = load(fileURL: fileURL).filter { $0.id != id }
        if remaining.isEmpty {
            clear(fileURL: fileURL)
        } else {
            try? save(remaining, fileURL: fileURL)
        }
    }

    public static func clearSessionScope(_ sessionScope: String, fileURL: URL = defaultFileURL) {
        guard let normalizedScope = normalized(sessionScope) else { return }
        let remaining = load(fileURL: fileURL).filter { $0.sessionScope != normalizedScope }
        if remaining.isEmpty {
            clear(fileURL: fileURL)
        } else {
            try? save(remaining, fileURL: fileURL)
        }
    }

    public static func clear(fileURL: URL = defaultFileURL) {
        try? FileManager.default.removeItem(at: fileURL)
    }

    private static func save(_ records: [SSHAutomationGrantRecord], fileURL: URL) throws {
        let directory = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: directoryPermissions]
        )
        try? FileManager.default.setAttributes([.posixPermissions: directoryPermissions], ofItemAtPath: directory.path)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(records)
        try data.write(to: fileURL, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: filePermissions], ofItemAtPath: fileURL.path)
    }

    private static func sameBinding(_ lhs: SSHAutomationGrantRecord, _ rhs: SSHAutomationGrantRecord) -> Bool {
        if let lhsScope = lhs.sessionScope,
           let rhsScope = rhs.sessionScope,
           lhsScope == rhsScope {
            return true
        }
        if let lhsPID = lhs.rootProcessID,
           let rhsPID = rhs.rootProcessID,
           lhsPID == rhsPID {
            return true
        }
        return false
    }

    private static func normalized(_ value: String?) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
