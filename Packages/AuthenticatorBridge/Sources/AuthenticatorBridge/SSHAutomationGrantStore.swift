import Darwin
import Foundation

public struct SSHAutomationGrantRecord: Codable, Equatable, Sendable {
    public let id: UUID
    public let leaseID: UUID
    public let sessionScope: String?
    public let rootProcessID: Int32?
    public let createdAt: Date
    public let expiresAt: Date

    public init(
        id: UUID = UUID(),
        leaseID: UUID,
        sessionScope: String?,
        rootProcessID: Int32?,
        createdAt: Date,
        expiresAt: Date
    ) {
        self.id = id
        self.leaseID = leaseID
        self.sessionScope = sessionScope
        self.rootProcessID = rootProcessID
        self.createdAt = createdAt
        self.expiresAt = expiresAt
    }
}

public enum SSHAutomationGrantStore {
    private static let directoryPermissions = 0o700
    private static let filePermissions = 0o600
    private static let filePermissionsMode: mode_t = S_IRUSR | S_IWUSR
    private static let mutationLock = NSLock()

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
        (try? mutationLock.withLock {
            try withFileLock(fileURL: fileURL) {
                loadUnlocked(fileURL: fileURL)
            }
        }) ?? []
    }

    private static func loadUnlocked(fileURL: URL) -> [SSHAutomationGrantRecord] {
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
        leaseID: UUID,
        sessionScope: String?,
        rootProcessID: Int32?,
        expiresAt: Date,
        fileURL: URL = defaultFileURL,
        currentDate: Date = Date()
    ) throws -> SSHAutomationGrantRecord {
        try mutationLock.withLock {
            try withFileLock(fileURL: fileURL) {
                let record = SSHAutomationGrantRecord(
                    leaseID: leaseID,
                    sessionScope: normalized(sessionScope),
                    rootProcessID: rootProcessID,
                    createdAt: currentDate,
                    expiresAt: expiresAt
                )
                let active = loadUnlocked(fileURL: fileURL).filter {
                    $0.expiresAt > currentDate
                }
                let remaining = active.filter { !sameBinding($0, record) }
                try saveUnlocked(remaining + [record], fileURL: fileURL)
                return record
            }
        }
    }

    public static func activeLeaseIDs(
        sessionScope: String?,
        ancestryPIDs: [Int32],
        currentDate: Date = Date(),
        fileURL: URL = defaultFileURL
    ) -> [UUID] {
        (try? mutationLock.withLock {
            try withFileLock(fileURL: fileURL) {
                let records = loadUnlocked(fileURL: fileURL)
                let active = records.filter { $0.expiresAt > currentDate }
                if active.count != records.count {
                    if active.isEmpty {
                        clearUnlocked(fileURL: fileURL)
                    } else {
                        try saveUnlocked(active, fileURL: fileURL)
                    }
                }

                let normalizedScope = normalized(sessionScope)
                let ancestrySet = Set(ancestryPIDs)
                return active.filter { record in
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
                }.map(\.leaseID)
            }
        }) ?? []
    }

    public static func clearGrant(id: UUID, fileURL: URL = defaultFileURL) {
        try? mutationLock.withLock {
            try withFileLock(fileURL: fileURL) {
                let remaining = loadUnlocked(fileURL: fileURL).filter { $0.id != id }
                if remaining.isEmpty {
                    clearUnlocked(fileURL: fileURL)
                } else {
                    try saveUnlocked(remaining, fileURL: fileURL)
                }
            }
        }
    }

    @discardableResult
    public static func clearSessionScope(
        _ sessionScope: String,
        fileURL: URL = defaultFileURL
    ) -> [UUID] {
        guard let normalizedScope = normalized(sessionScope) else { return [] }
        return (try? mutationLock.withLock {
            try withFileLock(fileURL: fileURL) {
                let records = loadUnlocked(fileURL: fileURL)
                let removed = records.filter {
                    $0.sessionScope == normalizedScope
                }
                let remaining = records.filter {
                    $0.sessionScope != normalizedScope
                }
                if remaining.isEmpty {
                    clearUnlocked(fileURL: fileURL)
                } else {
                    try saveUnlocked(remaining, fileURL: fileURL)
                }
                return removed.map(\.leaseID)
            }
        }) ?? []
    }

    public static func clear(fileURL: URL = defaultFileURL) {
        try? mutationLock.withLock {
            try withFileLock(fileURL: fileURL) {
                clearUnlocked(fileURL: fileURL)
            }
        }
    }

    private static func clearUnlocked(fileURL: URL) {
        try? FileManager.default.removeItem(at: fileURL)
    }

    private static func saveUnlocked(
        _ records: [SSHAutomationGrantRecord],
        fileURL: URL
    ) throws {
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

    private static func withFileLock<T>(
        fileURL: URL,
        _ body: () throws -> T
    ) throws -> T {
        let directory = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: directoryPermissions]
        )
        try? FileManager.default.setAttributes(
            [.posixPermissions: directoryPermissions],
            ofItemAtPath: directory.path
        )
        let lockPath = fileURL.path + ".lock"
        let fileDescriptor = open(
            lockPath,
            O_RDWR | O_CREAT,
            filePermissionsMode
        )
        guard fileDescriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { close(fileDescriptor) }
        try? FileManager.default.setAttributes(
            [.posixPermissions: filePermissions],
            ofItemAtPath: lockPath
        )
        guard flock(fileDescriptor, LOCK_EX) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { flock(fileDescriptor, LOCK_UN) }
        return try body()
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
