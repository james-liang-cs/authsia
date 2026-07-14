import Foundation

public struct BridgeSessionOrigin: Codable, Equatable, Sendable {
    public let processIdentifier: Int32
    public let processName: String
    public let bundleIdentifier: String?

    public init(processIdentifier: Int32, processName: String, bundleIdentifier: String?) {
        self.processIdentifier = processIdentifier
        self.processName = processName
        self.bundleIdentifier = bundleIdentifier
    }
}

public struct BridgeSessionStatusRecord: Codable, Equatable, Sendable {
    public let scope: String
    public let expiresAt: Date
    public let workingDirectory: String?
    public let origin: BridgeSessionOrigin?

    public init(
        scope: String,
        expiresAt: Date,
        workingDirectory: String? = nil,
        origin: BridgeSessionOrigin? = nil
    ) {
        self.scope = scope
        self.expiresAt = expiresAt
        self.workingDirectory = workingDirectory
        self.origin = origin
    }
}

public struct BridgeSessionStatusSnapshot: Codable, Equatable, Sendable {
    public let bridgePID: Int32
    public let sessions: [BridgeSessionStatusRecord]
    public let updatedAt: Date

    public init(bridgePID: Int32, sessions: [BridgeSessionStatusRecord], updatedAt: Date) {
        self.bridgePID = bridgePID
        self.sessions = sessions
        self.updatedAt = updatedAt
    }

    public func activeSessions(
        currentDate: Date = Date(),
        isBridgeProcessRunning: (Int32) -> Bool
    ) -> [BridgeSessionStatusRecord] {
        guard isBridgeProcessRunning(bridgePID) else { return [] }
        return sessions
            .filter { $0.expiresAt > currentDate }
            .sorted {
                if $0.expiresAt != $1.expiresAt {
                    return $0.expiresAt > $1.expiresAt
                }
                return $0.scope < $1.scope
            }
    }
}

public enum BridgeSessionStatusStore {
    public static let unscopedScope = "__unscoped__"

    public static var defaultFileURL: URL {
        // XCTest exercises the app singleton, so keep tests away from real CLI session state.
        if ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil {
            return FileManager.default.temporaryDirectory
                .appendingPathComponent("authsia-tests", isDirectory: true)
                .appendingPathComponent("cli-session-status-\(ProcessInfo.processInfo.processIdentifier).json")
        }

        #if os(macOS)
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".authsia", isDirectory: true)
            .appendingPathComponent("cli-session-status.json")
        #else
        return FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia", isDirectory: true)
            .appendingPathComponent("cli-session-status.json")
        #endif
    }

    public static func load(fileURL: URL = defaultFileURL) -> BridgeSessionStatusSnapshot? {
        guard let data = try? Data(contentsOf: fileURL), !data.isEmpty else {
            return nil
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(BridgeSessionStatusSnapshot.self, from: data)
    }

    public static func save(_ snapshot: BridgeSessionStatusSnapshot, fileURL: URL = defaultFileURL) throws {
        let directory = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(snapshot)
        try data.write(to: fileURL, options: .atomic)
    }

    public static func clear(fileURL: URL = defaultFileURL) {
        try? FileManager.default.removeItem(at: fileURL)
    }

    public static func activeSessions(
        fileURL: URL = defaultFileURL,
        currentDate: Date = Date()
    ) -> [BridgeSessionStatusRecord] {
        activeSessions(
            fileURL: fileURL,
            currentDate: currentDate,
            isBridgeProcessRunning: processIsRunning(pid:)
        )
    }

    public static func activeSessions(
        fileURL: URL,
        currentDate: Date,
        isBridgeProcessRunning: (Int32) -> Bool
    ) -> [BridgeSessionStatusRecord] {
        load(fileURL: fileURL)?
            .activeSessions(currentDate: currentDate, isBridgeProcessRunning: isBridgeProcessRunning) ?? []
    }

    public static func containsSession(
        scope: String,
        bridgePID: Int32,
        fileURL: URL = defaultFileURL,
        currentDate: Date = Date()
    ) -> Bool {
        guard let snapshot = load(fileURL: fileURL), snapshot.bridgePID == bridgePID else {
            return false
        }
        return snapshot
            .activeSessions(currentDate: currentDate) { $0 == bridgePID }
            .contains { $0.scope == scope }
    }

    public static func upsertSession(
        scope: String,
        expiresAt: Date,
        bridgePID: Int32,
        fileURL: URL = defaultFileURL,
        now: Date = Date(),
        workingDirectory: String? = nil,
        origin: BridgeSessionOrigin? = nil
    ) throws {
        let existing = load(fileURL: fileURL)
        let existingSessions = existing?.bridgePID == bridgePID ? existing?.sessions ?? [] : []
        let retained = existingSessions.filter { $0.scope != scope && $0.expiresAt > now }
        let snapshot = BridgeSessionStatusSnapshot(
            bridgePID: bridgePID,
            sessions: retained + [
                BridgeSessionStatusRecord(
                    scope: scope,
                    expiresAt: expiresAt,
                    workingDirectory: workingDirectory,
                    origin: origin
                ),
            ],
            updatedAt: now
        )
        try save(snapshot, fileURL: fileURL)
    }

    @discardableResult
    public static func clearSessionScope(_ scope: String, fileURL: URL = defaultFileURL) -> Bool {
        guard let snapshot = load(fileURL: fileURL) else {
            return false
        }

        let remainingSessions = snapshot.sessions.filter { $0.scope != scope }
        guard remainingSessions.count != snapshot.sessions.count else {
            return false
        }

        guard !remainingSessions.isEmpty else {
            clear(fileURL: fileURL)
            return true
        }

        let updated = BridgeSessionStatusSnapshot(
            bridgePID: snapshot.bridgePID,
            sessions: remainingSessions,
            updatedAt: Date()
        )
        try? save(updated, fileURL: fileURL)
        return true
    }

    private static func processIsRunning(pid: Int32) -> Bool {
        guard pid > 0 else { return false }
        return kill(pid, 0) == 0 || errno == EPERM
    }
}
