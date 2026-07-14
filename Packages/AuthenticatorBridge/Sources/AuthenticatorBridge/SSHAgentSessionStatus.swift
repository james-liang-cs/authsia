import Foundation

public struct SSHAgentSessionStatus: Equatable, Sendable {
    public static let inactive = SSHAgentSessionStatus(active: false, activeKeyCount: 0, expiresAt: nil)

    public let active: Bool
    public let activeKeyCount: Int
    public let expiresAt: Date?
    public let currentTerminal: Bool

    public init(active: Bool, activeKeyCount: Int, expiresAt: Date?, currentTerminal: Bool = true) {
        self.active = active
        self.activeKeyCount = activeKeyCount
        self.expiresAt = expiresAt
        self.currentTerminal = currentTerminal
    }
}

public struct SSHAgentSessionRecord: Codable, Equatable, Sendable {
    public let scope: String
    public let expiresAt: Date

    public init(scope: String, expiresAt: Date) {
        self.scope = scope
        self.expiresAt = expiresAt
    }
}

public struct SSHAgentSessionSnapshot: Codable, Equatable, Sendable {
    public let agentPID: Int32
    public let sessions: [SSHAgentSessionRecord]
    public let updatedAt: Date

    public init(agentPID: Int32, sessions: [SSHAgentSessionRecord], updatedAt: Date) {
        self.agentPID = agentPID
        self.sessions = sessions
        self.updatedAt = updatedAt
    }

    public func status(
        currentDate: Date = Date(),
        sessionScope: String?,
        isAgentProcessRunning: (Int32) -> Bool
    ) -> SSHAgentSessionStatus {
        guard isAgentProcessRunning(agentPID) else {
            return .inactive
        }
        guard let sessionScope else {
            return .inactive
        }

        let activeExpirations = sessions
            .filter { $0.scope == sessionScope && $0.expiresAt > currentDate }
            .map(\.expiresAt)
        guard let expiresAt = activeExpirations.max() else {
            return .inactive
        }

        return SSHAgentSessionStatus(
            active: true,
            activeKeyCount: activeExpirations.count,
            expiresAt: expiresAt,
            currentTerminal: true
        )
    }

    public func aggregateStatus(
        currentDate: Date = Date(),
        isAgentProcessRunning: (Int32) -> Bool
    ) -> SSHAgentSessionStatus {
        guard isAgentProcessRunning(agentPID) else {
            return .inactive
        }

        let activeExpirations = sessions
            .filter { $0.expiresAt > currentDate }
            .map(\.expiresAt)
        guard let expiresAt = activeExpirations.max() else {
            return .inactive
        }

        return SSHAgentSessionStatus(
            active: true,
            activeKeyCount: activeExpirations.count,
            expiresAt: expiresAt,
            currentTerminal: false
        )
    }
}

public enum SSHAgentSessionStatusStore {
    public static var defaultFileURL: URL {
        #if os(macOS)
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".authsia", isDirectory: true)
            .appendingPathComponent("ssh-agent-session.json")
        #else
        FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia", isDirectory: true)
            .appendingPathComponent("ssh-agent-session.json")
        #endif
    }

    public static func load(fileURL: URL = defaultFileURL) -> SSHAgentSessionSnapshot? {
        guard let data = try? Data(contentsOf: fileURL), !data.isEmpty else {
            return nil
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(SSHAgentSessionSnapshot.self, from: data)
    }

    public static func save(_ snapshot: SSHAgentSessionSnapshot, fileURL: URL = defaultFileURL) throws {
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

        let updated = SSHAgentSessionSnapshot(
            agentPID: snapshot.agentPID,
            sessions: remainingSessions,
            updatedAt: Date()
        )
        try? save(updated, fileURL: fileURL)
        return true
    }
}
