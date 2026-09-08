import Foundation

/// Metadata captured from the selected registry/grant, never from the preview text.
public struct MCPManagementActivityContext: Codable, Equatable, Sendable {
    public let identity: MCPServerIdentity
    public let client: String?
    public let transport: MCPUpstreamTransport?
    public init(identity: MCPServerIdentity, client: String? = nil, transport: MCPUpstreamTransport? = nil) {
        self.identity = identity; self.client = client; self.transport = transport
    }
}

public struct MCPManagementAuditEvent: Codable, Equatable, Sendable, Identifiable {
    public let schemaVersion: Int
    public let id: UUID
    public let operationID: UUID
    public let kind: String
    public let phase: String
    public let actorClass: String
    public let recordedAt: Date
    public let summary: String
    public let result: String
    public let context: MCPManagementActivityContext?

    public init(
        schemaVersion: Int = 1,
        id: UUID = UUID(),
        operationID: UUID,
        kind: String,
        phase: String,
        actorClass: String = "native",
        recordedAt: Date = Date(),
        summary: String,
        result: String,
        context: MCPManagementActivityContext? = nil
    ) {
        self.schemaVersion = schemaVersion
        self.id = id
        self.operationID = operationID
        self.kind = kind
        self.phase = phase
        self.actorClass = actorClass
        self.recordedAt = recordedAt
        self.summary = AgentCommandRedactor.sanitized(summary, maxLength: 4_000) ?? ""
        self.result = result
        self.context = context
    }
}

#if os(macOS)
import Darwin

public struct MCPAuditStatusView: Codable, Equatable, Sendable {
    public let verificationState: String
    public let completeness: String
    public let checkedAt: Date
    public let message: String

    public static func commandHistory(_ page: MCPActivityPage, now: Date = Date()) -> MCPAuditStatusView {
        MCPAuditStatusView(
            verificationState: page.sourceHealth == .ok || page.sourceHealth == .truncated ? "unverified" : "unavailable",
            completeness: page.completeness,
            checkedAt: now,
            message: "This summary reports command-history completeness. It does not claim HMAC verification of another audit log."
        )
    }
}

public protocol MCPManagementAuditing: AnyObject, Sendable {
    func record(_ event: MCPManagementAuditEvent) async throws
}

public struct MCPManagementAuditSnapshot: Sendable {
    public let events: [MCPManagementAuditEvent]
    public let retentionLimited: Bool
}

/// Bounded rolling activity projection. The Bridge audit chain is the canonical
/// evidence; this journal is never presented as independently verified.
public final class MCPManagementAuditStore: MCPManagementAuditing, @unchecked Sendable {
    public static var defaultFileURL: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return base.appendingPathComponent("Authsia", isDirectory: true)
            .appendingPathComponent("mcp-manager-audit.jsonl")
    }

    private let fileURL: URL
    private let fileManager: FileManager
    private let lock = NSLock()
    private let maximumBytes: Int
    private let maximumEvents: Int
    private let retentionInterval: TimeInterval
    private let clock: @Sendable () -> Date
    private struct Header: Codable {
        let journalVersion: Int
        let retentionLimited: Bool
    }

    public init(fileURL: URL = MCPManagementAuditStore.defaultFileURL, fileManager: FileManager = .default,
                maximumBytes: Int = 1_048_576, maximumEvents: Int = 2_000,
                retentionInterval: TimeInterval = 30 * 24 * 60 * 60,
                clock: @escaping @Sendable () -> Date = Date.init) {
        self.fileURL = fileURL
        self.fileManager = fileManager
        self.maximumBytes = max(1_024, min(maximumBytes, 1_048_576))
        self.maximumEvents = max(1, min(maximumEvents, 2_000))
        self.retentionInterval = max(1, retentionInterval)
        self.clock = clock
    }

    public func record(_ event: MCPManagementAuditEvent) throws {
        try lock.withLock {
            let directory = fileURL.deletingLastPathComponent()
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            // Separate descriptors also serialize distinct store instances and
            // Bridge processes. The wait is bounded so failed logging fails closed.
            let fd = open(fileURL.appendingPathExtension("lock").path, O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
            guard fd >= 0 else { throw MCPManagementError.auditUnavailable }
            defer { _ = flock(fd, LOCK_UN); close(fd) }
            let deadline = ProcessInfo.processInfo.systemUptime + 2
            while flock(fd, LOCK_EX | LOCK_NB) != 0 {
                guard errno == EWOULDBLOCK, ProcessInfo.processInfo.systemUptime < deadline else {
                    throw MCPManagementError.auditUnavailable
                }
                usleep(1_000)
            }
            let snapshot = try loadSnapshot()
            let encoder = JSONEncoder.agentCommandHistoryLine
            let incoming = try encoder.encode(event)
            guard incoming.count + 128 < maximumBytes else { throw MCPManagementError.auditUnavailable }
            var events = snapshot.events
            // A repeated IPC acknowledgement can repeat an event; keep one copy.
            if !events.contains(where: { $0.id == event.id }) { events.append(event) }
            var limited = snapshot.retentionLimited
            var lines: [Data] = [], size = 128
            for entry in events.reversed() {
                let line = try encoder.encode(entry)
                guard lines.count < maximumEvents, size + line.count + 1 <= maximumBytes else {
                    limited = true; break
                }
                lines.append(line); size += line.count + 1
            }
            var data = try encoder.encode(Header(journalVersion: 1, retentionLimited: limited))
            data.append(0x0A)
            for line in lines.reversed() { data.append(line); data.append(0x0A) }
            // Atomic rollover keeps readers on a complete bounded snapshot.
            try data.write(to: fileURL, options: .atomic)
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
            let handle = try FileHandle(forWritingTo: fileURL)
            defer { try? handle.close() }
            try handle.synchronize()
        }
    }

    public func load() throws -> [MCPManagementAuditEvent] {
        try loadSnapshot().events
    }

    public func loadSnapshot() throws -> MCPManagementAuditSnapshot {
        guard fileManager.fileExists(atPath: fileURL.path) else { return .init(events: [], retentionLimited: false) }
        let handle = try FileHandle(forReadingFrom: fileURL)
        defer { try? handle.close() }
        let end = try handle.seekToEnd()
        let offset = end > UInt64(maximumBytes) ? end - UInt64(maximumBytes) : 0
        try handle.seek(toOffset: offset)
        var data = try handle.read(upToCount: maximumBytes) ?? Data()
        var limited = offset > 0
        if offset > 0 {
            // Legacy oversized files are read from a bounded tail. Never decode
            // a partial first row as an event or allocate the entire old file.
            guard let newline = data.firstIndex(of: 0x0A) else { throw MCPManagementError.auditUnavailable }
            data = Data(data.suffix(from: data.index(after: newline)))
        }
        guard data.isEmpty || data.last == 0x0A else { throw MCPManagementError.auditUnavailable }
        var events: [MCPManagementAuditEvent] = []
        let cutoff = clock().addingTimeInterval(-retentionInterval)
        for (index, line) in data.split(separator: 0x0A, omittingEmptySubsequences: true).enumerated() {
            if index == 0, let header = try? JSONDecoder().decode(Header.self, from: Data(line)) {
                guard header.journalVersion == 1 else { throw MCPManagementError.auditUnavailable }
                limited = limited || header.retentionLimited
                continue
            }
            let event = try JSONDecoder.agentCommandHistory.decode(MCPManagementAuditEvent.self, from: Data(line))
            if event.recordedAt < cutoff { limited = true; continue }
            events.append(event)
        }
        if events.count > maximumEvents { limited = true; events = Array(events.suffix(maximumEvents)) }
        return .init(events: events, retentionLimited: limited)
    }
}
#endif
