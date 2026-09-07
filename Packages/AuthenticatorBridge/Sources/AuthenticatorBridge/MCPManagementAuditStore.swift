#if os(macOS)
import Foundation

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

    public init(
        schemaVersion: Int = 1,
        id: UUID = UUID(),
        operationID: UUID,
        kind: String,
        phase: String,
        actorClass: String = "native",
        recordedAt: Date = Date(),
        summary: String,
        result: String
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
    }
}

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
    func record(_ event: MCPManagementAuditEvent) throws
}

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

    public init(fileURL: URL = MCPManagementAuditStore.defaultFileURL, fileManager: FileManager = .default) {
        self.fileURL = fileURL
        self.fileManager = fileManager
    }

    public func record(_ event: MCPManagementAuditEvent) throws {
        var line = try JSONEncoder.agentCommandHistoryLine.encode(event)
        line.append(0x0A)
        try lock.withLock {
            let directory = fileURL.deletingLastPathComponent()
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            if !fileManager.fileExists(atPath: fileURL.path) {
                fileManager.createFile(atPath: fileURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
            }
            let handle = try FileHandle(forWritingTo: fileURL)
            defer { try? handle.close() }
            try handle.seekToEnd()
            try handle.write(contentsOf: line)
        }
    }

    public func load() throws -> [MCPManagementAuditEvent] {
        guard fileManager.fileExists(atPath: fileURL.path) else { return [] }
        let data = try Data(contentsOf: fileURL)
        return try data.split(separator: 0x0A, omittingEmptySubsequences: true).map {
            try JSONDecoder.agentCommandHistory.decode(MCPManagementAuditEvent.self, from: Data($0))
        }
    }
}
#endif
