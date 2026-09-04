import Foundation
import Darwin

/// Display-only sub-agent lifespan. Never an authorization input.
public struct AgentLineageRecord: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let kind: String
    public let platform: String?
    public let sessionID: String?
    public let agentID: String?
    public let agentType: String?
    public let workingDirectory: String?
    public let startedAt: Date?
    public let endedAt: Date?
    public let expiresAt: Date

    public init(
        id: UUID = UUID(),
        kind: String = AgentLineageRecord.subagentKind,
        platform: String? = nil,
        sessionID: String? = nil,
        agentID: String? = nil,
        agentType: String? = nil,
        workingDirectory: String? = nil,
        startedAt: Date? = nil,
        endedAt: Date? = nil,
        expiresAt: Date
    ) {
        self.id = id
        self.kind = AgentRuntimeContext.sanitize(kind) ?? AgentLineageRecord.subagentKind
        self.platform = AgentRuntimeContext.sanitize(platform)
        self.sessionID = AgentRuntimeContext.sanitize(sessionID)
        self.agentID = AgentRuntimeContext.sanitize(agentID)
        self.agentType = AgentRuntimeContext.sanitize(agentType)
        self.workingDirectory = AgentCommandRedactor.sanitized(workingDirectory, maxLength: 2048)
        self.startedAt = startedAt
        self.endedAt = endedAt
        self.expiresAt = expiresAt
    }

    public static let subagentKind = "subagent"

    var mergeKey: String? {
        guard let sessionID, let agentID else { return nil }
        return "\(sessionID)\u{1f}\(agentID)"
    }
}

public struct AgentSessionExportSummary: Codable, Equatable, Sendable {
    public let sessionID: String
    public let platform: String?
    public let grantCount: Int
    public let subAgentTypes: [String]

    public init(sessionID: String, platform: String?, grantCount: Int, subAgentTypes: [String]) {
        self.sessionID = sessionID
        self.platform = platform
        self.grantCount = grantCount
        self.subAgentTypes = subAgentTypes
    }
}

public enum AgentSessionGrouping {
    public static let allSelection = "all-sessions"

    public static func isMCPSession(_ context: AgentRuntimeContext?) -> Bool {
        AgentRuntimeContextAssociation.isMCPContext(
            agentType: context?.agentType,
            sessionID: context?.sessionID
        )
    }

    public static func codingSessionID(from context: AgentRuntimeContext?) -> String? {
        guard let sessionID = AgentRuntimeContext.sanitize(context?.sessionID) else { return nil }
        guard !isMCPSession(context) else { return nil }
        return sessionID
    }

    public static func codingSessionID(from grant: AgentJITGrant) -> String? {
        codingSessionID(from: grant.agentRuntimeContext)
    }

    public static func shouldShowSessionChrome(grants: [AgentJITGrant]) -> Bool {
        Set(grants.compactMap(codingSessionID(from:))).count > 1
    }

    public static func chips(from grants: [AgentJITGrant]) -> [(id: String, label: String)] {
        var seen = Set<String>()
        var chips: [(id: String, label: String)] = []
        for grant in grants {
            guard let sessionID = codingSessionID(from: grant), seen.insert(sessionID).inserted else {
                continue
            }
            let platform = AgentAttributionPresentation.platformDisplayName(
                grant.agentRuntimeContext?.platform
            ) ?? grant.agentName
            chips.append((
                id: sessionID,
                label: "\(platform) · \(AgentAttributionPresentation.shortSessionID(sessionID))"
            ))
        }
        return chips
    }

    public static func matches(grant: AgentJITGrant, selectedSessionID: String?) -> Bool {
        guard let selectedSessionID, selectedSessionID != allSelection else { return true }
        return codingSessionID(from: grant) == selectedSessionID
    }

    public static func groups(
        grants: [AgentJITGrant],
        lineage: [AgentLineageRecord]
    ) -> [(sessionID: String, header: String, grants: [AgentJITGrant])] {
        var order: [String] = []
        var buckets: [String: [AgentJITGrant]] = [:]
        for grant in grants {
            guard let sessionID = codingSessionID(from: grant) else { continue }
            if buckets[sessionID] == nil {
                order.append(sessionID)
                buckets[sessionID] = []
            }
            buckets[sessionID]?.append(grant)
        }
        return order.compactMap { sessionID in
            guard let grouped = buckets[sessionID], !grouped.isEmpty else { return nil }
            let platform = grouped.first.flatMap { $0.agentRuntimeContext?.platform }
            let types = subAgentTypes(sessionID: sessionID, grants: grouped, lineage: lineage)
            return (
                sessionID: sessionID,
                header: AgentAttributionPresentation.sessionGroupHeader(
                    platform: platform,
                    sessionID: sessionID,
                    grantCount: grouped.count,
                    subAgentCount: types.count
                ),
                grants: grouped
            )
        }
    }

    public static func exportSummaries(
        grants: [AgentJITGrant],
        events: [AgentCommandEvent],
        lineage: [AgentLineageRecord]
    ) -> [AgentSessionExportSummary] {
        var grantCounts: [String: Int] = [:]
        var platforms: [String: String] = [:]
        for grant in grants {
            guard let sessionID = codingSessionID(from: grant) else { continue }
            grantCounts[sessionID, default: 0] += 1
            if platforms[sessionID] == nil {
                platforms[sessionID] = grant.agentRuntimeContext?.platform
            }
        }
        for event in events {
            guard let sessionID = AgentRuntimeContext.sanitize(event.sessionID),
                  !sessionID.lowercased().hasPrefix("mcp:") else {
                continue
            }
            if platforms[sessionID] == nil {
                platforms[sessionID] = event.agentPlatform
            }
            grantCounts[sessionID] = grantCounts[sessionID] ?? 0
        }
        return grantCounts.keys.sorted().map { sessionID in
            AgentSessionExportSummary(
                sessionID: sessionID,
                platform: platforms[sessionID],
                grantCount: grantCounts[sessionID] ?? 0,
                subAgentTypes: subAgentTypes(
                    sessionID: sessionID,
                    grants: grants.filter { codingSessionID(from: $0) == sessionID },
                    events: events.filter { AgentRuntimeContext.sanitize($0.sessionID) == sessionID },
                    lineage: lineage.filter { $0.sessionID == sessionID }
                )
            )
        }
    }

    public static func records(
        matching context: AgentRuntimeContext?,
        from lineage: [AgentLineageRecord]
    ) -> [AgentLineageRecord] {
        guard let sessionID = AgentRuntimeContext.sanitize(context?.sessionID) else { return [] }
        let agentID = AgentRuntimeContext.sanitize(context?.agentID)
        return lineage.filter { record in
            record.sessionID == sessionID && (agentID == nil || record.agentID == agentID)
        }
    }

    private static func subAgentTypes(
        sessionID: String,
        grants: [AgentJITGrant],
        events: [AgentCommandEvent] = [],
        lineage: [AgentLineageRecord]
    ) -> [String] {
        var types = Set<String>()
        for grant in grants {
            if let type = AgentRuntimeContext.sanitize(grant.agentRuntimeContext?.agentType) {
                types.insert(type)
            }
        }
        for event in events {
            if let type = AgentRuntimeContext.sanitize(event.agentType) {
                types.insert(type)
            }
        }
        for record in lineage where record.sessionID == sessionID {
            if let type = record.agentType {
                types.insert(type)
            }
        }
        return types.sorted()
    }
}

public final class AgentLineageStore {
    public static let defaultTTL: TimeInterval = 24 * 60 * 60
    private static let directoryPermissions: NSNumber = 0o700
    private static let filePermissions: NSNumber = 0o600
    private static let filePermissionsMode: mode_t = S_IRUSR | S_IWUSR
    private static let mutationLock = NSLock()

    public static var defaultFileURL: URL {
        if let override = ProcessInfo.processInfo.environment["AUTHSIA_HOOK_LINEAGE_PATH"],
           !override.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return URL(fileURLWithPath: override)
        }
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first ?? FileManager.default.temporaryDirectory
        return base
            .appendingPathComponent("Authsia", isDirectory: true)
            .appendingPathComponent("AgentRuntimeContext", isDirectory: true)
            .appendingPathComponent("lineage.jsonl")
    }

    private let fileURL: URL
    private let fileManager: FileManager
    private let now: () -> Date

    public init(
        fileURL: URL = AgentLineageStore.defaultFileURL,
        fileManager: FileManager = .default,
        now: @escaping () -> Date = Date.init
    ) {
        self.fileURL = fileURL
        self.fileManager = fileManager
        self.now = now
    }

    public func record(_ incoming: AgentLineageRecord) throws {
        try Self.mutationLock.withLock {
            try withFileLock {
                var records = loadAllUnlocked()
                records.append(incoming)
                try writeUnlocked(Self.merged(records, now: now()))
            }
        }
        #if os(macOS)
        AccessCenterActivityNotifier.post()
        #endif
    }

    public func loadAll() throws -> [AgentLineageRecord] {
        try Self.mutationLock.withLock {
            try withFileLock {
                loadAllUnlocked()
            }
        }
    }

    static func merged(_ records: [AgentLineageRecord], now: Date) -> [AgentLineageRecord] {
        var merged: [AgentLineageRecord] = []
        var indexes: [String: Int] = [:]
        for record in records where record.expiresAt > now {
            guard record.kind == AgentLineageRecord.subagentKind else { continue }
            guard let key = record.mergeKey else {
                merged.append(record)
                continue
            }
            if let index = indexes[key] {
                merged[index] = combine(merged[index], record)
            } else {
                indexes[key] = merged.count
                merged.append(record)
            }
        }
        return merged.sorted { lhs, rhs in
            let lhsDate = lhs.startedAt ?? lhs.endedAt ?? lhs.expiresAt
            let rhsDate = rhs.startedAt ?? rhs.endedAt ?? rhs.expiresAt
            if lhsDate == rhsDate {
                return lhs.id.uuidString < rhs.id.uuidString
            }
            return lhsDate < rhsDate
        }
    }

    private static func combine(_ existing: AgentLineageRecord, _ incoming: AgentLineageRecord) -> AgentLineageRecord {
        let startedCandidates = [existing.startedAt, incoming.startedAt].compactMap { $0 }
        let endedCandidates = [existing.endedAt, incoming.endedAt].compactMap { $0 }
        return AgentLineageRecord(
            id: existing.id,
            kind: AgentLineageRecord.subagentKind,
            platform: incoming.platform ?? existing.platform,
            sessionID: existing.sessionID,
            agentID: existing.agentID,
            agentType: incoming.agentType ?? existing.agentType,
            workingDirectory: incoming.workingDirectory ?? existing.workingDirectory,
            startedAt: startedCandidates.min(),
            endedAt: endedCandidates.max(),
            expiresAt: max(existing.expiresAt, incoming.expiresAt)
        )
    }

    private func loadAllUnlocked() -> [AgentLineageRecord] {
        guard fileManager.fileExists(atPath: fileURL.path),
              let data = try? Data(contentsOf: fileURL) else {
            return []
        }
        let records = data.split(separator: 0x0A, omittingEmptySubsequences: true).compactMap { line -> AgentLineageRecord? in
            try? JSONDecoder.agentCommandHistory.decode(AgentLineageRecord.self, from: Data(line))
        }
        return Self.merged(records, now: now())
    }

    private func writeUnlocked(_ records: [AgentLineageRecord]) throws {
        try ensureDirectory()
        var data = Data()
        for record in records {
            var line = try JSONEncoder.agentCommandHistoryLine.encode(record)
            line.append(0x0A)
            data.append(line)
        }
        try data.write(to: fileURL, options: .atomic)
        try fileManager.setAttributes(
            [.posixPermissions: Self.filePermissions],
            ofItemAtPath: fileURL.path
        )
    }

    private func withFileLock<T>(_ body: () throws -> T) throws -> T {
        try ensureDirectory()
        let lockPath = fileURL.path + ".lock"
        let fileDescriptor = open(lockPath, O_RDWR | O_CREAT, Self.filePermissionsMode)
        guard fileDescriptor >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { close(fileDescriptor) }
        try fileManager.setAttributes([.posixPermissions: Self.filePermissions], ofItemAtPath: lockPath)
        guard flock(fileDescriptor, LOCK_EX) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        defer { flock(fileDescriptor, LOCK_UN) }
        return try body()
    }

    private func ensureDirectory() throws {
        let directory = fileURL.deletingLastPathComponent()
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: Self.directoryPermissions]
        )
        try fileManager.setAttributes(
            [.posixPermissions: Self.directoryPermissions],
            ofItemAtPath: directory.path
        )
    }
}
