import Foundation

public enum AgentCommandCaptureSource: String, Codable, Equatable, Sendable {
    case hook
    case process
    case injectedTree
    case mcpProxy
}

public enum MCPProxyCallOutcome: String, Codable, Equatable, Sendable {
    case started
    case succeeded
    case mcpError
    case timedOut
    case cancelled
    case upstreamUnavailable
    case denied
    case busy

    public var displayLabel: String {
        switch self {
        case .started:
            return "Outcome pending"
        case .succeeded:
            return "Succeeded"
        case .mcpError:
            return "MCP error"
        case .timedOut:
            return "Timed out"
        case .cancelled:
            return "Cancelled"
        case .upstreamUnavailable:
            return "Upstream unavailable"
        case .denied:
            return "Denied"
        case .busy:
            return "Busy"
        }
    }
}

public struct AgentCommandEvent: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let recordedAt: Date
    public let agentPlatform: String?
    public let sessionID: String?
    public let turnID: String?
    public let agentID: String?
    public let agentType: String?
    public let toolUseID: String?
    public let agentJITGrantID: UUID?
    public let captureSource: AgentCommandCaptureSource
    public let contextExpiresAt: Date?
    public let workingDirectory: String?
    public let terminalSessionScope: String?
    public let processIdentifier: String?
    public let executable: String?
    public let arguments: [String]
    public let command: String?
    public let exitStatus: Int32?
    public let mcpProxyOutcome: MCPProxyCallOutcome?
    public let responseOutcome: AgentLeakResponseOutcome?
    public let responseEvidence: AgentLeakEvidence?
    public let responsePreventedAction: Bool?

    public init(
        id: UUID = UUID(),
        recordedAt: Date,
        agentPlatform: String?,
        sessionID: String? = nil,
        turnID: String? = nil,
        agentID: String? = nil,
        agentType: String? = nil,
        toolUseID: String? = nil,
        agentJITGrantID: UUID? = nil,
        captureSource: AgentCommandCaptureSource,
        contextExpiresAt: Date? = nil,
        workingDirectory: String? = nil,
        terminalSessionScope: String? = nil,
        processIdentifier: String? = nil,
        executable: String? = nil,
        arguments: [String] = [],
        command: String? = nil,
        exitStatus: Int32? = nil,
        mcpProxyOutcome: MCPProxyCallOutcome? = nil,
        responseOutcome: AgentLeakResponseOutcome? = nil,
        responseEvidence: AgentLeakEvidence? = nil,
        responsePreventedAction: Bool? = nil
    ) {
        self.id = id
        self.recordedAt = recordedAt
        self.agentPlatform = AgentCommandRedactor.sanitized(agentPlatform)
        self.sessionID = AgentCommandRedactor.sanitized(sessionID)
        self.turnID = AgentCommandRedactor.sanitized(turnID)
        self.agentID = AgentCommandRedactor.sanitized(agentID)
        self.agentType = AgentCommandRedactor.sanitized(agentType)
        self.toolUseID = AgentCommandRedactor.sanitized(toolUseID)
        self.agentJITGrantID = agentJITGrantID
        self.captureSource = captureSource
        self.contextExpiresAt = contextExpiresAt
        self.workingDirectory = AgentCommandRedactor.sanitized(workingDirectory, maxLength: 2048)
        self.terminalSessionScope = AgentCommandRedactor.sanitized(terminalSessionScope, maxLength: 1024)
        self.processIdentifier = AgentCommandRedactor.sanitized(processIdentifier, maxLength: 128)
        self.executable = AgentCommandRedactor.sanitized(executable, maxLength: 1024)
        self.arguments = AgentCommandRedactor.redactedArguments(arguments)
        self.command = AgentCommandRedactor.redactedCommand(command)
        self.exitStatus = exitStatus
        self.mcpProxyOutcome = mcpProxyOutcome
        self.responseOutcome = responseOutcome
        self.responseEvidence = responseEvidence
        self.responsePreventedAction = responsePreventedAction
    }
}

public enum AgentCommandHistoryQuery {
    public static func events(for grant: AgentJITGrant, from events: [AgentCommandEvent]) -> [AgentCommandEvent] {
        events
            .filter { event in
                event.agentJITGrantID == grant.id
                    || matchesRuntimeContext(event: event, grant: grant)
                    || matchesTerminalScope(event: event, grant: grant)
            }
            .sorted { $0.recordedAt < $1.recordedAt }
    }

    /// Access Center process-fallback polls must not append another Commands row
    /// for a still-running process that already has the same grant, terminal
    /// scope, working directory, executable, and command.
    public static func unrecordedProcessEvents(
        from liveEvents: [AgentCommandEvent],
        alreadyStored storedEvents: [AgentCommandEvent]
    ) -> [AgentCommandEvent] {
        let storedKeys = Set(
            storedEvents
                .filter { $0.captureSource == .process }
                .compactMap(\.mergeKey)
        )
        return liveEvents.filter { event in
            guard event.captureSource == .process else { return true }
            guard let key = event.mergeKey else { return true }
            return !storedKeys.contains(key)
        }
    }

    private static func matchesRuntimeContext(event: AgentCommandEvent, grant: AgentJITGrant) -> Bool {
        guard let context = grant.agentRuntimeContext else { return false }
        guard let eventPlatform = normalizedPlatform(event.agentPlatform),
              let contextPlatform = normalizedPlatform(context.platform),
              eventPlatform == contextPlatform else {
            return false
        }

        let comparisons = [
            (event.sessionID, context.sessionID),
            (event.turnID, context.turnID),
            (event.agentID, context.agentID),
            (event.toolUseID, context.toolUseID),
        ]
        var hasMatchingIdentifier = false
        for (lhs, rhs) in comparisons {
            guard let lhs = normalized(lhs), let rhs = normalized(rhs) else { continue }
            guard lhs == rhs else { return false }
            hasMatchingIdentifier = true
        }
        return hasMatchingIdentifier
    }

    private static func matchesTerminalScope(event: AgentCommandEvent, grant: AgentJITGrant) -> Bool {
        guard event.captureSource == .process else { return false }
        guard AgentGrantActivityAttribution.matchesAgentPlatform(
            event.agentPlatform,
            grant: grant
        ) else {
            return false
        }
        guard let eventScope = normalized(event.terminalSessionScope),
              let grantScope = normalized(grant.callerFingerprint.sessionScope),
              eventScope == grantScope else {
            return false
        }
        guard let eventWorkingDirectory = normalizedPath(event.workingDirectory),
              let grantWorkingDirectory = normalizedPath(grant.callerFingerprint.workingDirectory) else {
            return true
        }
        return WorkspaceAuthority.matchesWorkingDirectory(
            eventWorkingDirectory,
            authorityPath: grantWorkingDirectory
        )
    }

    private static func normalizedPlatform(_ value: String?) -> String? {
        switch normalized(value)?.lowercased() {
        case "claude", "claude-code":
            return "claude-code"
        case "codex":
            return "codex"
        case let value?:
            return value
        case nil:
            return nil
        }
    }

    private static func normalizedPath(_ value: String?) -> String? {
        guard let value = normalized(value) else { return nil }
        return URL(fileURLWithPath: value).standardizedFileURL.path
    }

    private static func normalized(_ value: String?) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}

enum AgentGrantActivityAttribution {
    static func matchesAgentPlatform(_ eventPlatform: String?, grant: AgentJITGrant) -> Bool {
        guard let eventPlatform = normalizedPlatform(eventPlatform) else {
            return false
        }
        let grantPlatforms = [
            grant.agentRuntimeContext?.platform,
            AgenticProcessDetector.agentPlatform(
                processName: grant.callerFingerprint.parentProcessName,
                bundleIdentifier: grant.callerFingerprint.parentBundleIdentifier
            ),
            grant.agentName,
        ]
        return grantPlatforms.compactMap(normalizedPlatform).contains(eventPlatform)
    }

    private static func normalizedPlatform(_ value: String?) -> String? {
        switch value?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "claude", "claude code", "claude-code":
            return "claude-code"
        case "codex":
            return "codex"
        case let value? where !value.isEmpty:
            return value
        default:
            return nil
        }
    }
}

public final class AgentCommandHistoryStore {
    private static let directoryPermissions: NSNumber = 0o700
    private static let filePermissions: NSNumber = 0o600
    private static let filePermissionsMode: mode_t = S_IRUSR | S_IWUSR
    private static let mutationLock = NSLock()
    private static let compactionSizeThreshold: UInt64 = 128 * 1024 * 1024
    /// Aligns with Access Center's 30-day audit window.
    public static let defaultRetentionInterval: TimeInterval = 30 * 24 * 60 * 60
    /// Caps the materialized history returned to Access Center and retained by compaction.
    public static let defaultMaximumEventCount = 5_000

    public static var defaultFileURL: URL {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first ?? FileManager.default.temporaryDirectory
        return base
            .appendingPathComponent("Authsia", isDirectory: true)
            .appendingPathComponent("agent-command-history.jsonl")
    }

    private let fileURL: URL
    private let fileManager: FileManager
    private let retentionInterval: TimeInterval
    private let maximumEventCount: Int
    private let dataLoader: (URL) throws -> Data
    private let tailDataLoader: (URL, UInt64) throws -> Data
    private var historyCache: HistoryCache?

    private struct FileSnapshot: Equatable {
        let fileNumber: UInt64?
        let size: UInt64
        let modificationDate: Date?

        func isSameFile(as other: FileSnapshot) -> Bool {
            guard let fileNumber, let otherFileNumber = other.fileNumber else { return false }
            return fileNumber == otherFileNumber
        }
    }

    private struct HistoryCache {
        let snapshot: FileSnapshot
        let events: [AgentCommandEvent]
    }

    public init(
        fileURL: URL = AgentCommandHistoryStore.defaultFileURL,
        fileManager: FileManager = .default,
        retentionInterval: TimeInterval = AgentCommandHistoryStore.defaultRetentionInterval,
        maximumEventCount: Int = AgentCommandHistoryStore.defaultMaximumEventCount
    ) {
        self.fileURL = fileURL
        self.fileManager = fileManager
        self.retentionInterval = retentionInterval
        self.maximumEventCount = max(1, maximumEventCount)
        self.dataLoader = { try Data(contentsOf: $0) }
        self.tailDataLoader = Self.readData(from:offset:)
    }

    init(
        fileURL: URL,
        fileManager: FileManager = .default,
        retentionInterval: TimeInterval = AgentCommandHistoryStore.defaultRetentionInterval,
        maximumEventCount: Int = AgentCommandHistoryStore.defaultMaximumEventCount,
        dataLoader: @escaping (URL) throws -> Data,
        tailDataLoader: @escaping (URL, UInt64) throws -> Data
    ) {
        self.fileURL = fileURL
        self.fileManager = fileManager
        self.retentionInterval = retentionInterval
        self.maximumEventCount = max(1, maximumEventCount)
        self.dataLoader = dataLoader
        self.tailDataLoader = tailDataLoader
    }

    public func record(_ event: AgentCommandEvent) throws {
        var line = try JSONEncoder.agentCommandHistoryLine.encode(event)
        line.append(0x0A)

        try Self.mutationLock.withLock {
            try withFileLock(operation: LOCK_EX) {
                try appendLineUnlocked(line)
                if fileSnapshot()?.size ?? 0 > Self.compactionSizeThreshold {
                    try writeUnlocked(loadAllUnlocked())
                }
            }
        }
        #if os(macOS)
        AccessCenterActivityNotifier.post()
        #endif
    }

    public func loadAll() throws -> [AgentCommandEvent] {
        try Self.mutationLock.withLock {
            try withFileLock(operation: LOCK_SH) {
                try loadAllUnlocked()
            }
        }
    }

    public func events(for grant: AgentJITGrant) throws -> [AgentCommandEvent] {
        try AgentCommandHistoryQuery.events(for: grant, from: loadAll())
    }

    public func exportJSON(_ events: [AgentCommandEvent]) throws -> Data {
        try JSONEncoder.agentCommandHistory.encode(events.sorted { $0.recordedAt < $1.recordedAt })
    }

    public func exportJSON(events: [AgentCommandEvent], findings: [AgentCommandFinding]) throws -> Data {
        try JSONEncoder.agentCommandHistory.encode(
            AgentCommandHistoryExport(events: events, findings: findings)
        )
    }

    /// Drops events older than `retentionInterval` before the newest retained event,
    /// then caps at `maximumEventCount` (keeping the newest). Relative cutoff keeps
    /// fixture timestamps in tests stable while still bounding production history.
    static func pruned(
        _ events: [AgentCommandEvent],
        retentionInterval: TimeInterval,
        maximumEventCount: Int
    ) -> [AgentCommandEvent] {
        guard let newest = events.map(\.recordedAt).max() else { return events }
        let cutoff = newest.addingTimeInterval(-retentionInterval)
        var retained = events.filter { $0.recordedAt >= cutoff }
        if retained.count > maximumEventCount {
            retained = Array(retained.suffix(maximumEventCount))
        }
        return retained
    }

    private func loadAllUnlocked() throws -> [AgentCommandEvent] {
        guard fileManager.fileExists(atPath: fileURL.path) else {
            historyCache = nil
            return []
        }
        try enforceFilePermissions()
        guard let snapshot = fileSnapshot() else {
            historyCache = nil
            return try materializedEvents(from: dataLoader(fileURL))
        }

        if let historyCache, snapshot == historyCache.snapshot {
            return historyCache.events
        }

        if let historyCache,
           snapshot.isSameFile(as: historyCache.snapshot),
           snapshot.size > historyCache.snapshot.size {
            let appendedData = try tailDataLoader(fileURL, historyCache.snapshot.size)
            let appendedEvents = try decodedEvents(from: appendedData)
            let events = materializedEvents(historyCache.events + appendedEvents)
            self.historyCache = HistoryCache(snapshot: snapshot, events: events)
            return events
        }

        let events = try materializedEvents(from: dataLoader(fileURL))
        historyCache = HistoryCache(snapshot: snapshot, events: events)
        return events
    }

    private func materializedEvents(from data: Data) throws -> [AgentCommandEvent] {
        materializedEvents(try decodedEvents(from: data))
    }

    private func materializedEvents(_ events: [AgentCommandEvent]) -> [AgentCommandEvent] {
        var merged: [AgentCommandEvent] = []
        var indexesByMergeKey: [String: Int] = [:]
        for event in events {
            if let mergeKey = event.mergeKey, let index = indexesByMergeKey[mergeKey] {
                merged[index] = event
            } else {
                if let mergeKey = event.mergeKey {
                    indexesByMergeKey[mergeKey] = merged.count
                }
                merged.append(event)
            }
        }
        return Self.pruned(
            merged.sorted { $0.recordedAt < $1.recordedAt },
            retentionInterval: retentionInterval,
            maximumEventCount: maximumEventCount
        )
    }

    private func decodedEvents(from data: Data) throws -> [AgentCommandEvent] {
        try data.split(separator: 0x0A, omittingEmptySubsequences: true)
            .map { try JSONDecoder.agentCommandHistory.decode(AgentCommandEvent.self, from: Data($0)) }
    }

    private func appendLineUnlocked(_ line: Data) throws {
        try ensureDirectory()
        let fileDescriptor = open(fileURL.path, O_WRONLY | O_CREAT | O_APPEND, Self.filePermissionsMode)
        guard fileDescriptor >= 0 else {
            throw Self.posixError()
        }
        defer { close(fileDescriptor) }

        try Self.writeAll(line, to: fileDescriptor)
        try enforceFilePermissions()
    }

    private func writeUnlocked(_ events: [AgentCommandEvent]) throws {
        try ensureDirectory()
        var data = Data()
        for event in events {
            var line = try JSONEncoder.agentCommandHistoryLine.encode(event)
            line.append(0x0A)
            data.append(line)
        }
        try data.write(to: fileURL, options: .atomic)
        try enforceFilePermissions()
        if let snapshot = fileSnapshot() {
            historyCache = HistoryCache(snapshot: snapshot, events: events)
        } else {
            historyCache = nil
        }
    }

    private func withFileLock<T>(operation: Int32, _ body: () throws -> T) throws -> T {
        try ensureDirectory()
        let lockPath = fileURL.path + ".lock"
        let fileDescriptor = open(lockPath, O_RDWR | O_CREAT, Self.filePermissionsMode)
        guard fileDescriptor >= 0 else {
            throw Self.posixError()
        }
        defer { close(fileDescriptor) }
        try fileManager.setAttributes([.posixPermissions: Self.filePermissions], ofItemAtPath: lockPath)

        guard flock(fileDescriptor, operation) == 0 else {
            throw Self.posixError()
        }
        defer { flock(fileDescriptor, LOCK_UN) }
        return try body()
    }

    private func fileSnapshot() -> FileSnapshot? {
        guard let attributes = try? fileManager.attributesOfItem(atPath: fileURL.path),
              let size = (attributes[.size] as? NSNumber)?.uint64Value else {
            return nil
        }
        return FileSnapshot(
            fileNumber: (attributes[.systemFileNumber] as? NSNumber)?.uint64Value,
            size: size,
            modificationDate: attributes[.modificationDate] as? Date
        )
    }

    private static func readData(from fileURL: URL, offset: UInt64) throws -> Data {
        let handle = try FileHandle(forReadingFrom: fileURL)
        defer { try? handle.close() }
        try handle.seek(toOffset: offset)
        return try handle.readToEnd() ?? Data()
    }

    private static func writeAll(_ data: Data, to fileDescriptor: Int32) throws {
        try data.withUnsafeBytes { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            var offset = 0
            while offset < buffer.count {
                let written = write(fileDescriptor, baseAddress.advanced(by: offset), buffer.count - offset)
                if written < 0 {
                    if errno == EINTR { continue }
                    throw posixError()
                }
                guard written > 0 else { throw POSIXError(.EIO) }
                offset += written
            }
        }
    }

    private static func posixError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }

    private func ensureDirectory() throws {
        let directory = fileURL.deletingLastPathComponent()
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: Self.directoryPermissions]
        )
        try fileManager.setAttributes([.posixPermissions: Self.directoryPermissions], ofItemAtPath: directory.path)
    }

    private func enforceFilePermissions() throws {
        try fileManager.setAttributes([.posixPermissions: Self.filePermissions], ofItemAtPath: fileURL.path)
    }
}

private extension AgentCommandEvent {
    var mergeKey: String? {
        guard let command else {
            return nil
        }

        switch captureSource {
        case .hook:
            guard let platform = agentPlatform, let toolUseID else { return nil }
            return [platform, sessionID ?? "", toolUseID, command].joined(separator: "\u{1f}")
        case .process:
            guard let terminalSessionScope, let processIdentifier else { return nil }
            return [
                "process",
                agentJITGrantID?.uuidString ?? "",
                terminalSessionScope,
                processIdentifier,
                workingDirectory ?? "",
                executable ?? "",
                command,
            ].joined(separator: "\u{1f}")
        case .injectedTree:
            return [
                "injectedTree",
                agentJITGrantID?.uuidString ?? "",
                terminalSessionScope ?? "",
                workingDirectory ?? "",
                executable ?? "",
                command,
            ].joined(separator: "\u{1f}")
        case .mcpProxy:
            guard let toolUseID else { return nil }
            return [
                "mcpProxy",
                agentJITGrantID?.uuidString ?? "",
                toolUseID,
                executable ?? "",
                command,
            ].joined(separator: "\u{1f}")
        }
    }
}

public extension JSONEncoder {
    static var agentCommandHistory: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }

    static var agentCommandHistoryLine: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = .sortedKeys
        return encoder
    }
}

public extension JSONDecoder {
    static var agentCommandHistory: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}

enum AgentCommandRedactor {
    private static let sensitiveFragments = [
        "password",
        "passwd",
        "passphrase",
        "token",
        "secret",
        "private-key",
        "private_key",
        "api-key",
        "api_key",
        "apikey",
        "access-key",
        "access_key",
        "credential",
        "seed",
        "otp",
    ]

    static func sanitized(_ value: String?, maxLength: Int = 512) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let filtered = String(trimmed.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) })
        guard !filtered.isEmpty else { return nil }
        return String(filtered.prefix(maxLength))
    }

    static func redactedArguments(_ arguments: [String]) -> [String] {
        var redacted: [String] = []
        var redactNext = false
        for rawArgument in arguments {
            let argument = sanitized(rawArgument, maxLength: 4096) ?? ""
            if redactNext {
                redacted.append("[REDACTED]")
                redactNext = false
                continue
            }
            if let flagRedaction = redactedSensitiveFlagAssignment(argument) {
                redacted.append(flagRedaction)
                continue
            }
            if let assignmentRedaction = redactedSensitiveAssignment(argument) {
                redacted.append(assignmentRedaction)
                continue
            }
            redacted.append(argument)
            if isSensitiveFlag(argument) {
                redactNext = true
            }
        }
        return redacted
    }

    static func redactedCommand(_ command: String?) -> String? {
        guard let command = sanitized(command, maxLength: 8192) else { return nil }
        return redactedArguments(command.split(whereSeparator: \.isWhitespace).map(String.init)).joined(separator: " ")
    }

    private static func redactedSensitiveFlagAssignment(_ argument: String) -> String? {
        guard argument.hasPrefix("--"),
              let separatorIndex = argument.firstIndex(of: "=") else {
            return nil
        }
        let name = String(argument[..<separatorIndex])
        guard isSensitiveName(name) else { return nil }
        return "\(name)=[REDACTED]"
    }

    private static func redactedSensitiveAssignment(_ argument: String) -> String? {
        guard let separatorIndex = argument.firstIndex(of: "=") else { return nil }
        let name = String(argument[..<separatorIndex])
        guard isSensitiveName(name) else { return nil }
        return "\(name)=[REDACTED]"
    }

    private static func isSensitiveFlag(_ argument: String) -> Bool {
        guard argument.hasPrefix("--") else { return false }
        return isSensitiveName(argument)
    }

    private static func isSensitiveName(_ value: String) -> Bool {
        let normalized = value
            .trimmingCharacters(in: CharacterSet(charactersIn: "-_ "))
            .lowercased()
            .replacingOccurrences(of: "_", with: "-")
        return sensitiveFragments.contains { normalized.contains($0) }
    }
}
