import Darwin
import Foundation

public enum AgentFileActivityKind: String, Codable, CaseIterable, Equatable, Sendable {
    case file
    case directory
    case unknown
}

public enum AgentFileActivityAction: String, Codable, CaseIterable, Equatable, Sendable {
    case read
    case list
    case search
    case create
    case modify
    case delete
    case execute
}

public enum AgentFileActivityStatus: String, Codable, CaseIterable, Equatable, Sendable {
    case requested
    case succeeded
    case failed
    case denied
    case inferred
}

public enum AgentFileActivitySource: String, Codable, CaseIterable, Equatable, Sendable {
    case hook
    case workspaceDiff
}

public enum AgentFileActivityConfidence: String, Codable, CaseIterable, Equatable, Sendable {
    case direct
    case confirmed
    case inferred
    case fallback
}

public struct AgentFileActivityEvent: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let recordedAt: Date
    public let agentPlatform: String?
    public let sessionID: String?
    public let turnID: String?
    public let agentID: String?
    public let agentType: String?
    public let toolUseID: String?
    public let agentJITGrantID: UUID?
    public let captureSource: AgentFileActivitySource
    public let workingDirectory: String?
    public let terminalSessionScope: String?
    public let workspaceRoot: String?
    public let path: String
    public let workspaceRelativePath: String?
    public let kind: AgentFileActivityKind
    public let action: AgentFileActivityAction
    public let status: AgentFileActivityStatus
    public let confidence: AgentFileActivityConfidence
    public let detail: String?

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
        captureSource: AgentFileActivitySource,
        workingDirectory: String? = nil,
        terminalSessionScope: String? = nil,
        workspaceRoot: String? = nil,
        path: String,
        kind: AgentFileActivityKind,
        action: AgentFileActivityAction,
        status: AgentFileActivityStatus,
        confidence: AgentFileActivityConfidence,
        detail: String? = nil
    ) {
        let sanitizedPath = AgentFileActivitySanitizer.sanitized(path, maxLength: 4096) ?? ""
        let sanitizedWorkspaceRoot = AgentFileActivitySanitizer.sanitized(workspaceRoot, maxLength: 4096)

        self.id = id
        self.recordedAt = recordedAt
        self.agentPlatform = AgentFileActivitySanitizer.sanitized(agentPlatform)
        self.sessionID = AgentFileActivitySanitizer.sanitized(sessionID)
        self.turnID = AgentFileActivitySanitizer.sanitized(turnID)
        self.agentID = AgentFileActivitySanitizer.sanitized(agentID)
        self.agentType = AgentFileActivitySanitizer.sanitized(agentType)
        self.toolUseID = AgentFileActivitySanitizer.sanitized(toolUseID)
        self.agentJITGrantID = agentJITGrantID
        self.captureSource = captureSource
        self.workingDirectory = AgentFileActivitySanitizer.sanitized(workingDirectory, maxLength: 4096)
        self.terminalSessionScope = AgentFileActivitySanitizer.sanitized(terminalSessionScope, maxLength: 1024)
        self.workspaceRoot = sanitizedWorkspaceRoot
        self.path = sanitizedPath
        self.workspaceRelativePath = Self.relativePath(for: sanitizedPath, workspaceRoot: sanitizedWorkspaceRoot)
        self.kind = kind
        self.action = action
        self.status = status
        self.confidence = confidence
        self.detail = AgentFileActivitySanitizer.sanitized(detail, maxLength: 2048)
    }

    private static func relativePath(for path: String, workspaceRoot: String?) -> String? {
        guard let workspaceRoot else { return nil }

        let pathComponents = URL(fileURLWithPath: path).standardizedFileURL.pathComponents
        let rootComponents = URL(fileURLWithPath: workspaceRoot).standardizedFileURL.pathComponents
        guard pathComponents.count >= rootComponents.count else { return nil }
        guard Array(pathComponents.prefix(rootComponents.count)) == rootComponents else { return nil }

        let relativeComponents = pathComponents.dropFirst(rootComponents.count)
        guard !relativeComponents.isEmpty else { return "." }
        return relativeComponents.joined(separator: "/")
    }
}

public enum AgentFileActivityQuery {
    public static func events(for grant: AgentJITGrant, from events: [AgentFileActivityEvent]) -> [AgentFileActivityEvent] {
        events
            .filter { event in
                event.agentJITGrantID == grant.id
                    || matchesRuntimeContext(event: event, grant: grant)
                    || matchesTerminalScope(event: event, grant: grant)
            }
            .sorted { $0.recordedAt < $1.recordedAt }
    }

    private static func matchesRuntimeContext(event: AgentFileActivityEvent, grant: AgentJITGrant) -> Bool {
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

    private static func matchesTerminalScope(event: AgentFileActivityEvent, grant: AgentJITGrant) -> Bool {
        guard event.captureSource == .workspaceDiff else { return false }
        guard let eventScope = normalized(event.terminalSessionScope),
              let grantScope = normalized(grant.callerFingerprint.sessionScope),
              eventScope == grantScope else {
            return false
        }
        guard let eventWorkingDirectory = normalizedPath(event.workingDirectory),
              let grantWorkingDirectory = normalizedPath(grant.callerFingerprint.workingDirectory),
              eventWorkingDirectory == grantWorkingDirectory else {
            return false
        }
        return true
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

public final class AgentFileActivityStore {
    private static let directoryPermissions: NSNumber = 0o700
    private static let filePermissions: NSNumber = 0o600
    private static let filePermissionsMode: mode_t = S_IRUSR | S_IWUSR
    private static let mutationLock = NSLock()

    public static var defaultFileURL: URL {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first ?? FileManager.default.temporaryDirectory
        return base
            .appendingPathComponent("Authsia", isDirectory: true)
            .appendingPathComponent("agent-file-activity.jsonl")
    }

    private let fileURL: URL
    private let fileManager: FileManager

    public init(fileURL: URL = AgentFileActivityStore.defaultFileURL, fileManager: FileManager = .default) {
        self.fileURL = fileURL
        self.fileManager = fileManager
    }

    public func record(_ event: AgentFileActivityEvent) throws {
        var line = try JSONEncoder.agentFileActivityLine.encode(event)
        line.append(0x0A)

        try Self.mutationLock.withLock {
            try withFileLock(operation: LOCK_EX) {
                try appendLineUnlocked(line)
            }
        }
    }

    public func loadAll() throws -> [AgentFileActivityEvent] {
        try Self.mutationLock.withLock {
            try withFileLock(operation: LOCK_SH) {
                try loadAllUnlocked()
            }
        }
    }

    public func events(for grant: AgentJITGrant) throws -> [AgentFileActivityEvent] {
        try AgentFileActivityQuery.events(for: grant, from: loadAll())
    }

    public func exportJSON(_ events: [AgentFileActivityEvent]) throws -> Data {
        try JSONEncoder.agentFileActivity.encode(
            events
                .sorted { $0.recordedAt < $1.recordedAt }
                .map(AgentFileActivityExportEvent.init(event:))
        )
    }

    private func loadAllUnlocked() throws -> [AgentFileActivityEvent] {
        guard fileManager.fileExists(atPath: fileURL.path) else { return [] }
        try enforceFilePermissions()
        let data = try Data(contentsOf: fileURL)
        let events = try data.split(separator: 0x0A)
            .map { try JSONDecoder.agentFileActivity.decode(AgentFileActivityEvent.self, from: Data($0)) }
            .sorted { $0.recordedAt < $1.recordedAt }
        return Self.mergedHookEvents(events)
            .sorted { $0.recordedAt < $1.recordedAt }
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

    private static func mergedHookEvents(_ events: [AgentFileActivityEvent]) -> [AgentFileActivityEvent] {
        var mergedByKey: [String: AgentFileActivityEvent] = [:]
        var unkeyedEvents: [AgentFileActivityEvent] = []

        for event in events {
            guard let key = event.mergeKey else {
                unkeyedEvents.append(event)
                continue
            }
            mergedByKey[key] = event
        }

        return unkeyedEvents + mergedByKey.values
    }
}

private extension AgentFileActivityEvent {
    var mergeKey: String? {
        guard captureSource == .hook, let toolUseID else { return nil }
        return [
            agentPlatform ?? "",
            sessionID ?? "",
            turnID ?? "",
            agentID ?? "",
            agentType ?? "",
            terminalSessionScope ?? "",
            workingDirectory ?? "",
            toolUseID,
            action.rawValue,
            path,
        ].joined(separator: "\u{1f}")
    }
}

public struct AgentFileActivityExportEvent: Codable, Equatable, Sendable {
    public let id: UUID
    public let recordedAt: Date
    public let agentPlatform: String?
    public let sessionID: String?
    public let turnID: String?
    public let agentID: String?
    public let agentType: String?
    public let toolUseID: String?
    public let agentJITGrantID: UUID?
    public let captureSource: AgentFileActivitySource
    public let workingDirectory: String?
    public let terminalSessionScope: String?
    public let workspaceRoot: String?
    public let path: String?
    public let workspaceRelativePath: String?
    public let kind: AgentFileActivityKind
    public let action: AgentFileActivityAction
    public let status: AgentFileActivityStatus
    public let confidence: AgentFileActivityConfidence
    public let detail: String?

    public init(event: AgentFileActivityEvent) {
        let hasWorkspaceRelativePath = event.workspaceRelativePath != nil
        self.id = event.id
        self.recordedAt = event.recordedAt
        self.agentPlatform = event.agentPlatform
        self.sessionID = event.sessionID
        self.turnID = event.turnID
        self.agentID = event.agentID
        self.agentType = event.agentType
        self.toolUseID = event.toolUseID
        self.agentJITGrantID = event.agentJITGrantID
        self.captureSource = event.captureSource
        self.workingDirectory = hasWorkspaceRelativePath ? nil : event.workingDirectory
        self.terminalSessionScope = event.terminalSessionScope
        self.workspaceRoot = hasWorkspaceRelativePath ? nil : event.workspaceRoot
        self.path = hasWorkspaceRelativePath ? nil : event.path
        self.workspaceRelativePath = event.workspaceRelativePath
        self.kind = event.kind
        self.action = event.action
        self.status = event.status
        self.confidence = event.confidence
        self.detail = event.detail
    }
}

public extension JSONEncoder {
    static var agentFileActivity: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }

    static var agentFileActivityLine: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = .sortedKeys
        return encoder
    }
}

public extension JSONDecoder {
    static var agentFileActivity: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}

private enum AgentFileActivitySanitizer {
    static func sanitized(_ value: String?, maxLength: Int = 512) -> String? {
        guard let value else { return nil }
        return sanitized(value, maxLength: maxLength)
    }

    static func sanitized(_ value: String, maxLength: Int = 512) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let filtered = String(trimmed.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) })
        guard !filtered.isEmpty else { return nil }
        return String(filtered.prefix(maxLength))
    }
}
