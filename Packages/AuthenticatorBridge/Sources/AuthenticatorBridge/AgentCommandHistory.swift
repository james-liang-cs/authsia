import Foundation

public enum AgentCommandCaptureSource: String, Codable, Equatable, Sendable {
    case hook
    case process
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
    public let executable: String?
    public let arguments: [String]
    public let command: String?
    public let exitStatus: Int32?

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
        executable: String? = nil,
        arguments: [String] = [],
        command: String? = nil,
        exitStatus: Int32? = nil
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
        self.executable = AgentCommandRedactor.sanitized(executable, maxLength: 1024)
        self.arguments = AgentCommandRedactor.redactedArguments(arguments)
        self.command = AgentCommandRedactor.redactedCommand(command)
        self.exitStatus = exitStatus
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
        guard let eventScope = normalized(event.terminalSessionScope),
              let grantScope = normalized(grant.callerFingerprint.sessionScope),
              eventScope == grantScope else {
            return false
        }
        guard let eventWorkingDirectory = normalizedPath(event.workingDirectory),
              let grantWorkingDirectory = normalizedPath(grant.callerFingerprint.workingDirectory) else {
            return true
        }
        return eventWorkingDirectory == grantWorkingDirectory
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

public final class AgentCommandHistoryStore {
    private static let directoryPermissions: NSNumber = 0o700
    private static let filePermissions: NSNumber = 0o600
    private static let mutationLock = NSLock()

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

    public init(fileURL: URL = AgentCommandHistoryStore.defaultFileURL, fileManager: FileManager = .default) {
        self.fileURL = fileURL
        self.fileManager = fileManager
    }

    public func record(_ event: AgentCommandEvent) throws {
        try Self.mutationLock.withLock {
            var events = try loadAllUnlocked()
            if let index = events.firstIndex(where: { $0.mergeKey == event.mergeKey && event.mergeKey != nil }) {
                events[index] = event
            } else {
                events.append(event)
            }
            try writeUnlocked(events.sorted { $0.recordedAt < $1.recordedAt })
        }
    }

    public func loadAll() throws -> [AgentCommandEvent] {
        try Self.mutationLock.withLock {
            try loadAllUnlocked()
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

    private func loadAllUnlocked() throws -> [AgentCommandEvent] {
        guard fileManager.fileExists(atPath: fileURL.path) else { return [] }
        try enforceFilePermissions()
        let data = try Data(contentsOf: fileURL)
        return try data.split(separator: 0x0A)
            .map { try JSONDecoder.agentCommandHistory.decode(AgentCommandEvent.self, from: Data($0)) }
            .sorted { $0.recordedAt < $1.recordedAt }
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
            guard let terminalSessionScope else { return nil }
            return [
                "process",
                agentJITGrantID?.uuidString ?? "",
                terminalSessionScope,
                workingDirectory ?? "",
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

private enum AgentCommandRedactor {
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
