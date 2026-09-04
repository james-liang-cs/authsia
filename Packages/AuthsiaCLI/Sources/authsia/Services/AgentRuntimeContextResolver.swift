import Darwin
import Foundation
import AuthenticatorBridge

enum AgentRuntimeContextResolver {
    static let environmentPlatformKey = "AUTHSIA_AGENT_PLATFORM"
    static let environmentInvokesAuthsiaKey = "AUTHSIA_AGENT_INVOKES_AUTHSIA"
    static let environmentSessionIDKey = "AUTHSIA_AGENT_SESSION_ID"
    static let environmentTurnIDKey = "AUTHSIA_AGENT_TURN_ID"
    static let environmentAgentIDKey = "AUTHSIA_AGENT_ID"
    static let environmentAgentTypeKey = "AUTHSIA_AGENT_TYPE"
    static let environmentToolUseIDKey = "AUTHSIA_AGENT_TOOL_USE_ID"
    static let environmentHookContextPathKey = "AUTHSIA_HOOK_CONTEXT_PATH"
    static let attributionTTL: TimeInterval = 5 * 60

    private struct RecordsCache {
        let path: String
        let fileNumber: UInt64?
        let modificationEpochSecond: Int?
        let fileSize: Int
        let records: [AgentRuntimeContextRecord]
    }

    private final class RecordsCacheBox: @unchecked Sendable {
        let lock = NSLock()
        var caches: [String: RecordsCache] = [:]
    }

    private static let recordsCacheBox = RecordsCacheBox()

    static var defaultEventsURL: URL {
        AgentCommandHistoryStore.defaultFileURL
    }

    static var defaultHookContextURL: URL {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first ?? FileManager.default.temporaryDirectory
        return base
            .appendingPathComponent("Authsia", isDirectory: true)
            .appendingPathComponent("AgentRuntimeContext", isDirectory: true)
            .appendingPathComponent("events.jsonl")
    }

    static func resolve(
        now: Date = Date(),
        currentDirectoryPath: String = FileManager.default.currentDirectoryPath,
        processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry(),
        eventsURL: URL = defaultEventsURL,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        claimOwner: pid_t = getpid()
    ) -> AgentRuntimeContext? {
        if let explicitContext = explicitAgentRuntimeContext(environment: environment) {
            return explicitContext
        }

        let detectedPlatforms = detectedAgentPlatforms(in: processAncestry)
        guard !detectedPlatforms.isEmpty else { return nil }

        let candidates = attributionEventURLs(eventsURL: eventsURL, environment: environment)
            .flatMap { url in
                loadRecords(from: url).map { SourcedRecord(record: $0, sourceURL: url) }
            }
            .filter { now.timeIntervalSince($0.record.recordedAt) <= attributionTTL }
            .filter { workingDirectoryMatches($0.record.workingDirectory, currentDirectoryPath: currentDirectoryPath) }
            .filter { recordInvokesAuthsia($0.record) }
            .filter { platformMatches($0.record.platform, detectedPlatforms: detectedPlatforms) }
            .sorted { $0.record.recordedAt < $1.record.recordedAt }
        guard !candidates.isEmpty else { return nil }

        return selectContext(from: candidates, now: now, claimOwner: claimOwner)
    }

    static func hasExplicitAgentInvocationMarker(environment: [String: String]) -> Bool {
        explicitAgentRuntimeContext(environment: environment) != nil
    }

    static func explicitAgentSessionScope(
        environment: [String: String],
        processSessionIdentifier: Int32?
    ) -> String? {
        guard !SessionCache.hasAutomationCredential(in: environment),
              let processSessionIdentifier,
              processSessionIdentifier > 0,
              let platform = explicitAgentRuntimeContext(environment: environment)?.platform else {
            return nil
        }
        return "agent:\(platform):sid:\(processSessionIdentifier)"
    }

    private static func explicitAgentRuntimeContext(environment: [String: String]) -> AgentRuntimeContext? {
        guard isTruthy(environment[environmentInvokesAuthsiaKey]),
              let platform = normalizedPlatform(environment[environmentPlatformKey]) else {
            return nil
        }

        let context = AgentRuntimeContext(
            platform: platform,
            sessionID: environment[environmentSessionIDKey],
            turnID: environment[environmentTurnIDKey],
            agentID: environment[environmentAgentIDKey],
            agentType: environment[environmentAgentTypeKey],
            toolUseID: environment[environmentToolUseIDKey]
        )
        return context.isEmpty ? nil : context
    }

    private static func isTruthy(_ value: String?) -> Bool {
        switch value?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "1", "true", "yes", "y":
            return true
        default:
            return false
        }
    }

    static func loadRecords(from url: URL) -> [AgentRuntimeContextRecord] {
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        // Second granularity avoids false misses from filesystem timestamp rounding
        // after attribute round-trips, while still invalidating across real writes.
        let modificationEpochSecond = (attributes?[.modificationDate] as? Date)
            .map { Int($0.timeIntervalSince1970) }
        let fileNumber = (attributes?[.systemFileNumber] as? NSNumber)?.uint64Value
        let fileSize = attributes?[.size] as? Int ?? -1
        let path = url.path

        recordsCacheBox.lock.lock()
        if let cache = recordsCacheBox.caches[path] {
            if cache.modificationEpochSecond == modificationEpochSecond,
               cache.fileSize == fileSize {
                let cached = cache.records
                recordsCacheBox.lock.unlock()
                return cached
            }
            if let fileNumber,
               cache.fileNumber == fileNumber,
               fileSize > cache.fileSize {
                recordsCacheBox.lock.unlock()
                let appended = loadRecordsFromDisk(url: url, offset: UInt64(cache.fileSize))
                let records = cache.records + appended
                cacheRecords(
                    records,
                    path: path,
                    fileNumber: fileNumber,
                    modificationEpochSecond: modificationEpochSecond,
                    fileSize: fileSize
                )
                return records
            }
        }
        recordsCacheBox.lock.unlock()

        let records = loadRecordsFromDisk(url: url)
        cacheRecords(
            records,
            path: path,
            fileNumber: fileNumber,
            modificationEpochSecond: modificationEpochSecond,
            fileSize: fileSize
        )
        return records
    }

    private static func cacheRecords(
        _ records: [AgentRuntimeContextRecord],
        path: String,
        fileNumber: UInt64?,
        modificationEpochSecond: Int?,
        fileSize: Int
    ) {
        recordsCacheBox.lock.lock()
        recordsCacheBox.caches[path] = RecordsCache(
            path: path,
            fileNumber: fileNumber,
            modificationEpochSecond: modificationEpochSecond,
            fileSize: fileSize,
            records: records
        )
        // Bound process memory if many distinct temp paths appear in tests.
        if recordsCacheBox.caches.count > 32 {
            let overflow = recordsCacheBox.caches.count - 16
            for key in recordsCacheBox.caches.keys.prefix(overflow) {
                recordsCacheBox.caches.removeValue(forKey: key)
            }
        }
        recordsCacheBox.lock.unlock()
    }

    private static func loadRecordsFromDisk(url: URL, offset: UInt64 = 0) -> [AgentRuntimeContextRecord] {
        guard let data = try? readData(from: url, offset: offset) else {
            return []
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        // Byte-split: String.split(whereSeparator:) is grapheme-aware and dominates
        // latency on multi-megabyte history files (~300ms for 24MB).
        return data
            .split(separator: 0x0A, omittingEmptySubsequences: true)
            .compactMap { line in
                let lineData = Data(line)
                if let record = try? decoder.decode(AgentRuntimeContextRecord.self, from: lineData) {
                    return record
                }
                guard let event = try? decoder.decode(AgentCommandEvent.self, from: lineData) else {
                    return nil
                }
                return AgentRuntimeContextRecord(event: event)
            }
    }

    private static func readData(from url: URL, offset: UInt64) throws -> Data {
        if offset == 0 {
            return try Data(contentsOf: url)
        }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        try handle.seek(toOffset: offset)
        return try handle.readToEnd() ?? Data()
    }

    private static func workingDirectoryMatches(_ recordPath: String?, currentDirectoryPath: String) -> Bool {
        guard let recordPath = AgentRuntimeContext.sanitize(recordPath) else {
            return true
        }
        return standardizedPath(recordPath) == standardizedPath(currentDirectoryPath)
    }

    private static func commandInvokesAuthsia(_ command: String?) -> Bool {
        guard let trimmed = command?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty,
              trimmed.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            return false
        }
        let command = trimmed.lowercased()
        return command.split { $0.isWhitespace || $0 == "'" || $0 == "\"" }
            .contains { token in
                token == "authsia" || token.hasSuffix("/authsia")
            }
    }

    private static func recordInvokesAuthsia(_ record: AgentRuntimeContextRecord) -> Bool {
        if let invokesAuthsia = record.invokesAuthsia {
            return invokesAuthsia
        }
        return commandInvokesAuthsia(record.command)
    }

    private static func detectedAgentPlatforms(in ancestry: [AgenticProcessReference]) -> Set<String> {
        var platforms = Set<String>()
        for process in ancestry {
            let values = ([process.processName, process.bundleIdentifier ?? ""] + process.arguments)
                .map { $0.lowercased() }
            if values.contains(where: { $0.contains("codex") }) {
                platforms.insert("codex")
            }
            if values.contains(where: { $0.contains("claude") || $0.contains("com.anthropic.claude") }) {
                platforms.insert("claude-code")
            }
            if values.contains(where: { $0.contains("com.microsoft.vscode") || $0.contains("visual studio code") }) {
                platforms.insert("vscode")
            }
            if values.contains(where: { $0.contains("github.copilot") || $0.contains("github-copilot") }) {
                platforms.insert("copilot")
            }
            if values.contains(where: { $0.contains("com.cursor") || $0.contains("cursor") }) {
                platforms.insert("cursor")
            }
            if values.contains(where: {
                $0.contains("windsurf")
                    || $0.contains("devin-desktop")
                    || $0.contains("devin.app")
                    || $0.contains("com.cognition")
                    || $0.contains("/devin")
                    || $0 == "devin"
            }) {
                platforms.insert("devin")
            }
        }
        return platforms
    }

    private static func platformMatches(_ platform: String?, detectedPlatforms: Set<String>) -> Bool {
        guard !detectedPlatforms.isEmpty,
              let normalized = normalizedPlatform(platform) else {
            return false
        }
        if detectedPlatforms.contains(normalized) {
            return true
        }
        return normalized == "copilot" && detectedPlatforms.contains("vscode")
    }

    private static func normalizedPlatform(_ platform: String?) -> String? {
        guard let platform = AgentRuntimeContext.sanitize(platform)?.lowercased() else {
            return nil
        }
        if platform == "claude" || platform == "claude-code" {
            return "claude-code"
        }
        if platform == "codex" {
            return "codex"
        }
        if platform == "vscode" || platform == "vs-code" || platform == "visual-studio-code" {
            return "vscode"
        }
        if platform == "copilot" || platform == "github-copilot" || platform == "githubcopilot" {
            return "copilot"
        }
        if platform == "cursor" {
            return "cursor"
        }
        if platform == "devin" || platform == "devin-desktop" || platform == "windsurf" {
            return "devin"
        }
        return platform
    }

    private static func standardizedPath(_ path: String) -> String {
        URL(fileURLWithPath: path).standardizedFileURL.path
    }

    private static func attributionEventURLs(
        eventsURL: URL,
        environment: [String: String]
    ) -> [URL] {
        var urls = [eventsURL]
        if let override = environment[environmentHookContextPathKey]?
            .trimmingCharacters(in: .whitespacesAndNewlines),
           !override.isEmpty {
            let extra = URL(fileURLWithPath: override)
            if extra.standardizedFileURL != eventsURL.standardizedFileURL {
                urls.append(extra)
            }
        } else if eventsURL.standardizedFileURL == defaultEventsURL.standardizedFileURL {
            let hook = defaultHookContextURL
            if hook.standardizedFileURL != eventsURL.standardizedFileURL {
                urls.append(hook)
            }
        }
        return urls
    }

    private static func selectContext(
        from candidates: [SourcedRecord],
        now: Date,
        claimOwner: pid_t
    ) -> AgentRuntimeContext? {
        let grouped = Dictionary(grouping: candidates, by: \.sourceURL)
        var owned: [SourcedRecord] = []
        var unclaimed: [SourcedRecord] = []
        for (url, records) in grouped {
            let claims = AttributionClaimStore.load(for: url, now: now, liveIDs: Set(records.map(\.record.id)))
            for sourced in records {
                if let claim = claims[sourced.record.id], claim.pid == Int32(claimOwner) {
                    owned.append(sourced)
                } else if claims[sourced.record.id] == nil {
                    unclaimed.append(sourced)
                }
            }
        }
        owned.sort { $0.record.recordedAt < $1.record.recordedAt }
        unclaimed.sort { $0.record.recordedAt < $1.record.recordedAt }

        if let reused = owned.first {
            return context(from: reused.record, confidence: .high)
        }
        if unclaimed.count == 1, let sourced = unclaimed.first {
            AttributionClaimStore.claim(sourced.record.id, on: sourced.sourceURL, pid: claimOwner, now: now)
            return context(from: sourced.record, confidence: .high)
        }
        if unclaimed.count >= 2 {
            let platform = unclaimed.first?.record.platform
            return AgentRuntimeContext(platform: platform, attributionConfidence: .ambiguous)
        }
        return nil
    }

    private static func context(
        from record: AgentRuntimeContextRecord,
        confidence: AgentAttributionConfidence
    ) -> AgentRuntimeContext? {
        let context = AgentRuntimeContext(
            platform: record.platform,
            sessionID: record.sessionID,
            turnID: record.turnID,
            agentID: record.agentID,
            agentType: record.agentType,
            toolUseID: record.toolUseID,
            attributionConfidence: confidence
        )
        return context.isEmpty ? nil : context
    }
}

private struct SourcedRecord {
    let record: AgentRuntimeContextRecord
    let sourceURL: URL
}

private enum AttributionClaimStore {
    private static let filePermissions: NSNumber = 0o600
    private static let filePermissionsMode: mode_t = S_IRUSR | S_IWUSR
    private static let historyRetention: TimeInterval = 60 * 60

    struct Claim: Codable {
        let claimedAt: Date
        let pid: Int32
    }

    static func claimsURL(for eventsURL: URL) -> URL {
        eventsURL.deletingPathExtension().appendingPathExtension("claimed.json")
    }

    static func load(for eventsURL: URL, now: Date, liveIDs: Set<UUID>) -> [UUID: Claim] {
        let url = claimsURL(for: eventsURL)
        return (try? withFileLock(url) {
            var claims = decode(url)
            let pruned = claims.filter { id, claim in
                liveIDs.contains(id) && now.timeIntervalSince(claim.claimedAt) <= historyRetention
            }
            if pruned.count != claims.count {
                try encode(pruned, to: url)
                claims = pruned
            }
            return claims
        }) ?? [:]
    }

    static func claim(_ id: UUID, on eventsURL: URL, pid: pid_t, now: Date) {
        let url = claimsURL(for: eventsURL)
        try? withFileLock(url) {
            var claims = decode(url)
            claims[id] = Claim(claimedAt: now, pid: Int32(pid))
            try encode(claims, to: url)
        }
    }

    private static func decode(_ url: URL) -> [UUID: Claim] {
        guard let data = try? Data(contentsOf: url) else { return [:] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode([UUID: Claim].self, from: data)) ?? [:]
    }

    private static func encode(_ claims: [UUID: Claim], to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(claims)
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: filePermissions],
            ofItemAtPath: url.path
        )
    }

    private static func withFileLock<T>(_ url: URL, _ body: () throws -> T) throws -> T {
        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let lockPath = url.path + ".lock"
        let fileDescriptor = open(lockPath, O_RDWR | O_CREAT, filePermissionsMode)
        guard fileDescriptor >= 0 else {
            throw POSIXError(.EIO)
        }
        defer { close(fileDescriptor) }
        try FileManager.default.setAttributes(
            [.posixPermissions: filePermissions],
            ofItemAtPath: lockPath
        )
        guard flock(fileDescriptor, LOCK_EX) == 0 else {
            throw POSIXError(.EIO)
        }
        defer { flock(fileDescriptor, LOCK_UN) }
        return try body()
    }
}

struct AgentRuntimeContextRecord: Codable, Equatable {
    let id: UUID
    let platform: String?
    let sessionID: String?
    let turnID: String?
    let agentID: String?
    let agentType: String?
    let toolUseID: String?
    let workingDirectory: String?
    let command: String?
    let invokesAuthsia: Bool?
    let recordedAt: Date
    let expiresAt: Date

    init(
        id: UUID,
        platform: String?,
        sessionID: String?,
        turnID: String?,
        agentID: String?,
        agentType: String?,
        toolUseID: String?,
        workingDirectory: String?,
        command: String?,
        invokesAuthsia: Bool?,
        recordedAt: Date,
        expiresAt: Date
    ) {
        self.id = id
        self.platform = platform
        self.sessionID = sessionID
        self.turnID = turnID
        self.agentID = agentID
        self.agentType = agentType
        self.toolUseID = toolUseID
        self.workingDirectory = workingDirectory
        self.command = command
        self.invokesAuthsia = invokesAuthsia
        self.recordedAt = recordedAt
        self.expiresAt = expiresAt
    }

    init(event: AgentCommandEvent) {
        self.init(
            id: event.id,
            platform: event.agentPlatform,
            sessionID: event.sessionID,
            turnID: event.turnID,
            agentID: event.agentID,
            agentType: event.agentType,
            toolUseID: event.toolUseID,
            workingDirectory: event.workingDirectory,
            command: event.command,
            invokesAuthsia: nil,
            recordedAt: event.recordedAt,
            expiresAt: event.contextExpiresAt ?? event.recordedAt.addingTimeInterval(60 * 60)
        )
    }
}
