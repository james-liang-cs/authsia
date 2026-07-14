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

    static var defaultEventsURL: URL {
        AgentCommandHistoryStore.defaultFileURL
    }

    static func resolve(
        now: Date = Date(),
        currentDirectoryPath: String = FileManager.default.currentDirectoryPath,
        processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry(),
        eventsURL: URL = defaultEventsURL,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> AgentRuntimeContext? {
        if let explicitContext = explicitAgentRuntimeContext(environment: environment) {
            return explicitContext
        }

        let records = loadRecords(from: eventsURL)
            .filter { $0.expiresAt > now }
            .filter { workingDirectoryMatches($0.workingDirectory, currentDirectoryPath: currentDirectoryPath) }
            .filter { recordInvokesAuthsia($0) }
        guard !records.isEmpty else { return nil }

        let detectedPlatforms = detectedAgentPlatforms(in: processAncestry)
        guard !detectedPlatforms.isEmpty else { return nil }

        let platformCompatible = records.filter {
            platformMatches($0.platform, detectedPlatforms: detectedPlatforms)
        }
        guard let record = platformCompatible.max(by: { $0.recordedAt < $1.recordedAt }) else {
            return nil
        }

        let context = AgentRuntimeContext(
            platform: record.platform,
            sessionID: record.sessionID,
            turnID: record.turnID,
            agentID: record.agentID,
            agentType: record.agentType,
            toolUseID: record.toolUseID
        )
        return context.isEmpty ? nil : context
    }

    static func hasExplicitAgentInvocationMarker(environment: [String: String]) -> Bool {
        explicitAgentRuntimeContext(environment: environment) != nil
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

    private static func loadRecords(from url: URL) -> [AgentRuntimeContextRecord] {
        guard let data = try? Data(contentsOf: url),
              let text = String(data: data, encoding: .utf8) else {
            return []
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return text
            .split(whereSeparator: \.isNewline)
            .compactMap { line in
                let data = Data(String(line).utf8)
                if let record = try? decoder.decode(AgentRuntimeContextRecord.self, from: data) {
                    return record
                }
                guard let event = try? decoder.decode(AgentCommandEvent.self, from: data) else {
                    return nil
                }
                return AgentRuntimeContextRecord(event: event)
            }
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
            if values.contains(where: { $0.contains("windsurf") }) {
                platforms.insert("windsurf")
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
        if platform == "windsurf" {
            return "windsurf"
        }
        return platform
    }

    private static func standardizedPath(_ path: String) -> String {
        URL(fileURLWithPath: path).standardizedFileURL.path
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
