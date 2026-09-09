import Foundation

public enum AgentAttributionConfidence: String, Codable, Equatable, Sendable {
    case high
    case ambiguous
}

public struct AgentRuntimeContext: Codable, Equatable, Sendable {
    public let platform: String?
    public let sessionID: String?
    public let turnID: String?
    public let agentID: String?
    public let agentType: String?
    public let toolUseID: String?
    public let caller: AgentCallerIdentity?
    public let attributionConfidence: AgentAttributionConfidence

    public init(
        platform: String? = nil,
        sessionID: String? = nil,
        turnID: String? = nil,
        agentID: String? = nil,
        agentType: String? = nil,
        toolUseID: String? = nil,
        attributionConfidence: AgentAttributionConfidence = .high,
        caller: AgentCallerIdentity? = nil
    ) {
        self.caller = caller.map { AgentCallerIdentity(context: $0.runtimeContext(platform: nil)) }
        self.platform = Self.sanitize(platform)
        self.sessionID = Self.sanitize(sessionID)
        self.turnID = Self.sanitize(turnID)
        self.agentID = Self.sanitize(agentID)
        self.agentType = Self.sanitize(agentType)
        self.toolUseID = Self.sanitize(toolUseID)
        self.attributionConfidence = attributionConfidence
    }

    enum CodingKeys: String, CodingKey {
        case caller
        case platform
        case sessionID
        case turnID
        case agentID
        case agentType
        case toolUseID
        case attributionConfidence
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            platform: try container.decodeIfPresent(String.self, forKey: .platform),
            sessionID: try container.decodeIfPresent(String.self, forKey: .sessionID),
            turnID: try container.decodeIfPresent(String.self, forKey: .turnID),
            agentID: try container.decodeIfPresent(String.self, forKey: .agentID),
            agentType: try container.decodeIfPresent(String.self, forKey: .agentType),
            toolUseID: try container.decodeIfPresent(String.self, forKey: .toolUseID),
            attributionConfidence: try container.decodeIfPresent(
                AgentAttributionConfidence.self,
                forKey: .attributionConfidence
            ) ?? .high,
            caller: try container.decodeIfPresent(AgentCallerIdentity.self, forKey: .caller)
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(caller, forKey: .caller)
        try container.encodeIfPresent(platform, forKey: .platform)
        try container.encodeIfPresent(sessionID, forKey: .sessionID)
        try container.encodeIfPresent(turnID, forKey: .turnID)
        try container.encodeIfPresent(agentID, forKey: .agentID)
        try container.encodeIfPresent(agentType, forKey: .agentType)
        try container.encodeIfPresent(toolUseID, forKey: .toolUseID)
        if attributionConfidence != .high || Self.includeDefaultAttributionConfidence {
            try container.encode(attributionConfidence, forKey: .attributionConfidence)
        }
    }

    /// Historical audit HMAC payloads encoded the default `.high` confidence after
    /// that field existed. Verify both encodings so older rows still authenticate.
    @TaskLocal static var includeDefaultAttributionConfidence = false

    public static func encodingDefaultAttributionConfidence<T>(_ operation: () throws -> T) rethrows -> T {
        try $includeDefaultAttributionConfidence.withValue(true, operation: operation)
    }

    /// True when the context is worth encoding or showing. An empty context still matters when it
    /// is not high-confidence: it carries the fact that attribution was ambiguous.
    public var carriesAttribution: Bool {
        !isEmpty || attributionConfidence != .high
    }

    public var isEmpty: Bool {
        platform == nil
            && sessionID == nil
            && turnID == nil
            && agentID == nil
            && agentType == nil
            && toolUseID == nil
            && caller == nil
    }

    public static func sanitize(_ value: String?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty else {
            return nil
        }
        guard trimmed.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            return nil
        }
        return String(trimmed.prefix(128))
    }
}

/// Hook-reported caller identity, separate from MCP server and invocation correlation.
/// This metadata never grants authority.
public struct AgentCallerIdentity: Codable, Equatable, Sendable {
    public let sessionID: String?
    public let agentID: String?
    public let agentType: String?
    public let toolUseID: String?
    public let attributionConfidence: AgentAttributionConfidence

    public init(context: AgentRuntimeContext) {
        sessionID = context.sessionID
        agentID = context.agentID
        agentType = context.agentType
        toolUseID = context.toolUseID
        attributionConfidence = context.attributionConfidence
    }

    public func runtimeContext(platform: String?) -> AgentRuntimeContext {
        AgentRuntimeContext(
            platform: platform, sessionID: sessionID, agentID: agentID,
            agentType: agentType, toolUseID: toolUseID,
            attributionConfidence: attributionConfidence
        )
    }
}
