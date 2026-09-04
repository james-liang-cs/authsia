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
    public let attributionConfidence: AgentAttributionConfidence

    public init(
        platform: String? = nil,
        sessionID: String? = nil,
        turnID: String? = nil,
        agentID: String? = nil,
        agentType: String? = nil,
        toolUseID: String? = nil,
        attributionConfidence: AgentAttributionConfidence = .high
    ) {
        self.platform = Self.sanitize(platform)
        self.sessionID = Self.sanitize(sessionID)
        self.turnID = Self.sanitize(turnID)
        self.agentID = Self.sanitize(agentID)
        self.agentType = Self.sanitize(agentType)
        self.toolUseID = Self.sanitize(toolUseID)
        self.attributionConfidence = attributionConfidence
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
            ) ?? .high
        )
    }

    public var isEmpty: Bool {
        platform == nil
            && sessionID == nil
            && turnID == nil
            && agentID == nil
            && agentType == nil
            && toolUseID == nil
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
