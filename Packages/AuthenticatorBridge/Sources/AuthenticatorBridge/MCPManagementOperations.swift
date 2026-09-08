import Foundation

public enum MCPManagementOperationKind: String, Codable, Sendable {
    case declare, configure, policy, credential, catalog, wrap, unwrap, enrollHTTP, revoke
}
public struct MCPManagementOperationRequest: Codable, Sendable {
    public var kind: MCPManagementOperationKind
    public var serverID: String?
    /// Existing declaration selected for a confirmed cross-workspace setup.
    public var sourceServerID: String?
    public var workspaceID: String?
    public var name: String?
    public var transport: MCPUpstreamTransport?
    public var command: String?
    public var arguments: [String]?
    public var endpoint: String?
    public var policy: MCPUpstreamToolPolicy?
    public var client: MCPClientConfigSource?
    public var findingID: String?
    public var credentialID: String?
    public var bindingName: String?
    public var headerFormat: MCPUpstreamCredentialHeaderFormat?
    public var grantID: UUID?
    public var removeBinding: Bool?
    public init(kind: MCPManagementOperationKind, serverID: String? = nil) { self.kind = kind; self.serverID = serverID }
}
public struct MCPManagementOperationView: Codable, Sendable, Identifiable {
    public enum State: String, Codable, Sendable { case prepared, awaitingNativeConfirmation, applying, succeeded, failed, denied, stale, expired }
    public let id: UUID
    public let kind: MCPManagementOperationKind
    public let preview: String
    public let expiresAt: Date
    public var state: State
    public var message: String?
    public init(id: UUID, kind: MCPManagementOperationKind, preview: String, expiresAt: Date, state: State = .prepared, message: String? = nil) {
        self.id = id; self.kind = kind; self.preview = preview; self.expiresAt = expiresAt; self.state = state; self.message = message
    }
}
public struct MCPWorkspaceSummary: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let label: String
    public init(id: String, label: String) { self.id = id; self.label = label }
}
public struct MCPCredentialOption: Codable, Sendable {
    public let id: String
    public let label: String
    public let type: String
    /// Presentation metadata only; never contains a credential value.
    public let folderPath: String?
    public let environments: [String]?
    public let workspaceIDs: [String]?
    public init(id: String, label: String, type: String, folderPath: String? = nil,
                environments: [String]? = nil, workspaceIDs: [String]? = nil) {
        self.id = id; self.label = label; self.type = type
        self.folderPath = folderPath; self.environments = environments; self.workspaceIDs = workspaceIDs
    }
}
public struct MCPManagerGrantView: Codable, Sendable, Identifiable {
    public let id: UUID
    public let serverID: String?
    public let serverName: String
    public let workspaceID: String?
    public let workspacePath: String?
    public let clientLabel: String
    public let transport: MCPUpstreamTransport
    public let expiresAt: Date
    public let issuedAt: Date?
    public let scopeLabel: String?
    public let approvalOrigin: String?
    public let credentialLabels: [String]
    public init(
        id: UUID,
        serverName: String,
        clientLabel: String,
        transport: MCPUpstreamTransport,
        expiresAt: Date,
        serverID: String? = nil,
        workspaceID: String? = nil,
        workspacePath: String? = nil,
        issuedAt: Date? = nil,
        scopeLabel: String? = nil,
        approvalOrigin: String? = nil,
        credentialLabels: [String] = []
    ) {
        self.id = id
        self.serverID = serverID
        self.serverName = serverName
        self.workspaceID = workspaceID
        self.workspacePath = workspacePath
        self.clientLabel = clientLabel
        self.transport = transport
        self.expiresAt = expiresAt
        self.issuedAt = issuedAt
        self.scopeLabel = scopeLabel
        self.approvalOrigin = approvalOrigin
        self.credentialLabels = credentialLabels
    }
}

extension MCPManagerGrantView {
    enum CodingKeys: String, CodingKey {
        case id, serverID, serverName, workspaceID, workspacePath, clientLabel, transport, expiresAt, issuedAt, scopeLabel, approvalOrigin, credentialLabels
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        serverID = try container.decodeIfPresent(String.self, forKey: .serverID)
        serverName = try container.decode(String.self, forKey: .serverName)
        workspaceID = try container.decodeIfPresent(String.self, forKey: .workspaceID)
        workspacePath = try container.decodeIfPresent(String.self, forKey: .workspacePath)
        clientLabel = try container.decode(String.self, forKey: .clientLabel)
        transport = try container.decode(MCPUpstreamTransport.self, forKey: .transport)
        expiresAt = try container.decode(Date.self, forKey: .expiresAt)
        issuedAt = try container.decodeIfPresent(Date.self, forKey: .issuedAt)
        scopeLabel = try container.decodeIfPresent(String.self, forKey: .scopeLabel)
        approvalOrigin = try container.decodeIfPresent(String.self, forKey: .approvalOrigin)
        credentialLabels = try container.decodeIfPresent([String].self, forKey: .credentialLabels) ?? []
    }
}
