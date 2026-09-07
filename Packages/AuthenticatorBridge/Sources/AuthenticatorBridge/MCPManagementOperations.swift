import Foundation

public enum MCPManagementOperationKind: String, Codable, Sendable {
    case declare, policy, credential, catalog, wrap, unwrap, enrollHTTP, revoke
}
public struct MCPManagementOperationRequest: Codable, Sendable {
    public var kind: MCPManagementOperationKind
    public var serverID: String?
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
    public let serverName: String
    public let clientLabel: String
    public let transport: MCPUpstreamTransport
    public let expiresAt: Date
    public init(id: UUID, serverName: String, clientLabel: String, transport: MCPUpstreamTransport, expiresAt: Date) {
        self.id = id; self.serverName = serverName; self.clientLabel = clientLabel; self.transport = transport; self.expiresAt = expiresAt
    }
}
