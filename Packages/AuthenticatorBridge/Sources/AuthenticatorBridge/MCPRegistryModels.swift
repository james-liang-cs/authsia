import Foundation

/// Workspace-local identity for a declared MCP upstream.
public struct MCPServerIdentity: Codable, Equatable, Hashable, Sendable {
    public let workspacePath: String
    public let upstreamName: String

    public init(workspaceRoot: URL, upstreamName: String) {
        self.workspacePath = workspaceRoot.standardizedFileURL.path
        self.upstreamName = upstreamName
    }

    public init(workspacePath: String, upstreamName: String) {
        self.init(
            workspaceRoot: URL(fileURLWithPath: workspacePath, isDirectory: true),
            upstreamName: upstreamName
        )
    }
}

public struct MCPClientAssociation: Codable, Equatable, Identifiable, Sendable {
    public let id: String
    public let source: MCPClientConfigSource
    public let scope: MCPClientConfigScope
    public let precedence: MCPClientConfigPrecedence
    public let status: MCPClientServerAdmissionStatus
    public let configPathLabel: String

    public init(
        id: String,
        source: MCPClientConfigSource,
        scope: MCPClientConfigScope,
        precedence: MCPClientConfigPrecedence,
        status: MCPClientServerAdmissionStatus,
        configPathLabel: String
    ) {
        self.id = id
        self.source = source
        self.scope = scope
        self.precedence = precedence
        self.status = status
        self.configPathLabel = configPathLabel
    }
}

/// Sanitized server state shared with management presentation.
///
/// Credential references, child environment, client tokens, and raw config
/// payloads deliberately have no representation here.
public struct MCPServerSnapshot: Codable, Equatable, Identifiable, Sendable {
    public let id: String
    public let identity: MCPServerIdentity
    public let displayName: String
    public let transport: MCPUpstreamTransport
    public let commandLabel: String?
    public let endpointLabel: String?
    public let policy: MCPUpstreamToolPolicy
    public let catalog: [MCPUpstreamToolDescriptor]
    public let credentialLabels: [String]
    public let hasCredentialHeaders: Bool
    public let clientAssociations: [MCPClientAssociation]
    public let observedCallCount: Int
    public let authorizationRevision: String

    public init(
        id: String,
        identity: MCPServerIdentity,
        displayName: String,
        transport: MCPUpstreamTransport,
        commandLabel: String? = nil,
        endpointLabel: String? = nil,
        policy: MCPUpstreamToolPolicy,
        catalog: [MCPUpstreamToolDescriptor],
        credentialLabels: [String] = [],
        hasCredentialHeaders: Bool = false,
        clientAssociations: [MCPClientAssociation] = [],
        observedCallCount: Int = 0,
        authorizationRevision: String = ""
    ) {
        self.id = id
        self.identity = identity
        self.displayName = displayName
        self.transport = transport
        self.commandLabel = commandLabel
        self.endpointLabel = endpointLabel
        self.policy = policy
        self.catalog = catalog
        self.credentialLabels = credentialLabels
        self.hasCredentialHeaders = hasCredentialHeaders
        self.clientAssociations = clientAssociations
        self.observedCallCount = observedCallCount
        self.authorizationRevision = authorizationRevision
    }
}

public enum MCPRegistryDiagnosticCode: String, Codable, Equatable, Sendable {
    case missing
    case unreadable
    case malformed
    case oversized
}

public struct MCPRegistryDiagnostic: Codable, Equatable, Sendable {
    public let source: MCPClientConfigSource?
    public let pathLabel: String
    public let code: MCPRegistryDiagnosticCode

    public init(
        source: MCPClientConfigSource? = nil,
        pathLabel: String,
        code: MCPRegistryDiagnosticCode
    ) {
        self.source = source
        self.pathLabel = pathLabel
        self.code = code
    }
}

public struct MCPRegistrySnapshot: Codable, Equatable, Sendable {
    public let revision: String
    public let servers: [MCPServerSnapshot]
    public let diagnostics: [MCPRegistryDiagnostic]
    public let workspaces: [MCPWorkspaceSummary]

    public init(
        revision: String,
        servers: [MCPServerSnapshot],
        diagnostics: [MCPRegistryDiagnostic] = [],
        workspaces: [MCPWorkspaceSummary] = []
    ) {
        self.revision = revision
        self.servers = servers
        self.diagnostics = diagnostics
        self.workspaces = workspaces
    }
}

public enum MCPHTTPActivityOutcome: String, Codable, Equatable, Sendable {
    case started
    case succeeded
    case denied
    case upstreamUnavailable
    case mcpError
    case cancelled
    case timedOut
}

public struct MCPHTTPActivityEvent: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let recordedAt: Date
    public let serverID: String
    public let serverName: String
    public let workspacePath: String
    public let toolName: String
    public let outcome: MCPHTTPActivityOutcome
    public let attribution: String

    public init(
        id: UUID = UUID(),
        recordedAt: Date = Date(),
        serverID: String,
        serverName: String,
        workspacePath: String,
        toolName: String,
        outcome: MCPHTTPActivityOutcome,
        attribution: String = "configured-association"
    ) {
        self.id = id
        self.recordedAt = recordedAt
        self.serverID = serverID
        self.serverName = serverName
        self.workspacePath = workspacePath
        self.toolName = toolName
        self.outcome = outcome
        self.attribution = attribution
    }
}
