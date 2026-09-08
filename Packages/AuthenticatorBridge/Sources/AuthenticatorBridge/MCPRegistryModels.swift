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
    public let canEnrollHTTP: Bool?
    public let managementReason: String?

    public init(
        id: String,
        source: MCPClientConfigSource,
        scope: MCPClientConfigScope,
        precedence: MCPClientConfigPrecedence,
        status: MCPClientServerAdmissionStatus,
        configPathLabel: String,
        canEnrollHTTP: Bool? = nil,
        managementReason: String? = nil
    ) {
        self.id = id
        self.source = source
        self.scope = scope
        self.precedence = precedence
        self.status = status
        self.configPathLabel = configPathLabel
        self.canEnrollHTTP = canEnrollHTTP
        self.managementReason = managementReason
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
    public let launchCommand: String?
    public let catalogBlockReason: String?
    public let catalogCapturedAt: Date?
    public let catalogQuality: String?
    public let credentialBindings: [MCPCredentialBindingView]
    public let readiness: MCPServerReadiness?

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
        authorizationRevision: String = "",
        launchCommand: String? = nil,
        catalogBlockReason: String? = nil,
        catalogCapturedAt: Date? = nil,
        catalogQuality: String? = nil,
        credentialBindings: [MCPCredentialBindingView] = [],
        readiness: MCPServerReadiness? = nil
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
        self.launchCommand = launchCommand
        self.catalogBlockReason = catalogBlockReason
        self.catalogCapturedAt = catalogCapturedAt
        self.catalogQuality = catalogQuality
        self.credentialBindings = credentialBindings
        self.readiness = readiness
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
    public let discoveredServers: [MCPDiscoveredServer]?
    /// Clients the portal may offer for filter and Protect. VS Code and Devin
    /// appear only when that app is installed on this Mac.
    public let protectableClients: [MCPClientConfigSource]?

    public init(
        revision: String,
        servers: [MCPServerSnapshot],
        diagnostics: [MCPRegistryDiagnostic] = [],
        workspaces: [MCPWorkspaceSummary] = [],
        discoveredServers: [MCPDiscoveredServer]? = nil,
        protectableClients: [MCPClientConfigSource]? = nil
    ) {
        self.revision = revision
        self.servers = servers
        self.diagnostics = diagnostics
        self.workspaces = workspaces
        self.discoveredServers = discoveredServers
        self.protectableClients = protectableClients
    }
}

/// Metadata-only view of an observed client entry that has no workspace declaration.
public struct MCPDiscoveredServer: Codable, Equatable, Sendable, Identifiable {
    public let id: String
    public let findingID: String
    public let displayName: String
    public let workspaceID: String?
    public let workspacePath: String?
    public let client: MCPClientConfigSource
    public let scope: MCPClientConfigScope
    public let precedence: MCPClientConfigPrecedence
    public let commandLabel: String
    public let transportLabel: String
    public let configPathLabel: String
    public let canConfigure: Bool
    public let configurationHint: String
    public let isDisabled: Bool
    public let canEnrollHTTP: Bool
    public let unsupportedActionReason: String?

    public init(
        id: String,
        findingID: String,
        displayName: String,
        workspaceID: String?,
        workspacePath: String?,
        client: MCPClientConfigSource,
        scope: MCPClientConfigScope,
        precedence: MCPClientConfigPrecedence,
        commandLabel: String,
        transportLabel: String,
        configPathLabel: String,
        canConfigure: Bool,
        configurationHint: String,
        isDisabled: Bool = false,
        canEnrollHTTP: Bool = false,
        unsupportedActionReason: String? = nil
    ) {
        self.id = id
        self.findingID = findingID
        self.displayName = displayName
        self.workspaceID = workspaceID
        self.workspacePath = workspacePath
        self.client = client
        self.scope = scope
        self.precedence = precedence
        self.commandLabel = commandLabel
        self.transportLabel = transportLabel
        self.configPathLabel = configPathLabel
        self.canConfigure = canConfigure
        self.configurationHint = configurationHint
        self.isDisabled = isDisabled
        self.canEnrollHTTP = canEnrollHTTP
        self.unsupportedActionReason = unsupportedActionReason
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
    case busy
    case childStarted
    case childExited
    case incomplete
    case failed
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
    public let grantIDs: [UUID]
    public let transport: MCPUpstreamTransport?
    public let reasonCode: String?

    public init(
        id: UUID = UUID(),
        recordedAt: Date = Date(),
        serverID: String,
        serverName: String,
        workspacePath: String,
        toolName: String,
        outcome: MCPHTTPActivityOutcome,
        attribution: String = "configured-association",
        grantIDs: [UUID] = [],
        transport: MCPUpstreamTransport? = nil,
        reasonCode: String? = nil
    ) {
        self.id = id
        self.recordedAt = recordedAt
        self.serverID = serverID
        self.serverName = serverName
        self.workspacePath = workspacePath
        self.toolName = toolName
        self.outcome = outcome
        self.attribution = attribution
        self.grantIDs = grantIDs
        self.transport = transport
        self.reasonCode = reasonCode
    }
}
