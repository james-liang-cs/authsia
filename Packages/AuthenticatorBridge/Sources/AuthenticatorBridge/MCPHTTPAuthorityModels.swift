#if os(macOS)
import Foundation

public struct MCPHTTPAssociationBinding: Codable, Equatable, Sendable {
    public let serverID: String
    public let identity: MCPServerIdentity
    public let client: MCPClientConfigSource
    public init(serverID: String, identity: MCPServerIdentity, client: MCPClientConfigSource) {
        self.serverID = serverID; self.identity = identity; self.client = client
    }
}

public struct MCPHTTPPrincipal: Codable, Equatable, Sendable {
    public let id: UUID
    public let binding: MCPHTTPAssociationBinding
    public let generation: UUID
    public init(id: UUID, binding: MCPHTTPAssociationBinding, generation: UUID) {
        self.id = id; self.binding = binding; self.generation = generation
    }
}

public struct MCPHTTPGrantSummary: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let principal: MCPHTTPPrincipal
    public let sessionID: String
    public let revision: String
    public let expiresAt: Date
    public let credentialLabels: [String]
    public let createdAt: Date?
    public var revokedAt: Date?
    public func status(asOf now: Date) -> AgentJITGrantStatus {
        revokedAt != nil ? .revoked : (expiresAt <= now ? .expired : .active)
    }
    public init(id: UUID, principal: MCPHTTPPrincipal, sessionID: String, revision: String, expiresAt: Date, credentialLabels: [String], createdAt: Date? = nil, revokedAt: Date? = nil) {
        self.id = id; self.principal = principal; self.sessionID = sessionID; self.revision = revision
        self.expiresAt = expiresAt; self.credentialLabels = credentialLabels
        self.createdAt = createdAt; self.revokedAt = revokedAt
    }
}

/// Native IPC only: never serialize this object into a portal response or log.
public struct MCPHTTPLease: Codable, Sendable {
    public let grant: MCPHTTPGrantSummary
    public let headers: [String: String]
    public let secrets: [String]
    public init(grant: MCPHTTPGrantSummary, headers: [String: String], secrets: [String]) {
        self.grant = grant; self.headers = headers; self.secrets = secrets
    }
}

/// Uncommitted token. The verifier becomes active only after confirmed file
/// write/readback, then commitEnrollment. Failed prepares leave old tokens valid.
public struct MCPHTTPEnrollmentTicket: Codable, Sendable {
    public let id: UUID
    public let token: String
    public let expiresAt: Date
    public init(id: UUID, token: String, expiresAt: Date) { self.id = id; self.token = token; self.expiresAt = expiresAt }
}

public enum MCPHTTPAuthorityCommand: Codable, Sendable {
    case prepareEnrollment(MCPHTTPAssociationBinding)
    case commitEnrollment(UUID)
    case enrollmentStatus(UUID)
    case discardEnrollment(UUID)
    case authenticate(serverID: String, token: String)
    case authorize(principal: MCPHTTPPrincipal, sessionID: String, revision: String, tool: String)
    /// Refresh a background stream only from existing live admission; never prompt.
    case authorizeExisting(principal: MCPHTTPPrincipal, sessionID: String, revision: String, tool: String)
    case validate(grantID: UUID, principal: MCPHTTPPrincipal, sessionID: String, revision: String)
    case revoke(grantID: UUID?)
    case revokeAssociation(UUID)
    case revokeBinding(MCPHTTPAssociationBinding)
    case snapshot
    case catalogCapture(identity: MCPServerIdentity, revision: String)
}

public struct MCPHTTPAuthorityReply: Codable, Sendable {
    public var principal: MCPHTTPPrincipal?
    public var enrollment: MCPHTTPEnrollmentTicket?
    public var lease: MCPHTTPLease?
    public var grants: [MCPHTTPGrantSummary]?
    public var history: [MCPHTTPGrantSummary]?
    public var valid: Bool
    public var failure: MCPManagementError?
    public init(principal: MCPHTTPPrincipal? = nil, enrollment: MCPHTTPEnrollmentTicket? = nil,
                lease: MCPHTTPLease? = nil, grants: [MCPHTTPGrantSummary]? = nil, history: [MCPHTTPGrantSummary]? = nil, valid: Bool = true, failure: MCPManagementError? = nil) {
        self.principal = principal; self.enrollment = enrollment; self.lease = lease
        self.grants = grants; self.valid = valid; self.failure = failure
        self.history = history
    }
}

public enum MCPManagementError: String, Error, LocalizedError, Codable, Sendable {
    case unavailable, invalidRequest, denied, stale, notFound, unsupported, auditUnavailable, busy, mcpAccessDisabled
    case duplicateServerNames
    case catalogExecutableMissing, catalogEnvironmentRequired, catalogEmpty, catalogIncomplete, catalogStartupFailed, catalogHelperUnavailable, catalogTimedOut, catalogAccessDisabled
    public var errorDescription: String? {
        switch self {
        case .mcpAccessDisabled: return MCPAccessSettings.disabledMessage
        case .unavailable: return "Authsia management is unavailable."
        case .invalidRequest: return "Invalid MCP configuration or request."
        case .duplicateServerNames: return "This workspace contains duplicate MCP server names; names are case-insensitive. Authsia can prepare a repair for equivalent declarations. Conflicting launch settings, credentials, or tool permissions must be resolved before configuration can continue."
        case .denied: return "MCP access was not authorized."
        case .stale: return "The configuration or authorization changed. Prepare the operation again."
        case .notFound: return "The MCP server, session, or operation was not found."
        case .unsupported: return "This MCP operation is not supported."
        case .auditUnavailable: return "MCP activity could not be recorded; the call was not forwarded."
        case .busy: return "The MCP operation limit was reached."
        case .catalogExecutableMissing: return "The declared executable is not available to Authsia. Use Edit server to set an installed executable and its arguments. Agent-provided commands may not be standalone MCP servers."
        case .catalogEnvironmentRequired: return "This server requires environment setup. Catalog recording is limited to environment-free STDIO launches. Use Edit policy to name its tools and associate the required credential references before protecting the client."
        case .catalogEmpty: return "No tools were returned. Admission may have been declined, or the server advertised an empty catalog. Check the server setup and approval, then prepare a new catalog request."
        case .catalogIncomplete: return "The server advertised a paginated catalog that Authsia could not record in full. Name remaining tools in Edit policy, then prepare a new catalog request."
        case .catalogStartupFailed: return "The server could not start or did not answer tools/list. Check its executable, arguments, runtime requirements, and native admission. Use Edit server or Edit policy to continue setup."
        case .catalogHelperUnavailable: return "The Authsia catalog helper could not be started. Repair or rebuild the app's bundled CLI, then try again."
        case .catalogTimedOut: return "Catalog recording timed out. Check the server and any pending native approval, then prepare a new request."
        case .catalogAccessDisabled: return "Enable MCP Integrations in Authsia Settings > Developer Access before recording a catalog."
        }
    }
}
#endif
