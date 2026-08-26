import AuthenticatorBridge
import Foundation

struct MCPProxySecretResolver: SecretResolverClient {
    let client: AuthsiaBridgeClient
    let agentRuntimeContext: AgentRuntimeContext
    let workspaceRoot: URL

    func resolveSecret(
        type: SecretReference.ItemType,
        query: String,
        field: String,
        folder: String?,
        isFolderScoped: Bool
    ) throws -> String {
        guard type != .otp, type != .ssh else {
            throw MCPToolInputError.invalidArgument("OTP and SSH refs are not injectable")
        }
        return try client.withRequestedCommand("exec", includeAutomationCredential: false) {
            try client.resolveSecret(
                type: type,
                query: query,
                field: field,
                folder: folder,
                isFolderScoped: isFolderScoped,
                agentRuntimeContext: agentRuntimeContext,
                workspaceRoot: workspaceRoot
            )
        }
    }
}

protocol MCPProxyBridgeSession: Sendable {
    func withRequestedCommand<R>(
        _ command: String,
        includeAutomationCredential: Bool,
        _ body: () throws -> R
    ) rethrows -> R
    func agentJITPreflight(
        _ payload: AgentJITPreflightPayload,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?
    ) throws -> AgentJITPreflightResultPayload
    func resolveSecret(
        type: SecretReference.ItemType,
        query: String,
        field: String,
        folder: String?,
        isFolderScoped: Bool,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL
    ) throws -> String
}

extension AuthsiaBridgeClient: MCPProxyBridgeSession {}

protocol MCPProxySessionClient: Sendable {
    func prepareChildEnvironment(
        declared: [String: String],
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL,
        mcpUpstreamName: String?,
        mcpToolName: String?,
        mcpToolPolicy: AgentJITMCPToolPolicy?
    ) throws -> (environment: [String: String], secrets: [String], grantIDs: [UUID])
}

struct LiveMCPProxySessionClient: MCPProxySessionClient, @unchecked Sendable {
    let client: any MCPProxyBridgeSession
    private let makeResolver: @Sendable (AgentRuntimeContext, URL) -> any SecretResolverClient

    init(client: AuthsiaBridgeClient = .shared) {
        self.client = client
        self.makeResolver = { context, root in
            MCPProxySecretResolver(
                client: client,
                agentRuntimeContext: context,
                workspaceRoot: root
            )
        }
    }

    init(bridge: any MCPProxyBridgeSession) {
        self.client = bridge
        self.makeResolver = { context, root in
            MCPProxyBridgedSecretResolver(
                client: bridge,
                agentRuntimeContext: context,
                workspaceRoot: root
            )
        }
    }

    func prepareChildEnvironment(
        declared: [String: String],
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL,
        mcpUpstreamName: String? = nil,
        mcpToolName: String? = nil,
        mcpToolPolicy: AgentJITMCPToolPolicy? = nil
    ) throws -> (environment: [String: String], secrets: [String], grantIDs: [UUID]) {
        let unsupported = try SecretReferenceResolver.unsupportedAgentJITReferences(
            environment: declared
        )
        guard unsupported.isEmpty else {
            throw MCPToolInputError.invalidArgument("OTP and SSH refs are not injectable")
        }
        let references = try SecretReferenceResolver.preflightReferences(environment: declared)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: references,
            mcpUpstreamName: mcpUpstreamName,
            mcpToolName: mcpToolName,
            mcpToolPolicy: mcpToolPolicy,
            mcpAdmissionRequested: references.isEmpty
        )
        return try client.withRequestedCommand("exec", includeAutomationCredential: false) {
            let preflight = try client.agentJITPreflight(
                payload,
                agentRuntimeContext: agentRuntimeContext,
                workspaceRoot: workspaceRoot
            )
            // Preflight can succeed without opening Agent JIT (a paired human
            // terminal, for one). The proxy child is long-lived, so a grant it
            // can watch is the only thing that makes revocation reach it.
            // Refuse before resolving, so no plaintext leaves the vault.
            guard !preflight.grantIDs.isEmpty else {
                throw MCPProxySpawnError.grantUnavailable
            }
            guard !references.isEmpty else {
                return (declared, [], preflight.grantIDs)
            }
            let resolver = makeResolver(agentRuntimeContext, workspaceRoot)
            let resolved = try SecretReferenceResolver(client: resolver).resolveEnvironment(declared)
            return (resolved.resolved, resolved.secrets, preflight.grantIDs)
        }
    }
}

private struct MCPProxyBridgedSecretResolver: SecretResolverClient {
    let client: any MCPProxyBridgeSession
    let agentRuntimeContext: AgentRuntimeContext
    let workspaceRoot: URL

    func resolveSecret(
        type: SecretReference.ItemType,
        query: String,
        field: String,
        folder: String?,
        isFolderScoped: Bool
    ) throws -> String {
        guard type != .otp, type != .ssh else {
            throw MCPToolInputError.invalidArgument("OTP and SSH refs are not injectable")
        }
        return try client.resolveSecret(
            type: type,
            query: query,
            field: field,
            folder: folder,
            isFolderScoped: isFolderScoped,
            agentRuntimeContext: agentRuntimeContext,
            workspaceRoot: workspaceRoot
        )
    }
}

protocol MCPProxyToolCallRecording: Sendable {
    func record(
        upstreamName: String,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?,
        grantID: UUID?
    ) throws
}

struct LiveMCPProxyToolCallRecorder: MCPProxyToolCallRecording, @unchecked Sendable {
    private let store: AgentCommandHistoryStore

    init(store: AgentCommandHistoryStore = AgentCommandHistoryStore()) {
        self.store = store
    }

    func record(
        upstreamName: String,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?,
        grantID: UUID?
    ) throws {
        let executable = upstreamCommand ?? upstreamName
        try store.record(AgentCommandEvent(
            recordedAt: Date(),
            agentPlatform: agentRuntimeContext.platform,
            sessionID: agentRuntimeContext.sessionID,
            turnID: agentRuntimeContext.turnID,
            agentID: agentRuntimeContext.agentID,
            agentType: agentRuntimeContext.agentType,
            toolUseID: agentRuntimeContext.toolUseID,
            agentJITGrantID: grantID,
            captureSource: .mcpProxy,
            workingDirectory: workspaceRoot?.path,
            executable: executable,
            arguments: ["mcp-tool", toolName],
            command: "\(executable) mcp-tool \(toolName)"
        ))
    }
}
