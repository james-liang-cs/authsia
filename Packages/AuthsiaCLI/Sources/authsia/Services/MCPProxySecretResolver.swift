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
    ) throws -> (environment: [String: String], secrets: [String])
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
    ) throws -> (environment: [String: String], secrets: [String]) {
        let unsupported = try SecretReferenceResolver.unsupportedAgentJITReferences(
            environment: declared
        )
        guard unsupported.isEmpty else {
            throw MCPToolInputError.invalidArgument("OTP and SSH refs are not injectable")
        }
        let references = try SecretReferenceResolver.preflightReferences(environment: declared)
        guard !references.isEmpty else {
            return (declared, [])
        }
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: references,
            mcpUpstreamName: mcpUpstreamName,
            mcpToolName: mcpToolName,
            mcpToolPolicy: mcpToolPolicy
        )
        let resolver = makeResolver(agentRuntimeContext, workspaceRoot)
        return try client.withRequestedCommand("exec", includeAutomationCredential: false) {
            _ = try client.agentJITPreflight(
                payload,
                agentRuntimeContext: agentRuntimeContext,
                workspaceRoot: workspaceRoot
            )
            let resolved = try SecretReferenceResolver(client: resolver).resolveEnvironment(declared)
            return (resolved.resolved, resolved.secrets)
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
