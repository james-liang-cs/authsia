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

protocol MCPProxySessionClient: Sendable {
    func prepareChildEnvironment(
        declared: [String: String],
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL
    ) throws -> (environment: [String: String], secrets: [String])
}

struct LiveMCPProxySessionClient: MCPProxySessionClient, @unchecked Sendable {
    let client: AuthsiaBridgeClient

    init(client: AuthsiaBridgeClient = .shared) {
        self.client = client
    }

    func prepareChildEnvironment(
        declared: [String: String],
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL
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
            references: references
        )
        return try client.withRequestedCommand("exec", includeAutomationCredential: false) {
            _ = try client.agentJITPreflight(
                payload,
                agentRuntimeContext: agentRuntimeContext,
                workspaceRoot: workspaceRoot
            )
            let resolved = try SecretReferenceResolver(
                client: MCPProxySecretResolver(
                    client: client,
                    agentRuntimeContext: agentRuntimeContext,
                    workspaceRoot: workspaceRoot
                )
            ).resolveEnvironment(declared)
            return (resolved.resolved, resolved.secrets)
        }
    }
}
