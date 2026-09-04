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
        mcpUpstreamCommand: String?,
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
        mcpUpstreamCommand: String? = nil,
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
            mcpUpstreamCommand: mcpUpstreamCommand,
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

protocol MCPProxyActivityAuditing: Sendable {
    func recordMCPProxyActivity(
        _ payload: MCPProxyActivityPayload,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?
    ) throws
}

extension AuthsiaBridgeClient: MCPProxyActivityAuditing {}

protocol MCPProxyToolCallRecording: Sendable {
    func record(
        upstreamName: String,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?,
        grantID: UUID?
    ) throws

    func recordRejected(
        upstreamName: String,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?,
        grantID: UUID?,
        outcome: MCPProxyCallOutcome
    ) throws

    func recordOutcome(
        upstreamName: String,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?,
        grantID: UUID?,
        outcome: MCPProxyCallOutcome
    ) throws
}

extension MCPProxyToolCallRecording {
    func recordRejected(
        upstreamName: String,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?,
        grantID: UUID?,
        outcome: MCPProxyCallOutcome
    ) throws {
        _ = (upstreamName, upstreamCommand, toolName, agentRuntimeContext, workspaceRoot, grantID, outcome)
    }

    func recordOutcome(
        upstreamName: String,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?,
        grantID: UUID?,
        outcome: MCPProxyCallOutcome
    ) throws {
        _ = (upstreamName, upstreamCommand, toolName, agentRuntimeContext, workspaceRoot, grantID, outcome)
    }
}

struct LiveMCPProxyToolCallRecorder: MCPProxyToolCallRecording, @unchecked Sendable {
    private let store: AgentCommandHistoryStore
    private let auditor: (any MCPProxyActivityAuditing)?

    init(
        store: AgentCommandHistoryStore = AgentCommandHistoryStore(),
        auditor: (any MCPProxyActivityAuditing)? = AuthsiaBridgeClient.shared
    ) {
        self.store = store
        self.auditor = auditor
    }

    func record(
        upstreamName: String,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?,
        grantID: UUID?
    ) throws {
        try persist(
            upstreamName: upstreamName,
            upstreamCommand: upstreamCommand,
            toolName: toolName,
            agentRuntimeContext: agentRuntimeContext,
            workspaceRoot: workspaceRoot,
            grantID: grantID,
            outcome: .started
        )
    }

    func recordRejected(
        upstreamName: String,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?,
        grantID: UUID?,
        outcome: MCPProxyCallOutcome
    ) throws {
        try persist(
            upstreamName: upstreamName,
            upstreamCommand: upstreamCommand,
            toolName: toolName,
            agentRuntimeContext: agentRuntimeContext,
            workspaceRoot: workspaceRoot,
            grantID: grantID,
            outcome: outcome
        )
    }

    func recordOutcome(
        upstreamName: String,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?,
        grantID: UUID?,
        outcome: MCPProxyCallOutcome
    ) throws {
        try persist(
            upstreamName: upstreamName,
            upstreamCommand: upstreamCommand,
            toolName: toolName,
            agentRuntimeContext: agentRuntimeContext,
            workspaceRoot: workspaceRoot,
            grantID: grantID,
            outcome: outcome
        )
    }

    private func persist(
        upstreamName: String,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?,
        grantID: UUID?,
        outcome: MCPProxyCallOutcome
    ) throws {
        if let auditor {
            try auditor.recordMCPProxyActivity(
                MCPProxyActivityPayload(
                    toolName: toolName,
                    outcome: outcome,
                    invocationID: Self.invocationID(from: agentRuntimeContext),
                    grantID: grantID,
                    upstreamName: upstreamName,
                    workspaceRoot: workspaceRoot?.path
                ),
                agentRuntimeContext: agentRuntimeContext,
                workspaceRoot: workspaceRoot
            )
        }
        try store.record(event(
            upstreamName: upstreamName,
            upstreamCommand: upstreamCommand,
            toolName: toolName,
            agentRuntimeContext: agentRuntimeContext,
            workspaceRoot: workspaceRoot,
            grantID: grantID,
            outcome: outcome
        ))
    }

    private func event(
        upstreamName: String,
        upstreamCommand: String?,
        toolName: String,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL?,
        grantID: UUID?,
        outcome: MCPProxyCallOutcome
    ) -> AgentCommandEvent {
        let executable = upstreamCommand ?? upstreamName
        return AgentCommandEvent(
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
            command: "\(executable) mcp-tool \(toolName)",
            mcpProxyOutcome: outcome
        )
    }

    private static func invocationID(from context: AgentRuntimeContext) -> UUID {
        let prefix = "mcp-call:"
        if let toolUseID = context.toolUseID, toolUseID.hasPrefix(prefix),
           let uuid = UUID(uuidString: String(toolUseID.dropFirst(prefix.count))) {
            return uuid
        }
        return UUID()
    }
}
