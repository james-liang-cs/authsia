import AuthenticatorBridge
import Foundation

protocol MCPGrantClient: Sendable {
    func agentJITSnapshot(
        agentRuntimeContext: AgentRuntimeContext
    ) throws -> AgentJITGrantSnapshotPayload
    func revokeAgentJITGrant(
        id: UUID,
        agentRuntimeContext: AgentRuntimeContext
    ) throws -> AgentJITGrantMutationPayload
}

extension AuthsiaBridgeClient: MCPGrantClient {}

enum MCPGrantServiceError: Error, Equatable {
    case invalidGrantID
    case grantNotOwned
    case grantUnavailable
}

struct MCPGrantService: @unchecked Sendable {
    let serverInstanceID: UUID
    let client: any MCPGrantClient

    init(
        serverInstanceID: UUID,
        client: any MCPGrantClient = AuthsiaBridgeClient.shared
    ) {
        self.serverInstanceID = serverInstanceID
        self.client = client
    }

    func status(now: Date = Date()) throws -> MCPAccessStatusOutput {
        let snapshot = try client.agentJITSnapshot(agentRuntimeContext: runtimeContext)
        let grants = (snapshot.active + snapshot.history)
            .filter(isOwned)
            .sorted { $0.createdAt > $1.createdAt }
            .map { summary($0, now: now) }
        return MCPAccessStatusOutput(grants: grants)
    }

    func revoke(
        _ rawID: String,
        agentRuntimeContext: AgentRuntimeContext,
        now: Date = Date()
    ) throws -> MCPAccessRevokeOutput {
        guard let id = UUID(uuidString: rawID) else {
            throw MCPGrantServiceError.invalidGrantID
        }
        let snapshot = try client.agentJITSnapshot(agentRuntimeContext: agentRuntimeContext)
        guard let grant = (snapshot.active + snapshot.history).first(where: { $0.id == id }),
              isOwned(grant) else {
            throw MCPGrantServiceError.grantNotOwned
        }
        switch grant.status(asOf: now) {
        case .expired:
            throw MCPGrantServiceError.grantUnavailable
        case .revoked:
            return MCPAccessRevokeOutput(
                grantID: id.uuidString,
                status: "revoked",
                revokedAt: grant.revokedAt
            )
        case .active:
            _ = try client.revokeAgentJITGrant(
                id: id,
                agentRuntimeContext: agentRuntimeContext
            )
            return MCPAccessRevokeOutput(
                grantID: id.uuidString,
                status: "revoked",
                revokedAt: now
            )
        }
    }

    func revokeActiveOwnedGrants(now: Date = Date()) {
        guard let snapshot = try? client.agentJITSnapshot(agentRuntimeContext: runtimeContext) else {
            return
        }
        for grant in snapshot.active where isOwned(grant) && grant.status(asOf: now) == .active {
            _ = try? client.revokeAgentJITGrant(
                id: grant.id,
                agentRuntimeContext: runtimeContext
            )
        }
    }

    func activeOwnedGrantIDs(now: Date = Date()) throws -> Set<UUID> {
        let snapshot = try client.agentJITSnapshot(agentRuntimeContext: runtimeContext)
        return Set(snapshot.active.compactMap { grant in
            guard isOwned(grant), grant.status(asOf: now) == .active else { return nil }
            return grant.id
        })
    }

    private var runtimeContext: AgentRuntimeContext {
        AgentRuntimeContext(
            sessionID: "mcp:\(serverInstanceID.uuidString)",
            agentType: "authsia-mcp"
        )
    }

    private func isOwned(_ grant: AgentJITGrant) -> Bool {
        grant.agentRuntimeContext?.agentType == "authsia-mcp"
            && grant.matchesAgentRuntimeContext(runtimeContext)
    }

    private func summary(_ grant: AgentJITGrant, now: Date) -> MCPGrantSummary {
        MCPGrantSummary(
            grantID: grant.id.uuidString,
            status: grant.status(asOf: now).rawValue,
            sourceLabel: grant.agentName,
            scopeSummary: grant.folderScope.displayName,
            itemCount: grant.requestedItems.count,
            capabilities: grant.capabilities.map(\.rawValue).sorted(),
            environment: environmentName(grant.environmentScope),
            createdAt: grant.createdAt,
            expiresAt: grant.expiresAt,
            lastUsedAt: grant.lastUsedAt,
            revokedAt: grant.revokedAt,
            approvedBy: grant.approvedBy,
            serverInstanceID: serverInstanceID.uuidString,
            invocationID: grant.agentRuntimeContext?.toolUseID
        )
    }

    private func environmentName(_ scope: EnvironmentAccessScope?) -> String? {
        switch scope {
        case .defaultOnly:
            return "default"
        case .named(let name):
            return name
        case nil:
            return nil
        }
    }
}
