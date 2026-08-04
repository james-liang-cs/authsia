#if os(macOS)
import Foundation
@preconcurrency import AuthenticatorBridge

extension XPCRequestHandler {
    public func agentJITSnapshot(
        _ request: Data,
        _ rawReply: @escaping (Data?, NSError?) -> Void
    ) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request),
              bridgeRequest.type == .agentJITSnapshot else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Invalid JIT snapshot request"))
            return
        }
        guard let controlScope = authorizedGrantControlScope(for: bridgeRequest) else {
            replyError(
                id: bridgeRequest.id,
                code: .policyDenied,
                message: "JIT grant control is restricted to Authsia.app",
                reply: reply
            )
            return
        }

        do {
            let now = agentJITApprovalClock()
            _ = try agentJITGrantStore.revokeClosedTerminalGrants(now: now)
            let grants = try agentJITGrantStore.loadAll().filter {
                controlScope.allows($0)
            }
            let payload = AgentJITGrantSnapshotPayload(
                active: grants.filter { $0.status(asOf: now) == .active },
                history: grants.filter { $0.status(asOf: now) != .active }
            )
            let response: BridgeResponse<AgentJITGrantSnapshotPayload> =
                BridgeResponseBuilder.success(id: bridgeRequest.id, payload: payload)
            reply(encodeResponse(response), nil)
        } catch {
            replyError(
                id: bridgeRequest.id,
                code: .appUnavailable,
                message: "JIT grant snapshot is unavailable",
                reply: reply
            )
        }
    }

    public func revokeAgentJITGrant(
        _ request: Data,
        _ rawReply: @escaping (Data?, NSError?) -> Void
    ) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request),
              bridgeRequest.type == .agentJITRevoke,
              let body = bridgeRequest.body,
              let payload = try? BridgeCoder.decode(AgentJITGrantRevokePayload.self, from: body) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Invalid JIT revocation request"))
            return
        }
        guard let controlScope = authorizedGrantControlScope(for: bridgeRequest) else {
            replyError(
                id: bridgeRequest.id,
                code: .policyDenied,
                message: "JIT grant control is restricted to Authsia.app",
                reply: reply
            )
            return
        }

        do {
            guard let existing = try agentJITGrantStore.loadAll().first(where: {
                $0.id == payload.id
            }), controlScope.allows(existing) else {
                replyError(
                    id: bridgeRequest.id,
                    code: .policyDenied,
                    message: "JIT grant is not owned by this MCP server",
                    reply: reply
                )
                return
            }
            if existing.revokedAt != nil {
                replyMutationSuccess(
                    id: bridgeRequest.id,
                    revokedGrantIDs: [existing.id],
                    reply: reply
                )
                return
            }
            let revoked = try agentJITGrantStore.revoke(
                id: payload.id,
                revokedAt: agentJITApprovalClock()
            )
            recordGrantRevocation(revoked, requestContext: bridgeRequest.context)
            postAgentJITGrantDidChange()
            replyMutationSuccess(
                id: bridgeRequest.id,
                revokedGrantIDs: [revoked.id],
                reply: reply
            )
        } catch AgentJITGrantStoreError.notFound {
            replyError(
                id: bridgeRequest.id,
                code: .notFound,
                message: "JIT grant was not found",
                reply: reply
            )
        } catch {
            replyError(
                id: bridgeRequest.id,
                code: .appUnavailable,
                message: "JIT grant could not be revoked",
                reply: reply
            )
        }
    }

    public func revokeAllAgentJITGrants(
        _ request: Data,
        _ rawReply: @escaping (Data?, NSError?) -> Void
    ) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request),
              bridgeRequest.type == .agentJITRevokeAll else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Invalid revoke-all request"))
            return
        }
        guard callerIdentityProvider()?.bundleIdentifier == "app.authsia" else {
            replyError(
                id: bridgeRequest.id,
                code: .policyDenied,
                message: "JIT grant control is restricted to Authsia.app",
                reply: reply
            )
            return
        }

        do {
            let revoked = try agentJITGrantStore.revokeAll(revokedAt: agentJITApprovalClock())
            revoked.forEach {
                recordGrantRevocation($0, requestContext: bridgeRequest.context)
            }
            if !revoked.isEmpty {
                postAgentJITGrantDidChange()
            }
            replyMutationSuccess(
                id: bridgeRequest.id,
                revokedGrantIDs: revoked.map(\.id),
                reply: reply
            )
        } catch {
            replyError(
                id: bridgeRequest.id,
                code: .appUnavailable,
                message: "JIT grants could not be revoked",
                reply: reply
            )
        }
    }

    private func replyMutationSuccess(
        id: UUID,
        revokedGrantIDs: [UUID],
        reply: XPCReply
    ) {
        let payload = AgentJITGrantMutationPayload(revokedGrantIDs: revokedGrantIDs)
        let response: BridgeResponse<AgentJITGrantMutationPayload> =
            BridgeResponseBuilder.success(id: id, payload: payload)
        reply(encodeResponse(response), nil)
    }

    /// Notifies the app (a separate process) that the JIT grant set changed so Access
    /// Center refreshes immediately instead of waiting for its periodic poll. Mirrors the
    /// `.agentLeakIncidentDidRecord` distributed-notification pattern.
    func postAgentJITGrantDidChange() {
        DistributedNotificationCenter.default().post(
            name: .agentJITGrantDidChange,
            object: nil
        )
    }

    private func recordGrantRevocation(
        _ grant: AgentJITGrant,
        requestContext: BridgeContext
    ) {
        try? auditLogger.record(
            BridgeAuditRecord(
                command: .agentJITPreflight,
                itemId: grant.id.uuidString,
                itemName: grant.folderScope.displayName,
                approvedBy: "revoked",
                timestamp: grant.revokedAt ?? agentJITApprovalClock(),
                requestedCommand: requestContext.requestedCommand,
                fullCommand: requestContext.fullCommand,
                agentJITGrantID: grant.id,
                agentRuntimeContext: requestContext.agentRuntimeContext,
                workspaceContext: requestContext.workspaceContext,
                environmentScope: grant.environmentScope
            )
        )
    }

    private enum GrantControlScope {
        case all
        case mcp(AgentRuntimeContext)

        func allows(_ grant: AgentJITGrant) -> Bool {
            switch self {
            case .all:
                return true
            case .mcp(let context):
                return grant.agentRuntimeContext?.agentType == "authsia-mcp"
                    && grant.matchesAgentRuntimeContext(context)
            }
        }
    }

    private func authorizedGrantControlScope(for request: BridgeRequest) -> GrantControlScope? {
        switch callerIdentityProvider()?.bundleIdentifier {
        case "app.authsia":
            return .all
        case "com.authsia.cli":
            guard let context = request.context.agentRuntimeContext,
                  context.agentType == "authsia-mcp",
                  AgentRuntimeContext.sanitize(context.sessionID) != nil else {
                return nil
            }
            return .mcp(context)
        default:
            return nil
        }
    }
}
#endif
