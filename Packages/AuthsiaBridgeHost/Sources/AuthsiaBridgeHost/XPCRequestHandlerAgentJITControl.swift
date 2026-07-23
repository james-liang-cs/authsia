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
        guard isAuthorizedGrantControlCaller else {
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
            let grants = try agentJITGrantStore.loadAll()
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
        guard isAuthorizedGrantControlCaller else {
            replyError(
                id: bridgeRequest.id,
                code: .policyDenied,
                message: "JIT grant control is restricted to Authsia.app",
                reply: reply
            )
            return
        }

        do {
            let revoked = try agentJITGrantStore.revoke(
                id: payload.id,
                revokedAt: agentJITApprovalClock()
            )
            recordGrantRevocation(revoked)
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
        guard isAuthorizedGrantControlCaller else {
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
            revoked.forEach(recordGrantRevocation)
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

    private func recordGrantRevocation(_ grant: AgentJITGrant) {
        try? auditLogger.record(
            BridgeAuditRecord(
                command: .agentJITPreflight,
                itemId: grant.id.uuidString,
                itemName: grant.folderScope.displayName,
                approvedBy: "revoked",
                timestamp: grant.revokedAt ?? agentJITApprovalClock(),
                agentJITGrantID: grant.id
            )
        )
    }

    private var isAuthorizedGrantControlCaller: Bool {
        callerIdentityProvider()?.bundleIdentifier == "app.authsia"
    }
}
#endif
