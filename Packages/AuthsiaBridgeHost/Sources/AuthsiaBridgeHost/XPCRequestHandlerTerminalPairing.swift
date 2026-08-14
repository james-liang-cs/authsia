#if os(macOS)
import Foundation
@preconcurrency import AuthenticatorBridge

extension XPCRequestHandler {
    public func completeTerminalPairing(
        _ request: Data,
        _ rawReply: @escaping (Data?, NSError?) -> Void
    ) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request),
              bridgeRequest.type == .terminalPairingComplete,
              let body = bridgeRequest.body,
              let payload = try? BridgeCoder.decode(TerminalPairingCompletionRequest.self, from: body) else {
            replyError(id: UUID(), code: .invalidRequest, message: "Invalid terminal pairing request", reply: reply)
            return
        }
        if let denial = BridgeRequestPolicy.denial(for: bridgeRequest) {
            replyError(id: bridgeRequest.id, code: denial.code, message: denial.message, reply: reply)
            return
        }

        let callerIdentity = callerIdentityProvider()
        Task { @MainActor [weak self] in
            guard let self else { return }
            let result = terminalPairingCoordinator.complete(
                id: payload.pairingRequestID,
                code: payload.code,
                request: bridgeRequest,
                callerIdentity: callerIdentity,
                pairingTTL: Self.configuredSessionTTL
            )
            switch result {
            case .retryRemaining:
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .requiresPairing,
                    message: "Pairing code did not match. One attempt remains.",
                    pairingRequestID: payload.pairingRequestID
                )
                reply(encodeResponse(response), nil)
            case .invalid:
                (approver as? TerminalPairingApproving)?.finishTerminalPairing(
                    id: payload.pairingRequestID
                )
                replyError(
                    id: bridgeRequest.id,
                    code: .policyDenied,
                    message: "Terminal pairing is invalid or expired.",
                    reply: reply
                )
            case .paired(let pairing):
                do {
                    try terminalPairingStore.save(pairing)
                } catch {
                    (approver as? TerminalPairingApproving)?.finishTerminalPairing(
                        id: payload.pairingRequestID
                    )
                    replyError(
                        id: bridgeRequest.id,
                        code: .appUnavailable,
                        message: "Failed to save terminal pairing.",
                        reply: reply
                    )
                    return
                }
                guard let session = Self.sharedSessionManager.createSessionOrNil(
                    ttlSeconds: Self.configuredSessionTTL,
                    scope: bridgeRequest.context.sessionScope,
                    workingDirectory: pairing.workspaceRoot,
                    origin: Self.sessionOrigin(from: callerIdentity, request: bridgeRequest),
                    approvedBy: "paired-human"
                ) else {
                    _ = try? terminalPairingStore.revoke(id: pairing.id)
                    (approver as? TerminalPairingApproving)?.finishTerminalPairing(
                        id: payload.pairingRequestID
                    )
                    replyError(
                        id: bridgeRequest.id,
                        code: .appUnavailable,
                        message: "Session creation failed.",
                        reply: reply
                    )
                    return
                }

                (approver as? TerminalPairingApproving)?.finishTerminalPairing(
                    id: payload.pairingRequestID
                )
                recordAudit(
                    command: .terminalPairingComplete,
                    itemId: pairing.id.uuidString,
                    approvedBy: "paired-human",
                    caller: callerIdentity,
                    requestedCommand: bridgeRequest.context.requestedCommand,
                    terminalPairingID: pairing.id,
                    workspaceContext: bridgeRequest.context.workspaceContext
                )
                let response: BridgeResponse<TerminalPairingSessionPayload> = BridgeResponseBuilder.success(
                    id: bridgeRequest.id,
                    payload: TerminalPairingSessionPayload(
                        pairingID: pairing.id,
                        expiresAt: session.expiresAt,
                        ttlSeconds: Int(Self.configuredSessionTTL),
                        sessionToken: session.sessionToken
                    ),
                    sessionToken: session.sessionToken,
                    sessionExpiresAt: session.expiresAt
                )
                reply(encodeResponse(response), nil)
            }
        }
    }

}
#endif
