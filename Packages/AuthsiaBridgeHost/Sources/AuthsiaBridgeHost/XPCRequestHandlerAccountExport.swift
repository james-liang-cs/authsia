#if os(macOS)
import Foundation
import Security
@preconcurrency import AuthenticatorBridge
import AuthenticatorData
import AuthenticatorCore

extension XPCRequestHandler {
    public func auditVerify(_ request: Data, _ rawReply: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Failed to decode auditVerify request"))
            return
        }

        do {
            let isValid = try auditLogger.verifyIntegrity()
            let payload = AuditVerifyPayload(valid: isValid)
            let response: BridgeResponse<AuditVerifyPayload> = BridgeResponseBuilder.success(
                id: bridgeRequest.id,
                payload: payload
            )
            reply(encodeResponse(response), nil)
        } catch {
            let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                id: bridgeRequest.id,
                code: .appUnavailable,
                message: "Audit verification failed: \(error.localizedDescription)"
            )
            reply(encodeResponse(response), nil)
        }
    }

    public func exportAccounts(_ request: Data, _ rawReply: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Failed to decode exportAccounts request"))
            return
        }

        // Bulk 2FA export is intentionally high-friction and must never originate from
        // an automation credential — not even an `exec`-scoped one with an active session.
        // Explicit deny (rather than a capability check) keeps the policy obvious to
        // reviewers and prevents `--allow exec` from being silently widened.
        if AutomationAuthorizationPolicy.isExportDenied(for: bridgeRequest) {
            let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                id: bridgeRequest.id,
                code: .policyDenied,
                message: "Automation credentials are not permitted to export accounts."
            )
            reply(encodeResponse(response), nil)
            return
        }

        if let policyError = BridgeRequestPolicy.denial(for: bridgeRequest) {
            let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                id: bridgeRequest.id,
                code: policyError.code,
                message: policyError.message
            )
            reply(encodeResponse(response), nil)
            return
        }

        let callerIdentity = callerIdentityProvider()
        if let denial = Self.unsupportedAgentJITBridgeCommandDenial(
            for: bridgeRequest,
            callerIdentity: callerIdentity
        ) {
            replyError(id: bridgeRequest.id, code: denial.code, message: denial.message, reply: reply)
            return
        }

        let callback = NSXPCConnection.current()?.remoteObjectProxy as? AuthsiaBridgeApprovalCallbackProtocol

        let exportPayload = bridgeRequest.body.flatMap { try? BridgeCoder.decode(ExportAccountsRequestPayload.self, from: $0) }
        let password = exportPayload?.password

        Task { @MainActor [weak self] in
            guard let self else { return }

            guard Self.isCliAccessEnabled else {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .policyDenied,
                    message: "CLI access is disabled"
                )
                reply(self.encodeResponse(response), nil)
                return
            }

            // Export is a bulk operation — always require explicit local approval or a valid session.
            var newSessionToken: String?
            var newSessionExpiresAt: Date?
            var interactiveApprovalAttribution: String?
            let sessionToken = bridgeRequest.sessionToken
            let needsApproval = !self.validateSessionAndRequest(bridgeRequest, sessionToken: sessionToken, callerIdentity: callerIdentity)
            if needsApproval {
                let authorization = await self.requestLocalApproval(
                    prompt: "Allow CLI to export all 2FA accounts",
                    command: .exportAccounts,
                    itemLabel: nil,
                    field: nil,
                    callback: callback
                )
                guard case .allowed(_, let attribution) = authorization else {
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: .notAuthorized,
                        message: "Access denied"
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }
                interactiveApprovalAttribution = attribution
                let session = self.issueReusableHumanSession(
                    for: bridgeRequest,
                    callerIdentity: callerIdentity
                )
                guard !session.failed else {
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: .appUnavailable,
                        message: "Session creation failed"
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }
                newSessionToken = session.token
                newSessionExpiresAt = session.expiresAt
            }

            do {
                let jsonData = try await AccountRepository.shared.exportAccounts()
                let outputData: Data
                let isEncrypted: Bool
                let ext: String
                if let password {
                    outputData = try ExportEncryptor.encrypt(data: jsonData, password: password)
                    isEncrypted = true
                    ext = "authsia"
                } else {
                    outputData = jsonData
                    isEncrypted = false
                    ext = "json"
                }
                let date = ISO8601DateFormatter().string(from: Date()).prefix(10)
                let filename = "authenticator-backup-\(date).\(ext)"
                let payload = ExportAccountsPayload(
                    data: outputData.base64EncodedString(),
                    encrypted: isEncrypted,
                    suggestedFilename: String(filename)
                )
                let response: BridgeResponse<ExportAccountsPayload> = BridgeResponseBuilder.success(
                    id: bridgeRequest.id,
                    payload: payload,
                    sessionToken: newSessionToken,
                    sessionExpiresAt: newSessionExpiresAt
                )
                self.recordAudit(
                    command: .exportAccounts,
                    itemId: "all-accounts",
                    itemName: "All Accounts",
                    approvedBy: interactiveApprovalAttribution ?? "session",
                    caller: callerIdentity,
                    requestedCommand: bridgeRequest.context.requestedCommand,
                    fullCommand: bridgeRequest.context.fullCommand,
                    agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                    workspaceContext: bridgeRequest.context.workspaceContext
                )
                reply(self.encodeResponse(response), nil)
            } catch {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .appUnavailable,
                    message: "Export failed: \(error.localizedDescription)"
                )
                reply(self.encodeResponse(response), nil)
            }
        }
    }

}
#endif
