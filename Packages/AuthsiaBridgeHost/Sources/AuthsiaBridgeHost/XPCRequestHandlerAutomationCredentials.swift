#if os(macOS)
import Foundation
@preconcurrency import AuthenticatorBridge

extension XPCRequestHandler {
    public func listAccessCredentials(
        _ request: Data,
        _ rawReply: @escaping (Data?, NSError?) -> Void
    ) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request),
              bridgeRequest.type == .listAccess,
              let body = bridgeRequest.body,
              let payload = try? BridgeCoder.decode(
                AutomationCredentialListRequestPayload.self,
                from: body
              ) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Invalid access list request"))
            return
        }
        if let policyError = BridgeRequestPolicy.denial(for: bridgeRequest) {
            replyError(
                id: bridgeRequest.id,
                code: policyError.code,
                message: policyError.message,
                reply: reply
            )
            return
        }
        guard !bridgeRequest.context.hasAutomationCredential else {
            replyError(
                id: bridgeRequest.id,
                code: .policyDenied,
                message: "Automation credentials cannot manage access credentials",
                reply: reply
            )
            return
        }
        guard Self.isCliAccessEnabled else {
            replyError(
                id: bridgeRequest.id,
                code: .policyDenied,
                message: "CLI access is disabled",
                reply: reply
            )
            return
        }
        if let denial = Self.unsupportedAgentJITBridgeCommandDenial(
            for: bridgeRequest,
            callerIdentity: callerIdentityProvider()
        ) {
            replyError(
                id: bridgeRequest.id,
                code: denial.code,
                message: denial.message,
                reply: reply
            )
            return
        }

        do {
            let credentials = try automationCredentialAuthorityProvider().list(
                includeAll: payload.includeAll,
                now: agentJITApprovalClock()
            )
            let response: BridgeResponse<AutomationCredentialListPayload> =
                BridgeResponseBuilder.success(
                    id: bridgeRequest.id,
                    payload: AutomationCredentialListPayload(credentials: credentials)
                )
            reply(encodeResponse(response), nil)
        } catch {
            replyError(
                id: bridgeRequest.id,
                code: .appUnavailable,
                message: "Access credentials are unavailable",
                reply: reply
            )
        }
    }

    public func revokeAccessCredential(
        _ request: Data,
        _ rawReply: @escaping (Data?, NSError?) -> Void
    ) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request),
              bridgeRequest.type == .revokeAccess,
              let body = bridgeRequest.body,
              let payload = try? BridgeCoder.decode(
                AutomationCredentialRevokePayload.self,
                from: body
              ) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Invalid access revoke request"))
            return
        }
        if let policyError = BridgeRequestPolicy.denial(for: bridgeRequest) {
            replyError(
                id: bridgeRequest.id,
                code: policyError.code,
                message: policyError.message,
                reply: reply
            )
            return
        }
        guard !bridgeRequest.context.hasAutomationCredential else {
            replyError(
                id: bridgeRequest.id,
                code: .policyDenied,
                message: "Automation credentials cannot manage access credentials",
                reply: reply
            )
            return
        }
        guard Self.isCliAccessEnabled else {
            replyError(
                id: bridgeRequest.id,
                code: .policyDenied,
                message: "CLI access is disabled",
                reply: reply
            )
            return
        }
        if let denial = Self.unsupportedAgentJITBridgeCommandDenial(
            for: bridgeRequest,
            callerIdentity: callerIdentityProvider()
        ) {
            replyError(
                id: bridgeRequest.id,
                code: denial.code,
                message: denial.message,
                reply: reply
            )
            return
        }

        do {
            let credential = try automationCredentialAuthorityProvider().revoke(
                id: payload.id,
                at: agentJITApprovalClock()
            )
            recordAudit(
                command: .revokeAccess,
                itemId: credential.id.uuidString,
                itemName: credential.name,
                approvedBy: "automation-management",
                caller: callerIdentityProvider(),
                requestedCommand: bridgeRequest.context.requestedCommand
            )
            let response: BridgeResponse<AutomationCredentialMetadata> =
                BridgeResponseBuilder.success(id: bridgeRequest.id, payload: credential)
            reply(encodeResponse(response), nil)
        } catch AutomationCredentialAuthorityError.notFound {
            replyError(
                id: bridgeRequest.id,
                code: .notFound,
                message: "Access credential was not found",
                reply: reply
            )
        } catch {
            replyError(
                id: bridgeRequest.id,
                code: .appUnavailable,
                message: "Access credential could not be revoked",
                reply: reply
            )
        }
    }

    public func validateAccessCredential(
        _ request: Data,
        _ rawReply: @escaping (Data?, NSError?) -> Void
    ) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request),
              bridgeRequest.type == .validateAccess,
              let body = bridgeRequest.body,
              let payload = try? BridgeCoder.decode(
                AutomationCredentialValidatePayload.self,
                from: body
              ) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Invalid access validation request"))
            return
        }
        guard let machineId = currentMachineIdProvider() else {
            replyError(
                id: bridgeRequest.id,
                code: .policyDenied,
                message: "This machine has no Authsia identity",
                reply: reply
            )
            return
        }

        do {
            let credential = try automationCredentialAuthorityProvider().validate(
                token: payload.token,
                requestedCommand: payload.requestedCommand,
                currentMachineId: machineId,
                now: agentJITApprovalClock()
            )
            recordAudit(
                command: .validateAccess,
                itemId: credential.id.uuidString,
                itemName: credential.name,
                approvedBy: "automation",
                caller: callerIdentityProvider(),
                requestedCommand: bridgeRequest.context.requestedCommand
            )
            let response: BridgeResponse<AutomationCredentialValidationPayload> =
                BridgeResponseBuilder.success(
                    id: bridgeRequest.id,
                    payload: AutomationCredentialValidationPayload(credential: credential)
                )
            reply(encodeResponse(response), nil)
        } catch {
            replyError(
                id: bridgeRequest.id,
                code: .policyDenied,
                message: "Automation credential is invalid or unavailable",
                reply: reply
            )
        }
    }
}
#endif
