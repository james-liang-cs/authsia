#if os(macOS)
import Foundation
import Security
@preconcurrency import AuthenticatorBridge
import AuthenticatorData
import AuthenticatorCore

extension XPCRequestHandler {
    public func list(_ request: Data, _ rawReply: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Failed to decode list request"))
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

        let callback = NSXPCConnection.current()?.remoteObjectProxy as? AuthsiaBridgeApprovalCallbackProtocol
        Task { @MainActor [weak self] in
            guard let self else { return }

            // Check global CLI access first (before approval)
            guard Self.isCliAccessEnabled else {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .policyDenied,
                    message: "CLI access is disabled"
                )
                reply(self.encodeResponse(response), nil)
                return
            }

            if bridgeRequest.type == .workspaceMetadata {
                // Served while the app is locked on purpose: the payload is scoped,
                // non-secret metadata (names/folders and targeted existence state only),
                // and the lock is routinely engaged in the headless helper where no unlock UI exists.
                do {
                    var payload = try BridgeWorkspaceMetadataFilter.filteredPayload(
                        try await self.currentWorkspaceMetadataPayload(for: bridgeRequest),
                        for: bridgeRequest
                    )
                    if bridgeRequest.context.requestedCommand == BridgeContext.workspaceEnvValidateRequestedCommand ||
                        bridgeRequest.context.requestedCommand == BridgeContext.workspaceRunRequestedCommand {
                        payload = BridgeListPayloadFactory.validationPayload(
                            payload,
                            passwordHasSecret: self.passwordSecretExistenceProvider,
                            apiKeyHasSecret: self.apiKeySecretExistenceProvider
                        )
                    }
                    self.recordAudit(
                        command: .workspaceMetadata,
                        itemId: bridgeRequest.context.workspaceContext?.authsiaFolder ?? "workspace",
                        itemName: bridgeRequest.context.workspaceContext?.displayName,
                        approvedBy: "workspace-metadata",
                        caller: callerIdentity,
                        requestedCommand: bridgeRequest.context.requestedCommand,
                        fullCommand: bridgeRequest.context.fullCommand,
                        agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                        workspaceContext: bridgeRequest.context.workspaceContext
                    )
                    let response: BridgeResponse<BridgeListPayload> = BridgeResponseBuilder.success(
                        id: bridgeRequest.id,
                        payload: payload
                    )
                    reply(self.encodeResponse(response), nil)
                } catch {
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: .policyDenied,
                        message: error.localizedDescription
                    )
                    reply(self.encodeResponse(response), nil)
                }
                return
            }

            guard bridgeRequest.type == .list else {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .invalidRequest,
                    message: "Invalid list request type"
                )
                reply(self.encodeResponse(response), nil)
                return
            }

            // Validate session and request for replay protection
            var newSessionToken: String?
            var newSessionExpiresAt: Date?
            let sessionToken = bridgeRequest.sessionToken
            guard let bypassApproval = self.resolveAutomationApproval(
                for: bridgeRequest, itemFolderPath: nil, itemKind: "list", reply: reply
            ) else { return }
            let interactiveHumanBootstrap = Self.interactiveHumanBootstrapEligible(request: bridgeRequest)
            let callerUsesAgentJIT = !bypassApproval
                && Self.isAgentJITCaller(request: bridgeRequest, callerIdentity: callerIdentity)
                && !interactiveHumanBootstrap
            let jitListScopes: [AgentJITFolderScope]
            if !callerUsesAgentJIT {
                jitListScopes = []
            } else {
                do {
                    jitListScopes = try self.activeAgentJITScopes(
                        capability: .list,
                        request: bridgeRequest,
                        callerIdentity: callerIdentity
                    )
                } catch {
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: .policyDenied,
                        message: "JIT list scope lookup failed. Run agent JIT preflight again."
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }
            }
            let agentCommandListWithoutJIT = bridgeRequest.context.requestedCommand != "list"
                && jitListScopes.isEmpty
                && !bypassApproval
                && callerUsesAgentJIT
            let agentDirectListWithoutJIT = bridgeRequest.context.requestedCommand == "list"
                && jitListScopes.isEmpty
                && !bypassApproval
                && callerUsesAgentJIT
            if agentDirectListWithoutJIT {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .policyDenied,
                    message: "Agent list requests require a valid JIT preflight grant for a supported Vault scope."
                )
                reply(self.encodeResponse(response), nil)
                return
            }
            if agentCommandListWithoutJIT,
               let message = Self.unsupportedAgentJITCommandMessage(
                    for: bridgeRequest.context.requestedCommand
               ) {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .policyDenied,
                    message: message
                )
                reply(self.encodeResponse(response), nil)
                return
            }
            let needsApproval = !bypassApproval
                && jitListScopes.isEmpty
                && !agentCommandListWithoutJIT
                && !self.validateSessionAndRequest(bridgeRequest, sessionToken: sessionToken)

            if needsApproval {
                // A direct CLI command (e.g. `code`, `read`) bootstraps its session via a
                // `.list` request that carries the real verb in `requestedCommand`. Phrase the
                // prompt from that verb so the user isn't told this is a "list" when it isn't.
                let approvalPrompt: String
                if let requestedCommand = bridgeRequest.context.requestedCommand, requestedCommand != "list" {
                    approvalPrompt = "Allow CLI to run '\(requestedCommand)'"
                } else {
                    approvalPrompt = "Allow CLI to list items"
                }
                let approved = await self.approver.requestApproval(
                    prompt: approvalPrompt,
                    command: .list,
                    itemLabel: nil,
                    field: nil,
                    callback: callback
                )
                guard approved else {
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: .notAuthorized,
                        message: "Access denied"
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }
                guard let session = Self.sharedSessionManager.createSessionOrNil(
                    ttlSeconds: Self.configuredSessionTTL,
                    scope: bridgeRequest.context.sessionScope,
                    workingDirectory: bridgeRequest.context.workingDirectory,
                    origin: sessionOrigin(from: callerIdentity)
                ) else {
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: .appUnavailable,
                        message: "Session creation failed"
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }
                newSessionToken = session.sessionToken
                newSessionExpiresAt = session.expiresAt
            }

            do {
                let payload = self.filteredListPayload(
                    try self.currentListPayload(),
                    for: bridgeRequest,
                    callerIdentity: callerIdentity,
                    activeJITScopes: jitListScopes,
                    callerUsesAgentJIT: callerUsesAgentJIT
                )
                let response: BridgeResponse<BridgeListPayload> = BridgeResponseBuilder.success(
                    id: bridgeRequest.id,
                    payload: payload,
                    sessionToken: newSessionToken,
                    sessionExpiresAt: newSessionExpiresAt
                )
                // Audit only direct `authsia list` invocations. Bootstrap lists
                // issued by other commands carry that command's verb and are
                // already represented by their own audit records.
                if bridgeRequest.context.requestedCommand == "list" {
                    self.recordAudit(
                        command: .list,
                        itemId: "list",
                        itemName: nil,
                        approvedBy: bypassApproval ? "automation" : (needsApproval ? "biometric" : "session"),
                        caller: callerIdentity,
                        requestedCommand: bridgeRequest.context.requestedCommand,
                        fullCommand: bridgeRequest.context.fullCommand,
                        agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                        workspaceContext: bridgeRequest.context.workspaceContext
                    )
                }
                reply(self.encodeResponse(response), nil)
            } catch {
                let (code, message) = BridgeListFailureMapper.mapping(for: error)
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: code,
                    message: message
                )
                reply(self.encodeResponse(response), nil)
            }
        }
    }

}
#endif
