#if os(macOS)
import Foundation
import Security
@preconcurrency import AuthenticatorBridge
import AuthenticatorData
import AuthenticatorCore

extension XPCRequestHandler {
    // MARK: - AuthsiaBridgeXPCProtocol

    public func ping(_ rawReply: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(rawReply)
        let currentSession = Self.sharedSessionManager.currentSession
        let payload = BridgePingPayload(
            protocolVersion: String(BridgeContext.securityProtocolVersion),
            appVersion: runningAppVersion(),
            bundledCLIPath: bundledCLIHelperPath(),
            sessionActive: currentSession != nil,
            sessionExpiresAt: currentSession?.expiresAt
        )
        let requestId = UUID()
        let response: BridgeResponse<BridgePingPayload> = BridgeResponseBuilder.success(id: requestId, payload: payload)

        do {
            let data = try BridgeCoder.encode(response)
            reply(data, nil)
        } catch {
            reply(nil, makeNSError(code: .invalidRequest, message: "Failed to encode ping response"))
        }
    }

    public func status(_ request: Data, _ rawReply: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Failed to decode status request"))
            return
        }

        let currentSession = Self.sharedSessionManager.currentSession(scope: bridgeRequest.context.sessionScope)
        let payload = BridgePingPayload(
            protocolVersion: String(BridgeContext.securityProtocolVersion),
            appVersion: runningAppVersion(),
            bundledCLIPath: bundledCLIHelperPath(),
            sessionActive: currentSession != nil,
            sessionExpiresAt: currentSession?.expiresAt
        )
        let response: BridgeResponse<BridgePingPayload> = BridgeResponseBuilder.success(
            id: bridgeRequest.id,
            payload: payload
        )

        do {
            let data = try BridgeCoder.encode(response)
            reply(data, nil)
        } catch {
            reply(nil, makeNSError(code: .invalidRequest, message: "Failed to encode status response"))
        }
    }

    private func runningAppVersion() -> String? {
        let infoURL = URL(fileURLWithPath: appBundlePath)
            .appendingPathComponent("Contents/Info.plist")
        if let info = NSDictionary(contentsOf: infoURL) as? [String: Any],
           let version = info["CFBundleShortVersionString"] as? String {
            return version
        }
        return Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
    }

    private func bundledCLIHelperPath() -> String? {
        let path = URL(fileURLWithPath: appBundlePath)
            .appendingPathComponent("Contents/Helpers/authsia")
            .path
        return FileManager.default.fileExists(atPath: path) ? path : nil
    }

    public func unlock(_ request: Data, _ rawReply: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Failed to decode unlock request"))
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
        guard AgentJITCallerContext.isTrustedHumanTerminal(callerIdentity) else {
            replyError(
                id: bridgeRequest.id,
                code: .policyDenied,
                message: "Reusable CLI sessions require a signed, supported terminal host.",
                reply: reply
            )
            return
        }

        let callback = NSXPCConnection.current()?.remoteObjectProxy as? AuthsiaBridgeApprovalCallbackProtocol
        Task { @MainActor [weak self] in
            guard let self else { return }

            let ttlSeconds = Self.configuredSessionTTL
            let authorization = await self.requestLocalApproval(
                prompt: "Unlock CLI session for \(Int(ttlSeconds)) seconds",
                command: .unlock,
                itemLabel: nil,
                field: nil,
                callback: callback
            )

            guard case .allowed(_, let approvalAttribution) = authorization else {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .notAuthorized,
                    message: "Unlock denied"
                )
                reply(self.encodeResponse(response), nil)
                return
            }

            guard let session = Self.sharedSessionManager.createSessionOrNil(
                ttlSeconds: ttlSeconds,
                scope: bridgeRequest.context.sessionScope,
                workingDirectory: bridgeRequest.context.workingDirectory,
                origin: Self.sessionOrigin(from: callerIdentity)
            ) else {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .appUnavailable,
                    message: "Session creation failed"
                )
                reply(self.encodeResponse(response), nil)
                return
            }

            let payload = UnlockPayload(
                expiresAt: session.expiresAt,
                ttlSeconds: Int(ttlSeconds),
                sessionToken: session.sessionToken
            )
            let response: BridgeResponse<UnlockPayload> = BridgeResponseBuilder.success(
                id: bridgeRequest.id,
                payload: payload
            )
            self.recordAudit(
                command: .unlock,
                itemId: "",
                approvedBy: approvalAttribution,
                caller: callerIdentity,
                requestedCommand: bridgeRequest.context.requestedCommand,
                fullCommand: bridgeRequest.context.fullCommand,
                agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                workspaceContext: bridgeRequest.context.workspaceContext
            )
            reply(self.encodeResponse(response), nil)
        }
    }

    public func lock(_ request: Data, _ rawReply: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Failed to decode lock request"))
            return
        }

        let didInvalidate: Bool
        if let token = bridgeRequest.sessionToken, !token.isEmpty {
            didInvalidate = Self.sharedSessionManager.invalidate(
                sessionToken: token,
                scope: bridgeRequest.context.sessionScope
            )
        } else {
            didInvalidate = Self.sharedSessionManager.invalidate(scope: bridgeRequest.context.sessionScope)
        }
        let message = didInvalidate ? "Session locked" : "No matching active session"
        let payload = WriteResultPayload(id: "session", message: message)
        replyWriteSuccess(id: bridgeRequest.id, payload: payload, reply: reply)
    }

}
#endif
