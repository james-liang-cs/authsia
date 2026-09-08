#if os(macOS)
import AuthenticatorBridge
import Foundation

extension XPCRequestHandler {
    public func mcpManagementRecordActivity(_ data: Data, _ callback: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(callback)
        let caller = callerIdentityProvider()
        guard caller?.bundleIdentifier == "app.authsia", data.count <= 64 * 1_024,
              let event = try? JSONDecoder().decode(MCPManagementAuditEvent.self, from: data) else {
            reply(nil, makeNSError(code: .policyDenied, message: "Management audit is restricted to Authsia.app")); return
        }
        do {
            try MCPManagementAuditRecorder(audit: auditLogger).record(event, caller: caller)
            reply(Data(), nil)
        } catch { reply(nil, makeNSError(code: .appUnavailable, message: "Management audit is unavailable")) }
    }

    public func mcpHTTPAuthority(_ data: Data, _ callback: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(callback)
        guard callerIdentityProvider()?.bundleIdentifier == "app.authsia", data.count <= 1_048_576,
              let command = try? JSONDecoder().decode(MCPHTTPAuthorityCommand.self, from: data) else {
            reply(nil, makeNSError(code: .policyDenied, message: "HTTP authority is restricted to Authsia.app")); return
        }
        Task { @MainActor in
            do { reply(try JSONEncoder().encode(await self.httpAuthority.execute(command)), nil) }
            catch {
                // Keep domain reasons intact across XPC; NSError policyDenied erased
                // the distinction between human denial, stale policy and availability.
                reply(try? JSONEncoder().encode(MCPHTTPAuthorityReply(valid: false, failure: error as? MCPManagementError ?? .unavailable)), nil)
            }
        }
    }

    public func mcpHTTPRecordActivity(_ data: Data, _ callback: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(callback)
        guard callerIdentityProvider()?.bundleIdentifier == "app.authsia", data.count <= 64 * 1_024,
              let event = try? JSONDecoder().decode(MCPHTTPActivityEvent.self, from: data),
              AgentRuntimeContext.sanitize(event.toolName) == event.toolName else {
            reply(nil, makeNSError(code: .policyDenied, message: "HTTP audit is restricted to Authsia.app")); return
        }
        do {
            try auditLogger.record(BridgeAuditRecord(command: .mcpProxyActivity, itemId: event.serverID,
                itemName: event.serverName, approvedBy: event.outcome.rawValue, timestamp: event.recordedAt,
                requestedCommand: "mcp-http", agentRuntimeContext: AgentRuntimeContext(
                    platform: event.attribution, sessionID: "mcp-http", turnID: MCPHTTPActivityRecording.toolUseID(event.id),
                    agentID: "http:\(event.serverName)", agentType: "authsia-mcp",
                    toolUseID: MCPHTTPActivityRecording.toolUseID(event.id),
                    attributionConfidence: .ambiguous)))
            try AgentCommandHistoryStore().record(MCPHTTPActivityRecording.commandEvent(from: event))
            reply(Data(), nil)
        } catch { reply(nil, makeNSError(code: .appUnavailable, message: "HTTP audit is unavailable")) }
    }
}
#endif
