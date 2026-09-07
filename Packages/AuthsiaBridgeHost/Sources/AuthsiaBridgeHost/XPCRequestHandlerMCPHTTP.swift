#if os(macOS)
import AuthenticatorBridge
import Foundation

extension XPCRequestHandler {
    public func mcpHTTPAuthority(_ data: Data, _ callback: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(callback)
        guard callerIdentityProvider()?.bundleIdentifier == "app.authsia", data.count <= 1_048_576,
              let command = try? JSONDecoder().decode(MCPHTTPAuthorityCommand.self, from: data) else {
            reply(nil, makeNSError(code: .policyDenied, message: "HTTP authority is restricted to Authsia.app")); return
        }
        Task { @MainActor in
            do { reply(try JSONEncoder().encode(await self.httpAuthority.execute(command)), nil) }
            catch { reply(nil, self.makeNSError(code: .policyDenied, message: (error as? MCPManagementError ?? .denied).localizedDescription)) }
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
                    platform: event.attribution, sessionID: "mcp-http", turnID: "mcp-call:\(event.id)",
                    agentID: "http:\(event.serverName)", agentType: "authsia-mcp", toolUseID: event.toolName,
                    attributionConfidence: .ambiguous)))
            try AgentCommandHistoryStore().record(AgentCommandEvent(recordedAt: event.recordedAt,
                agentPlatform: event.attribution, sessionID: "mcp-http", turnID: "mcp-call:\(event.id)",
                agentID: "http:\(event.serverName)", captureSource: .mcpProxy,
                workingDirectory: event.workspacePath, executable: event.serverName,
                arguments: ["mcp-tool", event.toolName], command: "MCP HTTP tool",
                mcpProxyOutcome: MCPProxyCallOutcome(rawValue: event.outcome.rawValue) ?? .upstreamUnavailable))
            reply(Data(), nil)
        } catch { reply(nil, makeNSError(code: .appUnavailable, message: "HTTP audit is unavailable")) }
    }
}
#endif
