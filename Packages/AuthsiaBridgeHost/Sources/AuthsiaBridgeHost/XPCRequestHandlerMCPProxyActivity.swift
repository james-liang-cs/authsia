#if os(macOS)
import Foundation
@preconcurrency import AuthenticatorBridge

extension XPCRequestHandler {
    /// HMAC-chain a redacted MCP proxy tool-call row. Fail closed: if this
    /// write throws, the proxy must not forward.
    func handleMCPProxyActivity(
        _ bridgeRequest: BridgeRequest,
        body: Data,
        callerIdentity: CallerIdentity?,
        reply: XPCReply
    ) {
        guard let payload = try? BridgeCoder.decode(MCPProxyActivityPayload.self, from: body) else {
            replyError(
                id: bridgeRequest.id,
                code: .invalidRequest,
                message: "Invalid MCP proxy activity payload",
                reply: reply
            )
            return
        }
        let runtime = bridgeRequest.context.agentRuntimeContext
        guard runtime?.agentType == "authsia-mcp" else {
            replyError(
                id: bridgeRequest.id,
                code: .policyDenied,
                message: "MCP proxy activity is restricted to the Authsia MCP proxy",
                reply: reply
            )
            return
        }
        let record = BridgeAuditRecord(
            command: .mcpProxyActivity,
            itemId: payload.invocationID.uuidString,
            itemName: payload.toolName,
            approvedBy: "mcp-proxy",
            timestamp: Date(),
            caller: callerIdentity,
            requestedCommand: "mcp-proxy",
            fullCommand: "mcp-tool \(payload.toolName) \(payload.outcome.rawValue)",
            agentJITGrantID: payload.grantID,
            agentRuntimeContext: runtime,
            workspaceContext: bridgeRequest.context.workspaceContext
        )
        do {
            try auditLogger.record(record)
            let response: BridgeResponse<MCPProxyActivityResultPayload> =
                BridgeResponseBuilder.success(
                    id: bridgeRequest.id,
                    payload: MCPProxyActivityResultPayload(recorded: true)
                )
            reply(encodeResponse(response), nil)
        } catch {
            replyError(
                id: bridgeRequest.id,
                code: .appUnavailable,
                message: "The call was not recorded",
                reply: reply
            )
        }
    }
}
#endif
