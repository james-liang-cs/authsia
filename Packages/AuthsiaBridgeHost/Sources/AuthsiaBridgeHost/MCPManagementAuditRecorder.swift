#if os(macOS)
import AuthenticatorBridge
import Foundation

/// Only called after the signed-app XPC boundary authenticates the writer.
/// The complete redacted event is covered by the existing Bridge HMAC chain;
/// the bounded local journal remains a disposable, unverified activity view.
struct MCPManagementAuditRecorder {
    let audit: BridgeAuditLogger
    var journal = MCPManagementAuditStore()

    func record(_ event: MCPManagementAuditEvent, caller: CallerIdentity? = nil) throws {
        guard event.schemaVersion == 1, MCPManagementOperationKind(rawValue: event.kind) != nil,
              event.actorClass == "native",
              (event.phase == "intent" && event.result == "pending")
                || (event.phase == "outcome" && ["applied", "notApplied"].contains(event.result)) else {
            throw MCPManagementError.invalidRequest
        }
        // Codable does not call the sanitizing initializer.
        let safe = MCPManagementAuditEvent(id: event.id, operationID: event.operationID,
            kind: event.kind, phase: event.phase, recordedAt: event.recordedAt,
            summary: event.summary, result: event.result, context: event.context)
        let record = BridgeAuditRecord(command: .mcpManagementActivity,
            itemId: "mcp-operation:" + safe.operationID.uuidString,
            itemName: safe.kind, approvedBy: safe.phase + ":" + safe.result,
            timestamp: safe.recordedAt, caller: caller, requestedCommand: "mcp-manager",
            mcpManagementEvent: safe)
        // Leave room for the chain envelope and preserve the bounded tail reader.
        guard try JSONEncoder.bridge.encode(record).count < 48 * 1_024 else { throw MCPManagementError.invalidRequest }
        try audit.record(record, synchronize: true)
        try journal.record(safe)
    }
}
#endif
