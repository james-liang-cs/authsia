import Foundation
import AuthenticatorBridge

struct AuditFormatter {
    static func formatList(_ events: [AuditEvent], format: OutputFormat) throws -> String {
        switch format {
        case .json:
            return try encodeJSON(events)
        case .table:
            return renderTable(events)
        }
    }

    static func formatExport(_ events: [AuditEvent], format: Audit.ExportFormat) throws -> String {
        switch format {
        case .json:
            return try encodeJSON(events)
        case .ndjson:
            return try encodeNDJSON(events)
        }
    }

    private static func renderTable(_ events: [AuditEvent]) -> String {
        guard !events.isEmpty else {
            return "No audit events found."
        }

        let headers = [
            "Timestamp", "Command", "Item", "Caller", "Agent", "Workspace", "Environment", "Approved", "Hash",
        ]
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium

        let rows = events.map { event in
            [
                formatter.string(from: event.record.timestamp),
                commandDisplayName(for: event),
                event.record.itemName ?? event.record.itemId,
                callerDisplayName(for: event),
                agentAttribution(event.record.agentRuntimeContext) ?? "-",
                event.record.workspaceContext?.displayName ?? "-",
                environmentDisplayName(event.record.environmentScope) ?? "-",
                event.record.approvedBy,
                shortHash(event.entryHash)
            ]
        }
        return renderTable(headers: headers, rows: rows)
    }

    private static func commandDisplayName(for event: AuditEvent) -> String {
        guard let requestedCommand = event.record.requestedCommand,
              !requestedCommand.isEmpty,
              requestedCommand != event.record.command.rawValue else {
            return event.record.command.rawValue
        }
        return "\(requestedCommand) (\(event.record.command.rawValue))"
    }

    private static func callerDisplayName(for event: AuditEvent) -> String {
        if let caller = event.record.caller {
            return caller.parentProcess?.processName ?? caller.processName
        }
        if let requester = event.record.sshAgent?.instigator ?? event.record.sshAgent?.peer {
            return requester.name
        }
        return "-"
    }

    private static func agentAttribution(_ context: AgentRuntimeContext?) -> String? {
        guard let context else { return nil }
        let platform = platformDisplayName(context.platform)
        let label = context.agentType ?? shortAgentID(context.agentID)
        guard let label else { return platform }
        guard let platform else { return "Agent: \(label)" }
        return "\(platform) / \(label)"
    }

    private static func environmentDisplayName(_ scope: EnvironmentAccessScope?) -> String? {
        switch scope {
        case .defaultOnly:
            return "Default environment"
        case .named(let name):
            return name
        case nil:
            return nil
        }
    }

    private static func platformDisplayName(_ platform: String?) -> String? {
        switch platform?.lowercased() {
        case "claude", "claude-code":
            return "Claude Code"
        case "codex":
            return "Codex"
        case "vscode", "vs-code", "visual-studio-code":
            return "Visual Studio Code"
        case "copilot", "github-copilot", "githubcopilot":
            return "GitHub Copilot"
        case "cursor":
            return "Cursor"
        case "windsurf":
            return "Windsurf"
        case let value?:
            return value
        case nil:
            return nil
        }
    }

    private static func shortAgentID(_ agentID: String?) -> String? {
        guard let agentID else { return nil }
        return agentID.count > 12 ? String(agentID.prefix(12)) : agentID
    }

    private static func shortHash(_ hash: String) -> String {
        guard hash.count > 12 else { return hash }
        return String(hash.prefix(12))
    }

    private static func renderTable(headers: [String], rows: [[String]]) -> String {
        TableFormatter.renderTable(headers: headers, rows: rows)
    }

    private static func encodeJSON<T: Encodable>(_ value: T) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(value)
        return String(decoding: data, as: UTF8.self)
    }

    private static func encodeNDJSON(_ events: [AuditEvent]) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601

        let lines = try events.map { event in
            let data = try encoder.encode(event)
            return String(decoding: data, as: UTF8.self)
        }
        return lines.joined(separator: "\n")
    }
}
