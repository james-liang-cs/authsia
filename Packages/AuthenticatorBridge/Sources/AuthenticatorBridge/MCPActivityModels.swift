#if os(macOS)
import Foundation

public enum MCPActivityEventKind: String, Codable, Equatable, Sendable {
    case toolCall = "toolCall"
    case serverLifecycle = "serverLifecycle"
    case managementChange = "managementChange"
}

public enum MCPActivitySourceHealth: String, Codable, Equatable, Sendable {
    case ok
    case unavailable
    case incomplete
    case truncated
}

public struct MCPActivityQuery: Equatable, Sendable {
    public var workspacePath: String?
    public var serverID: String?
    public var client: String?
    public var transport: String?
    public var outcome: String?
    public var kind: String?
    public var search: String?
    public var cursor: String?
    public var limit: Int

    public init(
        workspacePath: String? = nil,
        serverID: String? = nil,
        client: String? = nil,
        transport: String? = nil,
        outcome: String? = nil,
        kind: String? = nil,
        search: String? = nil,
        cursor: String? = nil,
        limit: Int = 200
    ) {
        self.workspacePath = workspacePath
        self.serverID = serverID
        self.client = client
        self.transport = transport
        self.outcome = outcome
        self.kind = kind
        self.search = search
        self.cursor = cursor
        self.limit = max(1, min(limit, 200))
    }

    public static func parse(uri: String) -> MCPActivityQuery {
        let components = URLComponents(string: uri.hasPrefix("/") ? "http://127.0.0.1\(uri)" : uri)
        let items = Dictionary((components?.queryItems ?? []).compactMap { item in
            item.value.map { (item.name, $0) }
        }, uniquingKeysWith: { first, _ in first })
        func value(_ key: String) -> String? {
            items[key].flatMap { $0.isEmpty ? nil : $0 }
        }
        return MCPActivityQuery(
            workspacePath: value("workspace"),
            serverID: value("server"),
            client: value("client"),
            transport: value("transport"),
            outcome: value("outcome"),
            kind: value("kind"),
            search: value("q"),
            cursor: value("cursor"),
            limit: Int(value("limit") ?? "") ?? 200
        )
    }
}

public struct MCPActivityRecord: Codable, Equatable, Identifiable, Sendable {
    public let schemaVersion: Int
    public let id: UUID
    public let callID: String?
    public let kind: MCPActivityEventKind
    public let recordedAt: Date
    public let workspacePath: String
    public let serverID: String
    public let serverName: String
    public let transport: MCPUpstreamTransport?
    public let toolName: String
    public let clientLabel: String
    public let attributionConfidence: String
    public let outcome: MCPHTTPActivityOutcome
    public let reasonCode: String?
    public let grantIDs: [UUID]
    public let evidenceStatus: String

    public init(
        schemaVersion: Int = 1,
        id: UUID,
        callID: String? = nil,
        kind: MCPActivityEventKind,
        recordedAt: Date,
        workspacePath: String,
        serverID: String,
        serverName: String,
        transport: MCPUpstreamTransport? = nil,
        toolName: String,
        clientLabel: String,
        attributionConfidence: String = "configured-association",
        outcome: MCPHTTPActivityOutcome,
        reasonCode: String? = nil,
        grantIDs: [UUID] = [],
        evidenceStatus: String = "recorded"
    ) {
        self.schemaVersion = schemaVersion
        self.id = id
        self.callID = callID
        self.kind = kind
        self.recordedAt = recordedAt
        self.workspacePath = workspacePath
        self.serverID = serverID
        self.serverName = serverName
        self.transport = transport
        self.toolName = toolName
        self.clientLabel = clientLabel
        self.attributionConfidence = attributionConfidence
        self.outcome = outcome
        self.reasonCode = reasonCode
        self.grantIDs = grantIDs
        self.evidenceStatus = evidenceStatus
    }
}

public struct MCPActivityPage: Codable, Equatable, Sendable {
    public let records: [MCPActivityRecord]
    public let cursor: String?
    public let asOf: Date
    public let retainedFrom: Date?
    public let retainedTo: Date?
    public let truncated: Bool
    public let completeness: String
    public let sourceHealth: MCPActivitySourceHealth
    public let lastUpdate: Date
    public let message: String?
    public let auditStatus: MCPAuditStatusView?

    public init(
        records: [MCPActivityRecord],
        cursor: String? = nil,
        asOf: Date = Date(),
        retainedFrom: Date? = nil,
        retainedTo: Date? = nil,
        truncated: Bool = false,
        completeness: String = "complete",
        sourceHealth: MCPActivitySourceHealth = .ok,
        lastUpdate: Date = Date(),
        message: String? = nil,
        auditStatus: MCPAuditStatusView? = nil
    ) {
        self.records = records
        self.cursor = cursor
        self.asOf = asOf
        self.retainedFrom = retainedFrom
        self.retainedTo = retainedTo
        self.truncated = truncated
        self.completeness = completeness
        self.sourceHealth = sourceHealth
        self.lastUpdate = lastUpdate
        self.message = message
        self.auditStatus = auditStatus
    }

    public static func unavailable(_ message: String, now: Date = Date()) -> MCPActivityPage {
        MCPActivityPage(
            records: [],
            asOf: now,
            completeness: "unavailable",
            sourceHealth: .unavailable,
            lastUpdate: now,
            message: message,
            auditStatus: MCPAuditStatusView(
                verificationState: "unavailable",
                completeness: "unavailable",
                checkedAt: now,
                message: "Activity history could not be verified because it could not be read."
            )
        )
    }
}

public enum MCPHTTPActivityRecording {
    public static func toolUseID(_ invocation: UUID) -> String {
        "mcp-call:\(invocation.uuidString)"
    }

    public static func commandEvent(from event: MCPHTTPActivityEvent) -> AgentCommandEvent {
        let invocation = toolUseID(event.id)
        let stdio = event.transport == .stdio
        return AgentCommandEvent(
            id: event.id,
            recordedAt: event.recordedAt,
            agentPlatform: event.attribution,
            sessionID: stdio ? nil : "mcp-http",
            turnID: invocation,
            agentID: (stdio ? "proxy:" : "http:") + event.serverName,
            agentType: "authsia-mcp",
            toolUseID: invocation,
            agentJITGrantID: event.grantIDs.sorted { $0.uuidString < $1.uuidString }.first,
            captureSource: .mcpProxy,
            workingDirectory: event.workspacePath,
            executable: event.serverName,
            arguments: ["mcp-tool", event.toolName],
            command: stdio ? "MCP tool" : "MCP HTTP tool",
            mcpProxyOutcome: MCPProxyCallOutcome(rawValue: event.outcome.rawValue),
            mcpProxyErrorCode: event.reasonCode,
            mcpProxyGrantIDs: event.grantIDs.isEmpty ? nil : event.grantIDs
        )
    }
}

public enum MCPActivityProjection {
    public static func page(loading: () throws -> [AgentCommandEvent], query: MCPActivityQuery = .init(), now: Date = Date()) -> MCPActivityPage {
        do {
            return page(events: try loading(), query: query, now: now)
        } catch {
            return .unavailable("Activity history could not be read.", now: now)
        }
    }

    public static func page(events: [AgentCommandEvent], query: MCPActivityQuery = .init(), now: Date = Date()) -> MCPActivityPage {
        let mcpEvents = events.filter { $0.captureSource == .mcpProxy }
        let retainedFrom = mcpEvents.map(\.recordedAt).min()
        let retainedTo = mcpEvents.map(\.recordedAt).max()
        let records = Dictionary(grouping: mcpEvents.compactMap(record(from:)), by: { $0.callID ?? $0.id.uuidString })
            .values.map { rows in rows.first { $0.outcome != .started } ?? rows[0] }
            .filter { matches($0, query: query) }
            .sorted(by: newerThan)
        let cursor = query.cursor.flatMap(decodeCursor)
        let paged = records.filter { cursor == nil || afterCursor($0, cursor: cursor!) }
        let limit = query.limit
        let pageRecords = Array(paged.prefix(limit))
        let truncated = paged.count > limit
        return MCPActivityPage(
            records: pageRecords,
            cursor: truncated ? encodeCursor(pageRecords.last) : nil,
            asOf: now,
            retainedFrom: retainedFrom,
            retainedTo: retainedTo,
            truncated: truncated,
            completeness: truncated ? "truncated" : "complete",
            sourceHealth: truncated ? .truncated : .ok,
            lastUpdate: now,
            message: pageRecords.isEmpty && !records.isEmpty
                ? "No activity matches the current filters in the retained range."
                : nil,
            auditStatus: MCPAuditStatusView(
                verificationState: "unverified",
                completeness: truncated ? "truncated" : "complete",
                checkedAt: now,
                message: "This summary reports command-history completeness. It does not claim HMAC verification of another audit log."
            )
        )
    }

    private static func record(from event: AgentCommandEvent) -> MCPActivityRecord? {
        guard let agentID = event.agentID, let workspace = event.workingDirectory else { return nil }
        let http = agentID.hasPrefix("http:")
        let name = http ? String(agentID.dropFirst(5))
            : agentID.hasPrefix("proxy:") ? String(agentID.dropFirst(6)) : agentID
        let identity = MCPServerIdentity(workspacePath: workspace, upstreamName: name)
        let kind: MCPActivityEventKind
        let outcome: MCPHTTPActivityOutcome
        switch event.mcpProxyOutcome {
        case .childStarted:
            kind = .serverLifecycle
            outcome = .childStarted
        case .childExited:
            kind = .serverLifecycle
            outcome = .childExited
        case .started:
            kind = .toolCall
            outcome = .started
        case .succeeded:
            kind = .toolCall
            outcome = .succeeded
        case .denied:
            kind = .toolCall
            outcome = .denied
        case .busy:
            kind = .toolCall
            outcome = .busy
        case .mcpError:
            kind = .toolCall
            outcome = .mcpError
        case .cancelled:
            kind = .toolCall
            outcome = .cancelled
        case .timedOut:
            kind = .toolCall
            outcome = .timedOut
        case .upstreamUnavailable:
            kind = .toolCall
            outcome = .upstreamUnavailable
        case nil:
            kind = .toolCall
            outcome = .incomplete
        }
        let callID = event.toolUseID.flatMap { value in
            value.hasPrefix("mcp-call:") ? String(value.dropFirst("mcp-call:".count)) : value
        }
        return MCPActivityRecord(
            id: event.id,
            callID: callID,
            kind: kind,
            recordedAt: event.recordedAt,
            workspacePath: workspace,
            serverID: MCPWorkspaceStore.serverID(identity),
            serverName: name,
            transport: http ? .streamableHTTP : .stdio,
            toolName: event.arguments.count > 1 ? event.arguments[1] : "unknown",
            clientLabel: event.agentPlatform ?? "unknown",
            attributionConfidence: "configured-association",
            outcome: outcome,
            reasonCode: event.mcpProxyErrorCode,
            grantIDs: event.mcpProxyGrantIDs ?? event.agentJITGrantID.map { [$0] } ?? [],
            evidenceStatus: event.mcpProxyOutcome == nil ? "incomplete" : "recorded"
        )
    }

    private static func matches(_ record: MCPActivityRecord, query: MCPActivityQuery) -> Bool {
        if let workspacePath = query.workspacePath, record.workspacePath != workspacePath { return false }
        if let serverID = query.serverID, record.serverID != serverID { return false }
        if let client = query.client, record.clientLabel != client { return false }
        if let transport = query.transport, record.transport?.rawValue != transport { return false }
        if let outcome = query.outcome, record.outcome.rawValue != outcome { return false }
        if let kind = query.kind, record.kind.rawValue != kind { return false }
        if let search = query.search?.lowercased(), !search.isEmpty {
            let haystack = [record.serverName, record.toolName, record.clientLabel, record.callID, record.workspacePath]
                .compactMap { $0 }.joined(separator: " ").lowercased()
            if !haystack.contains(search) { return false }
        }
        return true
    }

    private static func newerThan(_ lhs: MCPActivityRecord, _ rhs: MCPActivityRecord) -> Bool {
        if lhs.recordedAt != rhs.recordedAt { return lhs.recordedAt > rhs.recordedAt }
        return lhs.id.uuidString > rhs.id.uuidString
    }

    private static func afterCursor(_ record: MCPActivityRecord, cursor: (date: Date, id: UUID?)) -> Bool {
        if record.recordedAt != cursor.date { return record.recordedAt < cursor.date }
        guard let id = cursor.id else { return false }
        return record.id.uuidString < id.uuidString
    }

    private static func encodeCursor(_ record: MCPActivityRecord?) -> String? {
        guard let record else { return nil }
        return "\(isoFormatter(fractional: true).string(from: record.recordedAt))|\(record.id.uuidString)"
    }

    private static func decodeCursor(_ value: String) -> (date: Date, id: UUID?)? {
        let parts = value.split(separator: "|", maxSplits: 1, omittingEmptySubsequences: false)
        let dateString = String(parts[0])
        guard let date = isoFormatter(fractional: true).date(from: dateString)
                ?? ISO8601DateFormatter().date(from: dateString) else { return nil }
        return (date, parts.count == 2 ? UUID(uuidString: String(parts[1])) : nil)
    }

    private static func isoFormatter(fractional: Bool) -> ISO8601DateFormatter {
        let formatter = ISO8601DateFormatter()
        if fractional {
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        }
        return formatter
    }
}
#endif
