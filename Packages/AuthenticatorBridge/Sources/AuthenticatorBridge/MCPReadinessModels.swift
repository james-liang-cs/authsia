import Foundation

public struct MCPReadinessFact: Codable, Equatable, Sendable {
    public let id: String
    public let state: String
    public let detail: String
    public let complete: Bool

    public init(id: String, state: String, detail: String, complete: Bool) {
        self.id = id
        self.state = state
        self.detail = detail
        self.complete = complete
    }
}

public struct MCPReadinessAction: Codable, Equatable, Sendable {
    public let kind: String
    public let label: String
    public let reason: String

    public init(kind: String, label: String, reason: String) {
        self.kind = kind
        self.label = label
        self.reason = reason
    }
}

public struct MCPServerReadiness: Codable, Equatable, Sendable {
    public let facts: [MCPReadinessFact]
    public let next: MCPReadinessAction?
    public let checkedAt: Date

    public init(facts: [MCPReadinessFact], next: MCPReadinessAction?, checkedAt: Date = Date()) {
        self.facts = facts
        self.next = next
        self.checkedAt = checkedAt
    }
}

public struct MCPCredentialBindingView: Codable, Equatable, Sendable {
    public let name: String
    public let itemLabel: String
    public let itemID: String
    public let folderPath: String?
    public let environments: [String]?
    public let kind: String

    public init(
        name: String,
        itemLabel: String,
        itemID: String,
        folderPath: String? = nil,
        environments: [String]? = nil,
        kind: String
    ) {
        self.name = name
        self.itemLabel = itemLabel
        self.itemID = itemID
        self.folderPath = folderPath
        self.environments = environments
        self.kind = kind
    }
}

#if os(macOS)
public enum MCPServerReadinessProjection {
    public static func readiness(
        for server: MCPServerSnapshot,
        activity: [MCPActivityRecord] = [],
        grants: [MCPManagerGrantView] = [],
        now: Date = Date()
    ) -> MCPServerReadiness {
        let relevant = activity.filter { $0.serverID == server.id }
        let observed = relevant.contains { $0.kind == .toolCall && $0.outcome == .succeeded }
        let failed = relevant.contains { $0.kind == .toolCall && [.denied, .mcpError, .upstreamUnavailable, .timedOut].contains($0.outcome) }
        let grant = grants.contains { $0.serverID == server.id || ($0.serverID == nil && $0.serverName == server.displayName && $0.workspacePath == server.identity.workspacePath) }
        let effective = server.clientAssociations.filter { $0.precedence != .overridden && $0.status != .disabled }
        let protectedConfig = !effective.isEmpty && effective.allSatisfy { $0.status == .admittedWrapped }
        let bypass = effective.contains { $0.status == .directBypass }
        let unclassified = Set(server.catalog.map(\.name)).subtracting(server.policy.allow + server.policy.approve + server.policy.deny)
        let launchComplete = server.transport == .stdio ? server.launchCommand != nil : server.endpointLabel != nil
        let catalogComplete = !server.catalog.isEmpty || !MCPToolPolicyEvaluator.advertisedToolNames(in: server.policy).isEmpty
        let facts = [
            MCPReadinessFact(id: "declaration", state: "valid", detail: "Workspace declaration is present.", complete: true),
            MCPReadinessFact(
                id: "launch",
                state: launchComplete ? "available" : "unknown",
                detail: server.catalogBlockReason ?? (launchComplete ? "Launch target is recorded." : "Set the executable or localhost endpoint."),
                complete: launchComplete && server.catalogBlockReason == nil
            ),
            MCPReadinessFact(
                id: "catalog",
                state: server.catalog.isEmpty ? (catalogComplete ? "name-only" : "missing") : "recorded",
                detail: server.catalog.isEmpty ? "Tool names come from policy until a catalog is recorded." : "\(server.catalog.count) tool descriptor(s) recorded.",
                complete: catalogComplete
            ),
            MCPReadinessFact(
                id: "policy",
                state: unclassified.isEmpty && catalogComplete ? "reviewed" : (catalogComplete ? "unclassified" : "no permitted tools"),
                detail: unclassified.isEmpty ? "Every known tool has an explicit decision." : "\(unclassified.count) catalog tool(s) have no policy decision.",
                complete: unclassified.isEmpty && catalogComplete
            ),
            MCPReadinessFact(
                id: "clientRoute",
                state: protectedConfig ? "protected config" : (bypass ? "direct" : "unknown"),
                detail: protectedConfig ? "Scanned clients route through Authsia." : (bypass ? "At least one client still launches directly." : "No effective client association yet."),
                complete: protectedConfig
            ),
            MCPReadinessFact(
                id: "runtime",
                state: observed ? "successful call observed" : (grant ? "active grant" : (failed ? "failure" : "not observed")),
                detail: observed ? "A protected call succeeded." : (grant ? "A grant is active; no successful call is in the retained activity window." : "Ask the client to reload, then make an explicit permitted call."),
                complete: observed
            ),
            MCPReadinessFact(
                id: "evidence",
                state: relevant.contains(where: { $0.evidenceStatus == "incomplete" }) ? "incomplete" : (relevant.isEmpty ? "unavailable" : "available"),
                detail: "Activity is redacted command-history evidence, not HMAC verification of another log.",
                complete: !relevant.contains(where: { $0.evidenceStatus != "recorded" })
            ),
        ]
        let next: MCPReadinessAction?
        if server.catalogBlockReason != nil {
            next = .init(kind: "configure", label: "Edit server", reason: server.catalogBlockReason ?? "")
        } else if !catalogComplete {
            next = .init(kind: "catalog", label: "Record catalog", reason: "Record or name the tools this server may expose.")
        } else if !unclassified.isEmpty {
            next = .init(kind: "policy", label: "Edit tool policy", reason: "Review unclassified catalog tools before protecting a client.")
        } else if !protectedConfig {
            let enrollable = effective.contains { MCPClientActionSupport.supportsHTTPEnrollment($0.source) }
            if server.transport == .stdio {
                next = .init(kind: "wrap", label: "Protect connection", reason: "Route a supported client through Authsia.")
            } else if enrollable {
                next = .init(kind: "enrollHTTP", label: "Protect connection", reason: "Point a supported client at the protected localhost endpoint.")
            } else {
                next = .init(kind: "observe", label: "Configure the client endpoint", reason: "This HTTP client has no automatic enrollment writer.")
            }
        } else if !observed {
            next = .init(kind: "observe", label: "Reload the client and make a permitted call", reason: "Configuration is not proof of protected use.")
        } else {
            next = nil
        }
        return MCPServerReadiness(facts: facts, next: next, checkedAt: now)
    }
}
#endif

public enum MCPClientActionSupport {
    public static func supportsHTTPEnrollment(_ source: MCPClientConfigSource) -> Bool {
        switch source {
        case .codex, .claude, .cursor:
            return true
        case .vscode, .devin, .claudeDesktop:
            return false
        }
    }

    public static func httpEnrollmentReason(_ source: MCPClientConfigSource) -> String? {
        supportsHTTPEnrollment(source) ? nil :
            "Authsia can show this \(source.displayName) HTTP entry, but it has no automatic enrollment writer. Configure the protected localhost endpoint in the client."
    }
}
