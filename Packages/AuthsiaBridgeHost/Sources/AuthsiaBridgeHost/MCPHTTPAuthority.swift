#if os(macOS)
import AuthenticatorBridge
import CryptoKit
import Foundation
import Security

struct MCPHTTPResolvedItem: Codable, Equatable, Sendable {
    let header: MCPUpstreamCredentialHeader
    let id: UUID
    let type: String
    let field: String
    let label: String
    let revision: String
}

struct MCPHTTPAuthorityState: Codable {
    struct Association: Codable {
        let principal: MCPHTTPPrincipal
        let digest: Data
        var enrollmentID: UUID?
    }
    struct Grant: Codable {
        let summary: MCPHTTPGrantSummary
        let items: [MCPHTTPResolvedItem]
    }
    var version = 1
    var associations: [Association] = []
    var grants: [Grant] = []
}

/// Separate Keychain record: never add unknown grant cases to the legacy store.
final class MCPHTTPAuthorityBlob: AuthorityBlobStoring, @unchecked Sendable {
    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "app.authsia.bridge.mcp-http",
         kSecAttrAccount as String: "authority-v1",
         kSecUseDataProtectionKeychain as String: true,
         kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
    }
    func load() throws -> Data? {
        var query = query
        query[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw MCPManagementError.unavailable }
        return data
    }
    func save(_ data: Data) throws {
        let update = [kSecValueData as String: data]
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw MCPManagementError.unavailable }
        var add = query; add[kSecValueData as String] = data
        guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else { throw MCPManagementError.unavailable }
    }
}

/// Bridge-owned authority. All checks and secret resolution run on the host's
/// main actor; an approval suspension is followed by complete revalidation.
@MainActor
final class MCPHTTPAuthority {
    struct Pending { let binding: MCPHTTPAssociationBinding; let token: String; let expiry: Date }
    private let storage: any AuthorityBlobStoring
    private let definition: @MainActor (MCPServerIdentity) throws -> MCPServerDefinition
    private let items: @MainActor ([MCPUpstreamCredentialHeader]) throws -> [MCPHTTPResolvedItem]
    private let secret: @MainActor (MCPHTTPResolvedItem) throws -> String
    private let approve: @MainActor (MCPServerDefinition, MCPHTTPPrincipal, String, [MCPHTTPResolvedItem]) async -> Bool
    private let recordAdmission: @MainActor (MCPHTTPGrantSummary) throws -> Void
    private let enabled: () -> Bool
    private let clock: () -> Date
    private let ttl: (Bool) -> TimeInterval
    private var pending: [UUID: Pending] = [:]
    private var epoch = UUID()

    init(storage: any AuthorityBlobStoring = MCPHTTPAuthorityBlob(),
         definition: @escaping @MainActor (MCPServerIdentity) throws -> MCPServerDefinition = MCPWorkspaceStore.definition,
         items: @escaping @MainActor ([MCPUpstreamCredentialHeader]) throws -> [MCPHTTPResolvedItem],
         secret: @escaping @MainActor (MCPHTTPResolvedItem) throws -> String,
         approve: @escaping @MainActor (MCPServerDefinition, MCPHTTPPrincipal, String, [MCPHTTPResolvedItem]) async -> Bool,
         recordAdmission: @escaping @MainActor (MCPHTTPGrantSummary) throws -> Void = { _ in throw MCPManagementError.auditUnavailable },
         enabled: @escaping () -> Bool = { MCPAccessSettings.isEnabled() && BridgeSettings.isCliAccessEnabled() },
         clock: @escaping () -> Date = Date.init,
         ttl: @escaping (Bool) -> TimeInterval = { credentialed in
             credentialed ? min(BridgeSettings.mcpAdmissionTTL(), BridgeSessionManager.configuredTTL) : BridgeSettings.mcpAdmissionTTL()
         }) {
        self.storage = storage; self.definition = definition; self.items = items; self.secret = secret
        self.approve = approve; self.enabled = enabled; self.clock = clock; self.ttl = ttl
        self.recordAdmission = recordAdmission
    }

    func execute(_ command: MCPHTTPAuthorityCommand) async throws -> MCPHTTPAuthorityReply {
        switch command {
        case .prepareEnrollment(let binding):
            guard binding.serverID == MCPWorkspaceStore.serverID(binding.identity),
                  [.codex, .claude, .cursor].contains(binding.client) else { throw MCPManagementError.invalidRequest }
            let server = try definition(binding.identity)
            guard !server.upstream.requiresStdioPolicy else { throw MCPManagementError.unsupported }
            pending = pending.filter { $0.value.expiry > clock() }
            guard pending.count < 32 else { throw MCPManagementError.busy }
            var bytes = [UInt8](repeating: 0, count: 32)
            guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw MCPManagementError.unavailable }
            let token = Data(bytes).base64EncodedString()
            let id = UUID(), expiry = clock().addingTimeInterval(300)
            pending[id] = Pending(binding: binding, token: token, expiry: expiry)
            return MCPHTTPAuthorityReply(enrollment: MCPHTTPEnrollmentTicket(id: id, token: token, expiresAt: expiry))
        case .discardEnrollment(let id):
            pending.removeValue(forKey: id)
            return MCPHTTPAuthorityReply()
        case .enrollmentStatus(let id):
            let principal = try load().associations.first(where: { $0.enrollmentID == id })?.principal
            return MCPHTTPAuthorityReply(principal: principal, valid: principal != nil)
        case .commitEnrollment(let id):
            if let existing = try load().associations.first(where: { $0.enrollmentID == id }) {
                return MCPHTTPAuthorityReply(principal: existing.principal)
            }
            guard let ticket = pending[id], ticket.expiry > clock() else { throw MCPManagementError.stale }
            var state = try load()
            let oldIDs = state.associations.filter { $0.principal.binding == ticket.binding }.map { $0.principal.id }
            state.associations.removeAll { oldIDs.contains($0.principal.id) }
            state.grants.removeAll { oldIDs.contains($0.summary.principal.id) }
            let principal = MCPHTTPPrincipal(id: UUID(), binding: ticket.binding, generation: UUID())
            state.associations.append(.init(principal: principal, digest: Data(SHA256.hash(data: Data(ticket.token.utf8))), enrollmentID: id))
            try save(state)
            pending.removeValue(forKey: id)
            return MCPHTTPAuthorityReply(principal: principal)
        case .authenticate(let serverID, let token):
            guard enabled(), token.utf8.count <= 256 else { throw MCPManagementError.denied }
            let digest = Data(SHA256.hash(data: Data(token.utf8)))
            guard let association = try load().associations.first(where: {
                $0.principal.binding.serverID == serverID && constantTimeEqual($0.digest, digest)
            }) else { throw MCPManagementError.denied }
            return MCPHTTPAuthorityReply(principal: association.principal)
        case .authorize(let principal, let sessionID, let revision, let tool):
            guard enabled(), UUID(uuidString: sessionID) != nil else { throw MCPManagementError.denied }
            let server = try checkedDefinition(principal, revision: revision)
            let decision = MCPToolPolicyEvaluator.decision(for: tool, policy: server.upstream.tools)
            guard tool == "initialize" || tool == "catalog" || decision == .allow || decision == .approve else { throw MCPManagementError.denied }
            let resolved = try items(server.upstream.credentialHeaders)
            let originalEpoch = epoch
            var state = try load()
            var existing = matchingGrant(state, principal: principal, sessionID: sessionID, revision: revision, items: resolved)
            if existing == nil {
                guard await approve(server, principal, tool, resolved), epoch == originalEpoch, enabled() else { throw MCPManagementError.denied }
                _ = try checkedDefinition(principal, revision: revision)
                guard try items(server.upstream.credentialHeaders) == resolved else { throw MCPManagementError.stale }
                state = try load()
                existing = matchingGrant(state, principal: principal, sessionID: sessionID, revision: revision, items: resolved)
                if existing == nil {
                    let grant = MCPHTTPAuthorityState.Grant(summary: MCPHTTPGrantSummary(
                        id: UUID(), principal: principal, sessionID: sessionID, revision: revision,
                        expiresAt: clock().addingTimeInterval(max(1, ttl(!resolved.isEmpty))), credentialLabels: resolved.map(\.label)), items: resolved)
                    state.grants.removeAll { $0.summary.expiresAt <= clock() }
                    guard state.grants.count < 128 else { throw MCPManagementError.busy }
                    try recordAdmission(grant.summary)
                    state.grants.append(grant)
                    try save(state)
                    existing = grant
                }
            }
            guard let grant = existing else { throw MCPManagementError.denied }
            try recordAdmission(grant.summary)
            // No await between final identity/revision check and secret reads.
            _ = try checkedDefinition(principal, revision: revision)
            guard try items(server.upstream.credentialHeaders) == resolved else { throw MCPManagementError.stale }
            var headers: [String: String] = [:], secrets: [String] = []
            for item in resolved {
                let value = try secret(item)
                guard !value.isEmpty, !value.contains("\r"), !value.contains("\n") else { throw MCPManagementError.invalidRequest }
                let header = item.header.format == .bearer ? "Bearer " + value : value
                headers[item.header.headerName] = header
                secrets.append(contentsOf: [value, header])
            }
            return MCPHTTPAuthorityReply(lease: MCPHTTPLease(grant: grant.summary, headers: headers, secrets: secrets))
        case .validate(let id, let principal, let sessionID, let revision):
            guard enabled() else { return MCPHTTPAuthorityReply(valid: false) }
            do {
                let server = try checkedDefinition(principal, revision: revision)
                let resolved = try items(server.upstream.credentialHeaders)
                let found = matchingGrant(try load(), principal: principal, sessionID: sessionID, revision: revision, items: resolved)
                return MCPHTTPAuthorityReply(valid: found?.summary.id == id)
            } catch { return MCPHTTPAuthorityReply(valid: false) }
        case .revoke(let id):
            epoch = UUID()
            var state = try load()
            state.grants.removeAll { id == nil || $0.summary.id == id }
            try save(state)
            return MCPHTTPAuthorityReply()
        case .revokeAssociation(let id):
            epoch = UUID()
            var state = try load()
            state.associations.removeAll { $0.principal.id == id }
            state.grants.removeAll { $0.summary.principal.id == id }
            try save(state)
            return MCPHTTPAuthorityReply()
        case .revokeBinding(let binding):
            epoch = UUID()
            var state = try load()
            state.associations.removeAll { $0.principal.binding == binding }
            state.grants.removeAll { $0.summary.principal.binding == binding }
            try save(state)
            return MCPHTTPAuthorityReply()
        case .snapshot:
            return MCPHTTPAuthorityReply(grants: try load().grants.filter { $0.summary.expiresAt > clock() }.map(\.summary))
        case .catalogCapture(let identity, let revision):
            guard enabled() else { throw MCPManagementError.denied }
            let server = try definition(identity)
            guard server.revision == revision, !server.upstream.requiresStdioPolicy else { throw MCPManagementError.stale }
            guard (try? MCPLocalHTTPEndpointValidator.validate(server.upstream.url ?? "")) != nil else { throw MCPManagementError.invalidRequest }
            let resolved = try items(server.upstream.credentialHeaders)
            if !resolved.isEmpty {
                let principal = MCPHTTPPrincipal(
                    id: UUID(),
                    binding: MCPHTTPAssociationBinding(serverID: server.serverID, identity: identity, client: .claudeDesktop),
                    generation: UUID())
                guard await approve(server, principal, "catalog", resolved), enabled() else { throw MCPManagementError.denied }
                guard try definition(identity).revision == revision else { throw MCPManagementError.stale }
                guard try items(server.upstream.credentialHeaders) == resolved else { throw MCPManagementError.stale }
            }
            var headers: [String: String] = [:], secrets: [String] = []
            for item in resolved {
                let value = try secret(item)
                guard !value.isEmpty, !value.contains("\r"), !value.contains("\n") else { throw MCPManagementError.invalidRequest }
                let header = item.header.format == .bearer ? "Bearer " + value : value
                headers[item.header.headerName] = header
                secrets.append(contentsOf: [value, header])
            }
            let grant = MCPHTTPGrantSummary(
                id: UUID(),
                principal: MCPHTTPPrincipal(
                    id: UUID(),
                    binding: MCPHTTPAssociationBinding(serverID: server.serverID, identity: identity, client: .claudeDesktop),
                    generation: UUID()),
                sessionID: UUID().uuidString,
                revision: revision,
                expiresAt: clock().addingTimeInterval(60),
                credentialLabels: resolved.map(\.label))
            return MCPHTTPAuthorityReply(lease: MCPHTTPLease(grant: grant, headers: headers, secrets: secrets))
        }
    }

    private func checkedDefinition(_ principal: MCPHTTPPrincipal, revision: String) throws -> MCPServerDefinition {
        guard try load().associations.contains(where: { $0.principal == principal }) else { throw MCPManagementError.denied }
        let current = try definition(principal.binding.identity)
        guard current.serverID == principal.binding.serverID, current.revision == revision else { throw MCPManagementError.stale }
        return current
    }
    private func matchingGrant(_ state: MCPHTTPAuthorityState, principal: MCPHTTPPrincipal, sessionID: String,
                               revision: String, items: [MCPHTTPResolvedItem]) -> MCPHTTPAuthorityState.Grant? {
        state.grants.first { $0.summary.principal == principal && $0.summary.sessionID == sessionID &&
            $0.summary.revision == revision && $0.summary.expiresAt > clock() && $0.items == items }
    }
    private func load() throws -> MCPHTTPAuthorityState {
        guard let data = try storage.load() else { return MCPHTTPAuthorityState() }
        guard data.count <= 4_194_304, let value = try? JSONDecoder().decode(MCPHTTPAuthorityState.self, from: data), value.version == 1 else {
            throw MCPManagementError.unavailable
        }
        return value
    }
    private func save(_ state: MCPHTTPAuthorityState) throws { try storage.save(JSONEncoder().encode(state)) }
    private func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        return zip(a,b).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }
}
#endif
