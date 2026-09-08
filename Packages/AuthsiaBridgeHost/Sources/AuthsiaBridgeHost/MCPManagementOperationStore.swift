#if os(macOS)
import AuthenticatorBridge
import Foundation

public struct MCPPreparedManagementChange: Sendable {
    public let preview: String
    public let validate: @Sendable () async throws -> Void
    public let apply: @Sendable () async throws -> String
    public init(preview: String, validate: @escaping @Sendable () async throws -> Void,
                apply: @escaping @Sendable () async throws -> String) {
        self.preview = preview; self.validate = validate; self.apply = apply
    }
}

/// The browser can request a prompt; only the injected native presenter decides.
/// Neither a second browser payload nor a replay can replace an approved change.
actor MCPManagementOperationStore {
    private struct Entry { let owner: String; let change: MCPPreparedManagementChange; let context: MCPManagementActivityContext?; var view: MCPManagementOperationView }
    private var entries: [UUID: Entry] = [:]
    private var applying = false
    private let clock: @Sendable () -> Date
    private let audit: MCPManagementAuditing?
    init(clock: @escaping @Sendable () -> Date = Date.init, audit: MCPManagementAuditing? = nil) {
        self.clock = clock
        self.audit = audit
    }
    func prepare(owner: String, kind: MCPManagementOperationKind, change: MCPPreparedManagementChange, context: MCPManagementActivityContext? = nil) throws -> MCPManagementOperationView {
        entries = entries.filter { $0.value.view.expiresAt > clock() || [.applying, .awaitingNativeConfirmation].contains($0.value.view.state) }
        guard entries.count < 128 else { throw MCPManagementError.busy }
        let view = MCPManagementOperationView(id: UUID(), kind: kind, preview: change.preview, expiresAt: clock().addingTimeInterval(300))
        entries[view.id] = Entry(owner: owner, change: change, context: context, view: view)
        return view
    }
    func get(_ id: UUID, owner: String) throws -> MCPManagementOperationView {
        guard let entry = entries[id], entry.owner == owner else { throw MCPManagementError.notFound }
        return entry.view
    }
    func confirm(_ id: UUID, owner: String, present: @Sendable (MCPManagementOperationView) async -> Bool,
                 sessionValid: @Sendable () -> Bool) async throws -> MCPManagementOperationView {
        guard var entry = entries[id], entry.owner == owner else { throw MCPManagementError.notFound }
        guard entry.view.state == .prepared else { return entry.view }
        guard entry.view.expiresAt > clock() else { return finish(id, state: .expired) }
        entry.view.state = .awaitingNativeConfirmation; entries[id] = entry
        let approved = await present(entry.view)
        guard sessionValid() else { return finish(id, state: .denied) }
        guard approved else { return finish(id, state: .denied) }
        guard entry.view.expiresAt > clock() else { return finish(id, state: .expired) }
        guard !applying else { return finish(id, state: .failed, message: MCPManagementError.busy.localizedDescription) }
        applying = true
        defer { applying = false }
        do {
            guard let audit else { throw MCPManagementError.auditUnavailable }
            try await audit.record(MCPManagementAuditEvent(operationID: id, kind: entry.view.kind.rawValue, phase: "intent",
                summary: entry.view.preview, result: "pending", context: entry.context))
        } catch {
            return finish(id, state: .failed, message: "The change was not applied because its intent could not be recorded.")
        }
        do {
            try await entry.change.validate()
            guard sessionValid(), entry.view.expiresAt > clock() else {
                try? await audit?.record(MCPManagementAuditEvent(operationID: id, kind: entry.view.kind.rawValue, phase: "outcome",
                    summary: entry.view.preview, result: "notApplied", context: entry.context))
                return finish(id, state: .expired)
            }
            _ = finish(id, state: .applying)
            let message = try await entry.change.apply()
            do {
                try await audit?.record(MCPManagementAuditEvent(operationID: id, kind: entry.view.kind.rawValue, phase: "outcome",
                    summary: entry.view.preview, result: "applied", context: entry.context))
                return finish(id, state: .succeeded, message: message)
            } catch {
                return finish(id, state: .succeeded, message: message + " The change applied, but evidence recording was incomplete.")
            }
        } catch {
            try? await audit?.record(MCPManagementAuditEvent(operationID: id, kind: entry.view.kind.rawValue, phase: "outcome",
                summary: entry.view.preview, result: "notApplied", context: entry.context))
            let error = error as? MCPManagementError ?? .unavailable
            return finish(id, state: error == .stale ? .stale : .failed, message: error.localizedDescription)
        }
    }
    private func finish(_ id: UUID, state: MCPManagementOperationView.State, message: String? = nil) -> MCPManagementOperationView {
        entries[id]!.view.state = state; entries[id]!.view.message = message
        return entries[id]!.view
    }
}
#endif
