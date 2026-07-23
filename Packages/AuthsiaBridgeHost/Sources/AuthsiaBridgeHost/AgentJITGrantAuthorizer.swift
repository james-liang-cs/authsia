#if os(macOS)
import Foundation
import AuthenticatorBridge

public final class AgentJITGrantAuthorizer {
    private let store: AgentJITGrantStoring

    public init(store: AgentJITGrantStoring = AgentJITGrantStore()) {
        self.store = store
    }

    public func activeGrant(
        capability: AgentJITCapability,
        itemIdentity: AgentJITItemIdentity? = nil,
        itemFolderPath: String?,
        itemEnvironments: [String] = [],
        caller: AgentJITCallerFingerprint,
        now: Date = Date()
    ) throws -> AgentJITGrant? {
        try store.markUsedIfAllowed(
            capability: capability,
            itemIdentity: itemIdentity,
            itemFolderPath: itemFolderPath,
            itemEnvironments: itemEnvironments,
            caller: caller,
            now: now
        )
    }

    public func activeScopes(
        capability: AgentJITCapability,
        caller: AgentJITCallerFingerprint,
        now: Date = Date()
    ) throws -> [AgentJITFolderScope] {
        try store.markUsedScopes(capability: capability, caller: caller, now: now)
    }

    public func activeGrants(
        capability: AgentJITCapability,
        caller: AgentJITCallerFingerprint,
        now: Date = Date()
    ) throws -> [AgentJITGrant] {
        try store.loadAll().filter {
            $0.status(asOf: now) == .active
                && $0.capabilities.contains(capability)
                && $0.callerFingerprint.matches(caller)
        }
    }
}
#endif
