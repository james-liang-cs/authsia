#if os(macOS)
import Foundation
import AuthenticatorBridge

public enum AgentJITAuthorityViolation: Equatable {
    case callerBindingMismatch(AgentJITGrant)
    case outsideApprovedItemScope(AgentJITGrant)

    public var grant: AgentJITGrant {
        switch self {
        case .callerBindingMismatch(let grant), .outsideApprovedItemScope(let grant):
            return grant
        }
    }
}

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
        agentRuntimeContext: AgentRuntimeContext? = nil,
        now: Date = Date()
    ) throws -> AgentJITGrant? {
        try store.markUsedIfAllowedForRuntime(
            capability: capability,
            itemIdentity: itemIdentity,
            itemFolderPath: itemFolderPath,
            itemEnvironments: itemEnvironments,
            caller: caller,
            agentRuntimeContext: agentRuntimeContext,
            now: now
        )
    }

    public func activeScopes(
        capability: AgentJITCapability,
        caller: AgentJITCallerFingerprint,
        agentRuntimeContext: AgentRuntimeContext? = nil,
        now: Date = Date()
    ) throws -> [AgentJITFolderScope] {
        try store.markUsedScopesForRuntime(
            capability: capability,
            caller: caller,
            agentRuntimeContext: agentRuntimeContext,
            now: now
        )
    }

    public func activeGrants(
        capability: AgentJITCapability,
        caller: AgentJITCallerFingerprint,
        agentRuntimeContext: AgentRuntimeContext? = nil,
        now: Date = Date()
    ) throws -> [AgentJITGrant] {
        try store.loadAll().filter {
            $0.status(asOf: now) == .active
                && $0.capabilities.contains(capability)
                && $0.callerFingerprint.matches(caller)
                && $0.matchesAgentRuntimeContext(agentRuntimeContext)
        }
    }

    public func revokeOnAuthorityViolation(
        capability: AgentJITCapability,
        itemIdentity: AgentJITItemIdentity?,
        itemFolderPath: String?,
        itemEnvironments: [String],
        caller: AgentJITCallerFingerprint,
        agentRuntimeContext: AgentRuntimeContext? = nil,
        now: Date = Date()
    ) throws -> AgentJITAuthorityViolation? {
        try store.revokeOnAuthorityViolationForRuntime(
            capability: capability,
            itemIdentity: itemIdentity,
            itemFolderPath: itemFolderPath,
            itemEnvironments: itemEnvironments,
            caller: caller,
            agentRuntimeContext: agentRuntimeContext,
            now: now
        )
    }
}
#endif
