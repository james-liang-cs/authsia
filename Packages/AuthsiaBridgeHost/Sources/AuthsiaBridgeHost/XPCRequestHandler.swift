#if os(macOS)
import Foundation
import Security
@preconcurrency import AuthenticatorBridge
import AuthenticatorData
import AuthenticatorCore

public typealias CallerIdentityRevalidationProvider = (CallerIdentity) -> CallerIdentity?
public typealias AgentJITApprovalClock = () -> Date

final class XPCReply: @unchecked Sendable {
    private let callback: (Data?, NSError?) -> Void

    init(_ callback: @escaping (Data?, NSError?) -> Void) {
        self.callback = callback
    }

    func callAsFunction(_ data: Data?, _ error: NSError?) {
        callback(data, error)
    }
}

/// Handles XPC requests from the CLI, implementing the AuthsiaBridgeXPCProtocol.
/// This is the native XPC replacement for the file-based BridgeCLIHandler.
public final class XPCRequestHandler: NSObject, AuthsiaBridgeXPCProtocol, @unchecked Sendable {
    public typealias ListProvider = () throws -> BridgeListPayload
    public typealias AccountProvider = () throws -> [BridgeAccount]
    public typealias WorkspaceMetadataProvider = () async throws -> Data
    public typealias SecretExistenceProvider = (UUID) -> Bool?
    public typealias AutomationCredentialLookupProvider = (UUID) -> AutomationCredentialLookup.Result
    public typealias AutomationCredentialAuthorityProvider = () throws -> AutomationCredentialAuthority
    public typealias AutomationCredentialValidationProvider = (
        String,
        CapabilityCommand,
        Bool
    ) -> AutomationCredentialLookup.Result
    public typealias CurrentMachineIdProvider = () -> String?
    public typealias CallerIdentityProvider = () -> CallerIdentity?
    
    // MARK: - Dependencies
    let listProvider: ListProvider?
    let accountProvider: AccountProvider
    let approver: BridgeApprover
    let repository: VaultRepositoryProviding
    let workspaceMetadataProvider: WorkspaceMetadataProvider
    let passwordSecretExistenceProvider: SecretExistenceProvider
    let apiKeySecretExistenceProvider: SecretExistenceProvider
    let automationCredentialLookupProvider: AutomationCredentialLookupProvider
    let automationCredentialAuthorityProvider: AutomationCredentialAuthorityProvider
    let automationCredentialValidationProvider: AutomationCredentialValidationProvider
    let currentMachineIdProvider: CurrentMachineIdProvider
    let authorityStore: AuthorityStoring
    let agentJITGrantStore: AgentJITGrantStoring
    let agentJITGrantAuthorizer: AgentJITGrantAuthorizer
    let callerIdentityProvider: CallerIdentityProvider
    let callerIdentityRevalidationProvider: CallerIdentityRevalidationProvider
    let remoteJITApprovalRequestBuilder: RemoteJITApprovalRequestBuilding?
    let remoteJITApprovalEnabled: @Sendable () -> Bool
    let agentJITApprovalClock: AgentJITApprovalClock
    let auditLogger: BridgeAuditLogger
    let appBundlePath: String

    static let sharedSessionManager = BridgeSessionManager.shared

    // MARK: - Initialization

    /// Returns the configured CLI session TTL (delegates to BridgeSessionManager)
    static var configuredSessionTTL: TimeInterval {
        BridgeSessionManager.configuredTTL
    }

    /// Returns whether CLI access is globally enabled (default: true for backward compatibility)
    static var isCliAccessEnabled: Bool {
        BridgeSettings.isCliAccessEnabled()
    }

    static func itemCLIRestrictionAllowsAccess(
        isCliEnabled: Bool,
        request: BridgeRequest,
        callerIdentity: CallerIdentity?
    ) -> Bool {
        if isCliEnabled {
            return true
        }
        guard request.context.requestedCommand == BridgeContext.chromeNativeHostRequestedCommand else {
            return false
        }
        return BridgeContext.isChromeNativeHostProcessName(callerIdentity?.parentProcess?.processName)
    }

    /// These default providers must be built outside the @MainActor init: closure
    /// literals in its body inherit main-actor isolation and trap in
    /// dispatch_assert_queue when the XPC queue invokes them during synchronous
    /// dispatch (listAccess/revokeAccess/validateAccess).
    nonisolated static func defaultAutomationCredentialAuthorityProvider(
        authorityStore: AuthorityStoring,
        digestKeyLoader: @escaping () throws -> Data = {
            try AutomationCredentialDigestKeyStore().loadOrCreate()
        }
    ) -> AutomationCredentialAuthorityProvider {
        {
            AutomationCredentialAuthority(
                authorityStore: authorityStore,
                digestKey: try digestKeyLoader()
            )
        }
    }

    nonisolated static func defaultAutomationCredentialValidationProvider(
        authorityProvider: @escaping AutomationCredentialAuthorityProvider,
        currentMachineIdProvider: @escaping CurrentMachineIdProvider
    ) -> AutomationCredentialValidationProvider {
        { token, command, consumingUse in
            guard let machineId = currentMachineIdProvider() else { return .credentialNotFound }
            do {
                let metadata = try authorityProvider().validate(
                    token: token,
                    requestedCommand: command,
                    currentMachineId: machineId,
                    consumingUse: consumingUse
                )
                return .found(AutomationCredentialLookup.CredentialRecord(metadata: metadata))
            } catch AutomationCredentialAuthorityError.corruptedStore {
                return .corruptedStore
            } catch {
                return .credentialNotFound
            }
        }
    }

    @MainActor
    public init(
        listProvider: ListProvider? = nil,
        accountProvider: AccountProvider? = nil,
        approver: BridgeApprover,
        repository: VaultRepositoryProviding = VaultRepository.shared,
        workspaceMetadataProvider: @escaping WorkspaceMetadataProvider = {
            try await Task.detached(priority: .userInitiated) {
                try BridgeCoder.encode(BridgeListPayloadFactory.workspaceMetadataPayload())
            }.value
        },
        passwordSecretExistenceProvider: @escaping SecretExistenceProvider = {
            BridgeListPayloadFactory.passwordHasSecret(id: $0)
        },
        apiKeySecretExistenceProvider: @escaping SecretExistenceProvider = {
            BridgeListPayloadFactory.apiKeyHasSecret(id: $0)
        },
        automationCredentialLookupProvider: @escaping AutomationCredentialLookupProvider = {
            AutomationCredentialLookup.lookup(credentialID: $0)
        },
        automationCredentialAuthorityProvider: AutomationCredentialAuthorityProvider? = nil,
        automationCredentialValidationProvider: AutomationCredentialValidationProvider? = nil,
        currentMachineIdProvider: @escaping CurrentMachineIdProvider = {
            AutomationCredentialLookup.currentMachineId()
        },
        authorityStore: AuthorityStoring = KeychainAuthorityStore(),
        agentJITGrantStore: AgentJITGrantStoring? = nil,
        callerIdentityProvider: @escaping CallerIdentityProvider = {
            CallerIdentityExtractor.extract(from: NSXPCConnection.current())
        },
        callerIdentityRevalidationProvider: @escaping CallerIdentityRevalidationProvider = { original in
            CallerIdentityExtractor.extract(fromPID: original.pid)
        },
        remoteJITApprovalRequestBuilder: RemoteJITApprovalRequestBuilding? = nil,
        remoteJITApprovalEnabled: @escaping @Sendable () -> Bool = {
            BridgeSettings.isRemoteApprovalEnabled()
        },
        agentJITApprovalClock: @escaping AgentJITApprovalClock = Date.init,
        auditLogger: BridgeAuditLogger = BridgeAuditLogger(),
        appBundlePath: String = Bundle.main.bundlePath
    ) {
        self.listProvider = listProvider
        self.accountProvider = accountProvider ?? BridgeListPayloadFactory.defaultAccounts
        self.approver = approver
        self.repository = repository
        self.workspaceMetadataProvider = workspaceMetadataProvider
        self.passwordSecretExistenceProvider = passwordSecretExistenceProvider
        self.apiKeySecretExistenceProvider = apiKeySecretExistenceProvider
        self.automationCredentialLookupProvider = automationCredentialLookupProvider
        let resolvedAutomationCredentialAuthorityProvider = automationCredentialAuthorityProvider
            ?? Self.defaultAutomationCredentialAuthorityProvider(authorityStore: authorityStore)
        self.automationCredentialAuthorityProvider = resolvedAutomationCredentialAuthorityProvider
        self.automationCredentialValidationProvider = automationCredentialValidationProvider
            ?? Self.defaultAutomationCredentialValidationProvider(
                authorityProvider: resolvedAutomationCredentialAuthorityProvider,
                currentMachineIdProvider: currentMachineIdProvider
            )
        self.currentMachineIdProvider = currentMachineIdProvider
        self.authorityStore = authorityStore
        let resolvedAgentJITGrantStore = agentJITGrantStore
            ?? AgentJITGrantStore(authorityStore: authorityStore)
        self.agentJITGrantStore = resolvedAgentJITGrantStore
        self.agentJITGrantAuthorizer = AgentJITGrantAuthorizer(store: resolvedAgentJITGrantStore)
        self.callerIdentityProvider = callerIdentityProvider
        self.callerIdentityRevalidationProvider = callerIdentityRevalidationProvider
        self.remoteJITApprovalRequestBuilder = remoteJITApprovalRequestBuilder
        self.remoteJITApprovalEnabled = remoteJITApprovalEnabled
        self.agentJITApprovalClock = agentJITApprovalClock
        self.auditLogger = auditLogger
        self.appBundlePath = appBundlePath
        super.init()
    }

    @MainActor
    func currentListPayload() throws -> BridgeListPayload {
        if let listProvider {
            return try listProvider()
        }

        try repository.load()

        let accounts = try accountProvider()
        return BridgeListPayloadFactory.repositoryPayload(accounts: accounts, repository: repository)
    }

    /// Builds the payload for a workspace metadata request without per-item secret probes.
    /// Sync and validation read persisted metadata off the main actor so changes made by another
    /// process are visible. Routine status requests reuse warm repository state to avoid repeated I/O.
    @MainActor
    func currentWorkspaceMetadataPayload(for request: BridgeRequest) async throws -> BridgeListPayload {
        if let listProvider {
            return try listProvider()
        }

        let requiresPersistedMetadata = [
            BridgeContext.workspaceSyncPreviewRequestedCommand,
            BridgeContext.workspaceEnvValidateRequestedCommand,
            BridgeContext.workspaceEnvUseRequestedCommand,
            BridgeContext.workspaceEnvBindingsListRequestedCommand,
            BridgeContext.workspaceRunRequestedCommand,
        ].contains(request.context.requestedCommand)
        if !requiresPersistedMetadata, repository.hasLoadedVaultState {
            return BridgeListPayloadFactory.repositoryMetadataPayload(repository: repository)
        }

        return try BridgeCoder.decode(
            BridgeListPayload.self,
            from: try await workspaceMetadataProvider()
        )
    }

    func durationDescription(for ttl: TimeInterval) -> String {
        let seconds = Int(ttl.rounded())
        if seconds < 60 {
            return "\(seconds) seconds"
        }
        let minutes = seconds / 60
        if minutes < 60 {
            return "\(minutes) minutes"
        }
        let hours = minutes / 60
        return "\(hours) hours"
    }

}
#endif
