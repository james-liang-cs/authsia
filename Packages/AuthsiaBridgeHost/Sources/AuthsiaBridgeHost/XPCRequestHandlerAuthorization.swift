#if os(macOS)
import Foundation
import Security
@preconcurrency import AuthenticatorBridge
import AuthenticatorData
import AuthenticatorCore

extension XPCRequestHandler {
    // MARK: - Audit Logging

    /// Records a successful access event to the audit log. Fire-and-forget; errors are logged in debug builds only.
    func recordAudit(
        command: BridgeRequestType,
        itemId: String,
        itemName: String? = nil,
        approvedBy: String,
        caller: CallerIdentity?,
        requestedCommand: String? = nil,
        fullCommand: String? = nil,
        agentJITGrantID: UUID? = nil,
        agentRuntimeContext: AgentRuntimeContext? = nil,
        workspaceContext: WorkspaceRuntimeContext? = nil,
        environmentScope: EnvironmentAccessScope? = nil
    ) {
        let grantEnvironmentScope = agentJITGrantID.flatMap { grantID -> EnvironmentAccessScope? in
            guard let grants = try? agentJITGrantStore.loadAll() else { return nil }
            return grants.first(where: { $0.id == grantID })?.environmentScope
        }
        let record = BridgeAuditRecord(
            command: command,
            itemId: itemId,
            itemName: itemName,
            approvedBy: approvedBy,
            timestamp: Date(),
            caller: caller,
            requestedCommand: requestedCommand,
            fullCommand: fullCommand,
            agentJITGrantID: agentJITGrantID,
            agentRuntimeContext: agentRuntimeContext,
            workspaceContext: workspaceContext,
            environmentScope: environmentScope ?? grantEnvironmentScope
        )
        do {
            try auditLogger.record(record)
        } catch {
            print("[Audit] Failed to record audit entry: \(error)")
        }
    }

    // MARK: - Private Helpers

    func decodeRequest(_ data: Data) -> BridgeRequest? {
        try? BridgeCoder.decode(BridgeRequest.self, from: data)
    }

    func encodeResponse<T: Codable & Equatable>(_ response: BridgeResponse<T>) -> Data? {
        try? BridgeCoder.encode(response)
    }

    func replyError(
        id: UUID,
        code: BridgeErrorCode,
        message: String,
        reply: XPCReply
    ) {
        let response: BridgeResponse<String> = BridgeResponseBuilder.error(id: id, code: code, message: message)
        reply(encodeResponse(response), nil)
    }

    func replyWriteSuccess(
        id: UUID,
        payload: WriteResultPayload,
        sessionToken: String? = nil,
        sessionExpiresAt: Date? = nil,
        reply: XPCReply
    ) {
        let response: BridgeResponse<WriteResultPayload> = BridgeResponseBuilder.success(id: id, payload: payload, sessionToken: sessionToken, sessionExpiresAt: sessionExpiresAt)
        reply(encodeResponse(response), nil)
    }

    /// Validates the session token and request ID to prevent replay attacks.
    /// Returns true if the request is valid and not a replay.
    /// `callerIdentity` must be the identity captured at the synchronous XPC entry;
    /// re-extracting here would read NSXPCConnection.current() outside the message
    /// context and yield nil, so no stored session origin could ever match.
    func validateSessionAndRequest(
        _ request: BridgeRequest,
        sessionToken: String?,
        callerIdentity: CallerIdentity?
    ) -> Bool {
        guard let token = sessionToken else {
            return false
        }
        return Self.sharedSessionManager.validateRequestId(
            request.id,
            sessionToken: token,
            scope: request.context.sessionScope,
            origin: Self.sessionOrigin(from: callerIdentity, request: request)
        )
    }

    func unsupportedAgentJITSecretReadDecision(
        request: BridgeRequest,
        itemKind: String
    ) -> SecretReadApprovalDecision {
        unsupportedAgentJITSecretReadDecision(
            request: request,
            itemKind: itemKind,
            callerIdentity: callerIdentityProvider()
        )
    }

    func unsupportedAgentJITSecretReadDecision(
        request: BridgeRequest,
        itemKind: String,
        callerIdentity: CallerIdentity?
    ) -> SecretReadApprovalDecision {
        if request.context.hasAutomationCredential {
            return .allowed(approvedBy: "automation", needsApproval: false, agentJITGrantID: nil)
        }
        if Self.interactiveHumanBootstrapEligible(request: request, callerIdentity: callerIdentity)
            && !Self.hasValidatedInteractiveHumanSession(request: request, callerIdentity: callerIdentity) {
            return .allowed(approvedBy: "biometric", needsApproval: true, agentJITGrantID: nil)
        }
        guard Self.isAgentJITCaller(request: request, callerIdentity: callerIdentity) else {
            return .allowed(approvedBy: "session", needsApproval: false, agentJITGrantID: nil)
        }
        guard request.context.requestedCommand == "exec" else {
            return .denied(
                code: .policyDenied,
                message: Self.unsupportedAgentJITCommandMessage(for: request.context.requestedCommand)
                    ?? "Agent secret reads are only allowed through authsia exec with a valid JIT grant."
            )
        }
        return .denied(
            code: .policyDenied,
            message: "Agent exec JIT does not support \(itemKind) items."
        )
    }

    enum SecretReadApprovalDecision: Equatable {
        case allowed(approvedBy: String, needsApproval: Bool, agentJITGrantID: UUID?)
        case denied(code: BridgeErrorCode, message: String)
    }

    static func unsupportedAgentJITCommandMessage(for requestedCommand: String?) -> String? {
        switch requestedCommand {
        case .some(let command) where command == "get" || command == "load":
            "Agent JIT grants do not allow authsia \(command). " +
                "Use authsia exec with an approved JIT grant to inject secrets into a command."
        case .some(let command) where command == "exec" || command == "list":
            nil
        case .some(let command) where !command.isEmpty:
            "Agent JIT grants do not allow authsia \(command). " +
                "JIT grants only permit authsia list and authsia exec."
        default:
            nil
        }
    }

    static func isAgentJITCaller(request: BridgeRequest, callerIdentity: CallerIdentity?) -> Bool {
        // Chrome autofill uses the CLI transport via AuthsiaNativeHost, but it is not an
        // agent caller and must keep the normal biometric/session approval path.
        if isChromeNativeHostCaller(request: request, callerIdentity: callerIdentity) {
            return false
        }
        if request.context.agentRuntimeContext != nil {
            return true
        }
        if AgentJITCallerContext.hasAgenticCaller(callerIdentity) {
            return true
        }
        if AgentJITCallerContext.hasAutomationSuspectCaller(callerIdentity) {
            return true
        }
        if AgentJITCallerContext.isTrustedHumanTerminal(callerIdentity),
           hasValidatedInteractiveHumanSession(request: request, callerIdentity: callerIdentity) {
            return false
        }
        guard request.context.requestedCommand != nil else { return false }
        return !AgentJITCallerContext.isTrustedHumanTerminal(callerIdentity)
    }

    static func isChromeNativeHostCaller(
        request: BridgeRequest,
        callerIdentity: CallerIdentity?
    ) -> Bool {
        // Require both the hidden CLI marker and AuthsiaNativeHost ancestry so
        // this path cannot open for terminal, agent, or IDE-hosted CLI callers.
        request.context.requestedCommand == BridgeContext.chromeNativeHostRequestedCommand
            && isChromeNativeHostCallerIdentity(callerIdentity)
    }

    private static func hasValidatedInteractiveHumanSession(
        request: BridgeRequest,
        callerIdentity: CallerIdentity?
    ) -> Bool {
        guard request.context.isTTY,
              let sessionToken = request.sessionToken,
              !sessionToken.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let origin = sessionOrigin(from: callerIdentity, request: request),
              let currentSession = sharedSessionManager.currentSession(scope: request.context.sessionScope) else {
            return false
        }
        return AgentJITCallerContext.isTrustedHumanTerminal(callerIdentity)
            && currentSession.sessionToken == sessionToken
            && sharedSessionManager.hasOrigin(origin, scope: request.context.sessionScope)
    }

    static func interactiveHumanBootstrapEligible(
        request: BridgeRequest,
        callerIdentity: CallerIdentity? = nil
    ) -> Bool {
        request.context.isTTY
            && request.context.agentRuntimeContext == nil
            && !AgentJITCallerContext.hasAgenticCaller(callerIdentity)
            && !AgentJITCallerContext.hasAutomationSuspectCaller(callerIdentity)
    }

    static func unsupportedAgentJITBridgeCommandDenial(
        for request: BridgeRequest,
        callerIdentity: CallerIdentity?
    ) -> BridgeErrorPayload? {
        guard Self.isAgentJITCaller(request: request, callerIdentity: callerIdentity),
              !Self.interactiveHumanBootstrapEligible(
                request: request,
                callerIdentity: callerIdentity
              ) else {
            return nil
        }
        guard request.type != .agentJITPreflight else {
            return nil
        }
        let command = Self.agentJITCommandName(for: request)
        return BridgeErrorPayload(
            code: .policyDenied,
            message: Self.unsupportedAgentJITCommandMessage(for: command)
                ?? "Agent JIT grants do not allow this command. JIT grants only permit authsia list and authsia exec."
        )
    }

    private static func agentJITCommandName(for request: BridgeRequest) -> String {
        switch request.type {
        case .unlock:
            return "unlock"
        case .exportAccounts:
            return "export"
        case .createAccess:
            return "access"
        case .addPassword, .addAPIKey, .addCertificate, .addNote, .addSSH:
            return request.context.requestedCommand == "scrape" ? "scrape" : "add"
        case .updatePassword, .updateAPIKey, .updateCertificate, .updateNote, .updateSSH:
            return "edit"
        case .convertPasswordToAPIKey:
            return "convert"
        case .deletePassword, .deleteAPIKey, .deleteCertificate, .deleteNote, .deleteSSH, .deleteVaultFolder:
            return "delete"
        default:
            return request.context.requestedCommand ?? request.type.rawValue
        }
    }

    func secretReadApprovalDecision(
        itemIdentity: AgentJITItemIdentity? = nil,
        itemFolderPath: String?,
        itemEnvironments: [String] = [],
        request: BridgeRequest,
        bypassApproval: Bool
    ) -> SecretReadApprovalDecision {
        secretReadApprovalDecision(
            itemIdentity: itemIdentity,
            itemFolderPath: itemFolderPath,
            itemEnvironments: itemEnvironments,
            request: request,
            bypassApproval: bypassApproval,
            callerIdentity: callerIdentityProvider()
        )
    }

    func secretReadApprovalDecision(
        itemIdentity: AgentJITItemIdentity? = nil,
        itemFolderPath: String?,
        itemEnvironments: [String],
        request: BridgeRequest,
        bypassApproval: Bool,
        callerIdentity: CallerIdentity?
    ) -> SecretReadApprovalDecision {
        if bypassApproval {
            return .allowed(approvedBy: "automation", needsApproval: false, agentJITGrantID: nil)
        }

        if Self.isAgentJITCaller(request: request, callerIdentity: callerIdentity)
            && !Self.interactiveHumanBootstrapEligible(
                request: request,
                callerIdentity: callerIdentity
            ) {
            guard request.context.requestedCommand == "exec" else {
                return .denied(
                    code: .policyDenied,
                    message: Self.unsupportedAgentJITCommandMessage(for: request.context.requestedCommand)
                        ?? "Agent secret reads are only allowed through authsia exec with a valid JIT grant."
                )
            }
            do {
                if let grant = try agentJITGrant(
                    capability: .exec,
                    itemIdentity: itemIdentity,
                    itemFolderPath: itemFolderPath,
                    itemEnvironments: itemEnvironments,
                    request: request,
                    callerIdentity: callerIdentity
                ) {
                    return .allowed(approvedBy: "jit", needsApproval: false, agentJITGrantID: grant.id)
                }
                if let caller = AgentJITCallerContext.fingerprint(
                    for: request,
                    caller: callerIdentity
                ), let violation = try agentJITGrantAuthorizer.revokeOnAuthorityViolation(
                    capability: .exec,
                    itemIdentity: itemIdentity,
                    itemFolderPath: itemFolderPath,
                    itemEnvironments: itemEnvironments,
                    caller: caller
                ) {
                    let evidence: AgentLeakEvidence
                    switch violation {
                    case .callerBindingMismatch:
                        evidence = .callerBindingMismatch
                    case .outsideApprovedItemScope:
                        evidence = .outsideApprovedItemScope
                    }
                    recordAudit(
                        command: request.type,
                        itemId: itemIdentity?.id.uuidString ?? "unknown-item",
                        approvedBy: "incident:\(evidence.rawValue):revokeAndDeny",
                        caller: callerIdentity,
                        requestedCommand: request.context.requestedCommand,
                        agentJITGrantID: violation.grant.id,
                        agentRuntimeContext: request.context.agentRuntimeContext,
                        workspaceContext: request.context.workspaceContext
                    )
                }
            } catch {
                return .denied(
                    code: .policyDenied,
                    message: "Agent exec secret reads require a valid JIT preflight grant for this item scope."
                )
            }
            return .denied(
                code: .policyDenied,
                message: "Agent exec secret reads require a valid JIT preflight grant for this item scope."
            )
        }

        let needsApproval = !validateSessionAndRequest(request, sessionToken: request.sessionToken, callerIdentity: callerIdentity)
        return .allowed(
            approvedBy: needsApproval ? "biometric" : "session",
            needsApproval: needsApproval,
            agentJITGrantID: nil
        )
    }

    func agentJITGrant(
        capability: AgentJITCapability,
        itemIdentity: AgentJITItemIdentity? = nil,
        itemFolderPath: String?,
        itemEnvironments: [String] = [],
        request: BridgeRequest
    ) throws -> AgentJITGrant? {
        try agentJITGrant(
            capability: capability,
            itemIdentity: itemIdentity,
            itemFolderPath: itemFolderPath,
            itemEnvironments: itemEnvironments,
            request: request,
            callerIdentity: callerIdentityProvider()
        )
    }

    private func agentJITGrant(
        capability: AgentJITCapability,
        itemIdentity: AgentJITItemIdentity?,
        itemFolderPath: String?,
        itemEnvironments: [String],
        request: BridgeRequest,
        callerIdentity: CallerIdentity?
    ) throws -> AgentJITGrant? {
        guard requestedCommandAllowsJITCapability(capability, request: request),
              let caller = AgentJITCallerContext.fingerprint(for: request, caller: callerIdentity) else {
            return nil
        }
        return try agentJITGrantAuthorizer.activeGrant(
            capability: capability,
            itemIdentity: itemIdentity,
            itemFolderPath: itemFolderPath,
            itemEnvironments: itemEnvironments,
            caller: caller
        )
    }

    func activeAgentJITScopes(
        capability: AgentJITCapability,
        request: BridgeRequest,
        callerIdentity: CallerIdentity?
    ) throws -> [AgentJITFolderScope] {
        guard requestedCommandAllowsJITCapability(capability, request: request),
              let caller = AgentJITCallerContext.fingerprint(for: request, caller: callerIdentity) else {
            return []
        }
        return try agentJITGrantAuthorizer.activeScopes(capability: capability, caller: caller)
    }

    private func requestedCommandAllowsJITCapability(_ capability: AgentJITCapability, request: BridgeRequest) -> Bool {
        switch capability {
        case .exec:
            return request.context.requestedCommand == "exec"
        case .list:
            return request.context.requestedCommand == "list" || request.context.requestedCommand == "exec"
        }
    }

    func filteredListPayload(_ payload: BridgeListPayload, for request: BridgeRequest) -> BridgeListPayload {
        filteredListPayload(
            payload,
            for: request,
            callerIdentity: callerIdentityProvider(),
            activeJITScopes: nil
        )
    }

    func filteredListPayload(
        _ payload: BridgeListPayload,
        for request: BridgeRequest,
        callerIdentity: CallerIdentity?,
        activeJITScopes: [AgentJITFolderScope]?,
        activeJITGrants: [AgentJITGrant]? = nil,
        callerUsesAgentJIT: Bool? = nil
    ) -> BridgeListPayload {
        let callerUsesAgentJIT = callerUsesAgentJIT ?? (
            Self.isAgentJITCaller(request: request, callerIdentity: callerIdentity)
                && !Self.interactiveHumanBootstrapEligible(
                    request: request,
                    callerIdentity: callerIdentity
                )
        )
        let jitScopes = activeJITScopes ?? (
            callerUsesAgentJIT
                ? (try? activeAgentJITScopes(
                    capability: .list,
                    request: request,
                    callerIdentity: callerIdentity
                )) ?? []
                : []
        )
        let automationDecision = AutomationAuthorizationPolicy.authorization(
            for: request,
            itemFolderPath: nil,
            itemKind: "list",
            credentialLookup: automationCredentialLookupProvider,
            credentialValidation: automationCredentialValidationProvider,
            currentMachineId: currentMachineIdProvider()
        )
        let jitGrants = activeJITGrants ?? {
            guard callerUsesAgentJIT,
                  let caller = AgentJITCallerContext.fingerprint(for: request, caller: callerIdentity) else { return [] }
            return (try? agentJITGrantAuthorizer.activeGrants(capability: .list, caller: caller)) ?? []
        }()
        return BridgeListPayloadFilter.filteredPayload(
            payload,
            for: request,
            callerIsAgentic: callerUsesAgentJIT,
            activeJITScopes: jitScopes,
            automationAuthorization: automationDecision,
            automationEnvironmentScope: AutomationAuthorizationPolicy.environmentScope(
                for: request,
                credentialLookup: automationCredentialLookupProvider,
                credentialValidation: automationCredentialValidationProvider
            ),
            activeJITGrants: jitGrants
        )
    }

    // normalizeFolderPath and folderMatches are now shared via AuthenticatorBridge

    /// Evaluates the automation authorization decision for a request and handles the deny case.
    /// Returns `nil` if the request was denied (error reply already sent), or the `bypassApproval` flag.
    func resolveAutomationApproval(
        for request: BridgeRequest,
        itemFolderPath: String?,
        itemEnvironments: [String] = [],
        itemKind: String,
        reply: XPCReply
    ) -> Bool? {
        let decision = AutomationAuthorizationPolicy.authorization(
            for: request,
            itemFolderPath: itemFolderPath,
            itemEnvironments: itemEnvironments,
            itemKind: itemKind,
            credentialLookup: automationCredentialLookupProvider,
            credentialValidation: automationCredentialValidationProvider,
            currentMachineId: currentMachineIdProvider()
        )
        if case .deny(let message) = decision {
            let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                id: request.id,
                code: .policyDenied,
                message: message
            )
            reply(encodeResponse(response), nil)
            return nil
        }
        if case .allowWithoutApproval = decision { return true }
        return false
    }

    /// Ensures the request is authorized, either via valid session or explicit local approval.
    /// Returns the new session token and expiry if approval was required, or nil if an existing session was valid.
    @MainActor
    func requestLocalApproval(
        prompt: String,
        command: BridgeRequestType,
        itemLabel: String?,
        field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?
    ) async -> RemoteJITApprovalAuthorizationPolicy.Result {
        let outcome = await approver.requestApproval(
            prompt: prompt,
            command: command,
            itemLabel: itemLabel,
            field: field,
            callback: callback
        )
        return RemoteJITApprovalAuthorizationPolicy.authorize(
            outcome: outcome,
            command: command,
            remoteRequests: []
        )
    }

    @MainActor
    func ensureApproval(
        for request: BridgeRequest,
        prompt: String,
        itemLabel: String?,
        callerIdentity: CallerIdentity?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?
    ) async -> (approved: Bool, newSessionToken: String?, sessionExpiresAt: Date?) {
        // Validate session and request for replay protection
        let needsApproval = !validateSessionAndRequest(request, sessionToken: request.sessionToken, callerIdentity: callerIdentity)
        if !needsApproval {
            return (true, nil, nil)
        }

        let authorization = await requestLocalApproval(
            prompt: prompt,
            command: request.type,
            itemLabel: itemLabel,
            field: nil,
            callback: callback
        )
        if case .allowed = authorization {
            let session = issueReusableHumanSession(for: request, callerIdentity: callerIdentity)
            guard !session.failed else {
                return (false, nil, nil)
            }
            return (true, session.token, session.expiresAt)
        }
        return (false, nil, nil)
    }

    static func sessionOrigin(
        from callerIdentity: CallerIdentity?,
        request: BridgeRequest? = nil
    ) -> BridgeSessionOrigin? {
        guard let callerIdentity else { return nil }
        // Chrome launches a fresh AuthsiaNativeHost process per sendNativeMessage.
        // Bind the reusable chrome session to the stable host name, not that PID,
        // or match-count / menu / fill each re-prompt. Marker + native-host parent
        // are both required so terminal/agent sessions keep PID-bound origins.
        if let request, isChromeNativeHostCaller(request: request, callerIdentity: callerIdentity) {
            return BridgeSessionOrigin(
                processIdentifier: 0,
                processName: BridgeContext.chromeNativeHostProcessName,
                bundleIdentifier: nil
            )
        }
        if let hostProcess = callerIdentity.hostProcess {
            return BridgeSessionOrigin(
                processIdentifier: hostProcess.pid,
                processName: hostProcess.processName,
                bundleIdentifier: hostProcess.bundleIdentifier
            )
        }
        if let parentProcess = callerIdentity.parentProcess {
            return BridgeSessionOrigin(
                processIdentifier: parentProcess.pid,
                processName: parentProcess.processName,
                bundleIdentifier: parentProcess.bundleIdentifier
            )
        }
        return BridgeSessionOrigin(
            processIdentifier: callerIdentity.pid,
            processName: callerIdentity.processName,
            bundleIdentifier: callerIdentity.bundleIdentifier
        )
    }

    static func isChromeNativeHostCallerIdentity(_ callerIdentity: CallerIdentity?) -> Bool {
        BridgeContext.isChromeNativeHostProcessName(callerIdentity?.parentProcess?.processName)
            || BridgeContext.isChromeNativeHostProcessName(callerIdentity?.hostProcess?.processName)
    }

    func issueReusableHumanSession(
        for request: BridgeRequest,
        callerIdentity: CallerIdentity?
    ) -> (token: String?, expiresAt: Date?, failed: Bool) {
        let mayIssueReusableSession =
            AgentJITCallerContext.isTrustedHumanTerminal(callerIdentity)
            || Self.isChromeNativeHostCaller(request: request, callerIdentity: callerIdentity)
        guard mayIssueReusableSession else {
            return (nil, nil, false)
        }
        guard let session = Self.sharedSessionManager.createSessionOrNil(
            ttlSeconds: Self.configuredSessionTTL,
            scope: request.context.sessionScope,
            workingDirectory: request.context.workingDirectory,
            origin: Self.sessionOrigin(from: callerIdentity, request: request)
        ) else {
            return (nil, nil, true)
        }
        return (session.sessionToken, session.expiresAt, false)
    }

    func makeNSError(code: BridgeErrorCode, message: String) -> NSError {
        NSError(
            domain: "com.authsia.bridge.xpc",
            code: -1,
            userInfo: [
                NSLocalizedDescriptionKey: message,
                "BridgeErrorCode": code.rawValue
            ]
        )
    }

}
#endif
