#if os(macOS)
import Foundation
import Security
@preconcurrency import AuthenticatorBridge
import AuthenticatorData
import AuthenticatorCore

extension XPCRequestHandler {
    public func getOTP(_ request: Data, _ rawReply: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Failed to decode getOTP request"))
            return
        }

        if let policyError = BridgeRequestPolicy.denial(for: bridgeRequest) {
            let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                id: bridgeRequest.id,
                code: policyError.code,
                message: policyError.message
            )
            reply(encodeResponse(response), nil)
            return
        }

        let callerIdentity = callerIdentityProvider()
        let callback = NSXPCConnection.current()?.remoteObjectProxy as? AuthsiaBridgeApprovalCallbackProtocol
        Task { @MainActor [weak self] in
            guard let self else { return }

            // Check global CLI access first (before approval)
            guard Self.isCliAccessEnabled else {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .policyDenied,
                    message: "CLI access is disabled"
                )
                reply(self.encodeResponse(response), nil)
                return
            }
            switch self.unsupportedAgentJITSecretReadDecision(
                request: bridgeRequest,
                itemKind: "otp",
                callerIdentity: callerIdentity
            ) {
            case .allowed:
                break
            case .denied(let code, let message):
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: code,
                    message: message
                )
                reply(self.encodeResponse(response), nil)
                return
            }

            do {
                let accounts = try MetadataStore.shared.loadAll()

                guard let match = BridgeQueryMatcher.firstMatch(
                    query: bridgeRequest.query,
                    in: accounts,
                    id: { $0.id.uuidString },
                    searchable: { [$0.issuer, $0.label] }
                ) else {
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: .notFound,
                        message: "No matching account found"
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }

                // Chrome autofill uses the CLI transport but should not inherit the per-item CLI toggle.
                guard Self.itemCLIRestrictionAllowsAccess(
                    isCliEnabled: match.isCliEnabled,
                    request: bridgeRequest,
                    callerIdentity: callerIdentity
                ) else {
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: .policyDenied,
                        message: "CLI access is disabled for '\(match.issuer)'. Enable it in the Authsia app under item settings."
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }

                // Validate session and request approval after confirming CLI access is allowed.
                guard let bypassApproval = self.resolveAutomationApproval(
                    for: bridgeRequest, itemFolderPath: nil, itemKind: "otp", reply: reply
                ) else { return }
                var newSessionToken: String?
                var newSessionExpiresAt: Date?
                var interactiveApprovalAttribution: String?
                let sessionToken = bridgeRequest.sessionToken
                let needsApproval = !bypassApproval && !self.validateSessionAndRequest(bridgeRequest, sessionToken: sessionToken)
                if needsApproval {
                    let authorization = await self.requestLocalApproval(
                        prompt: "Allow CLI to access OTP code for \(match.issuer)",
                        command: .getOTP,
                        itemLabel: match.issuer,
                        field: "otp",
                        callback: callback
                    )
                    guard case .allowed(_, let attribution) = authorization else {
                        self.recordAudit(
                            command: .getOTP,
                            itemId: match.id.uuidString,
                            itemName: match.issuer,
                            approvedBy: authorization.attribution,
                            caller: callerIdentity,
                            requestedCommand: bridgeRequest.context.requestedCommand,
                            fullCommand: bridgeRequest.context.fullCommand,
                            agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                            workspaceContext: bridgeRequest.context.workspaceContext
                        )
                        let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                            id: bridgeRequest.id,
                            code: .notAuthorized,
                            message: "Access denied"
                        )
                        reply(self.encodeResponse(response), nil)
                        return
                    }
                    interactiveApprovalAttribution = attribution
                    guard let session = Self.sharedSessionManager.createSessionOrNil(
                        ttlSeconds: Self.configuredSessionTTL,
                        scope: bridgeRequest.context.sessionScope,
                        workingDirectory: bridgeRequest.context.workingDirectory,
                        origin: sessionOrigin(from: callerIdentity)
                    ) else {
                        let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                            id: bridgeRequest.id,
                            code: .appUnavailable,
                            message: "Session creation failed"
                        )
                        reply(self.encodeResponse(response), nil)
                        return
                    }
                    newSessionToken = session.sessionToken
                    newSessionExpiresAt = session.expiresAt
                }

                let secret = try KeychainStore.shared.retrieve(for: match.id)
                let now = Date()
                let code = OTPGenerator.totp(
                    secret: secret,
                    time: now,
                    period: match.period,
                    digits: match.digits,
                    algorithm: match.algorithm
                )
                let remaining = Int(match.period - now.timeIntervalSince1970.truncatingRemainder(dividingBy: match.period))
                let expiresAt = now.addingTimeInterval(TimeInterval(remaining))

                let payload = OTPPayload(
                    accountId: match.id.uuidString,
                    issuer: match.issuer,
                    label: match.label,
                    code: code,
                    remaining: remaining,
                    expiresAt: expiresAt,
                    isFavorite: match.isFavorite
                )
                let response: BridgeResponse<OTPPayload> = BridgeResponseBuilder.success(
                    id: bridgeRequest.id,
                    payload: payload,
                    sessionToken: newSessionToken,
                    sessionExpiresAt: newSessionExpiresAt
                )
                self.recordAudit(
                    command: .getOTP,
                    itemId: match.id.uuidString,
                    itemName: match.issuer,
                    approvedBy: bypassApproval
                        ? "automation"
                        : (interactiveApprovalAttribution ?? "session"),
                    caller: callerIdentity,
                    requestedCommand: bridgeRequest.context.requestedCommand,
                    fullCommand: bridgeRequest.context.fullCommand,
                    agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                    workspaceContext: bridgeRequest.context.workspaceContext
                )
                reply(self.encodeResponse(response), nil)
            } catch {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .notFound,
                    message: "Failed to retrieve account: \(error.localizedDescription)"
                )
                reply(self.encodeResponse(response), nil)
            }
        }
    }

    public func getPassword(_ request: Data, _ rawReply: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Failed to decode getPassword request"))
            return
        }

        if let policyError = BridgeRequestPolicy.denial(for: bridgeRequest) {
            let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                id: bridgeRequest.id,
                code: policyError.code,
                message: policyError.message
            )
            reply(encodeResponse(response), nil)
            return
        }

        let callerIdentity = callerIdentityProvider()
        let callback = NSXPCConnection.current()?.remoteObjectProxy as? AuthsiaBridgeApprovalCallbackProtocol
        Task { @MainActor [weak self] in
            guard let self else { return }

            // Check global CLI access first (before approval)
            guard Self.isCliAccessEnabled else {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .policyDenied,
                    message: "CLI access is disabled"
                )
                reply(self.encodeResponse(response), nil)
                return
            }

            do {
                let snapshot = try? VaultCLIMetadataSnapshotStore.shared.load()
                let passwords = BridgeListPayloadFactory.passwordMetadataForLookup(
                    loaded: try VaultMetadataStore.shared.loadPasswords(),
                    snapshot: snapshot?.passwords
                )

                guard let match = BridgeQueryMatcher.firstMatch(
                    query: bridgeRequest.query,
                    in: passwords,
                    id: { $0.id.uuidString },
                    searchable: { [$0.name, $0.username, $0.website ?? ""] }
                ) else {
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: .notFound,
                        message: "No matching password found"
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }

                // Check per-item CLI access before requesting approval. Chrome autofill
                // uses the CLI transport but should not inherit the per-item CLI toggle.
                guard Self.itemCLIRestrictionAllowsAccess(
                    isCliEnabled: match.isCliEnabled,
                    request: bridgeRequest,
                    callerIdentity: callerIdentity
                ) else {
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: .policyDenied,
                        message: "CLI access is disabled for '\(match.name)'. Enable it in the Authsia app under item settings."
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }

                // Validate session and request approval after confirming CLI access is allowed.
                guard let bypassApproval = self.resolveAutomationApproval(
                    for: bridgeRequest, itemFolderPath: match.folderPath, itemEnvironments: match.environments, itemKind: "password", reply: reply
                ) else { return }
                let approvalDecision = self.secretReadApprovalDecision(
                    itemIdentity: AgentJITItemIdentity(type: "password", id: match.id),
                    itemFolderPath: match.folderPath,
                    itemEnvironments: match.environments,
                    request: bridgeRequest,
                    bypassApproval: bypassApproval,
                    callerIdentity: callerIdentity
                )
                let approvedBy: String
                let needsApproval: Bool
                let agentJITGrantID: UUID?
                switch approvalDecision {
                case .allowed(let decisionApprovedBy, let decisionNeedsApproval, let decisionAgentJITGrantID):
                    approvedBy = decisionApprovedBy
                    needsApproval = decisionNeedsApproval
                    agentJITGrantID = decisionAgentJITGrantID
                case .denied(let code, let message):
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: code,
                        message: message
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }
                var newSessionToken: String?
                var newSessionExpiresAt: Date?
                var interactiveApprovalAttribution: String?
                if needsApproval {
                    let authorization = await self.requestLocalApproval(
                        prompt: "Allow CLI to access password for \(match.name)",
                        command: .getPassword,
                        itemLabel: match.name,
                        field: "password",
                        callback: callback
                    )
                    guard case .allowed(_, let attribution) = authorization else {
                        self.recordAudit(
                            command: .getPassword,
                            itemId: match.id.uuidString,
                            itemName: match.name,
                            approvedBy: authorization.attribution,
                            caller: callerIdentity,
                            requestedCommand: bridgeRequest.context.requestedCommand,
                            fullCommand: bridgeRequest.context.fullCommand,
                            agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                            workspaceContext: bridgeRequest.context.workspaceContext
                        )
                        let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                            id: bridgeRequest.id,
                            code: .notAuthorized,
                            message: "Access denied"
                        )
                        reply(self.encodeResponse(response), nil)
                        return
                    }
                    interactiveApprovalAttribution = attribution
                    guard let session = Self.sharedSessionManager.createSessionOrNil(
                        ttlSeconds: Self.configuredSessionTTL,
                        scope: bridgeRequest.context.sessionScope,
                        workingDirectory: bridgeRequest.context.workingDirectory,
                        origin: sessionOrigin(from: callerIdentity)
                    ) else {
                        let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                            id: bridgeRequest.id,
                            code: .appUnavailable,
                            message: "Session creation failed"
                        )
                        reply(self.encodeResponse(response), nil)
                        return
                    }
                    newSessionToken = session.sessionToken
                    newSessionExpiresAt = session.expiresAt
                }
                let auditApprovedBy = interactiveApprovalAttribution ?? approvedBy

                let secretData = try VaultKeychainStore.shared.retrievePassword(for: match.id)
                let passwordString = String(data: secretData, encoding: .utf8) ?? ""

                let payload = PasswordPayload(
                    id: match.id.uuidString,
                    name: match.name,
                    username: match.username,
                    password: passwordString,
                    website: match.website,
                    notes: match.notes,
                    createdAt: match.createdAt,
                    modifiedAt: match.modifiedAt,
                    isFavorite: match.isFavorite
                )
                let response: BridgeResponse<PasswordPayload> = BridgeResponseBuilder.success(
                    id: bridgeRequest.id,
                    payload: payload,
                    sessionToken: newSessionToken,
                    sessionExpiresAt: newSessionExpiresAt
                )
                self.recordAudit(
                    command: .getPassword,
                    itemId: match.id.uuidString,
                    itemName: match.name,
                    approvedBy: auditApprovedBy,
                    caller: callerIdentity,
                    requestedCommand: bridgeRequest.context.requestedCommand,
                    fullCommand: bridgeRequest.context.fullCommand,
                    agentJITGrantID: agentJITGrantID,
                    agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                    workspaceContext: bridgeRequest.context.workspaceContext
                )
                reply(self.encodeResponse(response), nil)
            } catch {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .notFound,
                    message: "Failed to retrieve password: \(error.localizedDescription)"
                )
                reply(self.encodeResponse(response), nil)
            }
        }
    }

    public func getAPIKey(_ request: Data, _ rawReply: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Failed to decode getAPIKey request"))
            return
        }

        if let policyError = BridgeRequestPolicy.denial(for: bridgeRequest) {
            let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                id: bridgeRequest.id,
                code: policyError.code,
                message: policyError.message
            )
            reply(encodeResponse(response), nil)
            return
        }

        let callerIdentity = callerIdentityProvider()
        let callback = NSXPCConnection.current()?.remoteObjectProxy as? AuthsiaBridgeApprovalCallbackProtocol
        Task { @MainActor [weak self] in
            guard let self else { return }

            guard Self.isCliAccessEnabled else {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .policyDenied,
                    message: "CLI access is disabled"
                )
                reply(self.encodeResponse(response), nil)
                return
            }

            do {
                let snapshot = try? VaultCLIMetadataSnapshotStore.shared.load()
                let apiKeys = BridgeListPayloadFactory.apiKeyMetadataForLookup(
                    loaded: try VaultMetadataStore.shared.loadAPIKeys(),
                    snapshot: snapshot?.apiKeys
                )

                guard let match = BridgeQueryMatcher.firstMatch(
                    query: bridgeRequest.query,
                    in: apiKeys,
                    id: { $0.id.uuidString },
                    searchable: { [$0.name, $0.website ?? ""] }
                ) else {
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: .notFound,
                        message: "No matching API key found"
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }

                guard Self.itemCLIRestrictionAllowsAccess(
                    isCliEnabled: match.isCliEnabled,
                    request: bridgeRequest,
                    callerIdentity: callerIdentity
                ) else {
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: .policyDenied,
                        message: "CLI access is disabled for '\(match.name)'. Enable it in the Authsia app under item settings."
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }

                guard let bypassApproval = self.resolveAutomationApproval(
                    for: bridgeRequest, itemFolderPath: match.folderPath, itemEnvironments: match.environments, itemKind: "api-key", reply: reply
                ) else { return }
                let approvalDecision = self.secretReadApprovalDecision(
                    itemIdentity: AgentJITItemIdentity(type: "api-key", id: match.id),
                    itemFolderPath: match.folderPath,
                    itemEnvironments: match.environments,
                    request: bridgeRequest,
                    bypassApproval: bypassApproval,
                    callerIdentity: callerIdentity
                )
                let approvedBy: String
                let needsApproval: Bool
                let agentJITGrantID: UUID?
                switch approvalDecision {
                case .allowed(let decisionApprovedBy, let decisionNeedsApproval, let decisionAgentJITGrantID):
                    approvedBy = decisionApprovedBy
                    needsApproval = decisionNeedsApproval
                    agentJITGrantID = decisionAgentJITGrantID
                case .denied(let code, let message):
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: code,
                        message: message
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }

                var newSessionToken: String?
                var newSessionExpiresAt: Date?
                var interactiveApprovalAttribution: String?
                if needsApproval {
                    let authorization = await self.requestLocalApproval(
                        prompt: "Allow CLI to access API key for \(match.name)",
                        command: .getAPIKey,
                        itemLabel: match.name,
                        field: "key",
                        callback: callback
                    )
                    guard case .allowed(_, let attribution) = authorization else {
                        self.recordAudit(
                            command: .getAPIKey,
                            itemId: match.id.uuidString,
                            itemName: match.name,
                            approvedBy: authorization.attribution,
                            caller: callerIdentity,
                            requestedCommand: bridgeRequest.context.requestedCommand,
                            fullCommand: bridgeRequest.context.fullCommand,
                            agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                            workspaceContext: bridgeRequest.context.workspaceContext
                        )
                        let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                            id: bridgeRequest.id,
                            code: .notAuthorized,
                            message: "Access denied"
                        )
                        reply(self.encodeResponse(response), nil)
                        return
                    }
                    interactiveApprovalAttribution = attribution
                    guard let session = Self.sharedSessionManager.createSessionOrNil(
                        ttlSeconds: Self.configuredSessionTTL,
                        scope: bridgeRequest.context.sessionScope,
                        workingDirectory: bridgeRequest.context.workingDirectory,
                        origin: sessionOrigin(from: callerIdentity)
                    ) else {
                        let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                            id: bridgeRequest.id,
                            code: .appUnavailable,
                            message: "Session creation failed"
                        )
                        reply(self.encodeResponse(response), nil)
                        return
                    }
                    newSessionToken = session.sessionToken
                    newSessionExpiresAt = session.expiresAt
                }
                let auditApprovedBy = interactiveApprovalAttribution ?? approvedBy

                let secretData = try VaultKeychainStore.shared.retrieveAPIKey(for: match.id)
                let keyString = String(data: secretData, encoding: .utf8) ?? ""

                let payload = APIKeyPayload(
                    id: match.id.uuidString,
                    name: match.name,
                    key: keyString,
                    website: match.website,
                    notes: match.notes,
                    createdAt: match.createdAt,
                    modifiedAt: match.modifiedAt,
                    isFavorite: match.isFavorite
                )
                let response: BridgeResponse<APIKeyPayload> = BridgeResponseBuilder.success(
                    id: bridgeRequest.id,
                    payload: payload,
                    sessionToken: newSessionToken,
                    sessionExpiresAt: newSessionExpiresAt
                )
                self.recordAudit(
                    command: .getAPIKey,
                    itemId: match.id.uuidString,
                    itemName: match.name,
                    approvedBy: auditApprovedBy,
                    caller: callerIdentity,
                    requestedCommand: bridgeRequest.context.requestedCommand,
                    fullCommand: bridgeRequest.context.fullCommand,
                    agentJITGrantID: agentJITGrantID,
                    agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                    workspaceContext: bridgeRequest.context.workspaceContext
                )
                reply(self.encodeResponse(response), nil)
            } catch {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .notFound,
                    message: "Failed to retrieve API key: \(error.localizedDescription)"
                )
                reply(self.encodeResponse(response), nil)
            }
        }
    }

    public func getCertificate(_ request: Data, _ rawReply: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Failed to decode getCertificate request"))
            return
        }

        if let policyError = BridgeRequestPolicy.denial(for: bridgeRequest) {
            let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                id: bridgeRequest.id,
                code: policyError.code,
                message: policyError.message
            )
            reply(encodeResponse(response), nil)
            return
        }

        let callerIdentity = callerIdentityProvider()
        let callback = NSXPCConnection.current()?.remoteObjectProxy as? AuthsiaBridgeApprovalCallbackProtocol
        Task { @MainActor [weak self] in
            guard let self else { return }

            // Check global CLI access first (before approval)
            guard Self.isCliAccessEnabled else {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .policyDenied,
                    message: "CLI access is disabled"
                )
                reply(self.encodeResponse(response), nil)
                return
            }
            do {
                let certificates = try VaultMetadataStore.shared.loadCertificates()

                guard let match = BridgeQueryMatcher.firstMatch(
                    query: bridgeRequest.query,
                    in: certificates,
                    id: { $0.id.uuidString },
                    searchable: { [$0.name, $0.issuer ?? "", $0.subject ?? ""] }
                ) else {
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: .notFound,
                        message: "No matching certificate found"
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }

                // Check per-item CLI access before requesting approval.
                guard match.isCliEnabled else {
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: .policyDenied,
                        message: "CLI access is disabled for '\(match.name)'. Enable it in the Authsia app under item settings."
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }

                guard let bypassApproval = self.resolveAutomationApproval(
                    for: bridgeRequest, itemFolderPath: match.folderPath, itemEnvironments: match.environments, itemKind: "certificate", reply: reply
                ) else { return }
                let approvalDecision = self.secretReadApprovalDecision(
                    itemIdentity: AgentJITItemIdentity(type: "certificate", id: match.id),
                    itemFolderPath: match.folderPath,
                    itemEnvironments: match.environments,
                    request: bridgeRequest,
                    bypassApproval: bypassApproval,
                    callerIdentity: callerIdentity
                )
                let approvedBy: String
                let needsApproval: Bool
                let agentJITGrantID: UUID?
                switch approvalDecision {
                case .allowed(let decisionApprovedBy, let decisionNeedsApproval, let decisionAgentJITGrantID):
                    approvedBy = decisionApprovedBy
                    needsApproval = decisionNeedsApproval
                    agentJITGrantID = decisionAgentJITGrantID
                case .denied(let code, let message):
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: code,
                        message: message
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }
                var newSessionToken: String?
                var newSessionExpiresAt: Date?
                var interactiveApprovalAttribution: String?
                if needsApproval {
                    let authorization = await self.requestLocalApproval(
                        prompt: "Allow CLI to access certificate for \(match.name)",
                        command: .getCertificate,
                        itemLabel: match.name,
                        field: "certificate",
                        callback: callback
                    )
                    guard case .allowed(_, let attribution) = authorization else {
                        self.recordAudit(
                            command: .getCertificate,
                            itemId: match.id.uuidString,
                            itemName: match.name,
                            approvedBy: authorization.attribution,
                            caller: callerIdentity,
                            requestedCommand: bridgeRequest.context.requestedCommand,
                            fullCommand: bridgeRequest.context.fullCommand,
                            agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                            workspaceContext: bridgeRequest.context.workspaceContext
                        )
                        let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                            id: bridgeRequest.id,
                            code: .notAuthorized,
                            message: "Access denied"
                        )
                        reply(self.encodeResponse(response), nil)
                        return
                    }
                    interactiveApprovalAttribution = attribution
                    guard let session = Self.sharedSessionManager.createSessionOrNil(
                        ttlSeconds: Self.configuredSessionTTL,
                        scope: bridgeRequest.context.sessionScope,
                        workingDirectory: bridgeRequest.context.workingDirectory,
                        origin: sessionOrigin(from: callerIdentity)
                    ) else {
                        let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                            id: bridgeRequest.id,
                            code: .appUnavailable,
                            message: "Session creation failed"
                        )
                        reply(self.encodeResponse(response), nil)
                        return
                    }
                    newSessionToken = session.sessionToken
                    newSessionExpiresAt = session.expiresAt
                }
                let auditApprovedBy = interactiveApprovalAttribution ?? approvedBy

                let (certData, keyData) = try VaultKeychainStore.shared.retrieveCertificate(for: match.id)
                let certString = String(data: certData, encoding: .utf8) ?? certData.base64EncodedString()
                let keyString = keyData.map { String(data: $0, encoding: .utf8) ?? $0.base64EncodedString() }

                let payload = CertificatePayload(
                    id: match.id.uuidString,
                    name: match.name,
                    certificate: certString,
                    privateKey: keyString,
                    issuer: match.issuer,
                    subject: match.subject,
                    expirationDate: match.expirationDate,
                    notes: match.notes,
                    createdAt: match.createdAt,
                    modifiedAt: match.modifiedAt,
                    isFavorite: match.isFavorite
                )
                let response: BridgeResponse<CertificatePayload> = BridgeResponseBuilder.success(
                    id: bridgeRequest.id,
                    payload: payload,
                    sessionToken: newSessionToken,
                    sessionExpiresAt: newSessionExpiresAt
                )
                self.recordAudit(
                    command: .getCertificate,
                    itemId: match.id.uuidString,
                    itemName: match.name,
                    approvedBy: auditApprovedBy,
                    caller: callerIdentity,
                    requestedCommand: bridgeRequest.context.requestedCommand,
                    fullCommand: bridgeRequest.context.fullCommand,
                    agentJITGrantID: agentJITGrantID,
                    agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                    workspaceContext: bridgeRequest.context.workspaceContext
                )
                reply(self.encodeResponse(response), nil)
            } catch {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .notFound,
                    message: "Failed to retrieve certificate: \(error.localizedDescription)"
                )
                reply(self.encodeResponse(response), nil)
            }
        }
    }

    public func getNote(_ request: Data, _ rawReply: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Failed to decode getNote request"))
            return
        }

        if let policyError = BridgeRequestPolicy.denial(for: bridgeRequest) {
            let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                id: bridgeRequest.id,
                code: policyError.code,
                message: policyError.message
            )
            reply(encodeResponse(response), nil)
            return
        }

        let callerIdentity = callerIdentityProvider()
        let callback = NSXPCConnection.current()?.remoteObjectProxy as? AuthsiaBridgeApprovalCallbackProtocol
        Task { @MainActor [weak self] in
            guard let self else { return }

            // Check global CLI access first (before approval)
            guard Self.isCliAccessEnabled else {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .policyDenied,
                    message: "CLI access is disabled"
                )
                reply(self.encodeResponse(response), nil)
                return
            }
            do {
                let notes = try VaultMetadataStore.shared.loadNotes()

                guard let match = BridgeQueryMatcher.firstMatch(
                    query: bridgeRequest.query,
                    in: notes,
                    id: { $0.id.uuidString },
                    searchable: { [$0.title] }
                ) else {
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: .notFound,
                        message: "No matching note found"
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }

                // Check per-item CLI access before requesting approval.
                guard match.isCliEnabled else {
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: .policyDenied,
                        message: "CLI access is disabled for '\(match.title)'. Enable it in the Authsia app under item settings."
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }

                guard let bypassApproval = self.resolveAutomationApproval(
                    for: bridgeRequest, itemFolderPath: match.folderPath, itemEnvironments: match.environments, itemKind: "note", reply: reply
                ) else { return }
                let approvalDecision = self.secretReadApprovalDecision(
                    itemIdentity: AgentJITItemIdentity(type: "note", id: match.id),
                    itemFolderPath: match.folderPath,
                    itemEnvironments: match.environments,
                    request: bridgeRequest,
                    bypassApproval: bypassApproval,
                    callerIdentity: callerIdentity
                )
                let approvedBy: String
                let needsApproval: Bool
                let agentJITGrantID: UUID?
                switch approvalDecision {
                case .allowed(let decisionApprovedBy, let decisionNeedsApproval, let decisionAgentJITGrantID):
                    approvedBy = decisionApprovedBy
                    needsApproval = decisionNeedsApproval
                    agentJITGrantID = decisionAgentJITGrantID
                case .denied(let code, let message):
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: code,
                        message: message
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }
                var newSessionToken: String?
                var newSessionExpiresAt: Date?
                var interactiveApprovalAttribution: String?
                if needsApproval {
                    let authorization = await self.requestLocalApproval(
                        prompt: "Allow CLI to access secure note for \(match.title)",
                        command: .getNote,
                        itemLabel: match.title,
                        field: "content",
                        callback: callback
                    )
                    guard case .allowed(_, let attribution) = authorization else {
                        self.recordAudit(
                            command: .getNote,
                            itemId: match.id.uuidString,
                            itemName: match.title,
                            approvedBy: authorization.attribution,
                            caller: callerIdentity,
                            requestedCommand: bridgeRequest.context.requestedCommand,
                            fullCommand: bridgeRequest.context.fullCommand,
                            agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                            workspaceContext: bridgeRequest.context.workspaceContext
                        )
                        let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                            id: bridgeRequest.id,
                            code: .notAuthorized,
                            message: "Access denied"
                        )
                        reply(self.encodeResponse(response), nil)
                        return
                    }
                    interactiveApprovalAttribution = attribution
                    guard let session = Self.sharedSessionManager.createSessionOrNil(
                        ttlSeconds: Self.configuredSessionTTL,
                        scope: bridgeRequest.context.sessionScope,
                        workingDirectory: bridgeRequest.context.workingDirectory,
                        origin: sessionOrigin(from: callerIdentity)
                    ) else {
                        let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                            id: bridgeRequest.id,
                            code: .appUnavailable,
                            message: "Session creation failed"
                        )
                        reply(self.encodeResponse(response), nil)
                        return
                    }
                    newSessionToken = session.sessionToken
                    newSessionExpiresAt = session.expiresAt
                }
                let auditApprovedBy = interactiveApprovalAttribution ?? approvedBy

                let contentData = try VaultKeychainStore.shared.retrieveNoteContent(for: match.id)
                let contentString = String(data: contentData, encoding: .utf8) ?? ""

                let payload = NotePayload(
                    id: match.id.uuidString,
                    title: match.title,
                    content: contentString,
                    createdAt: match.createdAt,
                    modifiedAt: match.modifiedAt,
                    isFavorite: match.isFavorite
                )
                let response: BridgeResponse<NotePayload> = BridgeResponseBuilder.success(
                    id: bridgeRequest.id,
                    payload: payload,
                    sessionToken: newSessionToken,
                    sessionExpiresAt: newSessionExpiresAt
                )
                self.recordAudit(
                    command: .getNote,
                    itemId: match.id.uuidString,
                    itemName: match.title,
                    approvedBy: auditApprovedBy,
                    caller: callerIdentity,
                    requestedCommand: bridgeRequest.context.requestedCommand,
                    fullCommand: bridgeRequest.context.fullCommand,
                    agentJITGrantID: agentJITGrantID,
                    agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                    workspaceContext: bridgeRequest.context.workspaceContext
                )
                reply(self.encodeResponse(response), nil)
            } catch {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .notFound,
                    message: "Failed to retrieve note: \(error.localizedDescription)"
                )
                reply(self.encodeResponse(response), nil)
            }
        }
    }

    public func getSSH(_ request: Data, _ rawReply: @escaping (Data?, NSError?) -> Void) {
        let reply = XPCReply(rawReply)
        guard let bridgeRequest = decodeRequest(request) else {
            reply(nil, makeNSError(code: .invalidRequest, message: "Failed to decode getSSH request"))
            return
        }

        if let policyError = BridgeRequestPolicy.denial(for: bridgeRequest) {
            let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                id: bridgeRequest.id,
                code: policyError.code,
                message: policyError.message
            )
            reply(encodeResponse(response), nil)
            return
        }

        let callerIdentity = callerIdentityProvider()
        let callback = NSXPCConnection.current()?.remoteObjectProxy as? AuthsiaBridgeApprovalCallbackProtocol
        Task { @MainActor [weak self] in
            guard let self else { return }

            guard Self.isCliAccessEnabled else {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .policyDenied,
                    message: "CLI access is disabled"
                )
                reply(self.encodeResponse(response), nil)
                return
            }
            switch self.unsupportedAgentJITSecretReadDecision(
                request: bridgeRequest,
                itemKind: "ssh key",
                callerIdentity: callerIdentity
            ) {
            case .allowed:
                break
            case .denied(let code, let message):
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: code,
                    message: message
                )
                reply(self.encodeResponse(response), nil)
                return
            }

            do {
                let sshKeys = try VaultMetadataStore.shared.loadSSHKeys()

                guard let match = BridgeQueryMatcher.firstMatch(
                    query: bridgeRequest.query,
                    in: sshKeys,
                    id: { $0.id.uuidString },
                    searchable: { [$0.name, $0.comment, $0.fingerprint] }
                ) else {
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: .notFound,
                        message: "No matching SSH key found"
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }

                // Check per-item CLI access before requesting approval.
                guard match.isCliEnabled else {
                    let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                        id: bridgeRequest.id,
                        code: .policyDenied,
                        message: "CLI access is disabled for '\(match.name)'. Enable it in the Authsia app under item settings."
                    )
                    reply(self.encodeResponse(response), nil)
                    return
                }

                guard let bypassApproval = self.resolveAutomationApproval(
                    for: bridgeRequest, itemFolderPath: match.folderPath, itemEnvironments: match.environments, itemKind: "ssh key", reply: reply
                ) else { return }
                var newSessionToken: String?
                var newSessionExpiresAt: Date?
                var interactiveApprovalAttribution: String?
                let sessionToken = bridgeRequest.sessionToken
                let needsApproval = !bypassApproval && !self.validateSessionAndRequest(bridgeRequest, sessionToken: sessionToken)
                if needsApproval {
                    let authorization = await self.requestLocalApproval(
                        prompt: "Allow CLI to access SSH key for \(match.name)",
                        command: .getSSH,
                        itemLabel: match.name,
                        field: "ssh",
                        callback: callback
                    )
                    guard case .allowed(_, let attribution) = authorization else {
                        self.recordAudit(
                            command: .getSSH,
                            itemId: match.id.uuidString,
                            itemName: match.name,
                            approvedBy: authorization.attribution,
                            caller: callerIdentity,
                            requestedCommand: bridgeRequest.context.requestedCommand,
                            fullCommand: bridgeRequest.context.fullCommand,
                            agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                            workspaceContext: bridgeRequest.context.workspaceContext
                        )
                        let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                            id: bridgeRequest.id,
                            code: .notAuthorized,
                            message: "Access denied"
                        )
                        reply(self.encodeResponse(response), nil)
                        return
                    }
                    interactiveApprovalAttribution = attribution
                    guard let session = Self.sharedSessionManager.createSessionOrNil(
                        ttlSeconds: Self.configuredSessionTTL,
                        scope: bridgeRequest.context.sessionScope,
                        workingDirectory: bridgeRequest.context.workingDirectory,
                        origin: sessionOrigin(from: callerIdentity)
                    ) else {
                        let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                            id: bridgeRequest.id,
                            code: .appUnavailable,
                            message: "Session creation failed"
                        )
                        reply(self.encodeResponse(response), nil)
                        return
                    }
                    newSessionToken = session.sessionToken
                    newSessionExpiresAt = session.expiresAt
                }

                let (publicKeyData, privateKeyData) = try VaultKeychainStore.shared.retrieveSSHKey(for: match.id)
                let publicKey = String(data: publicKeyData, encoding: .utf8) ?? publicKeyData.base64EncodedString()
                let privateKey = String(data: privateKeyData, encoding: .utf8) ?? privateKeyData.base64EncodedString()
                let passphraseData = try? VaultKeychainStore.shared.retrieveSSHKeyPassphrase(for: match.id)
                let passphrase = passphraseData.flatMap { String(data: $0, encoding: .utf8) }

                let payload = SSHPayload(
                    id: match.id.uuidString,
                    name: match.name,
                    publicKey: publicKey,
                    privateKey: privateKey,
                    comment: match.comment,
                    fingerprint: match.fingerprint,
                    keyType: match.keyType,
                    approvalPolicy: match.approvalPolicy,
                    boundHosts: match.boundHosts,
                    createdAt: match.createdAt,
                    modifiedAt: match.modifiedAt,
                    isFavorite: match.isFavorite,
                    passphrase: passphrase
                )
                let response: BridgeResponse<SSHPayload> = BridgeResponseBuilder.success(
                    id: bridgeRequest.id,
                    payload: payload,
                    sessionToken: newSessionToken,
                    sessionExpiresAt: newSessionExpiresAt
                )
                self.recordAudit(
                    command: .getSSH,
                    itemId: match.id.uuidString,
                    itemName: match.name,
                    approvedBy: bypassApproval
                        ? "automation"
                        : (interactiveApprovalAttribution ?? "session"),
                    caller: callerIdentity,
                    requestedCommand: bridgeRequest.context.requestedCommand,
                    fullCommand: bridgeRequest.context.fullCommand,
                    agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                    workspaceContext: bridgeRequest.context.workspaceContext
                )
                reply(self.encodeResponse(response), nil)
            } catch {
                let response: BridgeResponse<String> = BridgeResponseBuilder.error(
                    id: bridgeRequest.id,
                    code: .notFound,
                    message: "Failed to retrieve SSH key: \(error.localizedDescription)"
                )
                reply(self.encodeResponse(response), nil)
            }
        }
    }

}
#endif
