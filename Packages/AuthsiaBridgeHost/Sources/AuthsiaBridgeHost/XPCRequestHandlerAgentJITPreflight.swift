#if os(macOS)
import Foundation
import OSLog
import Security
@preconcurrency import AuthenticatorBridge
import AuthenticatorData
import AuthenticatorCore

private let remoteJITApprovalLogger = Logger(subsystem: "app.authsia", category: "RemoteApproval")

struct AgentJITFixedApprovalTiming: Equatable {
    let issuedAtMilliseconds: Int64
    let requestExpiresAtMilliseconds: Int64
    let grantExpiresAtMilliseconds: Int64

    var issuedAt: Date {
        Date(timeIntervalSince1970: Double(issuedAtMilliseconds) / 1_000)
    }

    var grantExpiresAt: Date {
        Date(timeIntervalSince1970: Double(grantExpiresAtMilliseconds) / 1_000)
    }
}

private struct AgentJITLocalItemAuthority: Equatable {
    let type: String
    let id: String
    let folderPath: String?
}

private struct AgentJITLocalResolutionAuthority: Equatable {
    let scope: AgentJITFolderScope
    let requestedItems: [AgentJITLocalItemAuthority]
}

private struct AgentJITLocalAuthoritySnapshot: Equatable {
    let bridgeRequestID: UUID
    let requestIssuedAtMilliseconds: Int64
    let callerFingerprint: AgentJITCallerFingerprint
    let capabilities: [AgentJITCapability]
    let environmentScope: EnvironmentAccessScope?
    let grantExpiresAtMilliseconds: Int64
    let pendingResolutions: [AgentJITLocalResolutionAuthority]
}

private struct AgentJITApprovedResolution {
    let resolution: AgentJITScopeResolution
    let source: RemoteJITApprovalSource
    let attribution: String
    let remoteRequest: RemoteJITApprovalRequest?
}

extension XPCRequestHandler {
    static func checkedAgentJITMilliseconds(_ date: Date) -> Int64? {
        let unixSeconds = date.timeIntervalSince1970
        guard unixSeconds.isFinite, unixSeconds >= 0 else { return nil }
        let millisecondsValue = unixSeconds * 1_000
        guard millisecondsValue.isFinite else { return nil }
        let truncatedMilliseconds = millisecondsValue.rounded(.towardZero)
        guard truncatedMilliseconds <= 253_402_300_799_999 else { return nil }
        return Int64(truncatedMilliseconds)
    }

    static func fixedAgentJITApprovalTiming(
        now: Date,
        ttl: TimeInterval
    ) -> AgentJITFixedApprovalTiming? {
        guard let issuedMilliseconds = checkedAgentJITMilliseconds(now) else { return nil }

        guard ttl.isFinite, ttl >= 0 else { return nil }
        let ttlMillisecondsValue = ttl * 1_000
        guard ttlMillisecondsValue.isFinite else { return nil }
        let truncatedTTLMilliseconds = ttlMillisecondsValue.rounded(.towardZero)
        guard truncatedTTLMilliseconds >= 1,
              truncatedTTLMilliseconds <= 86_400_000 else { return nil }
        let ttlMilliseconds = Int64(truncatedTTLMilliseconds)

        let (requestExpiry, requestOverflow) = issuedMilliseconds.addingReportingOverflow(
            RemoteJITApprovalDescriptor.requestLifetimeMilliseconds
        )
        let (grantExpiry, grantOverflow) = issuedMilliseconds.addingReportingOverflow(ttlMilliseconds)
        guard !requestOverflow,
              !grantOverflow,
              requestExpiry <= 253_402_300_799_999,
              grantExpiry <= 253_402_300_799_999 else { return nil }
        return AgentJITFixedApprovalTiming(
            issuedAtMilliseconds: issuedMilliseconds,
            requestExpiresAtMilliseconds: requestExpiry,
            grantExpiresAtMilliseconds: grantExpiry
        )
    }

    @MainActor
    func handleAgentJITPreflight(
        _ bridgeRequest: BridgeRequest,
        body: Data,
        callerIdentity: CallerIdentity?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?,
        reply: XPCReply
    ) async {
        guard let requestedCommand = bridgeRequest.context.requestedCommand,
              requestedCommand == "exec" || requestedCommand == "list" else {
            replyError(
                id: bridgeRequest.id,
                code: .invalidRequest,
                message: "Agent JIT preflight requires requestedCommand 'exec' or 'list'",
                reply: reply
            )
            return
        }

        guard let caller = AgentJITCallerContext.fingerprint(for: bridgeRequest, caller: callerIdentity) else {
            replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Missing caller identity", reply: reply)
            return
        }

        let payload: AgentJITPreflightPayload
        do {
            payload = try BridgeCoder.decode(AgentJITPreflightPayload.self, from: body)
        } catch {
            replyError(id: bridgeRequest.id, code: .invalidRequest, message: "Invalid JIT preflight payload", reply: reply)
            return
        }

        guard payload.requestedCommand == requestedCommand else {
            replyError(
                id: bridgeRequest.id,
                code: .invalidRequest,
                message: "Agent JIT preflight payload requestedCommand must match the request context",
                reply: reply
            )
            return
        }
        let capability: AgentJITCapability = requestedCommand == "list" ? .list : .exec

        let ttl = Self.configuredSessionTTL
        guard let timing = Self.fixedAgentJITApprovalTiming(
            now: agentJITApprovalClock(),
            ttl: ttl
        ) else {
            replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
            return
        }

        let scopes: [AgentJITScopeResolution]
        do {
            scopes = try AgentJITPreflightResolver().resolvedScopes(from: payload, list: currentListPayload())
        } catch let failure as AgentJITPreflightFailure {
            replyError(id: bridgeRequest.id, code: failure.code, message: failure.message, reply: reply)
            return
        } catch {
            replyError(
                id: bridgeRequest.id,
                code: .appUnavailable,
                message: "Failed to resolve JIT preflight references: \(error.localizedDescription)",
                reply: reply
            )
            return
        }

        let promptGrants: [AgentJITGrant]
        do {
            promptGrants = try agentJITGrantStore.loadAll()
        } catch {
            replyError(
                id: bridgeRequest.id,
                code: .appUnavailable,
                message: "Failed to load JIT grants: \(error.localizedDescription)",
                reply: reply
            )
            return
        }
        let promptGrantSnapshot = promptGrants.filter {
            $0.status(asOf: timing.issuedAt) == .active && $0.callerFingerprint.matches(caller)
        }
        let duration = durationDescription(for: ttl)
        var grantIDs: [UUID] = []
        var pendingResolutions: [AgentJITScopeResolution] = []

        for resolution in scopes {
            do {
                if let existing = try agentJITGrantAuthorizer.activeGrant(
                    capability: capability,
                    itemFolderPath: resolution.scope.storageValue,
                    itemEnvironments: agentJITItemEnvironments(payload.environmentScope),
                    caller: caller,
                    now: timing.issuedAt
                ) {
                    let merged = grant(existing, adding: resolution.requestedItems)
                    if merged.requestedItems != existing.requestedItems {
                        try? agentJITGrantStore.save(merged)
                    }
                    grantIDs.append(existing.id)
                    continue
                }
            } catch {
                replyError(
                    id: bridgeRequest.id,
                    code: .appUnavailable,
                    message: "Failed to check JIT grants: \(error.localizedDescription)",
                    reply: reply
                )
                return
            }

            pendingResolutions.append(resolution)
        }

        let grantCapabilities: [AgentJITCapability] = requestedCommand == "list" ? [.list] : [.exec, .list]
        let approvedSnapshot = localAgentJITAuthoritySnapshot(
            bridgeRequestID: bridgeRequest.id,
            timing: timing,
            caller: caller,
            capabilities: grantCapabilities,
            environmentScope: payload.environmentScope,
            pendingResolutions: pendingResolutions
        )
        var approvedResolutions: [AgentJITApprovedResolution] = []

        if shouldBatchAgentJITListApproval(payload) && !pendingResolutions.isEmpty {
            let remoteRequests = await remoteAgentJITApprovalRequests(
                bridgeRequestID: bridgeRequest.id,
                timing: timing,
                caller: caller,
                capabilities: grantCapabilities,
                environmentScope: payload.environmentScope,
                resolutions: pendingResolutions
            )
            let outcome = await approver.requestApproval(
                prompt: agentJITBroadListPreflightPrompt(
                    caller: caller,
                    duration: duration,
                    pendingScopes: pendingResolutions.map(\.scope),
                    activeScopes: promptGrantSnapshot.map(\.folderScope),
                    environmentScope: payload.environmentScope
                ),
                command: .agentJITPreflight,
                itemLabel: "All folders",
                field: nil,
                callback: callback,
                remoteRequests: remoteRequests
            )
            let authorization = RemoteJITApprovalAuthorizationPolicy.authorize(
                outcome: outcome,
                command: .agentJITPreflight,
                remoteRequests: remoteRequests
            )
            guard case .allowed(let source, let approvalAttribution) = authorization else {
                recordAudit(
                    command: .agentJITPreflight,
                    itemId: "All folders",
                    itemName: "All folders",
                    approvedBy: authorization.attribution,
                    caller: callerIdentity,
                    requestedCommand: bridgeRequest.context.requestedCommand,
                    fullCommand: bridgeRequest.context.fullCommand,
                    agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                    workspaceContext: bridgeRequest.context.workspaceContext,
                    environmentScope: payload.environmentScope
                )
                replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                return
            }

            for (index, resolution) in pendingResolutions.enumerated() {
                approvedResolutions.append(
                    AgentJITApprovedResolution(
                        resolution: resolution,
                        source: source,
                        attribution: approvalAttribution,
                        remoteRequest: remoteRequests.indices.contains(index) ? remoteRequests[index] : nil
                    )
                )
            }
        } else {
            for resolution in pendingResolutions {
                let scope = resolution.scope
                let remoteRequests = await remoteAgentJITApprovalRequests(
                    bridgeRequestID: bridgeRequest.id,
                    timing: timing,
                    caller: caller,
                    capabilities: grantCapabilities,
                    environmentScope: payload.environmentScope,
                    resolutions: [resolution]
                )
                let outcome = await approver.requestApproval(
                    prompt: agentJITPreflightPrompt(
                        caller: caller,
                        scope: scope,
                        duration: duration,
                        requestedCommand: requestedCommand,
                        activeGrants: promptGrantSnapshot,
                        environmentScope: payload.environmentScope
                    ),
                    command: .agentJITPreflight,
                    itemLabel: scope.displayName,
                    field: nil,
                    callback: callback,
                    remoteRequests: remoteRequests
                )
                let authorization = RemoteJITApprovalAuthorizationPolicy.authorize(
                    outcome: outcome,
                    command: .agentJITPreflight,
                    remoteRequests: remoteRequests
                )
                guard case .allowed(let source, let approvalAttribution) = authorization else {
                    recordAudit(
                        command: .agentJITPreflight,
                        itemId: scope.displayName,
                        itemName: scope.displayName,
                        approvedBy: authorization.attribution,
                        caller: callerIdentity,
                        requestedCommand: bridgeRequest.context.requestedCommand,
                        fullCommand: bridgeRequest.context.fullCommand,
                        agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                        workspaceContext: bridgeRequest.context.workspaceContext,
                        environmentScope: payload.environmentScope
                    )
                    replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                    return
                }

                approvedResolutions.append(
                    AgentJITApprovedResolution(
                        resolution: resolution,
                        source: source,
                        attribution: approvalAttribution,
                        remoteRequest: remoteRequests.first
                    )
                )
            }
        }

        if !approvedResolutions.isEmpty {
            guard let revalidationMilliseconds = Self.checkedAgentJITMilliseconds(agentJITApprovalClock()),
                  revalidationMilliseconds >= timing.issuedAtMilliseconds,
                  revalidationMilliseconds < timing.requestExpiresAtMilliseconds,
                  revalidationMilliseconds < timing.grantExpiresAtMilliseconds,
                  let originalCallerIdentity = callerIdentity,
                  let freshCallerIdentity = callerIdentityRevalidationProvider(originalCallerIdentity),
                  let freshCaller = AgentJITCallerContext.fingerprint(
                    for: bridgeRequest,
                    caller: freshCallerIdentity
                  ),
                  freshCaller == caller,
                  Self.isCliAccessEnabled else {
                replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                return
            }

            let freshScopes: [AgentJITScopeResolution]
            var freshPendingResolutions: [AgentJITScopeResolution] = []
            do {
                freshScopes = try AgentJITPreflightResolver().resolvedScopes(
                    from: payload,
                    list: currentListPayload()
                )
                _ = try agentJITGrantStore.loadAll()
                let revalidationDate = Date(
                    timeIntervalSince1970: Double(revalidationMilliseconds) / 1_000
                )
                for resolution in freshScopes {
                    let activeGrant = try agentJITGrantAuthorizer.activeGrant(
                        capability: capability,
                        itemFolderPath: resolution.scope.storageValue,
                        itemEnvironments: agentJITItemEnvironments(payload.environmentScope),
                        caller: freshCaller,
                        now: revalidationDate
                    )
                    if activeGrant == nil {
                        freshPendingResolutions.append(resolution)
                    }
                }
            } catch {
                replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                return
            }
            let freshSnapshot = localAgentJITAuthoritySnapshot(
                bridgeRequestID: bridgeRequest.id,
                timing: timing,
                caller: freshCaller,
                capabilities: grantCapabilities,
                environmentScope: payload.environmentScope,
                pendingResolutions: freshPendingResolutions
            )
            guard freshSnapshot == approvedSnapshot,
                  pairedRemoteAuthorityStillMatches(
                    approvedResolutions,
                    bridgeRequestID: bridgeRequest.id,
                    timing: timing,
                    caller: freshCaller,
                    capabilities: grantCapabilities,
                    environmentScope: payload.environmentScope,
                    freshResolutions: freshPendingResolutions
                  ) else {
                replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                return
            }

            let pendingGrants = approvedResolutions.map { approved in
                makeAgentJITGrant(
                    caller: freshCaller,
                    scope: approved.resolution.scope,
                    capabilities: Set(grantCapabilities),
                    createdAt: timing.issuedAt,
                    expiresAt: timing.grantExpiresAt,
                    requestedItems: approved.resolution.requestedItems,
                    agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                    environmentScope: payload.environmentScope,
                    approvedBy: approved.attribution
                )
            }
            do {
                try agentJITGrantStore.saveAll(pendingGrants)
            } catch {
                replyError(
                    id: bridgeRequest.id,
                    code: .appUnavailable,
                    message: "Failed to save JIT grants: \(error.localizedDescription)",
                    reply: reply
                )
                return
            }

            for grant in pendingGrants {
                recordAudit(
                    command: .agentJITPreflight,
                    itemId: grant.id.uuidString,
                    itemName: grant.folderScope.displayName,
                    approvedBy: grant.approvedBy,
                    caller: callerIdentity,
                    requestedCommand: bridgeRequest.context.requestedCommand,
                    fullCommand: bridgeRequest.context.fullCommand,
                    agentJITGrantID: grant.id,
                    agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                    workspaceContext: bridgeRequest.context.workspaceContext,
                    environmentScope: grant.environmentScope
                )
                grantIDs.append(grant.id)
            }
        }

        let response: BridgeResponse<AgentJITPreflightResultPayload> = BridgeResponseBuilder.success(
            id: bridgeRequest.id,
            payload: AgentJITPreflightResultPayload(grantIDs: grantIDs)
        )
        reply(encodeResponse(response), nil)
    }

    private func localAgentJITAuthoritySnapshot(
        bridgeRequestID: UUID,
        timing: AgentJITFixedApprovalTiming,
        caller: AgentJITCallerFingerprint,
        capabilities: [AgentJITCapability],
        environmentScope: EnvironmentAccessScope?,
        pendingResolutions: [AgentJITScopeResolution]
    ) -> AgentJITLocalAuthoritySnapshot {
        AgentJITLocalAuthoritySnapshot(
            bridgeRequestID: bridgeRequestID,
            requestIssuedAtMilliseconds: timing.issuedAtMilliseconds,
            callerFingerprint: caller,
            capabilities: capabilities,
            environmentScope: environmentScope,
            grantExpiresAtMilliseconds: timing.grantExpiresAtMilliseconds,
            pendingResolutions: pendingResolutions.map { resolution in
                AgentJITLocalResolutionAuthority(
                    scope: resolution.scope,
                    requestedItems: resolution.requestedItems.map {
                        AgentJITLocalItemAuthority(
                            type: $0.type,
                            id: $0.id,
                            folderPath: $0.folderPath
                        )
                    }
                )
            }
        )
    }

    private func agentJITItemEnvironments(_ environmentScope: EnvironmentAccessScope?) -> [String] {
        if case .named(let name) = environmentScope {
            return [name]
        }
        return []
    }

    @MainActor
    private func remoteAgentJITApprovalRequests(
        bridgeRequestID: UUID,
        timing: AgentJITFixedApprovalTiming,
        caller: AgentJITCallerFingerprint,
        capabilities: [AgentJITCapability],
        environmentScope: EnvironmentAccessScope?,
        resolutions: [AgentJITScopeResolution]
    ) async -> [RemoteJITApprovalRequest] {
        guard remoteJITApprovalEnabled(),
              let remoteJITApprovalRequestBuilder else { return [] }
        do {
            let inputs = try remoteAgentJITApprovalInputs(
                bridgeRequestID: bridgeRequestID,
                timing: timing,
                caller: caller,
                capabilities: capabilities,
                environmentScope: environmentScope,
                resolutions: resolutions
            )
            let requests = try await remoteJITApprovalRequestBuilder.buildRequests(for: inputs)
            guard requests.count == inputs.count,
                  zip(requests, inputs).allSatisfy({ request, input in
                      request.descriptor.input == input
                  }) else {
                remoteJITApprovalLogger.error("remote-request-batch-mismatch")
                return []
            }
            return requests
        } catch {
            remoteJITApprovalLogger.error(
                "remote-request-build-rejected: \(String(describing: error), privacy: .public)"
            )
            return []
        }
    }

    private func remoteAgentJITApprovalInputs(
        bridgeRequestID: UUID,
        timing: AgentJITFixedApprovalTiming,
        caller: AgentJITCallerFingerprint,
        capabilities: [AgentJITCapability],
        environmentScope: EnvironmentAccessScope?,
        resolutions: [AgentJITScopeResolution]
    ) throws -> [RemoteJITApprovalDescriptorInput] {
        try resolutions.map { resolution in
            let requestedItems = try resolution.requestedItems.map { item in
                let kind: RemoteJITApprovalItemKind
                switch item.type {
                case "password":
                    kind = .password
                case "api-key":
                    kind = .apiKey
                case "certificate":
                    kind = .certificate
                case "note":
                    kind = .note
                case "ssh":
                    kind = .ssh
                default:
                    throw RemoteJITApprovalValidationError.invalidItems
                }
                guard let id = UUID(uuidString: item.id) else {
                    throw RemoteJITApprovalValidationError.invalidItems
                }
                return try RemoteJITApprovalItemReference(
                    id: id,
                    kind: kind,
                    folderPath: item.folderPath
                )
            }
            return try RemoteJITApprovalDescriptorInput(
                bridgeRequestID: bridgeRequestID,
                requestIssuedAtMilliseconds: timing.issuedAtMilliseconds,
                callerFingerprint: caller,
                capabilities: capabilities,
                folderScope: resolution.scope,
                environmentScope: environmentScope,
                requestedItems: requestedItems,
                grantExpiresAtMilliseconds: timing.grantExpiresAtMilliseconds
            )
        }
    }

    private func pairedRemoteAuthorityStillMatches(
        _ approvedResolutions: [AgentJITApprovedResolution],
        bridgeRequestID: UUID,
        timing: AgentJITFixedApprovalTiming,
        caller: AgentJITCallerFingerprint,
        capabilities: [AgentJITCapability],
        environmentScope: EnvironmentAccessScope?,
        freshResolutions: [AgentJITScopeResolution]
    ) -> Bool {
        guard approvedResolutions.count == freshResolutions.count else { return false }
        for (approved, freshResolution) in zip(approvedResolutions, freshResolutions) {
            guard case .pairedIPhone = approved.source else { continue }
            guard let remoteRequest = approved.remoteRequest,
                  let freshInput = try? remoteAgentJITApprovalInputs(
                    bridgeRequestID: bridgeRequestID,
                    timing: timing,
                    caller: caller,
                    capabilities: capabilities,
                    environmentScope: environmentScope,
                    resolutions: [freshResolution]
                  ).first,
                  remoteRequest.descriptor.input == freshInput else {
                return false
            }
        }
        return true
    }

    private func makeAgentJITGrant(
        caller: AgentJITCallerFingerprint,
        scope: AgentJITFolderScope,
        capabilities: Set<AgentJITCapability>,
        createdAt: Date,
        expiresAt: Date,
        requestedItems: [AgentJITGrantItemReference],
        agentRuntimeContext: AgentRuntimeContext?,
        environmentScope: EnvironmentAccessScope?,
        approvedBy: String
    ) -> AgentJITGrant {
        AgentJITGrant(
            id: UUID(),
            agentName: caller.displayName,
            callerFingerprint: caller,
            folderScope: scope,
            capabilities: capabilities,
            createdAt: createdAt,
            expiresAt: expiresAt,
            revokedAt: nil,
            lastUsedAt: nil,
            requestedItems: requestedItems,
            agentRuntimeContext: agentRuntimeContext,
            approvedBy: approvedBy,
            environmentScope: environmentScope
        )
    }

    private func grant(
        _ grant: AgentJITGrant,
        adding requestedItems: [AgentJITGrantItemReference]
    ) -> AgentJITGrant {
        var mergedItems = grant.requestedItems
        for requestedItem in requestedItems where !mergedItems.contains(requestedItem) {
            mergedItems.append(requestedItem)
        }
        return AgentJITGrant(
            id: grant.id,
            agentName: grant.agentName,
            callerFingerprint: grant.callerFingerprint,
            folderScope: grant.folderScope,
            capabilities: grant.capabilities,
            createdAt: grant.createdAt,
            expiresAt: grant.expiresAt,
            revokedAt: grant.revokedAt,
            lastUsedAt: grant.lastUsedAt,
            requestedItems: mergedItems,
            agentRuntimeContext: grant.agentRuntimeContext,
            approvedBy: grant.approvedBy,
            environmentScope: grant.environmentScope
        )
    }

    private func agentJITPreflightPrompt(
        caller: AgentJITCallerFingerprint,
        scope: AgentJITFolderScope,
        duration: String,
        requestedCommand: String,
        activeGrants: [AgentJITGrant],
        environmentScope: EnvironmentAccessScope?
    ) -> String {
        let scopeText = agentJITBaseScopeDescription(scope)
        let environmentText = agentJITEnvironmentDescription(environmentScope)
        let basePrompt: String
        if requestedCommand == "list" {
            basePrompt = "Allow \(caller.displayName) temporary scoped list access to CLI-enabled Vault item " +
                "metadata " +
                "in \(scopeText) for \(duration).\(environmentText)"
        } else {
            basePrompt = "Allow \(caller.displayName) temporary access to CLI-enabled password, API key, " +
                "certificate, " +
                "and note items in \(scopeText) for \(duration), plus scoped list access.\(environmentText)"
        }

        switch agentJITApprovalReason(
            requestedScope: scope,
            requestedCapability: requestedCommand == "list" ? .list : .exec,
            activeGrants: activeGrants
        ) {
        case .firstApproval:
            return basePrompt
        case .newFolder(let activeScopes):
            return "Separate approval required: The requested scope \(agentJITScopeDescription(scope)) is outside " +
                "the active grant scopes \(agentJITScopeListDescription(activeScopes)) because unrelated folder " +
                "trees are isolated. \(basePrompt)"
        case .broaderFolder(let activeScopes):
            return "Separate approval required: The requested scope \(agentJITScopeDescription(scope)) is broader " +
                "than the active grant scope \(agentJITScopeListDescription(activeScopes)). Approval extends access " +
                "beyond the active subtree to additional descendants. \(basePrompt)"
        case .newCapability(let existingCapabilities):
            let coveringScopes = activeGrants
                .filter { $0.folderScope.matches(itemFolderPath: scope.storageValue) }
                .map(\.folderScope)
            let capabilities = existingCapabilities.map(\.rawValue).sorted().joined(separator: " and ")
            return "Separate approval required: The active grant for " +
                "\(agentJITScopeListDescription(coveringScopes)) allows \(capabilities) access; the requested " +
                "\(requestedCommand) capability requires separate approval. \(basePrompt)"
        }
    }

    private enum AgentJITApprovalReason {
        case firstApproval
        case newFolder(activeScopes: [AgentJITFolderScope])
        case broaderFolder(activeScopes: [AgentJITFolderScope])
        case newCapability(existingCapabilities: Set<AgentJITCapability>)
    }

    private func agentJITApprovalReason(
        requestedScope: AgentJITFolderScope,
        requestedCapability: AgentJITCapability,
        activeGrants: [AgentJITGrant]
    ) -> AgentJITApprovalReason {
        guard !activeGrants.isEmpty else { return .firstApproval }

        let coveringGrants = activeGrants.filter {
            $0.folderScope.matches(itemFolderPath: requestedScope.storageValue)
        }
        if !coveringGrants.isEmpty {
            let existingCapabilities = coveringGrants.reduce(into: Set<AgentJITCapability>()) {
                $0.formUnion($1.capabilities)
            }
            if !existingCapabilities.contains(requestedCapability) {
                return .newCapability(existingCapabilities: existingCapabilities)
            }
            return .firstApproval
        }

        let broaderActiveScopes = activeGrants.map(\.folderScope).filter {
            isBroaderAgentJITScope(requestedScope, than: $0)
        }
        if !broaderActiveScopes.isEmpty {
            return .broaderFolder(activeScopes: normalizedAgentJITScopes(broaderActiveScopes))
        }

        return .newFolder(activeScopes: normalizedAgentJITScopes(activeGrants.map(\.folderScope)))
    }

    private func isBroaderAgentJITScope(
        _ requestedScope: AgentJITFolderScope,
        than activeScope: AgentJITFolderScope
    ) -> Bool {
        guard case .folder = requestedScope, case .folder = activeScope else { return false }
        return requestedScope != activeScope
            && requestedScope.matches(itemFolderPath: activeScope.storageValue)
    }

    private func normalizedAgentJITScopes(_ scopes: [AgentJITFolderScope]) -> [AgentJITFolderScope] {
        let normalized = scopes.map { AgentJITFolderScope(folderPath: $0.storageValue) }
        return Array(Set(normalized)).sorted { agentJITScopeSortKey($0) < agentJITScopeSortKey($1) }
    }

    private func agentJITScopeSortKey(_ scope: AgentJITFolderScope) -> String {
        switch scope {
        case .root:
            return ""
        case .folder(let path):
            return path
        }
    }

    private func agentJITBaseScopeDescription(_ scope: AgentJITFolderScope) -> String {
        switch scope {
        case .root:
            return "Root only"
        case .folder(let path):
            return "folder '\(path)' and its descendants"
        }
    }

    private func agentJITScopeDescription(_ scope: AgentJITFolderScope) -> String {
        switch scope {
        case .root:
            return "Root only"
        case .folder(let path):
            return "\(path) and its descendants"
        }
    }

    private func agentJITScopeListDescription(_ scopes: [AgentJITFolderScope]) -> String {
        normalizedAgentJITScopes(scopes).map(agentJITScopeDescription).joined(separator: ", ")
    }

    private func agentJITEnvironmentDescription(_ scope: EnvironmentAccessScope?) -> String {
        switch scope {
        case .defaultOnly:
            return " Environment: Default environment."
        case .named(let name):
            return " Environment: \(name)."
        case nil:
            return ""
        }
    }

    private func shouldBatchAgentJITListApproval(_ payload: AgentJITPreflightPayload) -> Bool {
        payload.requestedCommand == "list"
            && !payload.references.isEmpty
            && payload.references.allSatisfy { reference in
                reference.query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    && !reference.isFolderScoped
                    && AgentJITFolderScope(folderPath: reference.folderPath) == .root
            }
    }

    private func agentJITBroadListPreflightPrompt(
        caller: AgentJITCallerFingerprint,
        duration: String,
        pendingScopes: [AgentJITFolderScope],
        activeScopes: [AgentJITFolderScope],
        environmentScope: EnvironmentAccessScope?
    ) -> String {
        let basePrompt = "Allow \(caller.displayName) temporary scoped list access to CLI-enabled Vault item " +
            "metadata " +
            "across all resolved folders for \(duration). Secret values are not included." +
            agentJITEnvironmentDescription(environmentScope)
        guard !activeScopes.isEmpty else { return basePrompt }

        let normalizedPendingScopes = normalizedAgentJITScopes(pendingScopes)
        let normalizedActiveScopes = normalizedAgentJITScopes(activeScopes)
        let broaderPendingScopes = normalizedPendingScopes.filter { pendingScope in
            normalizedActiveScopes.contains {
                isBroaderAgentJITScope(pendingScope, than: $0)
            }
        }
        guard !broaderPendingScopes.isEmpty else {
            return "Separate approval required: This request adds folder scopes " +
                "\(agentJITScopeListDescription(normalizedPendingScopes)). The active grant covers " +
                "\(agentJITScopeListDescription(normalizedActiveScopes)). Separate approval is needed because " +
                "unrelated folder trees are isolated. \(basePrompt)"
        }

        let broaderActiveScopes = normalizedActiveScopes.filter { activeScope in
            broaderPendingScopes.contains {
                isBroaderAgentJITScope($0, than: activeScope)
            }
        }
        let uncoveredPendingScopes = normalizedPendingScopes.filter { !broaderPendingScopes.contains($0) }
        var reason = "Separate approval required: Broader ancestor expansions " +
            "\(agentJITScopeListDescription(broaderPendingScopes)) extend access beyond active child subtrees " +
            "\(agentJITScopeListDescription(broaderActiveScopes)) to additional descendants."
        if !uncoveredPendingScopes.isEmpty {
            reason += " Separate uncovered scopes \(agentJITScopeListDescription(uncoveredPendingScopes)) require " +
                "approval because unrelated folder trees are isolated."
        }
        return "\(reason) The active grant covers \(agentJITScopeListDescription(normalizedActiveScopes)). " +
            basePrompt
    }

}
#endif
