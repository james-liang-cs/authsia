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

        // Pairing is host-authoritative. An installed CLI that still preflights
        // from IDE ancestry must not open Agent JIT for a paired human shell.
        if bridgeRequest.type == .agentJITPreflight,
           !shouldUseAgentJIT(request: bridgeRequest, callerIdentity: callerIdentity) {
            let response: BridgeResponse<AgentJITPreflightResultPayload> = BridgeResponseBuilder.success(
                id: bridgeRequest.id,
                payload: AgentJITPreflightResultPayload(grantIDs: [])
            )
            reply(encodeResponse(response), nil)
            return
        }

        if bridgeRequest.type == .directCLIPreflight {
            guard requestedCommand == "exec",
                  AgentJITCallerContext.isTrustedHumanTerminal(callerIdentity)
                    || hasPairedHumanSession(request: bridgeRequest, callerIdentity: callerIdentity) else {
                replyError(
                    id: bridgeRequest.id,
                    code: .policyDenied,
                    message: "Direct CLI preflight requires a trusted human terminal",
                    reply: reply
                )
                return
            }
            if validateSessionAndRequest(
                bridgeRequest,
                sessionToken: bridgeRequest.sessionToken,
                callerIdentity: callerIdentity
            ) {
                let response: BridgeResponse<AgentJITPreflightResultPayload> = BridgeResponseBuilder.success(
                    id: bridgeRequest.id,
                    payload: AgentJITPreflightResultPayload(grantIDs: [])
                )
                reply(encodeResponse(response), nil)
                return
            }
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
            let list: BridgeListPayload
            if bridgeRequest.type == .directCLIPreflight {
                list = try await currentWorkspaceMetadataPayload(for: bridgeRequest)
            } else {
                list = try currentListPayload()
            }
            scopes = try AgentJITPreflightResolver().resolvedScopes(from: payload, list: list)
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
        if bridgeRequest.type == .directCLIPreflight {
            let descriptors = agentJITApprovalDescriptors(
                timing: timing,
                caller: caller,
                capabilities: [.exec, .list],
                environmentScope: payload.environmentScope,
                resolutions: scopes
            )
            let itemCount = descriptors.flatMap(\.requestedItems).count
            let prompt = "Allow direct CLI access to \(itemCount) requested "
                + (itemCount == 1 ? "item" : "items")
                + " for \(durationDescription(for: ttl))."
            let outcome = await requestAgentJITApproval(
                prompt: prompt,
                command: .directCLIPreflight,
                itemLabel: itemCount == 1 ? descriptors.first?.requestedItems.first?.name : "\(itemCount) items",
                field: nil,
                callback: callback,
                approvalDescriptors: descriptors,
                remoteRequests: []
            )
            let authorization = RemoteJITApprovalAuthorizationPolicy.authorize(
                outcome: outcome,
                command: .directCLIPreflight,
                remoteRequests: []
            )
            guard case .allowed(_, let approvalAttribution) = authorization else {
                replyError(id: bridgeRequest.id, code: .notAuthorized, message: "Access denied", reply: reply)
                return
            }
            let session = issueReusableHumanSession(
                for: bridgeRequest,
                callerIdentity: callerIdentity,
                requestedItems: scopes.flatMap(\.requestedItems),
                capabilities: [.exec, .list],
                environmentScope: payload.environmentScope,
                approvedBy: approvalAttribution
            )
            guard !session.failed else {
                replyError(id: bridgeRequest.id, code: .appUnavailable, message: "Failed to create CLI session", reply: reply)
                return
            }
            let response: BridgeResponse<AgentJITPreflightResultPayload> = BridgeResponseBuilder.success(
                id: bridgeRequest.id,
                payload: AgentJITPreflightResultPayload(grantIDs: []),
                sessionToken: session.token,
                sessionExpiresAt: session.expiresAt
            )
            reply(encodeResponse(response), nil)
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
            $0.status(asOf: timing.issuedAt) == .active
                && $0.callerFingerprint.matches(caller)
                && $0.matchesAgentRuntimeContext(bridgeRequest.context.agentRuntimeContext)
        }
        let duration = durationDescription(for: ttl)
        var grantIDs: [UUID] = []
        var pendingResolutions: [AgentJITScopeResolution] = []

        for resolution in scopes {
            do {
                let requestedIdentities = Set(resolution.requestedItems.compactMap(\.itemIdentity))
                if let existing = try agentJITGrantAuthorizer.activeGrant(
                    capability: capability,
                    itemIdentity: requestedIdentities.first,
                    itemFolderPath: resolution.scope.storageValue,
                    itemEnvironments: resolution.itemEnvironments.isEmpty
                        ? agentJITItemEnvironments(payload.environmentScope)
                        : resolution.itemEnvironments,
                    caller: caller,
                    agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                    now: timing.issuedAt
                ), existing.resourceScope.covers(
                    itemIdentities: requestedIdentities,
                    itemFolderPath: resolution.scope.storageValue
                ) {
                    let merged = grant(existing, adding: resolution.requestedItems)
                    if merged.requestedItems != existing.requestedItems {
                        try? agentJITGrantStore.save(merged)
                        postAgentJITGrantDidChange()
                    }
                    if !grantIDs.contains(existing.id) {
                        grantIDs.append(existing.id)
                    }
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

        let isBroadListBatch = shouldBatchAgentJITListApproval(payload)
        if (isBroadListBatch || pendingResolutions.count > 1) && !pendingResolutions.isEmpty {
            let remoteRequests = await remoteAgentJITApprovalRequests(
                bridgeRequestID: bridgeRequest.id,
                timing: timing,
                caller: caller,
                capabilities: grantCapabilities,
                environmentScope: payload.environmentScope,
                resolutions: pendingResolutions
            )
            let approvalDescriptors = agentJITApprovalDescriptors(
                timing: timing,
                caller: caller,
                capabilities: grantCapabilities,
                environmentScope: payload.environmentScope,
                resolutions: pendingResolutions,
                mcpUpstreamName: payload.mcpUpstreamName,
                mcpToolName: payload.mcpToolName,
                mcpToolPolicy: payload.mcpToolPolicy
            )
            let mcpPromptSuffix = agentJTMCPPromptSuffix(
                mcpUpstreamName: payload.mcpUpstreamName,
                mcpToolName: payload.mcpToolName,
                workspaceLabel: approvalDescriptors.first?.workspaceLabel ?? "/"
            )
            let outcome = await requestAgentJITApproval(
                prompt: isBroadListBatch
                    ? agentJITBroadListPreflightPrompt(
                        caller: caller,
                        duration: duration,
                        pendingScopes: pendingResolutions.map(\.scope),
                        activeScopes: promptGrantSnapshot.map(\.folderScope),
                        environmentScope: payload.environmentScope,
                        mcpPromptSuffix: mcpPromptSuffix
                    )
                    : agentJITExactItemBatchPreflightPrompt(
                        caller: caller,
                        duration: duration,
                        requestedCommand: requestedCommand,
                        pendingScopes: pendingResolutions.map(\.scope),
                        hasActiveGrants: !promptGrantSnapshot.isEmpty,
                        environmentScope: payload.environmentScope,
                        mcpPromptSuffix: mcpPromptSuffix
                    ),
                command: .agentJITPreflight,
                itemLabel: isBroadListBatch ? "All folders" : "Multiple items",
                field: nil,
                callback: callback,
                approvalDescriptors: approvalDescriptors,
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
                    itemId: isBroadListBatch ? "All folders" : "Multiple items",
                    itemName: isBroadListBatch ? "All folders" : "Multiple items",
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
                let approvalDescriptors = agentJITApprovalDescriptors(
                    timing: timing,
                    caller: caller,
                    capabilities: grantCapabilities,
                    environmentScope: payload.environmentScope,
                    resolutions: [resolution],
                    mcpUpstreamName: payload.mcpUpstreamName,
                    mcpToolName: payload.mcpToolName,
                    mcpToolPolicy: payload.mcpToolPolicy
                )
                let outcome = await requestAgentJITApproval(
                    prompt: agentJITPreflightPrompt(
                        caller: caller,
                        scope: scope,
                        duration: duration,
                        requestedCommand: requestedCommand,
                        activeGrants: promptGrantSnapshot,
                        environmentScope: payload.environmentScope,
                        mcpUpstreamName: payload.mcpUpstreamName,
                        mcpToolName: payload.mcpToolName,
                        workspaceLabel: approvalDescriptors.first?.workspaceLabel ?? "/"
                    ),
                    command: .agentJITPreflight,
                    itemLabel: scope.displayName,
                    field: nil,
                    callback: callback,
                    approvalDescriptors: approvalDescriptors,
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
                  Self.agentJITCallersStillMatch(caller, freshCaller),
                  Self.isCliAccessEnabled else {
                recordAudit(
                    command: .agentJITPreflight,
                    itemId: "revalidation",
                    itemName: "revalidation",
                    approvedBy: "denied:revalidation",
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

            var freshPendingResolutions: [AgentJITScopeResolution] = []
            do {
                // Reload so a vault or grant-store outage still fails closed.
                // Do not re-resolve items: a second list after Touch ID can
                // reorder or drop metadata and void the just-approved set.
                _ = try currentListPayload()
                _ = try agentJITGrantStore.loadAll()
                let revalidationDate = Date(
                    timeIntervalSince1970: Double(revalidationMilliseconds) / 1_000
                )
                for resolution in scopes {
                    let requestedIdentities = Set(resolution.requestedItems.compactMap(\.itemIdentity))
                    let activeGrant = try agentJITGrantAuthorizer.activeGrant(
                        capability: capability,
                        itemIdentity: requestedIdentities.first,
                        itemFolderPath: resolution.scope.storageValue,
                        itemEnvironments: resolution.itemEnvironments.isEmpty
                            ? agentJITItemEnvironments(payload.environmentScope)
                            : resolution.itemEnvironments,
                        caller: caller,
                        agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                        now: revalidationDate
                    )
                    if activeGrant?.resourceScope.covers(
                        itemIdentities: requestedIdentities,
                        itemFolderPath: resolution.scope.storageValue
                    ) != true {
                        freshPendingResolutions.append(resolution)
                    }
                }
            } catch {
                recordAudit(
                    command: .agentJITPreflight,
                    itemId: "revalidation",
                    itemName: "revalidation",
                    approvedBy: "denied:revalidation-reload",
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
            let freshSnapshot = localAgentJITAuthoritySnapshot(
                bridgeRequestID: bridgeRequest.id,
                timing: timing,
                caller: caller,
                capabilities: grantCapabilities,
                environmentScope: payload.environmentScope,
                pendingResolutions: freshPendingResolutions
            )
            guard Self.agentJITAuthorityStillMatches(freshSnapshot, approvedSnapshot),
                  pairedRemoteAuthorityStillMatches(
                    approvedResolutions,
                    bridgeRequestID: bridgeRequest.id,
                    timing: timing,
                    caller: caller,
                    capabilities: grantCapabilities,
                    environmentScope: payload.environmentScope,
                    freshResolutions: freshPendingResolutions
                  ) else {
                recordAudit(
                    command: .agentJITPreflight,
                    itemId: "revalidation",
                    itemName: "revalidation",
                    approvedBy: "denied:revalidation-scope",
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

            // Bind the grant to the pre-approval fingerprint so a Touch ID
            // signing flicker cannot widen later reuse.
            let pendingGrants: [AgentJITGrant]
            if isBroadListBatch, let approved = approvedResolutions.first {
                pendingGrants = [
                    makeAgentJITGrant(
                        caller: caller,
                        scope: .root,
                        capabilities: Set(grantCapabilities),
                        createdAt: timing.issuedAt,
                        expiresAt: timing.grantExpiresAt,
                        requestedItems: approvedResolutions.flatMap(\.resolution.requestedItems),
                        agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                        environmentScope: payload.environmentScope,
                        approvedBy: approved.attribution
                    ),
                ]
            } else {
                pendingGrants = approvedResolutions.map { approved in
                    makeAgentJITGrant(
                        caller: caller,
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
            postAgentJITGrantDidChange()

            for grant in pendingGrants {
                let auditItemName: String
                if isBroadListBatch, case .items = grant.resourceScope {
                    auditItemName = "\(grant.requestedItems.count) listed items"
                } else {
                    auditItemName = grant.folderScope.displayName
                }
                recordAudit(
                    command: .agentJITPreflight,
                    itemId: grant.id.uuidString,
                    itemName: auditItemName,
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

    /// Revalidation may lose optional signing or parent/host fields after Touch ID
    /// without the caller having changed. Required session and workspace bindings
    /// must still agree.
    private static func agentJITCallersStillMatch(
        _ original: AgentJITCallerFingerprint,
        _ fresh: AgentJITCallerFingerprint
    ) -> Bool {
        original.processName == fresh.processName
            && optionalRevalidationMatch(original.bundleIdentifier, fresh.bundleIdentifier)
            && optionalRevalidationMatch(original.signingTeamId, fresh.signingTeamId)
            && optionalRevalidationMatch(original.signingIdentity, fresh.signingIdentity)
            && optionalRevalidationMatch(original.parentProcessName, fresh.parentProcessName)
            && optionalRevalidationMatch(original.parentBundleIdentifier, fresh.parentBundleIdentifier)
            && optionalRevalidationMatch(original.hostProcessName, fresh.hostProcessName)
            && optionalRevalidationMatch(original.hostBundleIdentifier, fresh.hostBundleIdentifier)
            && original.sessionScope == fresh.sessionScope
            && original.workingDirectory == fresh.workingDirectory
    }

    private static func optionalRevalidationMatch(_ original: String?, _ fresh: String?) -> Bool {
        switch (original, fresh) {
        case (nil, _), (_, nil):
            return true
        case let (original?, fresh?):
            return original == fresh
        }
    }

    private static func agentJITAuthorityStillMatches(
        _ lhs: AgentJITLocalAuthoritySnapshot,
        _ rhs: AgentJITLocalAuthoritySnapshot
    ) -> Bool {
        lhs.bridgeRequestID == rhs.bridgeRequestID
            && lhs.requestIssuedAtMilliseconds == rhs.requestIssuedAtMilliseconds
            && lhs.capabilities == rhs.capabilities
            && lhs.environmentScope == rhs.environmentScope
            && lhs.grantExpiresAtMilliseconds == rhs.grantExpiresAtMilliseconds
            && lhs.pendingResolutions == rhs.pendingResolutions
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

    private func agentJITApprovalDescriptors(
        timing: AgentJITFixedApprovalTiming,
        caller: AgentJITCallerFingerprint,
        capabilities: [AgentJITCapability],
        environmentScope: EnvironmentAccessScope?,
        resolutions: [AgentJITScopeResolution],
        mcpUpstreamName: String? = nil,
        mcpToolName: String? = nil,
        mcpToolPolicy: AgentJITMCPToolPolicy? = nil
    ) -> [AgentJITApprovalDescriptor] {
        resolutions.map { resolution in
            AgentJITApprovalDescriptor(
                callerFingerprint: caller,
                capabilities: capabilities,
                resourceScope: .items(Set(resolution.requestedItems.compactMap(\.itemIdentity))),
                environmentScope: environmentScope,
                requestedItems: resolution.requestedItems,
                requestIssuedAtMilliseconds: timing.issuedAtMilliseconds,
                grantExpiresAtMilliseconds: timing.grantExpiresAtMilliseconds,
                mcpUpstreamName: mcpUpstreamName,
                mcpToolName: mcpToolName,
                mcpToolPolicy: mcpToolPolicy
            )
        }
    }

    @MainActor
    private func requestAgentJITApproval(
        prompt: String,
        command: BridgeRequestType,
        itemLabel: String?,
        field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?,
        approvalDescriptors: [AgentJITApprovalDescriptor],
        remoteRequests: [RemoteJITApprovalRequest]
    ) async -> RemoteJITApprovalOutcome {
        if let descriptorApprover = approver as? any AgentJITDescriptorApproving {
            return await descriptorApprover.requestApproval(
                prompt: prompt,
                command: command,
                itemLabel: itemLabel,
                field: field,
                callback: callback,
                approvalDescriptors: approvalDescriptors,
                remoteRequests: remoteRequests
            )
        }
        return await approver.requestApproval(
            prompt: prompt,
            command: command,
            itemLabel: itemLabel,
            field: field,
            callback: callback,
            remoteRequests: remoteRequests
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
                    name: item.name,
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
        for requestedItem in requestedItems
        where grant.resourceScope.covers(
            itemIdentities: Set(requestedItem.itemIdentity.map { [$0] } ?? []),
            itemFolderPath: requestedItem.folderPath
        ) && !mergedItems.contains(requestedItem) {
            mergedItems.append(requestedItem)
        }
        return AgentJITGrant(
            id: grant.id,
            agentName: grant.agentName,
            callerFingerprint: grant.callerFingerprint,
            folderScope: grant.folderScope,
            resourceScope: grant.resourceScope,
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
        environmentScope: EnvironmentAccessScope?,
        mcpUpstreamName: String? = nil,
        mcpToolName: String? = nil,
        workspaceLabel: String = "/"
    ) -> String {
        let scopeText = agentJITBaseScopeDescription(scope)
        let environmentText = agentJITEnvironmentDescription(environmentScope)
        let mcpText = agentJTMCPPromptSuffix(
            mcpUpstreamName: mcpUpstreamName,
            mcpToolName: mcpToolName,
            workspaceLabel: workspaceLabel
        )
        let basePrompt: String
        if requestedCommand == "list" {
            basePrompt = "Allow \(caller.displayName) temporary scoped list access to CLI-enabled Vault item " +
                "metadata " +
                "in \(scopeText) for \(duration).\(environmentText)\(mcpText)"
        } else {
            basePrompt = "Allow \(caller.displayName) temporary access to CLI-enabled password, API key, " +
                "certificate, " +
                "and note items in \(scopeText) for \(duration), plus scoped list access.\(environmentText)\(mcpText)"
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

    private func agentJTMCPPromptSuffix(
        mcpUpstreamName: String?,
        mcpToolName: String?,
        workspaceLabel: String
    ) -> String {
        var parts: [String] = []
        if let toolName = nonEmptyMCPDisplay(mcpToolName) {
            parts.append("MCP tool: \(toolName).")
        }
        if let upstreamName = nonEmptyMCPDisplay(mcpUpstreamName) {
            parts.append("Upstream: \(upstreamName).")
        }
        guard !parts.isEmpty else { return "" }
        parts.append("Workspace: \(workspaceLabel).")
        return " " + parts.joined(separator: " ")
    }

    private func nonEmptyMCPDisplay(_ value: String?) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : String(trimmed.prefix(256))
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
        environmentScope: EnvironmentAccessScope?,
        mcpPromptSuffix: String = ""
    ) -> String {
        let basePrompt = "Allow \(caller.displayName) temporary scoped list access to CLI-enabled Vault item " +
            "metadata " +
            "across all resolved folders for \(duration). Secret values are not included." +
            agentJITEnvironmentDescription(environmentScope) +
            mcpPromptSuffix
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

    private func agentJITExactItemBatchPreflightPrompt(
        caller: AgentJITCallerFingerprint,
        duration: String,
        requestedCommand: String,
        pendingScopes: [AgentJITFolderScope],
        hasActiveGrants: Bool,
        environmentScope: EnvironmentAccessScope?,
        mcpPromptSuffix: String = ""
    ) -> String {
        let scopes = agentJITScopeListDescription(normalizedAgentJITScopes(pendingScopes))
        let access = requestedCommand == "list"
            ? "temporary scoped list access to the exact CLI-enabled Vault items shown"
            : "temporary access to the exact CLI-enabled Vault items shown, plus scoped list access"
        let basePrompt = "Allow \(caller.displayName) \(access) across \(scopes) for \(duration)." +
            agentJITEnvironmentDescription(environmentScope) +
            mcpPromptSuffix
        guard hasActiveGrants else { return basePrompt }
        return "Separate approval required: This request adds exact-item authority not covered by active grants. " +
            basePrompt
    }

}
#endif
