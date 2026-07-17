#if os(macOS)
import Foundation
import Security
@preconcurrency import AuthenticatorBridge
import AuthenticatorData
import AuthenticatorCore

extension XPCRequestHandler {
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
        let grantCapabilities: Set<AgentJITCapability> = requestedCommand == "list" ? [.list] : [.exec, .list]

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

        let ttl = Self.configuredSessionTTL
        let now = Date()
        let promptGrantSnapshot = ((try? agentJITGrantStore.loadAll()) ?? []).filter {
            $0.status(asOf: now) == .active && $0.callerFingerprint.matches(caller)
        }
        let expiresAt = now.addingTimeInterval(ttl)
        let duration = durationDescription(for: ttl)
        var grantIDs: [UUID] = []
        var pendingGrants: [AgentJITGrant] = []
        var pendingResolutions: [AgentJITScopeResolution] = []

        for resolution in scopes {
            let scope = resolution.scope
            if let existing = try? agentJITGrantAuthorizer.activeGrant(
                capability: capability,
                itemFolderPath: scope.storageValue,
                itemEnvironments: payload.environmentScope.map {
                    if case .named(let name) = $0 { return [name] }
                    return []
                } ?? [],
                caller: caller,
                now: now
            ) {
                let merged = grant(existing, adding: resolution.requestedItems)
                if merged.requestedItems != existing.requestedItems {
                    try? agentJITGrantStore.save(merged)
                }
                grantIDs.append(existing.id)
                continue
            }

            pendingResolutions.append(resolution)
        }

        if shouldBatchAgentJITListApproval(payload) && !pendingResolutions.isEmpty {
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
                callback: callback
            )
            let authorization = RemoteJITApprovalAuthorizationPolicy.authorize(
                outcome: outcome,
                command: .agentJITPreflight,
                remoteRequests: []
            )
            guard case .allowed(_, let approvalAttribution) = authorization else {
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

            for resolution in pendingResolutions {
                pendingGrants.append(
                    makeAgentJITGrant(
                        caller: caller,
                        scope: resolution.scope,
                        capabilities: grantCapabilities,
                        createdAt: now,
                        expiresAt: expiresAt,
                        requestedItems: resolution.requestedItems,
                        agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                        environmentScope: payload.environmentScope,
                        approvedBy: approvalAttribution
                    )
                )
            }
        } else {
            for resolution in pendingResolutions {
                let scope = resolution.scope
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
                    callback: callback
                )
                let authorization = RemoteJITApprovalAuthorizationPolicy.authorize(
                    outcome: outcome,
                    command: .agentJITPreflight,
                    remoteRequests: []
                )
                guard case .allowed(_, let approvalAttribution) = authorization else {
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

                let grant = makeAgentJITGrant(
                    caller: caller,
                    scope: scope,
                    capabilities: grantCapabilities,
                    createdAt: now,
                    expiresAt: expiresAt,
                    requestedItems: resolution.requestedItems,
                    agentRuntimeContext: bridgeRequest.context.agentRuntimeContext,
                    environmentScope: payload.environmentScope,
                    approvedBy: approvalAttribution
                )
                pendingGrants.append(grant)
            }
        }

        for grant in pendingGrants {
            do {
                try agentJITGrantStore.save(grant)
            } catch {
                replyError(
                    id: bridgeRequest.id,
                    code: .appUnavailable,
                    message: "Failed to save JIT grant: \(error.localizedDescription)",
                    reply: reply
                )
                return
            }
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

        let response: BridgeResponse<AgentJITPreflightResultPayload> = BridgeResponseBuilder.success(
            id: bridgeRequest.id,
            payload: AgentJITPreflightResultPayload(grantIDs: grantIDs)
        )
        reply(encodeResponse(response), nil)
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
