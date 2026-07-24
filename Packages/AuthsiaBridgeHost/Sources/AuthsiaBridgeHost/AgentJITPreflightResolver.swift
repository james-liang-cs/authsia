#if os(macOS)
import Foundation
import AuthenticatorBridge
import AuthenticatorCore

public struct AgentJITPreflightFailure: Error {
    public let code: BridgeErrorCode
    public let message: String

    public init(code: BridgeErrorCode, message: String) {
        self.code = code
        self.message = message
    }
}

public struct AgentJITScopeResolution: Equatable {
    public let scope: AgentJITFolderScope
    public var requestedItems: [AgentJITGrantItemReference]
    /// Environment tags of the resolved vault items (vault truth, not the caller's
    /// declared scope), so grant matching cannot be widened or broken by the request.
    public var itemEnvironments: [String]

    public init(
        scope: AgentJITFolderScope,
        requestedItems: [AgentJITGrantItemReference],
        itemEnvironments: [String] = []
    ) {
        self.scope = scope
        self.requestedItems = requestedItems
        self.itemEnvironments = VaultEnvironmentTags.normalize(itemEnvironments)
    }
}

public struct AgentJITPreflightResolver {
    public init() {}

    public func resolvedScopes(
        from payload: AgentJITPreflightPayload,
        list: BridgeListPayload
    ) throws -> [AgentJITScopeResolution] {
        var scopes: [AgentJITScopeResolution] = []
        var indicesByScope: [AgentJITFolderScope: Int] = [:]

        for reference in payload.references {
            let requestedScope = reference.isFolderScoped ? AgentJITFolderScope(folderPath: reference.folderPath) : nil
            if reference.query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                let resolutions = try resolvedTypeScope(
                    type: reference.type,
                    requestedScope: requestedScope,
                    list: list,
                    requestedCommand: payload.requestedCommand
                )
                for resolution in resolutions {
                    append(resolution, scopes: &scopes, indicesByScope: &indicesByScope)
                }
                continue
            }

            let scope: AgentJITFolderScope
            let itemEnvironments: [String]
            let itemReference: AgentJITGrantItemReference
            switch reference.type {
            case "password":
                guard let item = exactMatch(
                    query: reference.query,
                    in: list.passwords,
                    id: { $0.id.uuidString },
                    folderPath: { $0.folderPath },
                    requestedScope: requestedScope,
                    searchable: { [$0.name, $0.username, $0.website ?? ""] }
                ) else {
                    throw AgentJITPreflightFailure(code: .notFound, message: "No matching password found")
                }
                guard item.isCliEnabled else {
                    throw AgentJITPreflightFailure(
                        code: .policyDenied,
                        message: "CLI access is disabled for '\(item.name)'"
                    )
                }
                scope = requestedScope ?? AgentJITFolderScope(folderPath: item.folderPath)
                itemEnvironments = item.environments
                itemReference = AgentJITGrantItemReference(
                    type: "password",
                    id: item.id.uuidString,
                    name: item.name,
                    folderPath: item.folderPath
                )
            case "api-key":
                guard let item = exactMatch(
                    query: reference.query,
                    in: list.apiKeys,
                    id: { $0.id.uuidString },
                    folderPath: { $0.folderPath },
                    requestedScope: requestedScope,
                    searchable: { [$0.name, $0.website ?? ""] }
                ) else {
                    throw AgentJITPreflightFailure(code: .notFound, message: "No matching API key found")
                }
                guard item.isCliEnabled else {
                    throw AgentJITPreflightFailure(
                        code: .policyDenied,
                        message: "CLI access is disabled for '\(item.name)'"
                    )
                }
                scope = requestedScope ?? AgentJITFolderScope(folderPath: item.folderPath)
                itemEnvironments = item.environments
                itemReference = AgentJITGrantItemReference(
                    type: "api-key",
                    id: item.id.uuidString,
                    name: item.name,
                    folderPath: item.folderPath
                )
            case "cert", "certificate":
                guard let item = exactMatch(
                    query: reference.query,
                    in: list.certificates,
                    id: { $0.id.uuidString },
                    folderPath: { $0.folderPath },
                    requestedScope: requestedScope,
                    searchable: { [$0.name, $0.issuer ?? "", $0.subject ?? ""] }
                ) else {
                    throw AgentJITPreflightFailure(code: .notFound, message: "No matching certificate found")
                }
                guard item.isCliEnabled else {
                    throw AgentJITPreflightFailure(
                        code: .policyDenied,
                        message: "CLI access is disabled for '\(item.name)'"
                    )
                }
                scope = requestedScope ?? AgentJITFolderScope(folderPath: item.folderPath)
                itemEnvironments = item.environments
                itemReference = AgentJITGrantItemReference(
                    type: "certificate",
                    id: item.id.uuidString,
                    name: item.name,
                    folderPath: item.folderPath
                )
            case "note":
                guard let item = exactMatch(
                    query: reference.query,
                    in: list.notes,
                    id: { $0.id.uuidString },
                    folderPath: { $0.folderPath },
                    requestedScope: requestedScope,
                    searchable: { [$0.title] }
                ) else {
                    throw AgentJITPreflightFailure(code: .notFound, message: "No matching note found")
                }
                guard item.isCliEnabled else {
                    throw AgentJITPreflightFailure(
                        code: .policyDenied,
                        message: "CLI access is disabled for '\(item.title)'"
                    )
                }
                scope = requestedScope ?? AgentJITFolderScope(folderPath: item.folderPath)
                itemEnvironments = item.environments
                itemReference = AgentJITGrantItemReference(
                    type: "note",
                    id: item.id.uuidString,
                    name: item.title,
                    folderPath: item.folderPath
                )
            case "ssh" where payload.requestedCommand == "list":
                guard let item = exactMatch(
                    query: reference.query,
                    in: list.sshKeys,
                    id: { $0.id.uuidString },
                    folderPath: { $0.folderPath },
                    requestedScope: requestedScope,
                    searchable: { [$0.name, $0.comment, $0.fingerprint] }
                ) else {
                    throw AgentJITPreflightFailure(code: .notFound, message: "No matching SSH key found")
                }
                guard item.isCliEnabled else {
                    throw AgentJITPreflightFailure(
                        code: .policyDenied,
                        message: "CLI access is disabled for '\(item.name)'"
                    )
                }
                scope = requestedScope ?? AgentJITFolderScope(folderPath: item.folderPath)
                itemEnvironments = []
                itemReference = AgentJITGrantItemReference(
                    type: "ssh",
                    id: item.id.uuidString,
                    name: item.name,
                    folderPath: item.folderPath
                )
            default:
                throw AgentJITPreflightFailure(
                    code: .invalidRequest,
                    message: "Unsupported JIT preflight reference type '\(reference.type)'"
                )
            }

            append(
                AgentJITScopeResolution(
                    scope: scope,
                    requestedItems: [itemReference],
                    itemEnvironments: itemEnvironments
                ),
                scopes: &scopes,
                indicesByScope: &indicesByScope
            )
        }

        return collapsedDescendantScopes(scopes)
    }

    private func resolvedTypeScope(
        type: String,
        requestedScope: AgentJITFolderScope?,
        list: BridgeListPayload,
        requestedCommand: String
    ) throws -> [AgentJITScopeResolution] {
        let references: [AgentJITGrantItemReference]
        switch type {
        case "password":
            references = list.passwords
                .filter { requestedScope?.matches(itemFolderPath: $0.folderPath) ?? true }
                .filter(\.isCliEnabled)
                .map {
                    AgentJITGrantItemReference(
                        type: "password",
                        id: $0.id.uuidString,
                        name: $0.name,
                        folderPath: $0.folderPath
                    )
                }
        case "api-key":
            references = list.apiKeys
                .filter { requestedScope?.matches(itemFolderPath: $0.folderPath) ?? true }
                .filter(\.isCliEnabled)
                .map {
                    AgentJITGrantItemReference(
                        type: "api-key",
                        id: $0.id.uuidString,
                        name: $0.name,
                        folderPath: $0.folderPath
                    )
                }
        case "cert", "certificate":
            references = list.certificates
                .filter { requestedScope?.matches(itemFolderPath: $0.folderPath) ?? true }
                .filter(\.isCliEnabled)
                .map {
                    AgentJITGrantItemReference(
                        type: "certificate",
                        id: $0.id.uuidString,
                        name: $0.name,
                        folderPath: $0.folderPath
                    )
                }
        case "note":
            references = list.notes
                .filter { requestedScope?.matches(itemFolderPath: $0.folderPath) ?? true }
                .filter(\.isCliEnabled)
                .map {
                    AgentJITGrantItemReference(
                        type: "note",
                        id: $0.id.uuidString,
                        name: $0.title,
                        folderPath: $0.folderPath
                    )
                }
        case "ssh" where requestedCommand == "list":
            references = list.sshKeys
                .filter { requestedScope?.matches(itemFolderPath: $0.folderPath) ?? true }
                .filter(\.isCliEnabled)
                .map {
                    AgentJITGrantItemReference(
                        type: "ssh",
                        id: $0.id.uuidString,
                        name: $0.name,
                        folderPath: $0.folderPath
                    )
                }
        default:
            throw AgentJITPreflightFailure(
                code: .invalidRequest,
                message: "Unsupported JIT preflight reference type '\(type)'"
            )
        }

        guard !references.isEmpty else {
            throw AgentJITPreflightFailure(
                code: .notFound,
                message: "No CLI-enabled \(type) items found for the requested JIT scope"
            )
        }

        if let requestedScope {
            return [AgentJITScopeResolution(scope: requestedScope, requestedItems: references)]
        }

        let grouped = Dictionary(grouping: references) { AgentJITFolderScope(folderPath: $0.folderPath) }
        return grouped.map { scope, items in
            AgentJITScopeResolution(scope: scope, requestedItems: items)
        }
        .sorted { $0.scope.displayName < $1.scope.displayName }
    }

    private func append(
        _ resolution: AgentJITScopeResolution,
        scopes: inout [AgentJITScopeResolution],
        indicesByScope: inout [AgentJITFolderScope: Int]
    ) {
        if let index = indicesByScope[resolution.scope] {
            for item in resolution.requestedItems where !scopes[index].requestedItems.contains(item) {
                scopes[index].requestedItems.append(item)
            }
            scopes[index].itemEnvironments = VaultEnvironmentTags.normalize(
                scopes[index].itemEnvironments + resolution.itemEnvironments
            )
        } else {
            indicesByScope[resolution.scope] = scopes.count
            scopes.append(resolution)
        }
    }

    private func collapsedDescendantScopes(
        _ resolutions: [AgentJITScopeResolution]
    ) -> [AgentJITScopeResolution] {
        let ordered = resolutions.sorted { lhs, rhs in
            let lhsDepth = scopeDepth(lhs.scope)
            let rhsDepth = scopeDepth(rhs.scope)
            if lhsDepth != rhsDepth {
                return lhsDepth < rhsDepth
            }
            return lhs.scope.displayName < rhs.scope.displayName
        }
        var collapsed: [AgentJITScopeResolution] = []

        for resolution in ordered {
            if let index = collapsed.firstIndex(where: {
                $0.scope.matches(itemFolderPath: resolution.scope.storageValue)
            }) {
                for item in resolution.requestedItems where !collapsed[index].requestedItems.contains(item) {
                    collapsed[index].requestedItems.append(item)
                }
                collapsed[index].itemEnvironments = VaultEnvironmentTags.normalize(
                    collapsed[index].itemEnvironments + resolution.itemEnvironments
                )
            } else {
                collapsed.append(resolution)
            }
        }

        return collapsed.sorted { $0.scope.displayName < $1.scope.displayName }
    }

    private func scopeDepth(_ scope: AgentJITFolderScope) -> Int {
        switch scope {
        case .root:
            return 0
        case .folder:
            return scope.displayName.split(separator: "/").count
        }
    }

    private func exactMatch<T>(
        query: String,
        in items: [T],
        id: (T) -> String,
        folderPath: (T) -> String?,
        requestedScope: AgentJITFolderScope?,
        searchable: (T) -> [String]
    ) -> T? {
        let lowercasedQuery = query.lowercased()
        let scopedItems: [T]
        if let requestedScope {
            scopedItems = items.filter { requestedScope.matches(itemFolderPath: folderPath($0)) }
        } else {
            scopedItems = items
        }
        if let exactID = scopedItems.first(where: { id($0).lowercased() == lowercasedQuery }) {
            return exactID
        }
        let exactMatches = scopedItems.filter {
            searchable($0).contains { $0.lowercased() == lowercasedQuery }
        }
        return exactMatches.count == 1 ? exactMatches.first : nil
    }
}
#endif
