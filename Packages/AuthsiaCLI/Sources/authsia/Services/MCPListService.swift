import AuthenticatorBridge
import Foundation

protocol MCPListProviding: Sendable {
    func list(
        _ input: MCPListInput,
        invocation: MCPInvocationContext
    ) async throws -> MCPListOutput
}

protocol MCPListBridgeClient: Sendable {
    func list(
        preflight: AgentJITPreflightPayload,
        agentRuntimeContext: AgentRuntimeContext
    ) throws -> BridgeListPayload
}

struct LiveMCPListBridgeClient: MCPListBridgeClient, @unchecked Sendable {
    let client: AuthsiaBridgeClient

    init(client: AuthsiaBridgeClient = .shared) {
        self.client = client
    }

    func list(
        preflight: AgentJITPreflightPayload,
        agentRuntimeContext: AgentRuntimeContext
    ) throws -> BridgeListPayload {
        try client.withRequestedCommand("list", includeAutomationCredential: false) {
            _ = try client.agentJITPreflight(
                preflight,
                agentRuntimeContext: agentRuntimeContext
            )
            return try client.list(agentRuntimeContext: agentRuntimeContext)
        }
    }
}

struct MCPListService: MCPListProviding, @unchecked Sendable {
    let runtimeContext: MCPRuntimeContext
    let client: any MCPListBridgeClient
    let fileManager: FileManager

    init(
        runtimeContext: MCPRuntimeContext,
        client: any MCPListBridgeClient = LiveMCPListBridgeClient(),
        fileManager: FileManager = .default
    ) {
        self.runtimeContext = runtimeContext
        self.client = client
        self.fileManager = fileManager
    }

    func list(
        _ rawInput: MCPListInput,
        invocation: MCPInvocationContext
    ) async throws -> MCPListOutput {
        try await Task.detached {
            try listSynchronously(rawInput, invocation: invocation)
        }.value
    }

    private func listSynchronously(
        _ rawInput: MCPListInput,
        invocation: MCPInvocationContext
    ) throws -> MCPListOutput {
        let input = try rawInput.validated()
        try runtimeContext.requireWorkspace()
        guard let workspaceRoot = runtimeContext.workspaceRoot,
              let agentRuntimeContext = invocation.agentRuntimeContext else {
            throw MCPRuntimeContextError.workspaceUnavailable
        }
        let config = try WorkspaceConfigStore.read(
            fromWorkspaceRoot: workspaceRoot,
            fileManager: fileManager
        )
        guard let workspaceFolder = normalizeFolderPath(config.workspace.authsiaFolder) else {
            throw MCPRuntimeContextError.workspaceUnavailable
        }
        let requestedFolder = normalizeFolderPath(input.folder) ?? workspaceFolder
        guard isWithinFolderTree(requestedFolder, root: workspaceFolder) else {
            throw MCPToolInputError.invalidArgument(
                "folder must stay within the configured Authsia workspace folder."
            )
        }

        let environmentScope = input.environment.map(EnvironmentAccessScope.named)
        let preflight = AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [AgentJITPreflightReference(
                type: input.type.preflightType,
                query: "",
                folderPath: requestedFolder,
                isFolderScoped: true
            )],
            environmentScope: environmentScope
        )
        let payload = try client.list(
            preflight: preflight,
            agentRuntimeContext: agentRuntimeContext
        )
        let allItems = metadataItems(
            type: input.type,
            payload: payload,
            folder: requestedFolder,
            environmentScope: environmentScope
        ).sorted(by: Self.itemSort)
        let start = min(input.offset, allItems.count)
        let end = min(start + input.limit, allItems.count)
        let page = Array(allItems[start..<end])
        let hasMore = end < allItems.count
        return MCPListOutput(
            invocationID: invocation.id.uuidString,
            type: input.type,
            folder: requestedFolder,
            environment: input.environment,
            items: page,
            totalCount: allItems.count,
            count: page.count,
            offset: input.offset,
            hasMore: hasMore,
            nextOffset: hasMore ? end : nil
        )
    }

    private func metadataItems(
        type: MCPListItemType,
        payload: BridgeListPayload,
        folder: String,
        environmentScope: EnvironmentAccessScope?
    ) -> [MCPListItem] {
        switch type {
        case .password:
            return payload.passwords.compactMap {
                item(
                    id: $0.id.uuidString,
                    name: $0.name,
                    folderPath: $0.folderPath,
                    isFavorite: $0.isFavorite,
                    isCliEnabled: $0.isCliEnabled,
                    environments: $0.environments,
                    requestedFolder: folder,
                    environmentScope: environmentScope
                )
            }
        case .apiKey:
            return payload.apiKeys.compactMap {
                item(
                    id: $0.id.uuidString,
                    name: $0.name,
                    folderPath: $0.folderPath,
                    isFavorite: $0.isFavorite,
                    isCliEnabled: $0.isCliEnabled,
                    environments: $0.environments,
                    requestedFolder: folder,
                    environmentScope: environmentScope
                )
            }
        case .certificate:
            return payload.certificates.compactMap {
                item(
                    id: $0.id.uuidString,
                    name: $0.name,
                    folderPath: $0.folderPath,
                    isFavorite: $0.isFavorite,
                    isCliEnabled: $0.isCliEnabled,
                    environments: $0.environments,
                    requestedFolder: folder,
                    environmentScope: environmentScope
                )
            }
        case .note:
            return payload.notes.compactMap {
                item(
                    id: $0.id.uuidString,
                    name: $0.title,
                    folderPath: $0.folderPath,
                    isFavorite: $0.isFavorite,
                    isCliEnabled: $0.isCliEnabled,
                    environments: $0.environments,
                    requestedFolder: folder,
                    environmentScope: environmentScope
                )
            }
        case .ssh:
            return payload.sshKeys.compactMap {
                item(
                    id: $0.id.uuidString,
                    name: $0.name,
                    folderPath: $0.folderPath,
                    isFavorite: $0.isFavorite,
                    isCliEnabled: $0.isCliEnabled,
                    environments: $0.environments,
                    requestedFolder: folder,
                    environmentScope: environmentScope
                )
            }
        }
    }

    private func item(
        id: String,
        name: String,
        folderPath: String?,
        isFavorite: Bool,
        isCliEnabled: Bool,
        environments: [String],
        requestedFolder: String,
        environmentScope: EnvironmentAccessScope?
    ) -> MCPListItem? {
        guard isCliEnabled,
              folderMatches(itemFolderPath: folderPath, filterFolderPath: requestedFolder),
              environmentScope?.allows(itemEnvironments: environments) ?? true else {
            return nil
        }
        return MCPListItem(
            id: id,
            name: name,
            folderPath: normalizeFolderPath(folderPath),
            isFavorite: isFavorite,
            isCliEnabled: true,
            environments: environments
        )
    }

    private func isWithinFolderTree(_ folder: String, root: String) -> Bool {
        folder == root || folder.hasPrefix(root + "/")
    }

    private static func itemSort(_ lhs: MCPListItem, _ rhs: MCPListItem) -> Bool {
        let lhsFolder = lhs.folderPath ?? ""
        let rhsFolder = rhs.folderPath ?? ""
        if lhsFolder.caseInsensitiveCompare(rhsFolder) != .orderedSame {
            return lhsFolder.localizedCaseInsensitiveCompare(rhsFolder) == .orderedAscending
        }
        if lhs.name.caseInsensitiveCompare(rhs.name) != .orderedSame {
            return lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
        }
        return lhs.id < rhs.id
    }
}
