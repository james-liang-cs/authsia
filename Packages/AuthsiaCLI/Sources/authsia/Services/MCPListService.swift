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
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL
    ) throws -> BridgeListPayload
}

struct MCPListDeadlineError: Error {}

struct LiveMCPListBridgeClient: MCPListBridgeClient, @unchecked Sendable {
    let client: AuthsiaBridgeClient

    init(client: AuthsiaBridgeClient = .shared) {
        self.client = client
    }

    func list(
        preflight: AgentJITPreflightPayload,
        agentRuntimeContext: AgentRuntimeContext,
        workspaceRoot: URL
    ) throws -> BridgeListPayload {
        try client.withRequestedCommand("list", includeAutomationCredential: false) {
            _ = try client.agentJITPreflight(
                preflight,
                agentRuntimeContext: agentRuntimeContext,
                workspaceRoot: workspaceRoot
            )
            return try client.list(
                agentRuntimeContext: agentRuntimeContext,
                workspaceRoot: workspaceRoot
            )
        }
    }
}

struct MCPListService: MCPListProviding, @unchecked Sendable {
    static let defaultDeadlineSeconds = 900

    let runtimeContext: MCPRuntimeContext
    let client: any MCPListBridgeClient
    let fileManager: FileManager
    let deadlineSeconds: Int

    init(
        runtimeContext: MCPRuntimeContext,
        client: any MCPListBridgeClient = LiveMCPListBridgeClient(),
        fileManager: FileManager = .default,
        deadlineSeconds: Int = MCPListService.defaultDeadlineSeconds
    ) {
        self.runtimeContext = runtimeContext
        self.client = client
        self.fileManager = fileManager
        self.deadlineSeconds = deadlineSeconds
    }

    /// The bridge call is blocking and cannot be interrupted, so the caller must not wait on the
    /// detached task itself: awaiting a task's value ignores the awaiting task's cancellation and
    /// would keep shutdown blocked until a pending approval resolves. The completion box lets
    /// cancellation and the deadline return immediately while the abandoned work drains.
    func list(
        _ rawInput: MCPListInput,
        invocation: MCPInvocationContext
    ) async throws -> MCPListOutput {
        let completion = MCPListCompletion()
        let work = Task.detached {
            completion.finish(Result { try listSynchronously(rawInput, invocation: invocation) })
        }
        let deadline = Task {
            try await Task.sleep(nanoseconds: UInt64(deadlineSeconds) * 1_000_000_000)
            completion.finish(.failure(MCPListDeadlineError()))
        }
        defer {
            work.cancel()
            deadline.cancel()
        }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                completion.attach(continuation)
            }
        } onCancel: {
            completion.finish(.failure(CancellationError()))
        }
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
        let payload: BridgeListPayload
        do {
            payload = try client.list(
                preflight: preflight,
                agentRuntimeContext: agentRuntimeContext,
                workspaceRoot: workspaceRoot
            )
        } catch let error as BridgeClientError {
            guard case .bridgeError(let code, _, _) = error, code == "notFound" else {
                throw error
            }
            payload = BridgeListPayload(
                accounts: [],
                passwords: [],
                certificates: [],
                notes: [],
                sshKeys: []
            )
        }
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

/// Single-resume handoff between the blocking list work and its cancellable awaiter. Whichever of
/// the work, the deadline, or cancellation arrives first wins; later results are discarded.
private final class MCPListCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<MCPListOutput, Error>?
    private var continuation: CheckedContinuation<MCPListOutput, Error>?
    private var resumed = false

    func attach(_ continuation: CheckedContinuation<MCPListOutput, Error>) {
        let pending: Result<MCPListOutput, Error>? = lock.withLock {
            guard !resumed else { return nil }
            guard let result else {
                self.continuation = continuation
                return nil
            }
            resumed = true
            return result
        }
        guard let pending else { return }
        continuation.resume(with: pending)
    }

    func finish(_ result: Result<MCPListOutput, Error>) {
        let waiting: CheckedContinuation<MCPListOutput, Error>? = lock.withLock {
            guard !resumed else { return nil }
            guard let continuation else {
                if self.result == nil { self.result = result }
                return nil
            }
            resumed = true
            self.continuation = nil
            return continuation
        }
        waiting?.resume(with: result)
    }
}
