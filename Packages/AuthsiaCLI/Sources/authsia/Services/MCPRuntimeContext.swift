import AuthenticatorBridge
import Foundation

enum MCPRuntimeContextError: Error, Equatable {
    case workspaceUnavailable
}

/// Why a workspace binding could not be made.
///
/// Reporting every failure as "no workspace found" sends the human looking for
/// a missing file when the file is present and one entry in it is malformed.
enum MCPWorkspaceBindingFailure: Equatable, Sendable {
    case noWorkspaceFound
    case unreadableConfig(path: String, reason: String)
    case rootNotAuthorized(path: String)

    var message: String {
        switch self {
        case .noWorkspaceFound:
            return WorkspaceConfigError.missingConfig.localizedDescription
        case .unreadableConfig(let path, let reason):
            // The store's own error already says how to fix it. What it cannot
            // say is that one bad entry takes every upstream down with it.
            return "\(path) exists but could not be read, so no upstream in this "
                + "workspace resolves. \(reason)"
        case .rootNotAuthorized(let path):
            return "\(path) is not an authorized workspace root for this directory."
        }
    }
}

struct MCPInvocationContext: Equatable, Sendable {
    let id: UUID
    let environment: [String: String]
    let agentRuntimeContext: AgentRuntimeContext?

    init(
        id: UUID,
        environment: [String: String],
        agentRuntimeContext: AgentRuntimeContext? = nil
    ) {
        self.id = id
        self.environment = environment
        self.agentRuntimeContext = agentRuntimeContext
    }
}

actor MCPRuntimeContext {
    nonisolated let instanceID: UUID
    nonisolated private let workspaceBinding: MCPWorkspaceBindingState

    nonisolated var workspaceRoot: URL? { workspaceBinding.root }
    nonisolated var workspaceName: String? { workspaceBinding.name }
    nonisolated var workspaceBindingFailure: MCPWorkspaceBindingFailure? {
        workspaceBinding.failure
    }

    /// What to tell a human when `workspaceRoot` is nil.
    nonisolated var workspaceUnavailableMessage: String {
        (workspaceBindingFailure ?? .noWorkspaceFound).message
    }

    private var clientPlatform = "mcp-client"

    init(
        startingDirectory: URL,
        instanceID: UUID = UUID(),
        fileManager: FileManager = .default
    ) {
        self.instanceID = instanceID
        let resolution = Self.resolveWorkspace(
            startingAt: startingDirectory,
            fileManager: fileManager
        )
        self.workspaceBinding = MCPWorkspaceBindingState(
            binding: resolution.binding,
            failure: resolution.failure
        )
    }

    nonisolated func requireWorkspace() throws {
        guard workspaceRoot != nil, workspaceName != nil else {
            throw MCPRuntimeContextError.workspaceUnavailable
        }
    }

    func updateClientInfo(name: String, version: String) {
        _ = version
        clientPlatform = AgentRuntimeContext.sanitize(name) ?? "mcp-client"
    }

    nonisolated func bindToWorkspaceRoot(_ root: URL) throws {
        let resolution = Self.resolveWorkspace(startingAt: root, fileManager: .default)
        guard let binding = resolution.binding else {
            workspaceBinding.replace(with: nil, failure: resolution.failure)
            throw MCPRuntimeContextError.workspaceUnavailable
        }
        workspaceBinding.replace(with: binding)
    }

    func makeProxyAgentRuntimeContext(
        upstreamName: String,
        invocationID: UUID = UUID()
    ) -> AgentRuntimeContext {
        let invocation = "mcp-call:\(invocationID.uuidString)"
        return AgentRuntimeContext(
            platform: clientPlatform,
            sessionID: "mcp:\(instanceID.uuidString)",
            turnID: invocation,
            agentID: "proxy:\(upstreamName)",
            agentType: "authsia-mcp",
            toolUseID: invocation
        )
    }

    func makeInvocation(id: UUID = UUID()) -> MCPInvocationContext {
        let invocation = "mcp-call:\(id.uuidString)"
        let agentRuntimeContext = AgentRuntimeContext(
            platform: clientPlatform,
            sessionID: "mcp:\(instanceID.uuidString)",
            turnID: invocation,
            agentType: "authsia-mcp",
            toolUseID: invocation
        )
        return MCPInvocationContext(
            id: id,
            environment: [
                AgentRuntimeContextResolver.environmentInvokesAuthsiaKey: "1",
                AgentRuntimeContextResolver.environmentPlatformKey: clientPlatform,
                AgentRuntimeContextResolver.environmentSessionIDKey: "mcp:\(instanceID.uuidString)",
                AgentRuntimeContextResolver.environmentTurnIDKey: invocation,
                AgentRuntimeContextResolver.environmentAgentTypeKey: "authsia-mcp",
                AgentRuntimeContextResolver.environmentToolUseIDKey: invocation,
            ],
            agentRuntimeContext: agentRuntimeContext
        )
    }

    private nonisolated static func resolveWorkspace(
        startingAt startingDirectory: URL,
        fileManager: FileManager
    ) -> (binding: MCPWorkspaceBinding?, failure: MCPWorkspaceBindingFailure?) {
        guard let discoveredRoot = WorkspaceRootResolver.findWorkspaceRoot(
            startingAt: startingDirectory,
            fileManager: fileManager
        ) else {
            return (nil, .noWorkspaceFound)
        }
        let configPath = discoveredRoot
            .appendingPathComponent(WorkspaceConfigStore.relativeConfigPath)
            .path
        let config: WorkspaceConfig
        do {
            config = try WorkspaceConfigStore.read(
                fromWorkspaceRoot: discoveredRoot,
                fileManager: fileManager
            )
        } catch {
            // The file is right there. Saying it is missing sends the reader
            // to the wrong problem, and one bad entry takes the whole
            // workspace down with it.
            return (nil, .unreadableConfig(
                path: configPath,
                reason: (error as? LocalizedError)?.errorDescription
                    ?? error.localizedDescription
            ))
        }
        guard let authorityPath = WorkspaceAuthority.validatedRootPath(
            discoveredRoot.path,
            containing: startingDirectory.path,
            fileManager: fileManager
        ) else {
            return (nil, .rootNotAuthorized(path: discoveredRoot.path))
        }
        return (
            MCPWorkspaceBinding(
                root: URL(fileURLWithPath: authorityPath, isDirectory: true),
                name: config.workspace.name
            ),
            nil
        )
    }
}

private struct MCPWorkspaceBinding: Sendable {
    let root: URL
    let name: String
}

private final class MCPWorkspaceBindingState: @unchecked Sendable {
    private let lock = NSLock()
    private var binding: MCPWorkspaceBinding?
    private var bindingFailure: MCPWorkspaceBindingFailure?

    init(binding: MCPWorkspaceBinding?, failure: MCPWorkspaceBindingFailure? = nil) {
        self.binding = binding
        self.bindingFailure = failure
    }

    var failure: MCPWorkspaceBindingFailure? {
        lock.withLock { binding == nil ? bindingFailure : nil }
    }

    var root: URL? {
        lock.withLock { binding?.root }
    }

    var name: String? {
        lock.withLock { binding?.name }
    }

    func replace(
        with binding: MCPWorkspaceBinding?,
        failure: MCPWorkspaceBindingFailure? = nil
    ) {
        lock.withLock {
            self.binding = binding
            self.bindingFailure = binding == nil ? failure : nil
        }
    }
}
