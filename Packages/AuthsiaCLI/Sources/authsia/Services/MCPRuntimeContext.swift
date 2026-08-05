import AuthenticatorBridge
import Foundation

enum MCPRuntimeContextError: Error, Equatable {
    case workspaceUnavailable
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

    private var clientPlatform = "mcp-client"

    init(
        startingDirectory: URL,
        instanceID: UUID = UUID(),
        fileManager: FileManager = .default
    ) {
        self.instanceID = instanceID
        self.workspaceBinding = MCPWorkspaceBindingState(binding: Self.resolveWorkspace(
            startingAt: startingDirectory,
            fileManager: fileManager
        ))
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

    func bindToClientRoots(_ roots: [URL]) {
        var bindingsByPath: [String: MCPWorkspaceBinding] = [:]
        for root in roots {
            guard let binding = Self.resolveWorkspace(
                startingAt: root,
                fileManager: .default
            ) else {
                continue
            }
            bindingsByPath[binding.root.path] = binding
        }
        workspaceBinding.replace(
            with: bindingsByPath.count == 1 ? bindingsByPath.values.first : nil
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
    ) -> MCPWorkspaceBinding? {
        guard let discoveredRoot = WorkspaceRootResolver.findWorkspaceRoot(
            startingAt: startingDirectory,
            fileManager: fileManager
        ),
        let config = try? WorkspaceConfigStore.read(
            fromWorkspaceRoot: discoveredRoot,
            fileManager: fileManager
        ),
        let authorityPath = WorkspaceAuthority.validatedRootPath(
            discoveredRoot.path,
            containing: startingDirectory.path,
            fileManager: fileManager
        ) else {
            return nil
        }
        return MCPWorkspaceBinding(
            root: URL(fileURLWithPath: authorityPath, isDirectory: true),
            name: config.workspace.name
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

    init(binding: MCPWorkspaceBinding?) {
        self.binding = binding
    }

    var root: URL? {
        lock.withLock { binding?.root }
    }

    var name: String? {
        lock.withLock { binding?.name }
    }

    func replace(with binding: MCPWorkspaceBinding?) {
        lock.withLock { self.binding = binding }
    }
}
