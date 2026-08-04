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
    nonisolated let workspaceRoot: URL?
    nonisolated let workspaceName: String?

    private var clientPlatform = "mcp-client"

    init(
        startingDirectory: URL,
        instanceID: UUID = UUID(),
        fileManager: FileManager = .default
    ) {
        self.instanceID = instanceID

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
            self.workspaceRoot = nil
            self.workspaceName = nil
            return
        }

        self.workspaceRoot = URL(fileURLWithPath: authorityPath, isDirectory: true)
        self.workspaceName = config.workspace.name
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
}
