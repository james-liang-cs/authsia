import Foundation

public struct CallerIdentity: Codable, Equatable {
    public let pid: Int32
    public let processName: String
    public let bundleIdentifier: String?
    public let signingTeamId: String?
    public let signingIdentity: String?
    /// The parent process that spawned the CLI (e.g. Claude Code, Terminal, SSH)
    public let parentProcess: ParentProcessInfo?
    /// The host application above the parent process, when the CLI was launched
    /// through an editor or IDE helper (for example, Claude via VS Code).
    public let hostProcess: ParentProcessInfo?

    public init(
        pid: Int32,
        processName: String,
        bundleIdentifier: String?,
        signingTeamId: String?,
        signingIdentity: String?,
        parentProcess: ParentProcessInfo? = nil,
        hostProcess: ParentProcessInfo? = nil
    ) {
        self.pid = pid
        self.processName = processName
        self.bundleIdentifier = bundleIdentifier
        self.signingTeamId = signingTeamId
        self.signingIdentity = signingIdentity
        self.parentProcess = parentProcess
        self.hostProcess = hostProcess
    }
}

public struct ParentProcessInfo: Codable, Equatable {
    public let pid: Int32
    public let processName: String
    public let bundleIdentifier: String?
    public let signingTeamId: String?
    public let signingIdentity: String?
    public let isPlatformBinary: Bool?

    public init(
        pid: Int32,
        processName: String,
        bundleIdentifier: String?,
        signingTeamId: String? = nil,
        signingIdentity: String? = nil,
        isPlatformBinary: Bool? = nil
    ) {
        self.pid = pid
        self.processName = processName
        self.bundleIdentifier = bundleIdentifier
        self.signingTeamId = signingTeamId
        self.signingIdentity = signingIdentity
        self.isPlatformBinary = isPlatformBinary
    }
}

public struct SSHAgentProcessRef: Codable, Equatable {
    public let pid: Int32
    public let name: String
    public let path: String?

    public init(pid: Int32, name: String, path: String?) {
        self.pid = pid
        self.name = name
        self.path = path
    }
}

public struct SSHAgentAuditInfo: Codable, Equatable {
    public let peer: SSHAgentProcessRef?
    public let instigator: SSHAgentProcessRef?
    public let ancestry: [SSHAgentProcessRef]
    public let targetHost: String?

    public init(
        peer: SSHAgentProcessRef?,
        instigator: SSHAgentProcessRef?,
        ancestry: [SSHAgentProcessRef],
        targetHost: String?
    ) {
        self.peer = peer
        self.instigator = instigator
        self.ancestry = ancestry
        self.targetHost = targetHost
    }
}

public struct BridgeAuditRecord: Codable, Equatable, @unchecked Sendable {
    public let command: BridgeRequestType
    public let itemId: String
    public let itemName: String?
    public let approvedBy: String
    public let timestamp: Date
    public let caller: CallerIdentity?
    /// The high-level CLI intent that led to this RPC (e.g. `"exec"`, `"get"`).
    /// Lets operators distinguish, by grepping the log, which CLI command invoked
    /// an RPC — a single RPC like `.list` may be called by both `get` and `exec` flows.
    public let requestedCommand: String?
    /// Redacted, shell-quoted CLI invocation suitable for menu copy actions and audit inspection.
    public let fullCommand: String?
    public let agentJITGrantID: UUID?
    public let agentRuntimeContext: AgentRuntimeContext?
    public let workspaceContext: WorkspaceRuntimeContext?
    public let environmentScope: EnvironmentAccessScope?
    public let sshAgent: SSHAgentAuditInfo?

    public init(
        command: BridgeRequestType,
        itemId: String,
        itemName: String? = nil,
        approvedBy: String,
        timestamp: Date,
        caller: CallerIdentity? = nil,
        requestedCommand: String? = nil,
        fullCommand: String? = nil,
        agentJITGrantID: UUID? = nil,
        agentRuntimeContext: AgentRuntimeContext? = nil,
        workspaceContext: WorkspaceRuntimeContext? = nil,
        environmentScope: EnvironmentAccessScope? = nil,
        sshAgent: SSHAgentAuditInfo? = nil
    ) {
        self.command = command
        self.itemId = itemId
        self.itemName = itemName
        self.approvedBy = approvedBy
        self.timestamp = timestamp
        self.caller = caller
        self.requestedCommand = requestedCommand
        self.fullCommand = fullCommand
        self.agentJITGrantID = agentJITGrantID
        self.agentRuntimeContext = agentRuntimeContext
        self.workspaceContext = workspaceContext
        self.environmentScope = environmentScope
        self.sshAgent = sshAgent
    }
}
