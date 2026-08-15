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
    /// Host-derived controlling terminal name, for example `ttys004`.
    public let controllingTerminal: String?
    /// Maximal shell-only prefix of the host-observed ancestry. This is used for
    /// live authorization only and is intentionally omitted from audit encoding.
    public let shellAncestryPrefix: [ParentProcessInfo]?
    /// Host-observed argv rendered for a local approval panel. Never persisted.
    public let hostCommand: String?

    public init(
        pid: Int32,
        processName: String,
        bundleIdentifier: String?,
        signingTeamId: String?,
        signingIdentity: String?,
        parentProcess: ParentProcessInfo? = nil,
        hostProcess: ParentProcessInfo? = nil,
        controllingTerminal: String? = nil,
        shellAncestryPrefix: [ParentProcessInfo]? = nil,
        hostCommand: String? = nil
    ) {
        self.pid = pid
        self.processName = processName
        self.bundleIdentifier = bundleIdentifier
        self.signingTeamId = signingTeamId
        self.signingIdentity = signingIdentity
        self.parentProcess = parentProcess
        self.hostProcess = hostProcess
        self.controllingTerminal = controllingTerminal
        self.shellAncestryPrefix = shellAncestryPrefix
        self.hostCommand = hostCommand
    }

    private enum CodingKeys: String, CodingKey {
        case pid
        case processName
        case bundleIdentifier
        case signingTeamId
        case signingIdentity
        case parentProcess
        case hostProcess
        case controllingTerminal
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        pid = try container.decode(Int32.self, forKey: .pid)
        processName = try container.decode(String.self, forKey: .processName)
        bundleIdentifier = try container.decodeIfPresent(String.self, forKey: .bundleIdentifier)
        signingTeamId = try container.decodeIfPresent(String.self, forKey: .signingTeamId)
        signingIdentity = try container.decodeIfPresent(String.self, forKey: .signingIdentity)
        parentProcess = try container.decodeIfPresent(ParentProcessInfo.self, forKey: .parentProcess)
        hostProcess = try container.decodeIfPresent(ParentProcessInfo.self, forKey: .hostProcess)
        controllingTerminal = try container.decodeIfPresent(String.self, forKey: .controllingTerminal)
        shellAncestryPrefix = nil
        hostCommand = nil
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(pid, forKey: .pid)
        try container.encode(processName, forKey: .processName)
        try container.encodeIfPresent(bundleIdentifier, forKey: .bundleIdentifier)
        try container.encodeIfPresent(signingTeamId, forKey: .signingTeamId)
        try container.encodeIfPresent(signingIdentity, forKey: .signingIdentity)
        try container.encodeIfPresent(parentProcess, forKey: .parentProcess)
        try container.encodeIfPresent(hostProcess, forKey: .hostProcess)
        try container.encodeIfPresent(controllingTerminal, forKey: .controllingTerminal)
    }
}

public struct ParentProcessInfo: Codable, Equatable {
    public let pid: Int32
    public let processName: String
    public let bundleIdentifier: String?
    public let signingTeamId: String?
    public let signingIdentity: String?
    public let isPlatformBinary: Bool?
    public let executablePath: String?
    /// Process argv. Agent and IDE identity often lives only here — GitHub Copilot is
    /// recognised by its extension path, and Electron helpers by the `.app` bundle in
    /// argv[0] — so `AgenticProcessDetector` cannot classify this process without it.
    public let arguments: [String]?
    public let startTimeSeconds: UInt64?

    public init(
        pid: Int32,
        processName: String,
        bundleIdentifier: String?,
        signingTeamId: String? = nil,
        signingIdentity: String? = nil,
        isPlatformBinary: Bool? = nil,
        executablePath: String? = nil,
        arguments: [String]? = nil,
        startTimeSeconds: UInt64? = nil
    ) {
        self.pid = pid
        self.processName = processName
        self.bundleIdentifier = bundleIdentifier
        self.signingTeamId = signingTeamId
        self.signingIdentity = signingIdentity
        self.isPlatformBinary = isPlatformBinary
        self.executablePath = executablePath
        self.arguments = arguments
        self.startTimeSeconds = startTimeSeconds
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
    /// Scope the approval was cached against (`tty:…:sid:…` or `agent:…:pid:…`).
    /// `nil` means no scope resolved, which disables caching entirely and prompts on
    /// every signature — the single largest source of repeat prompts, and invisible
    /// in the log until it is recorded here. Absent on records written before this
    /// field existed.
    public let sessionScope: String?

    public init(
        peer: SSHAgentProcessRef?,
        instigator: SSHAgentProcessRef?,
        ancestry: [SSHAgentProcessRef],
        targetHost: String?,
        sessionScope: String? = nil
    ) {
        self.peer = peer
        self.instigator = instigator
        self.ancestry = ancestry
        self.targetHost = targetHost
        self.sessionScope = sessionScope
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
    public let terminalPairingID: UUID?
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
        terminalPairingID: UUID? = nil,
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
        self.terminalPairingID = terminalPairingID
        self.agentRuntimeContext = agentRuntimeContext
        self.workspaceContext = workspaceContext
        self.environmentScope = environmentScope
        self.sshAgent = sshAgent
    }
}
