import Foundation
import Darwin
import ArgumentParser
import AuthenticatorBridge

struct Status: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "status",
        abstract: "Show app, session, pairing, shell, SSH agent, and SSH approval status",
        discussion: """
            Displays the current Authsia runtime state.

            Output formats:
              table (default)
              json

            Examples:
              authsia status
              authsia status --format json
            """
    )

    @Option(name: .long, help: "Output format: table (default), json")
    var format: OutputFormat = .table

    @Flag(name: .long, help: "List shimmed tool names when the guarded terminal is active")
    var verbose = false

    func run() throws {
        let now = Date()
        let humanSessionScope = SessionCache.humanSessionScope()
        let statusPayload = try? AuthsiaBridgeClient.shared.status(sessionScope: humanSessionScope)
        let pingPayload = statusPayload == nil ? try? AuthsiaBridgeClient.shared.ping() : statusPayload
        let sshSessionStatus = Self.loadSSHSessionStatus(currentDate: now, sessionScope: humanSessionScope)
        let snapshot = Self.buildSnapshot(
            environment: ProcessInfo.processInfo.environment,
            localSessionExpiresAt: SessionCache.loadExpiresAt(keychainAccount: SessionCache.humanScopedKeychainAccount()),
            bridgeSessionActive: statusPayload?.sessionActive,
            bridgeSessionExpiresAt: statusPayload?.sessionExpiresAt,
            terminalPairing: statusPayload?.terminalPairing,
            isBridgeConnected: pingPayload != nil,
            sshSessionStatus: sshSessionStatus,
            currentDate: now,
            terminalScope: humanSessionScope,
            workspaceContext: WorkspaceRuntimeContextResolver.resolve(),
            reportsPairingAuthority: Self.reportsPairingAuthority()
        )
        print(Self.render(snapshot: snapshot, format: format, currentDate: now, verbose: verbose))
    }

    static func render(
        snapshot: StatusSnapshot,
        format: OutputFormat,
        currentDate: Date,
        verbose: Bool = false
    ) -> String {
        switch format {
        case .table:
            return renderTable(snapshot: snapshot, currentDate: currentDate, verbose: verbose)
        case .json:
            return renderJSON(snapshot: snapshot, currentDate: currentDate)
        }
    }

    static func buildSnapshot(
        environment: [String: String],
        localSessionExpiresAt: Date?,
        bridgeSessionActive: Bool?,
        bridgeSessionExpiresAt: Date?,
        terminalPairing: TerminalPairing? = nil,
        isBridgeConnected: Bool,
        sshSessionStatus: SSHAgentSessionStatus = .inactive,
        currentDate: Date,
        terminalScope: String? = nil,
        workspaceContext: WorkspaceRuntimeContext? = nil,
        reportsPairingAuthority: Bool = false
    ) -> StatusSnapshot {
        let sessionState = resolveSessionState(
            localSessionExpiresAt: localSessionExpiresAt,
            bridgeSessionActive: bridgeSessionActive,
            bridgeSessionExpiresAt: bridgeSessionExpiresAt,
            currentDate: currentDate
        )
        return StatusSnapshot(
            bridgeConnected: isBridgeConnected,
            sessionActive: sessionState.active,
            sessionExpiresAt: sessionState.expiresAt,
            terminalPairing: terminalPairing,
            shellIntegrationEnabled: environment["AUTHSIA_SHELL_INTEGRATION"] == "1",
            sshAgentRunning: SSHAgentLoader.isAgentRunning(environment: environment),
            sshSessionActive: sshSessionStatus.active,
            sshSessionExpiresAt: sshSessionStatus.expiresAt,
            sshSessionKeyCount: sshSessionStatus.activeKeyCount,
            sshSessionCurrentTerminal: sshSessionStatus.currentTerminal,
            terminalScope: terminalScope,
            workspaceContext: workspaceContext,
            guardedTerminal: resolveGuardedTerminalStatus(environment: environment),
            reportsPairingAuthority: reportsPairingAuthority
        )
    }

    static func reportsPairingAuthority(
        processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry()
    ) -> Bool {
        AgenticProcessDetector.containsAutomationSuspectProcess(processAncestry)
    }

    /// Reports what the *current shell* actually has, not what a guarded shell was meant
    /// to get: a shell can carry guard markers whose shim directory was swept from the
    /// temp dir, or a `authsia-guard-*` PATH entry whose markers were dropped by a child
    /// process. Both leave tools resolving to something other than the user expects, so
    /// they report as stale rather than active.
    static func resolveGuardedTerminalStatus(
        environment: [String: String],
        fileManager: FileManager = .default
    ) -> GuardedTerminalStatus {
        guard WorkspaceGuardedTerminal.isGuarded(environment: environment) else {
            let isAgentSession = AgentRuntimeContextResolver
                .hasExplicitAgentInvocationMarker(environment: environment)
            return GuardedTerminalStatus(
                state: .inactive,
                detail: isAgentSession ? "agent session" : nil
            )
        }

        let shimDirectory = environment["AUTHSIA_WORKSPACE_GUARD_SHIM_DIR"].flatMap {
            $0.isEmpty ? nil : $0
        }
        guard environment["AUTHSIA_WORKSPACE_GUARD"] == "1", let shimDirectory else {
            return GuardedTerminalStatus(state: .stale, detail: "guard markers missing")
        }
        guard (environment["PATH"] ?? "")
            .split(separator: ":")
            .map(String.init)
            .contains(where: WorkspaceGuardedTerminal.isShimDirectory) else {
            return GuardedTerminalStatus(state: .stale, detail: "shim directory not on PATH")
        }
        guard let shims = try? fileManager.contentsOfDirectory(atPath: shimDirectory) else {
            return GuardedTerminalStatus(
                state: .stale,
                shimDirectory: shimDirectory,
                detail: "shim directory missing"
            )
        }
        // A raw directory listing, not a filtered "known tools" list, so it captures
        // every shim actually on disk: default tools, a user's persisted `--tool` custom
        // additions, and the agent-launcher unguard shims alike. Launchers are split out
        // because they mean something different — they hand the launched agent an
        // unguarded environment rather than mediating it — so lumping them into one
        // undifferentiated "Tools" list would misstate what each shim does.
        let agentLauncherNames = Set(WorkspaceGuardedTerminal.agentLauncherTools)
        let tools = shims.filter { !agentLauncherNames.contains($0) }.sorted()
        let agentLaunchers = shims.filter { agentLauncherNames.contains($0) }.sorted()
        return GuardedTerminalStatus(
            state: .active,
            shimDirectory: shimDirectory,
            tools: tools,
            agentLaunchers: agentLaunchers.isEmpty ? nil : agentLaunchers
        )
    }

    private static func resolveSessionState(
        localSessionExpiresAt: Date?,
        bridgeSessionActive: Bool?,
        bridgeSessionExpiresAt: Date?,
        currentDate: Date
    ) -> (active: Bool, expiresAt: Date?) {
        let isLocalSessionActive = localSessionExpiresAt.map { $0 > currentDate } ?? false
        if let bridgeSessionActive {
            guard bridgeSessionActive else {
                return (false, nil)
            }
            return (true, bridgeSessionExpiresAt ?? localSessionExpiresAt)
        }

        guard isLocalSessionActive else {
            return (false, localSessionExpiresAt)
        }

        return (true, localSessionExpiresAt)
    }

    static func renderTable(snapshot: StatusSnapshot, currentDate: Date, verbose: Bool = false) -> String {
        var lines: [String] = []
        lines.append("Authsia Status")
        lines.append("Bridge: \(snapshot.bridgeConnected ? "Connected" : "Disconnected")")
        if snapshot.reportsPairingAuthority {
            lines.append("Terminal Pairing: \(terminalPairingStatusText(snapshot: snapshot, currentDate: currentDate))")
        } else {
            lines.append("Session: \(sessionStatusText(snapshot: snapshot, currentDate: currentDate))")
        }
        lines.append("Shell Integration: \(snapshot.shellIntegrationEnabled ? "Enabled" : "Disabled")")
        lines.append("Guarded Terminal: \(guardedTerminalStatusText(snapshot.guardedTerminal))")
        if verbose {
            if let tools = snapshot.guardedTerminal.tools, !tools.isEmpty {
                lines.append("  Tools: \(tools.joined(separator: ", "))")
            }
            if let agentLaunchers = snapshot.guardedTerminal.agentLaunchers, !agentLaunchers.isEmpty {
                lines.append("  Agent launchers (start unguarded): \(agentLaunchers.joined(separator: ", "))")
            }
        }
        lines.append("SSH Agent: \(snapshot.sshAgentRunning ? "Running" : "Not running")")
        lines.append("SSH Session: \(sshSessionStatusText(snapshot: snapshot, currentDate: currentDate))")
        if let workspaceContext = snapshot.workspaceContext {
            var workspaceLine = "Workspace: \(workspaceContext.displayName)"
            if let authsiaFolder = workspaceContext.authsiaFolder {
                workspaceLine += " - \(authsiaFolder)"
            }
            lines.append(workspaceLine)
        }
        return lines.joined(separator: "\n")
    }

    static func renderJSON(snapshot: StatusSnapshot, currentDate: Date) -> String {
        let payload = StatusJSONPayload(
            bridgeConnected: snapshot.bridgeConnected,
            sessionActive: snapshot.reportsPairingAuthority ? nil : snapshot.sessionActive,
            sessionExpiresAt: snapshot.reportsPairingAuthority
                ? nil
                : snapshot.sessionExpiresAt.map { ISO8601DateFormatter().string(from: $0) },
            shellIntegrationEnabled: snapshot.shellIntegrationEnabled,
            sshAgentRunning: snapshot.sshAgentRunning,
            sshSessionActive: snapshot.sshSessionActive,
            sshSessionExpiresAt: snapshot.sshSessionExpiresAt.map { ISO8601DateFormatter().string(from: $0) },
            session: snapshot.reportsPairingAuthority
                ? nil
                : StatusJSONSession(
                    status: snapshot.sessionActive ? "active" : "inactive",
                    remainingSeconds: snapshot.sessionExpiresAt.map {
                        max(Int($0.timeIntervalSince(currentDate)), 0)
                    }
                ),
            terminalPairing: snapshot.reportsPairingAuthority
                ? terminalPairingJSON(snapshot: snapshot, currentDate: currentDate)
                : nil,
            sshSession: StatusJSONSSHSession(
                status: snapshot.sshSessionActive ? "active" : "inactive",
                remainingSeconds: snapshot.sshSessionExpiresAt.map {
                    max(Int($0.timeIntervalSince(currentDate)), 0)
                },
                activeKeyCount: snapshot.sshSessionKeyCount,
                currentTerminal: snapshot.sshSessionCurrentTerminal
            ),
            terminalScope: snapshot.terminalScope,
            workspace: snapshot.workspaceContext,
            guardedTerminal: snapshot.guardedTerminal
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601

        guard let data = try? encoder.encode(payload),
              let output = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return output
    }

    private static func sessionStatusText(snapshot: StatusSnapshot, currentDate: Date) -> String {
        guard snapshot.sessionActive else {
            return "Inactive"
        }
        guard let expiresAt = snapshot.sessionExpiresAt else { return "Active" }
        let remaining = Int(expiresAt.timeIntervalSince(currentDate))
        return remaining > 0 ? "Active (\(remaining)s remaining)" : "Inactive"
    }

    private static func terminalPairingStatusText(snapshot: StatusSnapshot, currentDate: Date) -> String {
        guard let pairing = snapshot.terminalPairing, pairing.expiresAt > currentDate else {
            return "Inactive"
        }
        let terminal = pairing.controllingTerminal.hasPrefix("/dev/")
            ? pairing.controllingTerminal
            : "/dev/\(pairing.controllingTerminal)"
        let remaining = max(Int(pairing.expiresAt.timeIntervalSince(currentDate)), 0)
        return "Active (\(terminal), \(pairing.workspaceRoot), \(remaining)s remaining)"
    }

    private static func terminalPairingJSON(
        snapshot: StatusSnapshot,
        currentDate: Date
    ) -> StatusJSONTerminalPairing {
        guard let pairing = snapshot.terminalPairing, pairing.expiresAt > currentDate else {
            return StatusJSONTerminalPairing(
                status: "inactive",
                terminal: nil,
                workspaceRoot: nil,
                expiresAt: nil,
                remainingSeconds: nil
            )
        }
        let terminal = pairing.controllingTerminal.hasPrefix("/dev/")
            ? pairing.controllingTerminal
            : "/dev/\(pairing.controllingTerminal)"
        return StatusJSONTerminalPairing(
            status: "active",
            terminal: terminal,
            workspaceRoot: pairing.workspaceRoot,
            expiresAt: ISO8601DateFormatter().string(from: pairing.expiresAt),
            remainingSeconds: max(Int(pairing.expiresAt.timeIntervalSince(currentDate)), 0)
        )
    }

    private static func guardedTerminalStatusText(_ status: GuardedTerminalStatus) -> String {
        switch status.state {
        case .active:
            let toolCount = (status.tools?.count ?? 0) + (status.agentLaunchers?.count ?? 0)
            return "Active (\(toolCount) \(toolCount == 1 ? "tool" : "tools") shimmed)"
        case .stale:
            return "Stale (\(status.detail ?? "incomplete guard state"))"
        case .inactive:
            guard let detail = status.detail else { return "Inactive" }
            return "Inactive (\(detail))"
        }
    }

    private static func sshSessionStatusText(snapshot: StatusSnapshot, currentDate: Date) -> String {
        guard snapshot.sshSessionActive else {
            return "Inactive"
        }
        guard let expiresAt = snapshot.sshSessionExpiresAt else { return "Active" }
        let remaining = Int(expiresAt.timeIntervalSince(currentDate))
        guard remaining > 0 else { return "Inactive" }
        let keyLabel = snapshot.sshSessionKeyCount == 1 ? "key" : "keys"
        let scopeLabel = snapshot.sshSessionCurrentTerminal ? "Active" : "Active in another terminal"
        return "\(scopeLabel) (\(remaining)s remaining, \(snapshot.sshSessionKeyCount) \(keyLabel))"
    }

    /// Prefers the current terminal's SSH approval session, then falls back to a
    /// display-only aggregate so status does not report a live SSH approval as inactive.
    static func loadSSHSessionStatus(
        currentDate: Date,
        sessionScope: String? = SessionCache.humanSessionScope(),
        fileURL: URL = SSHAgentSessionStatusStore.defaultFileURL,
        isAgentProcessRunning: (Int32) -> Bool = Status.isProcessRunning
    ) -> SSHAgentSessionStatus {
        guard let snapshot = SSHAgentSessionStatusStore.load(fileURL: fileURL) else {
            return .inactive
        }
        let currentTerminalStatus = snapshot.status(
            currentDate: currentDate,
            sessionScope: sessionScope,
            isAgentProcessRunning: isAgentProcessRunning
        )
        guard !currentTerminalStatus.active else {
            return currentTerminalStatus
        }
        return snapshot.aggregateStatus(
            currentDate: currentDate,
            isAgentProcessRunning: isAgentProcessRunning
        )
    }

    private static func isProcessRunning(pid: Int32) -> Bool {
        if kill(pid, 0) == 0 {
            return true
        }
        return errno == EPERM
    }
}

struct GuardedTerminalStatus: Codable, Equatable {
    enum State: String, Codable {
        case active
        case stale
        case inactive
    }

    let state: State
    let shimDirectory: String?
    let tools: [String]?
    let agentLaunchers: [String]?
    let detail: String?

    init(
        state: State,
        shimDirectory: String? = nil,
        tools: [String]? = nil,
        agentLaunchers: [String]? = nil,
        detail: String? = nil
    ) {
        self.state = state
        self.shimDirectory = shimDirectory
        self.tools = tools
        self.agentLaunchers = agentLaunchers
        self.detail = detail
    }
}

struct StatusSnapshot {
    let bridgeConnected: Bool
    let sessionActive: Bool
    let sessionExpiresAt: Date?
    let terminalPairing: TerminalPairing?
    let shellIntegrationEnabled: Bool
    let sshAgentRunning: Bool
    let sshSessionActive: Bool
    let sshSessionExpiresAt: Date?
    let sshSessionKeyCount: Int
    let sshSessionCurrentTerminal: Bool
    let terminalScope: String?
    let workspaceContext: WorkspaceRuntimeContext?
    let guardedTerminal: GuardedTerminalStatus
    let reportsPairingAuthority: Bool

    init(
        bridgeConnected: Bool,
        sessionActive: Bool,
        sessionExpiresAt: Date?,
        terminalPairing: TerminalPairing? = nil,
        shellIntegrationEnabled: Bool,
        sshAgentRunning: Bool,
        sshSessionActive: Bool = false,
        sshSessionExpiresAt: Date? = nil,
        sshSessionKeyCount: Int = 0,
        sshSessionCurrentTerminal: Bool = true,
        terminalScope: String? = nil,
        workspaceContext: WorkspaceRuntimeContext? = nil,
        guardedTerminal: GuardedTerminalStatus = GuardedTerminalStatus(state: .inactive),
        reportsPairingAuthority: Bool = false
    ) {
        self.bridgeConnected = bridgeConnected
        self.sessionActive = sessionActive
        self.sessionExpiresAt = sessionExpiresAt
        self.terminalPairing = terminalPairing
        self.shellIntegrationEnabled = shellIntegrationEnabled
        self.sshAgentRunning = sshAgentRunning
        self.sshSessionActive = sshSessionActive
        self.sshSessionExpiresAt = sshSessionExpiresAt
        self.sshSessionKeyCount = sshSessionKeyCount
        self.sshSessionCurrentTerminal = sshSessionCurrentTerminal
        self.terminalScope = terminalScope
        self.workspaceContext = workspaceContext
        self.guardedTerminal = guardedTerminal
        self.reportsPairingAuthority = reportsPairingAuthority
    }
}

private struct StatusJSONPayload: Encodable {
    let bridgeConnected: Bool
    let sessionActive: Bool?
    let sessionExpiresAt: String?
    let shellIntegrationEnabled: Bool
    let sshAgentRunning: Bool
    let sshSessionActive: Bool
    let sshSessionExpiresAt: String?
    let session: StatusJSONSession?
    let terminalPairing: StatusJSONTerminalPairing?
    let sshSession: StatusJSONSSHSession
    let terminalScope: String?
    let workspace: WorkspaceRuntimeContext?
    let guardedTerminal: GuardedTerminalStatus

    enum CodingKeys: String, CodingKey {
        case bridgeConnected
        case sessionActive
        case sessionExpiresAt
        case shellIntegrationEnabled
        case sshAgentRunning
        case sshSessionActive
        case sshSessionExpiresAt
        case session
        case terminalPairing
        case sshSession
        case terminalScope
        case workspace
        case guardedTerminal
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(bridgeConnected, forKey: .bridgeConnected)
        try container.encodeIfPresent(sessionActive, forKey: .sessionActive)
        try container.encodeIfPresent(sessionExpiresAt, forKey: .sessionExpiresAt)
        try container.encode(shellIntegrationEnabled, forKey: .shellIntegrationEnabled)
        try container.encode(sshAgentRunning, forKey: .sshAgentRunning)
        try container.encode(sshSessionActive, forKey: .sshSessionActive)
        try container.encodeIfPresent(sshSessionExpiresAt, forKey: .sshSessionExpiresAt)
        try container.encodeIfPresent(session, forKey: .session)
        try container.encodeIfPresent(terminalPairing, forKey: .terminalPairing)
        try container.encode(sshSession, forKey: .sshSession)
        try container.encodeIfPresent(terminalScope, forKey: .terminalScope)
        try container.encodeIfPresent(workspace, forKey: .workspace)
        try container.encode(guardedTerminal, forKey: .guardedTerminal)
    }
}

private struct StatusJSONTerminalPairing: Codable {
    let status: String
    let terminal: String?
    let workspaceRoot: String?
    let expiresAt: String?
    let remainingSeconds: Int?
}

private struct StatusJSONSession: Codable {
    let status: String
    let remainingSeconds: Int?
}

private struct StatusJSONSSHSession: Codable {
    let status: String
    let remainingSeconds: Int?
    let activeKeyCount: Int
    let currentTerminal: Bool
}
