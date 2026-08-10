import Foundation
import Darwin
import ArgumentParser
import AuthenticatorBridge

struct Status: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "status",
        abstract: "Show app, session, shell, SSH agent, and SSH approval status",
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
            isBridgeConnected: pingPayload != nil,
            sshSessionStatus: sshSessionStatus,
            currentDate: now,
            terminalScope: humanSessionScope,
            workspaceContext: WorkspaceRuntimeContextResolver.resolve()
        )
        print(Self.render(snapshot: snapshot, format: format, currentDate: now))
    }

    static func render(snapshot: StatusSnapshot, format: OutputFormat, currentDate: Date) -> String {
        switch format {
        case .table:
            return renderTable(snapshot: snapshot, currentDate: currentDate)
        case .json:
            return renderJSON(snapshot: snapshot, currentDate: currentDate)
        }
    }

    static func buildSnapshot(
        environment: [String: String],
        localSessionExpiresAt: Date?,
        bridgeSessionActive: Bool?,
        bridgeSessionExpiresAt: Date?,
        isBridgeConnected: Bool,
        sshSessionStatus: SSHAgentSessionStatus = .inactive,
        currentDate: Date,
        terminalScope: String? = nil,
        workspaceContext: WorkspaceRuntimeContext? = nil
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
            shellIntegrationEnabled: environment["AUTHSIA_SHELL_INTEGRATION"] == "1",
            sshAgentRunning: SSHAgentLoader.isAgentRunning(environment: environment),
            sshSessionActive: sshSessionStatus.active,
            sshSessionExpiresAt: sshSessionStatus.expiresAt,
            sshSessionKeyCount: sshSessionStatus.activeKeyCount,
            sshSessionCurrentTerminal: sshSessionStatus.currentTerminal,
            terminalScope: terminalScope,
            workspaceContext: workspaceContext,
            guardedTerminal: resolveGuardedTerminalStatus(environment: environment)
        )
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
        return GuardedTerminalStatus(
            state: .active,
            shimDirectory: shimDirectory,
            toolCount: shims.count
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

    static func renderTable(snapshot: StatusSnapshot, currentDate: Date) -> String {
        var lines: [String] = []
        lines.append("Authsia Status")
        lines.append("Bridge: \(snapshot.bridgeConnected ? "Connected" : "Disconnected")")
        lines.append("Session: \(sessionStatusText(snapshot: snapshot, currentDate: currentDate))")
        lines.append("Shell Integration: \(snapshot.shellIntegrationEnabled ? "Enabled" : "Disabled")")
        lines.append("Guarded Terminal: \(guardedTerminalStatusText(snapshot.guardedTerminal))")
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
            sessionActive: snapshot.sessionActive,
            sessionExpiresAt: snapshot.sessionExpiresAt.map { ISO8601DateFormatter().string(from: $0) },
            shellIntegrationEnabled: snapshot.shellIntegrationEnabled,
            sshAgentRunning: snapshot.sshAgentRunning,
            sshSessionActive: snapshot.sshSessionActive,
            sshSessionExpiresAt: snapshot.sshSessionExpiresAt.map { ISO8601DateFormatter().string(from: $0) },
            session: StatusJSONSession(
                status: snapshot.sessionActive ? "active" : "inactive",
                remainingSeconds: snapshot.sessionExpiresAt.map {
                    max(Int($0.timeIntervalSince(currentDate)), 0)
                }
            ),
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

    private static func guardedTerminalStatusText(_ status: GuardedTerminalStatus) -> String {
        switch status.state {
        case .active:
            guard let toolCount = status.toolCount else { return "Active" }
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
    let toolCount: Int?
    let detail: String?

    init(state: State, shimDirectory: String? = nil, toolCount: Int? = nil, detail: String? = nil) {
        self.state = state
        self.shimDirectory = shimDirectory
        self.toolCount = toolCount
        self.detail = detail
    }
}

struct StatusSnapshot {
    let bridgeConnected: Bool
    let sessionActive: Bool
    let sessionExpiresAt: Date?
    let shellIntegrationEnabled: Bool
    let sshAgentRunning: Bool
    let sshSessionActive: Bool
    let sshSessionExpiresAt: Date?
    let sshSessionKeyCount: Int
    let sshSessionCurrentTerminal: Bool
    let terminalScope: String?
    let workspaceContext: WorkspaceRuntimeContext?
    let guardedTerminal: GuardedTerminalStatus

    init(
        bridgeConnected: Bool,
        sessionActive: Bool,
        sessionExpiresAt: Date?,
        shellIntegrationEnabled: Bool,
        sshAgentRunning: Bool,
        sshSessionActive: Bool = false,
        sshSessionExpiresAt: Date? = nil,
        sshSessionKeyCount: Int = 0,
        sshSessionCurrentTerminal: Bool = true,
        terminalScope: String? = nil,
        workspaceContext: WorkspaceRuntimeContext? = nil,
        guardedTerminal: GuardedTerminalStatus = GuardedTerminalStatus(state: .inactive)
    ) {
        self.bridgeConnected = bridgeConnected
        self.sessionActive = sessionActive
        self.sessionExpiresAt = sessionExpiresAt
        self.shellIntegrationEnabled = shellIntegrationEnabled
        self.sshAgentRunning = sshAgentRunning
        self.sshSessionActive = sshSessionActive
        self.sshSessionExpiresAt = sshSessionExpiresAt
        self.sshSessionKeyCount = sshSessionKeyCount
        self.sshSessionCurrentTerminal = sshSessionCurrentTerminal
        self.terminalScope = terminalScope
        self.workspaceContext = workspaceContext
        self.guardedTerminal = guardedTerminal
    }
}

private struct StatusJSONPayload: Codable {
    let bridgeConnected: Bool
    let sessionActive: Bool
    let sessionExpiresAt: String?
    let shellIntegrationEnabled: Bool
    let sshAgentRunning: Bool
    let sshSessionActive: Bool
    let sshSessionExpiresAt: String?
    let session: StatusJSONSession
    let sshSession: StatusJSONSSHSession
    let terminalScope: String?
    let workspace: WorkspaceRuntimeContext?
    let guardedTerminal: GuardedTerminalStatus
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
