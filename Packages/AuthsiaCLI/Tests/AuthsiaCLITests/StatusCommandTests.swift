import Foundation
import Testing
import AuthenticatorBridge
@testable import authsia

@Suite("Status command")
struct StatusCommandTests {

    @Test("buildSnapshot reports connected session shell and ssh state")
    func buildSnapshotReportsAllCoreStates() {
        let expiresAt = Date(timeIntervalSince1970: 1_700_000_000)
        let snapshot = Status.buildSnapshot(
            environment: [
                "AUTHSIA_SHELL_INTEGRATION": "1",
                "SSH_AUTH_SOCK": "/tmp/agent.sock"
            ],
            localSessionExpiresAt: expiresAt,
            bridgeSessionActive: nil,
            bridgeSessionExpiresAt: nil,
            isBridgeConnected: true,
            sshSessionStatus: SSHAgentSessionStatus(
                active: true,
                activeKeyCount: 1,
                expiresAt: expiresAt
            ),
            currentDate: Date(timeIntervalSince1970: 1_699_999_900)
        )

        #expect(snapshot.bridgeConnected)
        #expect(snapshot.sessionActive)
        #expect(snapshot.sessionExpiresAt == expiresAt)
        #expect(snapshot.shellIntegrationEnabled)
        #expect(snapshot.sshAgentRunning)
        #expect(snapshot.sshSessionActive)
        #expect(snapshot.sshSessionExpiresAt == expiresAt)
        #expect(snapshot.sshSessionKeyCount == 1)
        #expect(snapshot.sshSessionCurrentTerminal)
    }

    @Test("buildSnapshot reports inactive session when expired")
    func buildSnapshotReportsExpiredSession() {
        let expiresAt = Date(timeIntervalSince1970: 1_700_000_000)
        let snapshot = Status.buildSnapshot(
            environment: [:],
            localSessionExpiresAt: expiresAt,
            bridgeSessionActive: nil,
            bridgeSessionExpiresAt: nil,
            isBridgeConnected: false,
            currentDate: Date(timeIntervalSince1970: 1_700_000_001)
        )

        #expect(!snapshot.bridgeConnected)
        #expect(!snapshot.sessionActive)
        #expect(snapshot.sessionExpiresAt == expiresAt)
        #expect(!snapshot.shellIntegrationEnabled)
        #expect(!snapshot.sshAgentRunning)
    }

    @Test("missing local cache reports active when bridge confirms current scope")
    func missingLocalCacheReportsActiveWhenBridgeConfirmsCurrentScope() {
        let expiresAt = Date(timeIntervalSince1970: 1_700_000_000)
        let snapshot = Status.buildSnapshot(
            environment: [:],
            localSessionExpiresAt: nil,
            bridgeSessionActive: true,
            bridgeSessionExpiresAt: expiresAt,
            isBridgeConnected: true,
            currentDate: Date(timeIntervalSince1970: 1_699_999_900)
        )

        #expect(snapshot.sessionActive)
        #expect(snapshot.sessionExpiresAt == expiresAt)
    }

    @Test("connected bridge inactive session overrides stale local cache")
    func connectedBridgeInactiveSessionOverridesStaleLocalCache() {
        let snapshot = Status.buildSnapshot(
            environment: [:],
            localSessionExpiresAt: Date(timeIntervalSince1970: 1_700_000_000),
            bridgeSessionActive: false,
            bridgeSessionExpiresAt: nil,
            isBridgeConnected: true,
            currentDate: Date(timeIntervalSince1970: 1_699_999_900)
        )

        #expect(!snapshot.sessionActive)
        #expect(snapshot.sessionExpiresAt == nil)
    }

    @Test("renderTable includes high-level status labels")
    func renderTableIncludesLabels() {
        let snapshot = StatusSnapshot(
            bridgeConnected: true,
            sessionActive: true,
            sessionExpiresAt: Date(timeIntervalSince1970: 1_700_000_000),
            shellIntegrationEnabled: true,
            sshAgentRunning: false
        )

        let output = Status.renderTable(snapshot: snapshot, currentDate: Date(timeIntervalSince1970: 1_699_999_900))

        #expect(output.contains("Bridge"))
        #expect(output.contains("Session"))
        #expect(output.contains("Shell Integration"))
        #expect(output.contains("SSH Agent"))
        #expect(output.contains("Connected"))
    }

    @Test("renderTable includes ssh session status")
    func renderTableIncludesSSHSessionStatus() {
        let snapshot = StatusSnapshot(
            bridgeConnected: true,
            sessionActive: false,
            sessionExpiresAt: nil,
            shellIntegrationEnabled: true,
            sshAgentRunning: true,
            sshSessionActive: true,
            sshSessionExpiresAt: Date(timeIntervalSince1970: 1_700_000_000),
            sshSessionKeyCount: 1
        )

        let output = Status.renderTable(snapshot: snapshot, currentDate: Date(timeIntervalSince1970: 1_699_999_990))

        #expect(output.contains("SSH Session: Active"))
        #expect(output.contains("1 key"))
    }

    @Test("renderTable and JSON include display-only workspace context")
    func renderTableAndJSONIncludeWorkspaceContext() throws {
        let workspaceContext = WorkspaceRuntimeContext(
            name: "selected-api",
            rootLabel: "api",
            authsiaFolder: "Workspaces/selected-api"
        )
        let snapshot = StatusSnapshot(
            bridgeConnected: true,
            sessionActive: false,
            sessionExpiresAt: nil,
            shellIntegrationEnabled: true,
            sshAgentRunning: false,
            workspaceContext: workspaceContext
        )

        let table = Status.renderTable(snapshot: snapshot, currentDate: Date(timeIntervalSince1970: 1_699_999_990))
        let json = Status.renderJSON(snapshot: snapshot, currentDate: Date(timeIntervalSince1970: 1_699_999_990))
        let payload = try JSONDecoder().decode(StatusJSONPayload.self, from: Data(json.utf8))

        #expect(table.contains("Workspace: selected-api (api)"))
        #expect(table.contains("Workspaces/selected-api"))
        #expect(payload.workspace?.name == "selected-api")
        #expect(payload.workspace?.rootLabel == "api")
        #expect(payload.workspace?.authsiaFolder == "Workspaces/selected-api")
    }

    @Test("ssh session status reports active approvals from another terminal for diagnostics")
    func sshSessionStatusReportsActiveApprovalsFromAnotherTerminalForDiagnostics() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-status-\(UUID().uuidString)")
        let fileURL = directory.appendingPathComponent("ssh-agent-session.json")
        defer { try? FileManager.default.removeItem(at: directory) }

        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let snapshot = SSHAgentSessionSnapshot(
            agentPID: 4242,
            sessions: [
                SSHAgentSessionRecord(scope: "tty:/dev/ttys009:sid:9", expiresAt: now.addingTimeInterval(600)),
            ],
            updatedAt: now
        )
        try SSHAgentSessionStatusStore.save(snapshot, fileURL: fileURL)

        let sameTerminal = Status.loadSSHSessionStatus(
            currentDate: now,
            sessionScope: "tty:/dev/ttys009:sid:9",
            fileURL: fileURL,
            isAgentProcessRunning: { _ in true }
        )
        let otherTerminal = Status.loadSSHSessionStatus(
            currentDate: now,
            sessionScope: "tty:/dev/ttys001:sid:1",
            fileURL: fileURL,
            isAgentProcessRunning: { _ in true }
        )

        #expect(sameTerminal.active)
        #expect(sameTerminal.activeKeyCount == 1)
        #expect(sameTerminal.currentTerminal)
        #expect(otherTerminal.active)
        #expect(otherTerminal.activeKeyCount == 1)
        #expect(!otherTerminal.currentTerminal)
    }

    @Test("renderTable distinguishes ssh sessions from another terminal")
    func renderTableDistinguishesSSHSessionFromAnotherTerminal() {
        let snapshot = StatusSnapshot(
            bridgeConnected: true,
            sessionActive: false,
            sessionExpiresAt: nil,
            shellIntegrationEnabled: true,
            sshAgentRunning: true,
            sshSessionActive: true,
            sshSessionExpiresAt: Date(timeIntervalSince1970: 1_700_000_000),
            sshSessionKeyCount: 1,
            sshSessionCurrentTerminal: false
        )

        let output = Status.renderTable(snapshot: snapshot, currentDate: Date(timeIntervalSince1970: 1_699_999_990))

        #expect(output.contains("SSH Session: Active in another terminal"))
        #expect(output.contains("1 key"))
    }

    @Test("renderJSON returns structured status payload")
    func renderJSONReturnsStructuredPayload() throws {
        let snapshot = StatusSnapshot(
            bridgeConnected: true,
            sessionActive: true,
            sessionExpiresAt: Date(timeIntervalSince1970: 1_700_000_000),
            shellIntegrationEnabled: false,
            sshAgentRunning: true,
            sshSessionActive: true,
            sshSessionExpiresAt: Date(timeIntervalSince1970: 1_700_000_010),
            sshSessionKeyCount: 2,
            terminalScope: "tty:/dev/ttys001:sid:1001"
        )

        let output = Status.renderJSON(snapshot: snapshot, currentDate: Date(timeIntervalSince1970: 1_699_999_900))
        let data = Data(output.utf8)
        let payload = try JSONDecoder().decode(StatusJSONPayload.self, from: data)

        #expect(payload.bridgeConnected)
        #expect(payload.sessionActive)
        #expect(!payload.shellIntegrationEnabled)
        #expect(payload.sshAgentRunning)
        #expect(payload.session.status == "active")
        #expect(payload.sshSessionActive)
        #expect(payload.sshSession.status == "active")
        #expect(payload.sshSession.remainingSeconds == 110)
        #expect(payload.sshSession.activeKeyCount == 2)
        #expect(payload.sshSession.currentTerminal)
        #expect(payload.terminalScope == "tty:/dev/ttys001:sid:1001")
        #expect(payload.guardedTerminal.state == "inactive")
    }

    @Test("guarded terminal status counts the shims backing the current shell")
    func guardedTerminalStatusReportsActiveShims() throws {
        let shimDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-guard-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: shimDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: shimDirectory) }
        for tool in ["python", "git", "aws"] {
            try Data().write(to: shimDirectory.appendingPathComponent(tool))
        }

        let status = Status.resolveGuardedTerminalStatus(environment: [
            "AUTHSIA_WORKSPACE_GUARD": "1",
            "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": shimDirectory.path,
            "PATH": "\(shimDirectory.path):/usr/bin:/bin",
        ])

        #expect(status == GuardedTerminalStatus(
            state: .active,
            shimDirectory: shimDirectory.path,
            tools: ["aws", "git", "python"]
        ))
        #expect(Status.renderTable(
            snapshot: snapshot(guardedTerminal: status),
            currentDate: Date(timeIntervalSince1970: 1_699_999_900)
        ).contains("Guarded Terminal: Active (3 tools shimmed)"))
    }

    @Test("verbose status separates a persisted custom tool from agent launcher shims")
    func guardedTerminalStatusCapturesCustomToolsAndAgentLaunchers() throws {
        let shimDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-guard-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: shimDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: shimDirectory) }
        // "rails" stands in for a tool the user added with
        // `eval "$(authsia workspace guard --tool rails --print-env)"` and persisted to
        // guard.tools; "claude" and "codex" stand in for the agent-launcher unguard shims
        // `install()` writes into the same directory.
        for shim in ["python", "rails", "claude", "codex"] {
            try Data().write(to: shimDirectory.appendingPathComponent(shim))
        }

        let status = Status.resolveGuardedTerminalStatus(environment: [
            "AUTHSIA_WORKSPACE_GUARD": "1",
            "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": shimDirectory.path,
            "PATH": "\(shimDirectory.path):/usr/bin:/bin",
        ])

        #expect(status == GuardedTerminalStatus(
            state: .active,
            shimDirectory: shimDirectory.path,
            tools: ["python", "rails"],
            agentLaunchers: ["claude", "codex"]
        ))

        let currentDate = Date(timeIntervalSince1970: 1_699_999_900)
        let verboseOutput = Status.renderTable(
            snapshot: snapshot(guardedTerminal: status),
            currentDate: currentDate,
            verbose: true
        )
        #expect(verboseOutput.contains("Guarded Terminal: Active (4 tools shimmed)"))
        #expect(verboseOutput.contains("  Tools: python, rails"))
        #expect(verboseOutput.contains("  Agent launchers (start unguarded): claude, codex"))

        // Without --verbose, only the summary line prints.
        let terseOutput = Status.renderTable(snapshot: snapshot(guardedTerminal: status), currentDate: currentDate)
        #expect(!terseOutput.contains("Tools: python"))
        #expect(!terseOutput.contains("Agent launchers"))
    }

    @Test("partial guard state reports stale instead of active")
    func guardedTerminalStatusReportsStaleState() {
        let missingShimDirectory = "/tmp/authsia-guard-\(UUID().uuidString)"
        let sweptShimDirectory = Status.resolveGuardedTerminalStatus(environment: [
            "AUTHSIA_WORKSPACE_GUARD": "1",
            "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": missingShimDirectory,
            "PATH": "\(missingShimDirectory):/usr/bin:/bin",
        ])
        #expect(sweptShimDirectory == GuardedTerminalStatus(
            state: .stale,
            shimDirectory: missingShimDirectory,
            detail: "shim directory missing"
        ))

        // A child that dropped the markers but kept the inherited PATH.
        let markersDropped = Status.resolveGuardedTerminalStatus(environment: [
            "PATH": "/tmp/authsia-guard-abc:/usr/bin:/bin",
        ])
        #expect(markersDropped == GuardedTerminalStatus(state: .stale, detail: "guard markers missing"))

        let pathRestored = Status.resolveGuardedTerminalStatus(environment: [
            "AUTHSIA_WORKSPACE_GUARD": "1",
            "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": "/tmp/authsia-guard-abc",
            "PATH": "/usr/bin:/bin",
        ])
        #expect(pathRestored == GuardedTerminalStatus(state: .stale, detail: "shim directory not on PATH"))

        #expect(Status.renderTable(
            snapshot: snapshot(guardedTerminal: pathRestored),
            currentDate: Date(timeIntervalSince1970: 1_699_999_900)
        ).contains("Guarded Terminal: Stale (shim directory not on PATH)"))
    }

    @Test("an unguarded shell separates a plain shell from an agent session")
    func guardedTerminalStatusReportsInactiveStates() {
        let plainShell = Status.resolveGuardedTerminalStatus(environment: ["PATH": "/usr/bin:/bin"])
        #expect(plainShell == GuardedTerminalStatus(state: .inactive))

        let agentShell = Status.resolveGuardedTerminalStatus(environment: [
            "PATH": "/usr/bin:/bin",
            "AUTHSIA_AGENT_PLATFORM": "codex",
            "AUTHSIA_AGENT_INVOKES_AUTHSIA": "1",
        ])
        #expect(agentShell == GuardedTerminalStatus(state: .inactive, detail: "agent session"))

        let currentDate = Date(timeIntervalSince1970: 1_699_999_900)
        #expect(Status.renderTable(snapshot: snapshot(guardedTerminal: plainShell), currentDate: currentDate)
            .contains("Guarded Terminal: Inactive\n"))
        #expect(Status.renderTable(snapshot: snapshot(guardedTerminal: agentShell), currentDate: currentDate)
            .contains("Guarded Terminal: Inactive (agent session)"))
    }

    private func snapshot(guardedTerminal: GuardedTerminalStatus) -> StatusSnapshot {
        StatusSnapshot(
            bridgeConnected: true,
            sessionActive: false,
            sessionExpiresAt: nil,
            shellIntegrationEnabled: true,
            sshAgentRunning: false,
            guardedTerminal: guardedTerminal
        )
    }
}

private struct StatusJSONPayload: Decodable {
    let bridgeConnected: Bool
    let sessionActive: Bool
    let shellIntegrationEnabled: Bool
    let sshAgentRunning: Bool
    let session: StatusJSONSession
    let sshSessionActive: Bool
    let sshSession: StatusJSONSSHSession
    let terminalScope: String?
    let workspace: StatusJSONWorkspace?
    let guardedTerminal: StatusJSONGuardedTerminal
}

private struct StatusJSONGuardedTerminal: Decodable {
    let state: String
    let shimDirectory: String?
    let tools: [String]?
    let agentLaunchers: [String]?
    let detail: String?
}

private struct StatusJSONSession: Decodable {
    let status: String
}

private struct StatusJSONSSHSession: Decodable {
    let status: String
    let remainingSeconds: Int?
    let activeKeyCount: Int
    let currentTerminal: Bool
}

private struct StatusJSONWorkspace: Decodable {
    let name: String
    let rootLabel: String
    let authsiaFolder: String?
}
