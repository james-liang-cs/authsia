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
