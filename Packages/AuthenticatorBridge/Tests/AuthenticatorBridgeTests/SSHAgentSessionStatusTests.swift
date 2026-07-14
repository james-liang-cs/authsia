import Foundation
import Testing
@testable import AuthenticatorBridge

@Suite("SSH agent session status")
struct SSHAgentSessionStatusTests {
    @Test("snapshot reports active sessions for a live agent")
    func snapshotReportsActiveSessionsForLiveAgent() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let firstExpiry = now.addingTimeInterval(10)
        let secondExpiry = now.addingTimeInterval(20)
        let snapshot = SSHAgentSessionSnapshot(
            agentPID: 42,
            sessions: [
                SSHAgentSessionRecord(scope: "tty:/dev/ttys001:sid:1001", expiresAt: now.addingTimeInterval(-1)),
                SSHAgentSessionRecord(scope: "tty:/dev/ttys001:sid:1001", expiresAt: firstExpiry),
                SSHAgentSessionRecord(scope: "tty:/dev/ttys001:sid:1001", expiresAt: secondExpiry),
                SSHAgentSessionRecord(scope: "tty:/dev/ttys002:sid:1002", expiresAt: secondExpiry),
            ],
            updatedAt: now
        )

        let status = snapshot.status(currentDate: now, sessionScope: "tty:/dev/ttys001:sid:1001") { pid in
            pid == 42
        }

        #expect(status.active)
        #expect(status.activeKeyCount == 2)
        #expect(status.expiresAt == secondExpiry)
    }

    @Test("snapshot ignores sessions for a dead agent")
    func snapshotIgnoresSessionsForDeadAgent() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let snapshot = SSHAgentSessionSnapshot(
            agentPID: 42,
            sessions: [
                SSHAgentSessionRecord(scope: "tty:/dev/ttys001:sid:1001", expiresAt: now.addingTimeInterval(20)),
            ],
            updatedAt: now
        )

        let status = snapshot.status(currentDate: now, sessionScope: "tty:/dev/ttys001:sid:1001") { _ in
            false
        }

        #expect(!status.active)
        #expect(status.activeKeyCount == 0)
        #expect(status.expiresAt == nil)
    }

    @Test("snapshot ignores sessions from another terminal scope")
    func snapshotIgnoresSessionsFromAnotherTerminalScope() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let snapshot = SSHAgentSessionSnapshot(
            agentPID: 42,
            sessions: [
                SSHAgentSessionRecord(scope: "tty:/dev/ttys001:sid:1001", expiresAt: now.addingTimeInterval(20)),
            ],
            updatedAt: now
        )

        let status = snapshot.status(currentDate: now, sessionScope: "tty:/dev/ttys002:sid:1002") { _ in
            true
        }

        #expect(!status.active)
        #expect(status.activeKeyCount == 0)
        #expect(status.expiresAt == nil)
    }

    @Test("snapshot can summarize active sessions from another terminal for status display")
    func snapshotCanSummarizeActiveSessionsFromAnotherTerminalForStatusDisplay() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let expiry = now.addingTimeInterval(20)
        let snapshot = SSHAgentSessionSnapshot(
            agentPID: 42,
            sessions: [
                SSHAgentSessionRecord(scope: "tty:/dev/ttys001:sid:1001", expiresAt: expiry),
            ],
            updatedAt: now
        )

        let status = snapshot.aggregateStatus(currentDate: now) { _ in true }

        #expect(status.active)
        #expect(!status.currentTerminal)
        #expect(status.activeKeyCount == 1)
        #expect(status.expiresAt == expiry)
    }

    @Test("store clears only the requested terminal scope")
    func storeClearsOnlyRequestedTerminalScope() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-ssh-status-\(UUID().uuidString)")
        let fileURL = tempDir.appendingPathComponent("ssh-agent-session.json")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        try SSHAgentSessionStatusStore.save(
            SSHAgentSessionSnapshot(
                agentPID: 42,
                sessions: [
                    SSHAgentSessionRecord(scope: "tty:/dev/ttys001:sid:1001", expiresAt: Date().addingTimeInterval(60)),
                    SSHAgentSessionRecord(scope: "tty:/dev/ttys002:sid:1002", expiresAt: Date().addingTimeInterval(60)),
                ],
                updatedAt: Date()
            ),
            fileURL: fileURL
        )

        let didClear = SSHAgentSessionStatusStore.clearSessionScope(
            "tty:/dev/ttys001:sid:1001",
            fileURL: fileURL
        )

        let reloaded = try #require(SSHAgentSessionStatusStore.load(fileURL: fileURL))
        #expect(didClear)
        #expect(reloaded.sessions.map(\.scope) == ["tty:/dev/ttys002:sid:1002"])
    }
}
