import Foundation
import Testing
import AuthenticatorBridge
@testable import authsia

@Suite("Lock command")
struct LockCommandTests {
    @Test("lock clears cached session")
    func lockClearsCachedSession() throws {
        let secureStore = InMemorySessionSecureStore()
        let legacyFile = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-lock-\(UUID().uuidString)")
            .appendingPathComponent("session.json")
        defer { try? FileManager.default.removeItem(at: legacyFile.deletingLastPathComponent()) }

        SessionCache.save(
            token: "session-token",
            expiresAt: Date().addingTimeInterval(60),
            secureStore: secureStore,
            legacyFilePath: legacyFile,
            keychainAccount: "terminal-a"
        )

        let locker = SessionLockRecorder()
        try Lock.lockSession(
            client: locker,
            secureStore: secureStore,
            legacyFilePath: legacyFile,
            keychainAccount: "terminal-a"
        )

        #expect(locker.tokens == ["session-token"])
        #expect(
            SessionCache.load(
                secureStore: secureStore,
                legacyFilePath: legacyFile,
                keychainAccount: "terminal-a"
            ) == nil
        )
    }

    @Test("lock clears ssh approval session status")
    func lockClearsSSHApprovalSessionStatus() throws {
        let secureStore = InMemorySessionSecureStore()
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-lock-\(UUID().uuidString)")
        let legacyFile = tempDir.appendingPathComponent("session.json")
        let sshStatusFile = tempDir.appendingPathComponent("ssh-agent-session.json")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        try SSHAgentSessionStatusStore.save(
            SSHAgentSessionSnapshot(
                agentPID: 42,
                sessions: [
                    SSHAgentSessionRecord(
                        scope: "tty:/dev/ttys001:sid:1001",
                        expiresAt: Date().addingTimeInterval(60)
                    ),
                    SSHAgentSessionRecord(
                        scope: "tty:/dev/ttys002:sid:1002",
                        expiresAt: Date().addingTimeInterval(60)
                    ),
                ],
                updatedAt: Date()
            ),
            fileURL: sshStatusFile
        )

        let didLock = try Lock.lockSession(
            client: SessionLockRecorder(),
            secureStore: secureStore,
            legacyFilePath: legacyFile,
            keychainAccount: "terminal-a",
            terminalSessionScope: "tty:/dev/ttys001:sid:1001",
            sshSessionScope: "tty:/dev/ttys001:sid:1001",
            sshSessionStatusFileURL: sshStatusFile
        )

        #expect(didLock)
        let reloaded = try #require(SSHAgentSessionStatusStore.load(fileURL: sshStatusFile))
        #expect(reloaded.sessions.map(\.scope) == ["tty:/dev/ttys002:sid:1002"])
    }

    @Test("lock asks bridge to invalidate current scope without cached token")
    func lockAsksBridgeToInvalidateCurrentScopeWithoutCachedToken() throws {
        let secureStore = InMemorySessionSecureStore()
        let legacyFile = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-lock-\(UUID().uuidString)")
            .appendingPathComponent("session.json")
        defer { try? FileManager.default.removeItem(at: legacyFile.deletingLastPathComponent()) }

        let locker = SessionLockRecorder(didLock: true)
        let didLock = try Lock.lockSession(
            client: locker,
            secureStore: secureStore,
            legacyFilePath: legacyFile,
            keychainAccount: "terminal-a",
            terminalSessionScope: "tty:/dev/ttys001:sid:1001",
            sshSessionScope: "tty:/dev/ttys001:sid:1001"
        )

        #expect(didLock)
        #expect(locker.tokens == [nil])
        #expect(locker.sessionScopes == ["tty:/dev/ttys001:sid:1001"])
    }
}

private final class SessionLockRecorder: SessionLocking {
    private let didLock: Bool
    private(set) var tokens: [String?] = []
    private(set) var sessionScopes: [String?] = []

    init(didLock: Bool = true) {
        self.didLock = didLock
    }

    func lock(sessionToken: String?, sessionScope: String?) throws -> Bool {
        tokens.append(sessionToken)
        sessionScopes.append(sessionScope)
        return didLock
    }
}

private final class InMemorySessionSecureStore: SessionSecureStore {
    var dataByAccount: [String: Data] = [:]

    func save(data: Data, service: String, account: String) -> Bool {
        dataByAccount[account] = data
        return true
    }

    func loadData(service: String, account: String) -> Data? {
        dataByAccount[account]
    }

    func delete(service: String, account: String) {
        dataByAccount.removeValue(forKey: account)
    }
}
