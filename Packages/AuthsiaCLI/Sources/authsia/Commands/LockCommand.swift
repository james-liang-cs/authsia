import Foundation
import ArgumentParser
import AuthenticatorBridge

protocol SessionLocking {
    func lock(sessionToken: String?, sessionScope: String?) throws -> Bool
}

struct Lock: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "End active Authsia sessions",
        discussion: """
            Clears this terminal's cached CLI session, asks the Authsia app to
            revoke the active bridge session, and clears this terminal's SSH
            approval-session status. Protected commands and session-based SSH
            signing will require approval again.

            Examples:
              authsia lock
              authsia unlock --status
            """
    )

    func run() throws {
        let didLock = try Self.lockSession(client: AuthsiaBridgeClient.shared)
        print(didLock ? "Session locked." : "No active session.")
    }

    @discardableResult
    static func lockSession(
        client: SessionLocking,
        secureStore: any SessionSecureStore = KeychainSessionSecureStore(),
        legacyFilePath: URL = SessionCache.legacySessionFilePath,
        keychainAccount: String? = SessionCache.humanScopedKeychainAccount(),
        terminalSessionScope: String? = SessionCache.humanSessionScope(),
        sshSessionScope: String? = SessionCache.humanSessionScope(),
        sshSessionStatusFileURL: URL = SSHAgentSessionStatusStore.defaultFileURL
    ) throws -> Bool {
        let hadSSHSessionStatus = sshSessionScope.map { scope in
            SSHAgentSessionStatusStore.load(fileURL: sshSessionStatusFileURL)?
                .sessions
                .contains { $0.scope == scope } ?? false
        } ?? false
        defer {
            if let sshSessionScope {
                SSHAgentSessionStatusStore.clearSessionScope(sshSessionScope, fileURL: sshSessionStatusFileURL)
            }
        }

        let token = SessionCache.load(
            secureStore: secureStore,
            legacyFilePath: legacyFilePath,
            keychainAccount: keychainAccount
        )
        defer {
            SessionCache.clear(
                secureStore: secureStore,
                legacyFilePath: legacyFilePath,
                keychainAccount: keychainAccount
            )
        }

        let didLockBridgeSession = try client.lock(sessionToken: token, sessionScope: terminalSessionScope)
        return didLockBridgeSession || hadSSHSessionStatus
    }
}
