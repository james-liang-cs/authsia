import ArgumentParser
import Foundation
import AuthenticatorBridge

struct SSHAutomationGrantCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "__ssh-automation-grant",
        abstract: "Manage transient SSH automation grants",
        shouldDisplay: false
    )

    @Flag(name: .long, help: "Clear the current terminal's transient SSH automation grant")
    var clear = false

    func run() throws {
        if clear {
            Self.clearCurrentSessionGrant()
            return
        }
        try Self.activateCurrentSessionGrant()
    }

    static func activateCurrentSessionGrant(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        store: AccessCredentialStore = AccessCredentialStore(),
        now: Date = Date(),
        sessionScope: String? = TerminalSessionScope.currentAncestralScope(),
        grantFileURL: URL = SSHAutomationGrantStore.defaultFileURL
    ) throws {
        guard let credential = try AutomationAccessResolver.resolveActiveSSHCredential(
            environment: environment,
            store: store,
            now: now
        ) else {
            return
        }
        guard credential.allowedCommands == [.ssh] else {
            throw ValidationError(
                "SSH automation requires a separate SSH-only credential created with --allow ssh."
            )
        }
        // Bearer tokens are intentionally never copied into the user-writable
        // transient grant file. SSH children inherit the scoped token directly.
        _ = sessionScope
        _ = grantFileURL
    }

    static func clearCurrentSessionGrant(
        sessionScope: String? = TerminalSessionScope.currentAncestralScope(),
        grantFileURL: URL = SSHAutomationGrantStore.defaultFileURL
    ) {
        guard let sessionScope else { return }
        SSHAutomationGrantStore.clearSessionScope(sessionScope, fileURL: grantFileURL)
    }
}
