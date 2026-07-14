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
        guard credential.allowedCommands.contains(.ssh) else {
            throw ValidationError("Automation credential '\(credential.name)' does not permit 'ssh'.")
        }
        guard let sessionScope else { return }
        try SSHAutomationGrantStore.saveGrant(
            credentialID: credential.id,
            sessionScope: sessionScope,
            rootProcessID: nil,
            expiresAt: credential.expiresAt,
            fileURL: grantFileURL,
            currentDate: now
        )
    }

    static func clearCurrentSessionGrant(
        sessionScope: String? = TerminalSessionScope.currentAncestralScope(),
        grantFileURL: URL = SSHAutomationGrantStore.defaultFileURL
    ) {
        guard let sessionScope else { return }
        SSHAutomationGrantStore.clearSessionScope(sessionScope, fileURL: grantFileURL)
    }
}
