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
        grantFileURL: URL = SSHAutomationGrantStore.defaultFileURL,
        leaseIssuer: SSHAutomationExecutionLeaseIssuing = AuthsiaBridgeClient.shared
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
        guard let token = credential.bearerToken,
              let sessionScope else {
            return
        }
        let lease = try leaseIssuer.issueSSHAutomationExecutionLease(
            token: token,
            binding: SSHAutomationExecutionLeaseBinding(sessionScope: sessionScope)
        )
        try SSHAutomationGrantStore.saveGrant(
            leaseID: lease.id,
            sessionScope: sessionScope,
            rootProcessID: nil,
            expiresAt: lease.expiresAt,
            fileURL: grantFileURL,
            currentDate: now
        )
    }

    static func clearCurrentSessionGrant(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        store: AccessCredentialStore = AccessCredentialStore(),
        now: Date = Date(),
        sessionScope: String? = TerminalSessionScope.currentAncestralScope(),
        grantFileURL: URL = SSHAutomationGrantStore.defaultFileURL,
        leaseIssuer: SSHAutomationExecutionLeaseIssuing = AuthsiaBridgeClient.shared
    ) {
        guard let sessionScope else { return }
        let leaseIDs = SSHAutomationGrantStore.clearSessionScope(
            sessionScope,
            fileURL: grantFileURL
        )
        guard !leaseIDs.isEmpty,
              let credential = try? AutomationAccessResolver.resolveActiveSSHCredential(
                environment: environment,
                store: store,
                now: now
              ),
              credential.allowedCommands == [.ssh],
              let token = credential.bearerToken else {
            return
        }
        for leaseID in leaseIDs {
            try? leaseIssuer.retireSSHAutomationExecutionLease(
                token: token,
                leaseID: leaseID
            )
        }
    }
}
