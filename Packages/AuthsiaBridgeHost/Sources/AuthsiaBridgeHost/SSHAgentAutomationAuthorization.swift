#if os(macOS)
import Foundation
import AuthenticatorBridge

public enum SSHAgentAutomationAuthorizationDecision: Equatable {
    case notAutomation
    case allowWithoutApproval(scope: AutomationCredentialScope.Normalized)
    case deny(String)
}

public enum SSHAgentAutomationAuthorization {
    public static func authorize(
        environment: [String: String],
        keyFolderPath: String?,
        sessionScope: String? = nil,
        ancestryPIDs: [Int32] = [],
        credentialLookup: (UUID) -> AutomationCredentialLookup.Result = { AutomationCredentialLookup.lookup(credentialID: $0) },
        grantCredentialLookup: (String?, [Int32], Date) -> UUID? = {
            SSHAutomationGrantStore.activeCredentialID(sessionScope: $0, ancestryPIDs: $1, currentDate: $2)
        },
        now: Date = Date(),
        currentMachineId: String? = AutomationCredentialLookup.currentMachineId()
    ) -> SSHAgentAutomationAuthorizationDecision {
        guard let rawID = credentialID(
            from: environment,
            sessionScope: sessionScope,
            ancestryPIDs: ancestryPIDs,
            now: now,
            grantCredentialLookup: grantCredentialLookup
        ) else {
            return .notAutomation
        }
        guard let credentialID = UUID(uuidString: rawID) else {
            return .deny("SSH automation credential marker is invalid.")
        }

        let credential: AutomationCredentialLookup.CredentialRecord
        switch credentialLookup(credentialID) {
        case .fileMissing:
            return .deny("Automation credential store is missing or unreadable. Recreate the credential.")
        case .credentialNotFound:
            return .deny("Automation credential not found in local store.")
        case .corruptedStore:
            return .deny("Automation credential store is corrupted. Recreate the credential.")
        case .found(let foundCredential):
            credential = foundCredential
        }

        switch credential.status(asOf: now) {
        case .active:
            break
        case .expired:
            return .deny("Automation credential is expired.")
        case .revoked:
            return .deny("Automation credential is revoked.")
        }

        guard let currentMachineId, credential.machineId == currentMachineId else {
            return .deny("Automation credential is not valid for this machine.")
        }
        guard credential.allowedCommands.contains(.ssh) else {
            return .deny("Automation credential does not permit 'ssh'.")
        }
        guard let scope = AutomationCredentialScope.normalizeStored(credential.scope) else {
            return .deny("Automation credential scope is invalid.")
        }
        let scopeName = AutomationCredentialScope.displayName(scope)
        guard AutomationCredentialScope.contains(itemFolderPath: keyFolderPath, normalizedScope: scope) else {
            return .deny("Automation credential scope '\(scopeName)' does not allow access to this SSH key.")
        }

        return .allowWithoutApproval(scope: scope)
    }

    private static func credentialID(
        from environment: [String: String],
        sessionScope: String?,
        ancestryPIDs: [Int32],
        now: Date,
        grantCredentialLookup: (String?, [Int32], Date) -> UUID?
    ) -> String? {
        let keys = [
            AutomationCredentialEnvironment.sshCredentialKey,
            AutomationCredentialEnvironment.generalCredentialKey,
        ]
        for key in keys {
            let value = environment[key]?.trimmingCharacters(in: .whitespacesAndNewlines)
            if let value, !value.isEmpty {
                return value
            }
        }
        return grantCredentialLookup(sessionScope, ancestryPIDs, now)?.uuidString
    }
}
#endif
