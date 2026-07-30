#if os(macOS)
import Foundation
import AuthenticatorBridge

public enum SSHAgentAutomationAuthorizationDecision: Equatable {
    case notAutomation
    case allowWithoutApproval(scope: AutomationCredentialScope.Normalized)
    case allowWithoutApprovalUsingLease(
        scope: AutomationCredentialScope.Normalized,
        leaseID: UUID
    )
    case deny(String)
}

public enum SSHAgentAutomationAuthorization {
    public static func authorize(
        environment: [String: String],
        keyFolderPath: String?,
        sessionScope: String? = nil,
        ancestryPIDs: [Int32] = [],
        credentialLookup: (UUID) -> AutomationCredentialLookup.Result = { AutomationCredentialLookup.lookup(credentialID: $0) },
        credentialValidation: XPCRequestHandler.AutomationCredentialValidationProvider? = nil,
        grantLeaseLookup: (String?, [Int32], Date) -> [UUID] = {
            SSHAutomationGrantStore.activeLeaseIDs(
                sessionScope: $0,
                ancestryPIDs: $1,
                currentDate: $2
            )
        },
        executionLeaseLookup: (UUID, String?, [Int32], Date) -> AutomationCredentialLookup.Result = {
            SSHAutomationExecutionLeaseAuthority(authorityStore: KeychainAuthorityStore()).lookup(
                leaseID: $0,
                sessionScope: $1,
                ancestryPIDs: $2,
                now: $3
            )
        },
        now: Date = Date(),
        currentMachineId: String? = AutomationCredentialLookup.currentMachineId()
    ) -> SSHAgentAutomationAuthorizationDecision {
        let credential: AutomationCredentialLookup.CredentialRecord
        let lookupResult: AutomationCredentialLookup.Result
        let executionLeaseID: UUID?
        if let token = credentialToken(from: environment) {
            executionLeaseID = nil
            if let credentialValidation {
                lookupResult = credentialValidation(token, .ssh, false)
            } else {
                guard let credentialID = UUID(uuidString: token) else {
                    return .deny("SSH automation credential marker is invalid.")
                }
                lookupResult = credentialLookup(credentialID)
            }
        } else {
            var resolvedLease: (UUID, AutomationCredentialLookup.Result)?
            for leaseID in grantLeaseLookup(sessionScope, ancestryPIDs, now) {
                let result = executionLeaseLookup(
                    leaseID,
                    sessionScope,
                    ancestryPIDs,
                    now
                )
                if case .found = result {
                    resolvedLease = (leaseID, result)
                    break
                }
            }
            guard let resolvedLease else {
                return .notAutomation
            }
            executionLeaseID = resolvedLease.0
            lookupResult = resolvedLease.1
        }
        switch lookupResult {
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
        guard credential.allowedCommands == [.ssh] else {
            return .deny("SSH automation requires a separate SSH-only credential.")
        }
        guard let scope = AutomationCredentialScope.normalizeStored(credential.scope) else {
            return .deny("Automation credential scope is invalid.")
        }
        let scopeName = AutomationCredentialScope.displayName(scope)
        guard AutomationCredentialScope.contains(itemFolderPath: keyFolderPath, normalizedScope: scope) else {
            return .deny("Automation credential scope '\(scopeName)' does not allow access to this SSH key.")
        }

        if let executionLeaseID {
            return .allowWithoutApprovalUsingLease(
                scope: scope,
                leaseID: executionLeaseID
            )
        }
        return .allowWithoutApproval(scope: scope)
    }

    private static func credentialToken(from environment: [String: String]) -> String? {
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
        return nil
    }
}
#endif
