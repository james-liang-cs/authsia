#if os(macOS)
import Foundation
import AuthenticatorBridge

public enum AutomationAuthorizationDecision: Equatable {
    case notAutomation
    case allowWithoutApproval(scope: AutomationCredentialScope.Normalized)
    case deny(String)
}

public enum AutomationAuthorizationPolicy {
    public static func isExportDenied(for request: BridgeRequest) -> Bool {
        request.context.automationCredentialID != nil
    }

    public static func authorization(
        for request: BridgeRequest,
        itemFolderPath: String?,
        itemEnvironments: [String] = [],
        itemKind: String,
        credentialLookup: (UUID) -> AutomationCredentialLookup.Result = { AutomationCredentialLookup.lookup(credentialID: $0) },
        now: Date = Date(),
        currentMachineId: String? = AutomationCredentialLookup.currentMachineId()
    ) -> AutomationAuthorizationDecision {
        guard request.context.automationCredentialID != nil else {
            return .notAutomation
        }

        if request.type == .getOTP {
            return .deny("Automation credentials do not permit OTP access.")
        }

        let credential: AutomationCredentialLookup.CredentialRecord
        do {
            credential = try authorizedAutomationCredential(
                for: request,
                credentialLookup: credentialLookup,
                now: now,
                currentMachineId: currentMachineId
            )
        } catch let error as AuthorizationError {
            return .deny(error.message)
        } catch {
            return .deny("Automation credential could not be validated.")
        }

        guard let scope = AutomationCredentialScope.normalizeStored(credential.scope) else {
            return .deny("Automation credential scope is invalid.")
        }

        if request.type == .list {
            return .allowWithoutApproval(scope: scope)
        }

        let scopeName = AutomationCredentialScope.displayName(scope)
        guard AutomationCredentialScope.contains(itemFolderPath: itemFolderPath, normalizedScope: scope) else {
            return .deny("Automation credential scope '\(scopeName)' does not allow access to this \(itemKind).")
        }

        if let environmentScope = credential.environmentScope,
           !environmentScope.allows(itemEnvironments: itemEnvironments) {
            return .deny("Automation credential environment scope does not allow access to this \(itemKind).")
        }

        return .allowWithoutApproval(scope: scope)
    }

    public static func environmentScope(
        for request: BridgeRequest,
        credentialLookup: (UUID) -> AutomationCredentialLookup.Result
    ) -> EnvironmentAccessScope? {
        guard let rawID = request.context.automationCredentialID,
              let credentialID = UUID(uuidString: rawID),
              case .found(let credential) = credentialLookup(credentialID) else { return nil }
        return credential.environmentScope
    }

    private struct AuthorizationError: Error {
        let message: String
    }

    private static func authorizedAutomationCredential(
        for request: BridgeRequest,
        credentialLookup: (UUID) -> AutomationCredentialLookup.Result,
        now: Date,
        currentMachineId: String?
    ) throws -> AutomationCredentialLookup.CredentialRecord {
        guard let rawID = request.context.automationCredentialID,
              let credentialID = UUID(uuidString: rawID) else {
            throw AuthorizationError(message: "Automation request is missing a valid credential ID.")
        }

        guard let rawCommand = request.context.requestedCommand else {
            throw AuthorizationError(message: "Automation request is missing 'requestedCommand'. Upgrade the CLI.")
        }
        guard let command = CapabilityCommand(rawValue: rawCommand) else {
            throw AuthorizationError(message: "Automation request has unknown 'requestedCommand' '\(rawCommand)'.")
        }

        switch credentialLookup(credentialID) {
        case .fileMissing:
            throw AuthorizationError(
                message: "Automation credential store is missing or unreadable. Recreate the credential."
            )
        case .credentialNotFound:
            throw AuthorizationError(message: "Automation credential not found in local store.")
        case .corruptedStore:
            throw AuthorizationError(message: "Automation credential store is corrupted. Recreate the credential.")
        case .found(let credential):
            switch credential.status(asOf: now) {
            case .active:
                break
            case .expired:
                throw AuthorizationError(message: "Automation credential is expired.")
            case .revoked:
                throw AuthorizationError(message: "Automation credential is revoked.")
            }

            guard let currentMachineId, credential.machineId == currentMachineId else {
                throw AuthorizationError(message: "Automation credential is not valid for this machine.")
            }
            guard credential.allowedCommands.contains(command) else {
                throw AuthorizationError(
                    message: "Automation credential does not permit '\(command.rawValue)'."
                )
            }
            return credential
        }
    }
}
#endif
