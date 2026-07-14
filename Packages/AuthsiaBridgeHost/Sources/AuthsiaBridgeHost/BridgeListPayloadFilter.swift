#if os(macOS)
import Foundation
import AuthenticatorBridge

public enum BridgeListPayloadFilter {
    public static func filteredPayload(
        _ payload: BridgeListPayload,
        for request: BridgeRequest,
        callerIsAgentic: Bool,
        activeJITScopes jitScopes: [AgentJITFolderScope],
        automationAuthorization: AutomationAuthorizationDecision,
        automationEnvironmentScope: EnvironmentAccessScope? = nil,
        activeJITGrants: [AgentJITGrant] = []
    ) -> BridgeListPayload {
        if !jitScopes.isEmpty {
            let cliEnabledPayload = cliEnabledItems(in: payload)
            let matches: (String?, [String]) -> Bool = { folderPath, environments in
                if !activeJITGrants.isEmpty {
                    return activeJITGrants.contains {
                        $0.folderScope.matches(itemFolderPath: folderPath)
                            && ($0.environmentScope?.allows(itemEnvironments: environments) ?? true)
                    }
                }
                return jitScopes.contains { $0.matches(itemFolderPath: folderPath) }
            }
            return BridgeListPayload(
                accounts: [],
                passwords: cliEnabledPayload.passwords.filter { matches($0.folderPath, $0.environments) },
                apiKeys: cliEnabledPayload.apiKeys.filter { matches($0.folderPath, $0.environments) },
                certificates: cliEnabledPayload.certificates.filter { matches($0.folderPath, $0.environments) },
                notes: cliEnabledPayload.notes.filter { matches($0.folderPath, $0.environments) },
                sshKeys: cliEnabledPayload.sshKeys.filter { matches($0.folderPath, $0.environments) }
            )
        }

        guard case .allowWithoutApproval(let scope) = automationAuthorization else {
            if request.context.requestedCommand != "list", callerIsAgentic {
                return emptyPayload()
            }
            return payload
        }

        let cliEnabledPayload = cliEnabledItems(in: payload)
        let matches: (String?, [String]) -> Bool = { folderPath, environments in
            AutomationCredentialScope.contains(itemFolderPath: folderPath, normalizedScope: scope) &&
                (automationEnvironmentScope?.allows(itemEnvironments: environments) ?? true)
        }
        return BridgeListPayload(
            accounts: [],
            passwords: cliEnabledPayload.passwords.filter { matches($0.folderPath, $0.environments) },
            apiKeys: cliEnabledPayload.apiKeys.filter { matches($0.folderPath, $0.environments) },
            certificates: cliEnabledPayload.certificates.filter { matches($0.folderPath, $0.environments) },
            notes: cliEnabledPayload.notes.filter { matches($0.folderPath, $0.environments) },
            sshKeys: cliEnabledPayload.sshKeys.filter { matches($0.folderPath, $0.environments) }
        )
    }

    private static func cliEnabledItems(in payload: BridgeListPayload) -> BridgeListPayload {
        BridgeListPayload(
            accounts: [],
            passwords: payload.passwords.filter(\.isCliEnabled),
            apiKeys: payload.apiKeys.filter(\.isCliEnabled),
            certificates: payload.certificates.filter(\.isCliEnabled),
            notes: payload.notes.filter(\.isCliEnabled),
            sshKeys: payload.sshKeys.filter(\.isCliEnabled)
        )
    }

    private static func emptyPayload() -> BridgeListPayload {
        BridgeListPayload(accounts: [], passwords: [], apiKeys: [], certificates: [], notes: [], sshKeys: [])
    }
}
#endif
