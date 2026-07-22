import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge

final class AutomationAuthorizationPolicyTests: XCTestCase {
    func testAutomationAuthorizationAllowsInScopeFolder() {
        let credential = makeCredential(scope: "Team/API")
        let request = makeRequest(type: .getPassword, scope: "Team/API", credentialID: credential.id)

        let decision = AutomationAuthorizationPolicy.authorization(
            for: request,
            itemFolderPath: "Team/API/Prod",
            itemKind: "password",
            credentialLookup: { _ in .found(credential) },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(decision, .allowWithoutApproval(scope: .folder("Team/API")))
    }

    func testAutomationAuthorizationAllowsGlobalScope() {
        let credential = makeCredential(scope: nil)
        let request = makeRequest(type: .getPassword, scope: nil, credentialID: credential.id)

        let decision = AutomationAuthorizationPolicy.authorization(
            for: request,
            itemFolderPath: nil,
            itemKind: "password",
            credentialLookup: { _ in .found(credential) },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(decision, .allowWithoutApproval(scope: .global))
    }

    func testAutomationAuthorizationRestrictsNamedEnvironmentAndAllowsAllEnvironment() {
        let credential = makeCredential(environmentScope: .named("Production"))
        let request = makeRequest(type: .getPassword, scope: "Team/API", credentialID: credential.id)

        let defaultEnvironment = AutomationAuthorizationPolicy.authorization(
            for: request,
            itemFolderPath: "Team/API",
            itemEnvironments: [],
            itemKind: "password",
            credentialLookup: { _ in .found(credential) },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )
        let development = AutomationAuthorizationPolicy.authorization(
            for: request,
            itemFolderPath: "Team/API",
            itemEnvironments: ["Development"],
            itemKind: "password",
            credentialLookup: { _ in .found(credential) },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )
        let allEnvironments = AutomationAuthorizationPolicy.authorization(
            for: request,
            itemFolderPath: "Team/API",
            itemEnvironments: ["All"],
            itemKind: "password",
            credentialLookup: { _ in .found(credential) },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(
            defaultEnvironment,
            .deny("Automation credential environment scope does not allow access to this password.")
        )
        XCTAssertEqual(allEnvironments, .allowWithoutApproval(scope: .folder("Team/API")))
        XCTAssertEqual(
            development,
            .deny("Automation credential environment scope does not allow access to this password.")
        )
    }

    func testAutomationAuthorizationDeniesOutOfScopeFolder() {
        let credential = makeCredential(scope: "Team/API")
        let request = makeRequest(type: .getCertificate, scope: "Team/API", credentialID: credential.id)

        let decision = AutomationAuthorizationPolicy.authorization(
            for: request,
            itemFolderPath: "Team/Other",
            itemKind: "certificate",
            credentialLookup: { _ in .found(credential) },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(
            decision,
            .deny("Automation credential scope 'Team/API' does not allow access to this certificate.")
        )
    }

    func testAutomationAuthorizationDeniesOTPAccess() {
        let credential = makeCredential(scope: "Team/API")
        let request = makeRequest(type: .getOTP, scope: "Team/API", credentialID: credential.id)

        let decision = AutomationAuthorizationPolicy.authorization(
            for: request,
            itemFolderPath: nil,
            itemKind: "otp",
            credentialLookup: { _ in .found(credential) },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(
            decision,
            .deny("Automation credentials do not permit OTP access.")
        )
    }

    func testAutomationAuthorizationIgnoresStandardRequests() {
        let request = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "api-prod",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date())
        )

        let decision = AutomationAuthorizationPolicy.authorization(
            for: request,
            itemFolderPath: "Team/API",
            itemKind: "password"
        )

        XCTAssertEqual(decision, .notAutomation)
    }

    func testAutomationAuthorizationDeniesCapabilityNotInAllowlist() {
        let credentialID = UUID()
        let credential = makeCredential(id: credentialID, allowedCommands: [.exec])
        let request = makeRequest(
            type: .getPassword,
            scope: "Team/API",
            credentialID: credentialID,
            requestedCommand: "get"
        )

        let decision = AutomationAuthorizationPolicy.authorization(
            for: request,
            itemFolderPath: "Team/API/Prod",
            itemKind: "password",
            credentialLookup: { id in
                XCTAssertEqual(id, credentialID)
                return .found(credential)
            },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(decision, .deny("Automation credential does not permit 'get'."))
    }

    func testAutomationAuthorizationAllowsCapabilityInAllowlist() {
        let credential = makeCredential(allowedCommands: [.exec, .get])
        let request = makeRequest(
            type: .getPassword,
            scope: "Team/API",
            credentialID: credential.id,
            requestedCommand: "get"
        )

        let decision = AutomationAuthorizationPolicy.authorization(
            for: request,
            itemFolderPath: "Team/API/Prod",
            itemKind: "password",
            credentialLookup: { _ in .found(credential) },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(decision, .allowWithoutApproval(scope: .folder("Team/API")))
    }

    func testAutomationAuthorizationDeniesUnknownCredential() {
        let request = makeRequest(
            type: .getPassword,
            scope: "Team/API",
            credentialID: UUID(),
            requestedCommand: "get"
        )

        let decision = AutomationAuthorizationPolicy.authorization(
            for: request,
            itemFolderPath: "Team/API",
            itemKind: "password",
            credentialLookup: { _ in .credentialNotFound }
        )

        XCTAssertEqual(decision, .deny("Automation credential not found in local store."))
    }

    func testAutomationAuthorizationDeniesMissingRequestedCommand() {
        let credential = makeCredential(allowedCommands: [.exec, .get])
        let request = makeRequest(
            type: .getPassword,
            scope: "Team/API",
            credentialID: credential.id,
            requestedCommand: nil
        )

        let decision = AutomationAuthorizationPolicy.authorization(
            for: request,
            itemFolderPath: "Team/API",
            itemKind: "password",
            credentialLookup: { _ in .found(credential) },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(decision, .deny("Automation request is missing 'requestedCommand'. Upgrade the CLI."))
    }

    func testAutomationAuthorizationDeniesWhenCredentialsFileMissing() {
        let request = makeRequest(
            type: .getPassword,
            scope: "Team/API",
            credentialID: UUID(),
            requestedCommand: "get"
        )

        let decision = AutomationAuthorizationPolicy.authorization(
            for: request,
            itemFolderPath: "Team/API/Prod",
            itemKind: "password",
            credentialLookup: { _ in .fileMissing }
        )

        XCTAssertEqual(decision, .deny("Automation credential store is missing or unreadable. Recreate the credential."))
    }

    func testAutomationAuthorizationUsesStoredScopeInsteadOfCallerScope() {
        let credential = makeCredential(scope: "Team/API")
        let request = makeRequest(
            type: .getPassword,
            scope: "Team",
            credentialID: credential.id,
            requestedCommand: "get"
        )

        let decision = AutomationAuthorizationPolicy.authorization(
            for: request,
            itemFolderPath: "Team/Other",
            itemKind: "password",
            credentialLookup: { _ in .found(credential) },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(
            decision,
            .deny("Automation credential scope 'Team/API' does not allow access to this password.")
        )
    }

    func testAutomationAuthorizationDeniesExpiredCredential() {
        let credential = makeCredential(expiresAt: Date(timeIntervalSince1970: 1_700_000_050))
        let request = makeRequest(type: .getPassword, scope: "Team/API", credentialID: credential.id)

        let decision = AutomationAuthorizationPolicy.authorization(
            for: request,
            itemFolderPath: "Team/API",
            itemKind: "password",
            credentialLookup: { _ in .found(credential) },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(decision, .deny("Automation credential is expired."))
    }

    func testAutomationAuthorizationDeniesMachineMismatch() {
        let credential = makeCredential(machineId: "machine-2")
        let request = makeRequest(type: .getPassword, scope: "Team/API", credentialID: credential.id)

        let decision = AutomationAuthorizationPolicy.authorization(
            for: request,
            itemFolderPath: "Team/API",
            itemKind: "password",
            credentialLookup: { _ in .found(credential) },
            now: Date(timeIntervalSince1970: 1_700_000_100),
            currentMachineId: "machine-1"
        )

        XCTAssertEqual(decision, .deny("Automation credential is not valid for this machine."))
    }

    // MARK: - Export deny

    func testIsAutomationExportDeniedWhenCredentialPresent() {
        // Any automation credential — even one carrying `exec` capability with a
        // valid session — must be denied for exportAccounts. Bulk 2FA export is
        // interactive-only.
        let request = makeRequest(
            type: .exportAccounts,
            scope: "Team/API",
            credentialID: UUID(),
            requestedCommand: "exec"
        )

        XCTAssertTrue(AutomationAuthorizationPolicy.isExportDenied(for: request))
    }

    func testIsAutomationExportDeniedIgnoresStandardRequests() {
        // Non-automation requests (no credential ID) must flow through normal
        // biometric / session validation, not hit the automation deny.
        let request = BridgeRequest(
            id: UUID(),
            type: .exportAccounts,
            query: "",
            options: .init(field: nil, copy: false),
            context: .init(isTTY: true, isPiped: false, isSSH: false, isCI: false, timestamp: Date())
        )

        XCTAssertFalse(AutomationAuthorizationPolicy.isExportDenied(for: request))
    }

    private func makeRequest(
        type: BridgeRequestType,
        scope: String?,
        credentialID: UUID = UUID(),
        requestedCommand: String? = "get"
    ) -> BridgeRequest {
        BridgeRequest(
            id: UUID(),
            type: type,
            query: "item",
            options: .init(field: nil, copy: false),
            context: .init(
                isTTY: true,
                isPiped: false,
                isSSH: false,
                isCI: false,
                timestamp: Date(),
                automationCredentialID: credentialID.uuidString,
                automationScope: scope,
                requestedCommand: requestedCommand
            )
        )
    }

    private func makeCredential(
        id: UUID = UUID(),
        scope: String? = "Team/API",
        expiresAt: Date = Date(timeIntervalSince1970: 1_800_000_000),
        revokedAt: Date? = nil,
        machineId: String = "machine-1",
        allowedCommands: Set<CapabilityCommand> = [.exec, .get],
        environmentScope: EnvironmentAccessScope? = nil
    ) -> AutomationCredentialLookup.CredentialRecord {
        AutomationCredentialLookup.CredentialRecord(
            id: id,
            scope: scope,
            expiresAt: expiresAt,
            revokedAt: revokedAt,
            machineId: machineId,
            allowedCommands: allowedCommands,
            environmentScope: environmentScope
        )
    }
}
