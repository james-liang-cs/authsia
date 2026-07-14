import Testing
import Foundation
import AuthenticatorBridge
@testable import authsia

@Suite("Bridge client error messaging")
struct BridgeClientErrorTests {
    @Test("policy denied surfaces server message when available")
    func policyDeniedSurfacesServerMessage() {
        let error = BridgeClientError.bridgeError(
            code: "policyDenied",
            message: "Automation credential scope 'Team/API' does not allow access to this password.",
            query: nil
        )

        #expect(
            error.errorDescription == "Automation credential scope 'Team/API' does not allow access to this password."
        )
    }

    @Test("global CLI disabled policy includes settings guidance")
    func globalCLIDisabledPolicyIncludesSettingsGuidance() {
        let error = BridgeClientError.bridgeError(
            code: "policyDenied",
            message: "CLI access is disabled",
            query: nil
        )

        #expect(error.errorDescription?.contains("Enable CLI Access") == true)
        #expect(error.errorDescription?.contains("Settings") == true)
    }

    @Test("invalid request surfaces bridge detail when available")
    func invalidRequestSurfacesBridgeDetail() {
        let error = BridgeClientError.bridgeError(
            code: "invalidRequest",
            message: "Failed to add password: The operation couldn’t be completed.",
            query: nil
        )

        #expect(error.errorDescription == "Failed to add password: The operation couldn’t be completed.")
    }

    @Test("secret retrieval not found surfaces bridge detail")
    func secretRetrievalNotFoundSurfacesBridgeDetail() {
        let message = "Failed to retrieve password: Keychain item not found"
        let error = BridgeClientError.bridgeError(
            code: "notFound",
            message: message,
            query: UUID().uuidString
        )

        #expect(error.errorDescription == message)
    }

    @Test("app unavailable surfaces bridge detail when available")
    func appUnavailableSurfacesBridgeDetail() {
        let message = "Authsia helper is not authorized to read the keychain on this Mac."
        let error = BridgeClientError.bridgeError(
            code: "appUnavailable",
            message: message,
            query: nil
        )

        #expect(error.errorDescription == message)
    }

    @Test("connection failure mentions app and global CLI access")
    func connectionFailureMentionsAppAndGlobalCLIAccess() {
        let error = BridgeClientError.connectionFailed

        #expect(error.errorDescription?.contains("Authsia app") == true)
        #expect(error.errorDescription?.contains("CLI Access") == true)
    }

    @Test("approval denial is detected for notAuthorized and policyDenied codes")
    func approvalDenialDetectedForDenialCodes() {
        #expect(BridgeClientError.isApprovalDenied(
            BridgeClientError.bridgeError(code: "notAuthorized", message: "Access denied", query: nil)
        ))
        #expect(BridgeClientError.isApprovalDenied(
            BridgeClientError.bridgeError(code: "policyDenied", message: "CLI access is disabled", query: nil)
        ))
    }

    @Test("approval denial is not reported for unavailable, not-found, or transport errors")
    func approvalDenialNotReportedForNonDenialErrors() {
        #expect(!BridgeClientError.isApprovalDenied(
            BridgeClientError.bridgeError(code: "appUnavailable", message: "locked", query: nil)
        ))
        #expect(!BridgeClientError.isApprovalDenied(
            BridgeClientError.bridgeError(code: "notFound", message: "missing", query: nil)
        ))
        #expect(!BridgeClientError.isApprovalDenied(BridgeClientError.connectionFailed))
        #expect(!BridgeClientError.isApprovalDenied(BridgeClientError.timeout))
        #expect(!BridgeClientError.isApprovalDenied(BridgeClientError.appUnavailable))
    }

    @Test("bridge recovery retries a recoverable first failure")
    func bridgeRecoveryRetriesRecoverableFirstFailure() throws {
        var attempts = 0
        var recoveries = 0

        let result: String = try AuthsiaBridgeClient.withBridgeRecovery(
            retryDelays: [0.0, 0.0],
            sleep: { _ in },
            recover: {
                recoveries += 1
                return true
            },
            operation: {
                attempts += 1
                if attempts == 1 {
                    throw BridgeClientError.connectionFailed
                }
                return "connected"
            },
            logFinalFailure: { _, _ in }
        )

        #expect(result == "connected")
        #expect(attempts == 2)
        #expect(recoveries == 1)
    }

    @Test("approval prompt is shown for direct CLI secret requests")
    func approvalPromptShownForDirectCLISecretRequests() {
        let message = AuthsiaBridgeClient.approvalPromptMessage(
            for: .getPassword,
            context: Self.context(),
            hasSessionToken: false,
            stderrIsTTY: true,
            hasAlreadyShown: false
        )

        #expect(message?.contains("Waiting for Authsia Direct CLI approval") == true)
        #expect(message?.contains("CLI Access") == true)
    }

    @Test("approval prompt is shown for direct list requests")
    func approvalPromptShownForDirectListRequests() {
        let message = AuthsiaBridgeClient.approvalPromptMessage(
            for: .list,
            context: Self.context(requestedCommand: "list"),
            hasSessionToken: false,
            stderrIsTTY: true,
            hasAlreadyShown: false
        )

        #expect(message?.contains("Waiting for Authsia Direct CLI approval") == true)
        #expect(message?.contains("CLI Access") == true)
    }

    @Test("approval prompt identifies agent JIT requests")
    func approvalPromptIdentifiesAgentJITRequests() {
        let message = AuthsiaBridgeClient.approvalPromptMessage(
            for: .agentJITPreflight,
            context: Self.context(requestedCommand: "list"),
            hasSessionToken: false,
            stderrIsTTY: true,
            hasAlreadyShown: false
        )

        #expect(message?.contains("Waiting for Authsia Agent JIT approval") == true)
        #expect(message?.contains("temporary scoped grant") == true)
    }

    @Test("approval prompt is skipped for internal exec list requests")
    func approvalPromptSkippedForInternalExecListRequests() {
        let message = AuthsiaBridgeClient.approvalPromptMessage(
            for: .list,
            context: Self.context(requestedCommand: "exec"),
            hasSessionToken: false,
            stderrIsTTY: true,
            hasAlreadyShown: false
        )

        #expect(message == nil)
    }

    @Test("approval prompt is skipped for automation credentials")
    func approvalPromptSkippedForAutomationCredentials() {
        let message = AuthsiaBridgeClient.approvalPromptMessage(
            for: .getPassword,
            context: Self.context(automationCredentialID: UUID().uuidString),
            hasSessionToken: false,
            stderrIsTTY: true,
            hasAlreadyShown: false
        )

        #expect(message == nil)
    }

    @Test("approval prompt identifies access credential creation")
    func approvalPromptIdentifiesAccessCredentialCreation() {
        let message = AuthsiaBridgeClient.approvalPromptMessage(
            for: .createAccess,
            context: Self.context(automationCredentialID: UUID().uuidString),
            hasSessionToken: false,
            stderrIsTTY: true,
            hasAlreadyShown: false
        )

        #expect(message?.contains("Waiting for Authsia Access Credential approval") == true)
        #expect(message?.contains("scoped access credential") == true)
    }

    @Test("approval prompt is skipped for active sessions")
    func approvalPromptSkippedForActiveSessions() {
        let message = AuthsiaBridgeClient.approvalPromptMessage(
            for: .getPassword,
            context: Self.context(),
            hasSessionToken: true,
            stderrIsTTY: true,
            hasAlreadyShown: false
        )

        #expect(message == nil)
    }

    private static func context(
        isCI: Bool = false,
        automationCredentialID: String? = nil,
        requestedCommand: String = "read"
    ) -> BridgeContext {
        BridgeContext(
            isTTY: true,
            isPiped: false,
            isSSH: false,
            isCI: isCI,
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            automationCredentialID: automationCredentialID,
            automationScope: nil,
            requestedCommand: requestedCommand
        )
    }
}
