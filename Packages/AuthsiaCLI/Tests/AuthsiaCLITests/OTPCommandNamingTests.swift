import ArgumentParser
import Foundation
import Testing
import AuthenticatorBridge
@testable import authsia

@Suite("OTP command naming")
struct OTPCommandNamingTests {
    @Test("list uses otp as the canonical scope")
    func listUsesOTPCanonicalScope() throws {
        let command = try List.parse(["otp"])

        #expect(command.scope.rawValue == "otp")
        #expect(List.Scope.allValueStrings.contains("otp"))
        #expect(!List.Scope.allValueStrings.contains("accounts"))
    }

    @Test("list rejects account terminology for OTP")
    func listRejectsAccountTerminologyForOTP() {
        #expect(throws: (any Error).self) {
            _ = try List.parse(["accounts"])
        }
    }

    @Test("list table labels OTP item label as label")
    func listTableLabelsOTPItemLabelAsLabel() throws {
        let otpItem = BridgeAccount(
            id: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
            issuer: "GitHub",
            label: "alice@example.com",
            isFavorite: true,
            isCliEnabled: true,
            isScraped: false,
            createdAt: Date(timeIntervalSince1970: 0),
            updatedAt: Date(timeIntervalSince1970: 0)
        )

        let output = TableFormatter.formatOTPItems([otpItem])

        #expect(output.contains("Label"))
        #expect(!output.contains("Account"))
    }

    @Test("top-level export command is not available")
    func topLevelExportCommandIsNotAvailable() {
        #expect(throws: (any Error).self) {
            _ = try Authsia.parseAsRoot(["export", "otp", "--output", "backup.json"])
        }
    }

    @Test("top-level integration command is not available")
    func topLevelIntegrationCommandIsNotAvailable() {
        #expect(throws: (any Error).self) {
            _ = try Authsia.parseAsRoot(["integration", "list"])
        }
    }
}
