import Foundation
import Testing
import AuthenticatorBridge
@testable import authsia

@Suite("List JSON formatter")
struct ListJSONFormatterTests {
    @Test("password JSON includes expiresAt")
    func passwordJSONIncludesExpiresAt() throws {
        let passwordExpiresAt = Date(timeIntervalSince1970: 1_800_000_000)

        let passwordOutput = try OutputFormatter.formatPasswords([
            BridgePassword(
                id: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
                name: "API_KEY",
                username: "API_KEY",
                website: nil,
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 1_700_000_000),
                updatedAt: Date(timeIntervalSince1970: 1_700_000_001),
                expiresAt: passwordExpiresAt
            ),
        ], format: .json)

        #expect(try expiresAtString(in: passwordOutput) == "2027-01-15T08:00:00Z")
    }

    @Test("api key JSON omits username and includes expiry and environments")
    func apiKeyJSONOmitsUsernameAndIncludesExpiryAndEnvironments() throws {
        let output = try OutputFormatter.formatAPIKeys([
            BridgeAPIKey(
                id: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
                name: "Stripe",
                website: "https://dashboard.stripe.com",
                folderPath: "Team/API",
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 1_700_000_000),
                updatedAt: Date(timeIntervalSince1970: 1_700_000_001),
                expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
                environments: ["Production"]
            ),
        ], format: .json)

        let data = Data(output.utf8)
        let object = try JSONSerialization.jsonObject(with: data)
        let items = try #require(object as? [[String: Any]])
        let first = try #require(items.first)

        #expect(first["name"] as? String == "Stripe")
        #expect(first["username"] == nil)
        #expect(first["expiresAt"] as? String == "2027-01-15T08:00:00Z")
        #expect(first["environments"] as? [String] == ["Production"])
    }

    private func expiresAtString(in output: String) throws -> String? {
        let data = Data(output.utf8)
        let object = try JSONSerialization.jsonObject(with: data)
        let items = try #require(object as? [[String: Any]])
        return items.first?["expiresAt"] as? String
    }
}
