import AuthenticatorBridge
import Foundation
import Testing
@testable import authsia

@Suite("Vault item environment query resolver")
struct VaultItemQueryResolverTests {
    private let developmentID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
    private let productionID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!

    @Test("plain duplicate name is ambiguous and environment selects exact tag")
    func environmentDisambiguatesDuplicateNames() throws {
        let payload = makePayload()

        #expect(throws: CLIError.self) {
            try VaultItemQueryResolver.resolve(
                type: .apiKey,
                query: "DATABASE_URL",
                environment: nil,
                payload: payload
            )
        }
        let selected = try VaultItemQueryResolver.resolve(
            type: .apiKey,
            query: "DATABASE_URL",
            environment: " production ",
            payload: payload
        )

        #expect(selected == productionID)
    }

    @Test("UUID remains unambiguous without environment")
    func uuidRemainsUnambiguousWithoutEnvironment() throws {
        let selected = try VaultItemQueryResolver.resolve(
            type: .apiKey,
            query: developmentID.uuidString,
            environment: nil,
            payload: makePayload()
        )

        #expect(selected == developmentID)
    }

    @Test("environment falls back to All item and exact same-name item overrides it")
    func environmentUsesAllFallbackWithExactOverride() throws {
        let allFallbackID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
        let allOverrideID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!
        let timestamp = Date(timeIntervalSince1970: 0)
        let basePayload = makePayload()
        let allFallback = BridgeAPIKey(
            id: allFallbackID,
            name: "ALL_ENVIRONMENTS",
            website: nil,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            createdAt: timestamp,
            updatedAt: timestamp,
            environments: ["All"]
        )
        let allOverride = BridgeAPIKey(
            id: allOverrideID,
            name: "DATABASE_URL",
            website: nil,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            createdAt: timestamp,
            updatedAt: timestamp,
            environments: ["All"]
        )
        let payload = BridgeListPayload(
            accounts: basePayload.accounts,
            passwords: basePayload.passwords,
            apiKeys: basePayload.apiKeys + [allFallback, allOverride],
            certificates: basePayload.certificates,
            notes: basePayload.notes,
            sshKeys: basePayload.sshKeys
        )

        let fallback = try VaultItemQueryResolver.resolve(
            type: .apiKey,
            query: "ALL_ENVIRONMENTS",
            environment: "Production",
            payload: payload
        )
        let overridden = try VaultItemQueryResolver.resolve(
            type: .apiKey,
            query: "DATABASE_URL",
            environment: "Production",
            payload: payload
        )

        #expect(fallback == allFallbackID)
        #expect(overridden == productionID)
    }

    private func makePayload() -> BridgeListPayload {
        let timestamp = Date(timeIntervalSince1970: 0)
        return BridgeListPayload(
            accounts: [],
            passwords: [],
            apiKeys: [
                BridgeAPIKey(
                    id: developmentID,
                    name: "DATABASE_URL",
                    website: nil,
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: timestamp,
                    updatedAt: timestamp,
                    environments: ["Development"]
                ),
                BridgeAPIKey(
                    id: productionID,
                    name: "DATABASE_URL",
                    website: nil,
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: timestamp,
                    updatedAt: timestamp,
                    environments: ["Production"]
                ),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )
    }
}
