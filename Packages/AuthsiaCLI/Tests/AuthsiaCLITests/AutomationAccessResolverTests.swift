import Testing
import Foundation
import AuthenticatorBridge
@testable import authsia

@Suite("Automation access resolver")
struct AutomationAccessResolverTests {

    @Test("resolveActiveCredential returns nil when environment is unset")
    func resolveActiveCredentialReturnsNil() throws {
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "automation-access")
        defer { try? FileManager.default.removeItem(at: directory) }

        let credential = try AutomationAccessResolver.resolveActiveCredential(
            environment: [:],
            store: store,
            now: Date(timeIntervalSince1970: 1_700_000_000)
        )

        #expect(credential == nil)
    }

    @Test("resolveActiveCredential loads active credential from environment")
    func resolveActiveCredentialLoadsCredential() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let machine = MachineIdentity(machineId: "machine-123", hostname: "Example-MacBook.local")
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "automation-access")
        defer { try? FileManager.default.removeItem(at: directory) }

        let created = try Access.createCredential(
            name: "Claude",
            scope: "Team/API",
            ttl: "15m",
            store: store,
            machineIdentity: machine,
            now: now
        )
        let token = try AutomationCredentialToken.issue(
            id: created.id,
            randomBytes: Data(repeating: 0x41, count: AutomationCredentialToken.randomByteCount)
        )

        let credential = try AutomationAccessResolver.resolveActiveCredential(
            environment: [AutomationAccessResolver.environmentKey: token],
            store: store,
            now: now.addingTimeInterval(60)
        )

        #expect(credential?.id == created.id)
        #expect(credential?.scope == "Team/API")
        #expect(credential?.bearerToken == token)
    }

    @Test("resolver errors never echo an expired bearer token")
    func resolverErrorsNeverEchoExpiredBearerToken() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "automation-access")
        defer { try? FileManager.default.removeItem(at: directory) }
        let credential = AccessCredential(
            id: UUID(),
            name: "expired-ci",
            scope: "Team/API",
            createdAt: now.addingTimeInterval(-120),
            expiresAt: now.addingTimeInterval(-60),
            revokedAt: nil,
            machineId: "m",
            machineName: "h"
        )
        try store.save(credential)
        let token = AccessCredentialStoreFixture.token(for: credential)

        do {
            _ = try AutomationAccessResolver.resolveActiveCredential(
                environment: [AutomationAccessResolver.environmentKey: token],
                store: store,
                now: now
            )
            Issue.record("Expected expired credential to fail")
        } catch {
            let description = String(describing: error)
            #expect(!description.contains(token))
            #expect(description.contains(credential.id.uuidString))
        }
    }

    @Test("validateScopeSelection rejects global scope for automation credentials")
    func validateScopeSelectionRejectsGlobal() {
        #expect(throws: (any Error).self) {
            try AutomationAccessResolver.validateScopeSelection(
                .global,
                allowedScope: "Team/API"
            )
        }
    }

    @Test("validateScopeSelection allows all selections for global automation credentials")
    func validateScopeSelectionAllowsAllForGlobalCredential() throws {
        try AutomationAccessResolver.validateScopeSelection(
            .global,
            allowedScope: nil
        )
        try AutomationAccessResolver.validateScopeSelection(
            .folder("Team/API"),
            allowedScope: nil
        )
    }

    @Test("validateScopeSelection allows child folders inside the allowed scope")
    func validateScopeSelectionAllowsNestedFolder() throws {
        try AutomationAccessResolver.validateScopeSelection(
            .folder("Team/API/Prod"),
            allowedScope: "Team/API"
        )
    }

    @Test("validateScopeSelection allows multi-folder env inside the allowed scope")
    func validateScopeSelectionAllowsMultiFolderInsideScope() throws {
        try AutomationAccessResolver.validateScopeSelection(
            .folders(["Team/API/Prod", "Team/API/Web"]),
            allowedScope: "Team/API"
        )
    }

    @Test("validateScopeSelection rejects multi-folder env outside the allowed scope")
    func validateScopeSelectionRejectsMultiFolderOutsideScope() {
        #expect(throws: (any Error).self) {
            try AutomationAccessResolver.validateScopeSelection(
                .folders(["Team/API", "Team/Other"]),
                allowedScope: "Team/API"
            )
        }
    }

    @Test("filterPayload removes out-of-scope items and hides otp items")
    func filterPayloadRemovesOutOfScopeItems() {
        let payload = BridgeListPayload(
            accounts: [
                BridgeAccount(
                    id: UUID(),
                    issuer: "GitHub",
                    label: "me",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: Date(),
                    updatedAt: Date()
                )
            ],
            passwords: [
                BridgePassword(
                    id: UUID(),
                    name: "InScope",
                    username: "u",
                    website: nil,
                    folderPath: "Team/API",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: Date(),
                    updatedAt: Date()
                ),
                BridgePassword(
                    id: UUID(),
                    name: "OutOfScope",
                    username: "u",
                    website: nil,
                    folderPath: "Team/Other",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: Date(),
                    updatedAt: Date()
                )
            ],
            apiKeys: [
                BridgeAPIKey(
                    id: UUID(),
                    name: "Stripe",
                    website: nil,
                    folderPath: "Team/API",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: Date(),
                    updatedAt: Date()
                ),
                BridgeAPIKey(
                    id: UUID(),
                    name: "GitHub",
                    website: nil,
                    folderPath: "Team/Other",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: Date(),
                    updatedAt: Date()
                ),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let filtered = AutomationAccessResolver.filterPayload(payload, allowedScope: "Team/API")

        #expect(filtered.accounts.isEmpty)
        #expect(filtered.passwords.count == 1)
        #expect(filtered.passwords.first?.name == "InScope")
        #expect(filtered.apiKeys.map(\.name) == ["Stripe"])
    }

    @Test("filterPayload allows all non-OTP items for global automation scope")
    func filterPayloadAllowsAllForGlobalScope() {
        let payload = BridgeListPayload(
            accounts: [
                BridgeAccount(
                    id: UUID(),
                    issuer: "GitHub",
                    label: "me",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: Date(),
                    updatedAt: Date()
                )
            ],
            passwords: [
                BridgePassword(
                    id: UUID(),
                    name: "Root",
                    username: "u",
                    website: nil,
                    folderPath: nil,
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: Date(),
                    updatedAt: Date()
                ),
                BridgePassword(
                    id: UUID(),
                    name: "Nested",
                    username: "u",
                    website: nil,
                    folderPath: "Team/API",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: Date(),
                    updatedAt: Date()
                )
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let filtered = AutomationAccessResolver.filterPayload(payload, allowedScope: nil)

        #expect(filtered.accounts.isEmpty)
        #expect(filtered.passwords.map(\.name) == ["Root", "Nested"])
    }

    @Test("environment filtering prefers exact or Default over All with the same name")
    func environmentFilteringAppliesAllFallbackPrecedence() {
        let timestamp = Date(timeIntervalSince1970: 0)
        func apiKey(_ id: String, name: String, environments: [String]) -> BridgeAPIKey {
            BridgeAPIKey(
                id: UUID(uuidString: id)!,
                name: name,
                website: nil,
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: timestamp,
                updatedAt: timestamp,
                environments: environments
            )
        }
        let defaultItem = apiKey(
            "11111111-1111-1111-1111-111111111111",
            name: "DATABASE_URL",
            environments: []
        )
        let allItem = apiKey(
            "22222222-2222-2222-2222-222222222222",
            name: "DATABASE_URL",
            environments: ["All"]
        )
        let productionItem = apiKey(
            "33333333-3333-3333-3333-333333333333",
            name: "DATABASE_URL",
            environments: ["Production"]
        )
        let allOnlyItem = apiKey(
            "44444444-4444-4444-4444-444444444444",
            name: "SHARED_TOKEN",
            environments: ["All"]
        )
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [],
            apiKeys: [defaultItem, allItem, productionItem, allOnlyItem],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let production = AutomationAccessResolver.filterPayload(
            payload,
            allowedScope: nil,
            environmentScope: .named("Production")
        )
        let `default` = AutomationAccessResolver.filterPayload(
            payload,
            allowedScope: nil,
            environmentScope: .defaultOnly
        )

        #expect(production.apiKeys.map(\.id) == [productionItem.id, allOnlyItem.id])
        #expect(`default`.apiKeys.map(\.id) == [defaultItem.id, allOnlyItem.id])
    }

    @Test("filterPayload treats star as a literal folder scope")
    func filterPayloadTreatsStarAsLiteralFolderScope() {
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                BridgePassword(
                    id: UUID(),
                    name: "Star",
                    username: "u",
                    website: nil,
                    folderPath: "*",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: Date(),
                    updatedAt: Date()
                ),
                BridgePassword(
                    id: UUID(),
                    name: "Nested",
                    username: "u",
                    website: nil,
                    folderPath: "Team/API",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: Date(),
                    updatedAt: Date()
                )
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let filtered = AutomationAccessResolver.filterPayload(payload, allowedScope: "*")

        #expect(filtered.passwords.map(\.name) == ["Star"])
    }

    @Test("authorizeGetType rejects otp under automation credentials")
    func authorizeGetTypeRejectsOTP() {
        #expect(throws: (any Error).self) {
            try AutomationAccessResolver.authorizeGetType(.otp)
        }
    }

    @Test("authorizeCommand allows commands in allowedCommands")
    func authorizeCommandAllowsWhenPermitted() throws {
        let credential = AccessCredential(
            id: UUID(),
            name: "c",
            scope: "Team/API",
            createdAt: Date(),
            expiresAt: Date().addingTimeInterval(600),
            revokedAt: nil,
            machineId: "m",
            machineName: "h",
            allowedCommands: [.exec, .load]
        )
        try AutomationAccessResolver.authorizeCommand(.exec, credential: credential)
        try AutomationAccessResolver.authorizeCommand(.load, credential: credential)
    }

    @Test("authorizeCommand rejects commands not in allowedCommands")
    func authorizeCommandRejectsWhenMissing() {
        let credential = AccessCredential(
            id: UUID(),
            name: "exec-only",
            scope: "Team/API",
            createdAt: Date(),
            expiresAt: Date().addingTimeInterval(600),
            revokedAt: nil,
            machineId: "m",
            machineName: "h",
            allowedCommands: [.exec]
        )
        #expect(throws: (any Error).self) {
            try AutomationAccessResolver.authorizeCommand(.get, credential: credential)
        }
        #expect(throws: (any Error).self) {
            try AutomationAccessResolver.authorizeCommand(.load, credential: credential)
        }
        #expect(throws: (any Error).self) {
            try AutomationAccessResolver.authorizeCommand(.read, credential: credential)
        }
    }

    @Test("bridgeContext includes requestedCommand when provided")
    func bridgeContextIncludesRequestedCommand() throws {
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "automation-access")
        defer { try? FileManager.default.removeItem(at: directory) }
        let ctx = AutomationAccessResolver.bridgeContext(
            requestedCommand: .exec,
            environment: [:],
            store: store,
            now: Date()
        )
        #expect(ctx.requestedCommand == "exec")
    }

    @Test("bridgeContext includes current directory when provided")
    func bridgeContextIncludesCurrentDirectory() throws {
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "automation-access")
        defer { try? FileManager.default.removeItem(at: directory) }
        let ctx = AutomationAccessResolver.bridgeContext(
            requestedCommand: .exec,
            environment: [:],
            store: store,
            now: Date(),
            currentDirectoryPath: "/Users/example/project"
        )
        #expect(ctx.workingDirectory == "/Users/example/project")
    }

    @Test("bridgeContext omits requestedCommand by default")
    func bridgeContextOmitsWhenUnset() throws {
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "automation-access")
        defer { try? FileManager.default.removeItem(at: directory) }
        let ctx = AutomationAccessResolver.bridgeContext(
            environment: [:],
            store: store,
            now: Date()
        )
        #expect(ctx.requestedCommand == nil)
    }

    @Test("bridgeContext does not warn for revoked ambient credentials")
    func bridgeContextDoesNotWarnForRevokedAmbientCredential() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "automation-access")
        defer { try? FileManager.default.removeItem(at: directory) }

        let created = try Access.createCredential(
            name: "release",
            scope: "Authsia",
            ttl: "15m",
            store: store,
            machineIdentity: MachineIdentity(machineId: "machine-123", hostname: "release-mac.local"),
            now: now,
            allowedCommands: [.exec]
        )
        _ = try Access.revokeCredential(id: created.id, store: store, now: now.addingTimeInterval(60))

        var warnings: [String] = []
        let ctx = AutomationAccessResolver.bridgeContext(
            requestedCommand: .exec,
            environment: [AutomationAccessResolver.environmentKey: created.id.uuidString],
            store: store,
            now: now.addingTimeInterval(120),
            warningHandler: { warnings.append($0) }
        )

        #expect(ctx.automationCredentialID == nil)
        #expect(warnings.isEmpty)
    }
}
