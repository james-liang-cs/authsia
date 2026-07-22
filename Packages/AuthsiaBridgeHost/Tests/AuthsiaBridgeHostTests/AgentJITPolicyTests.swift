#if os(macOS)
import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge

final class AgentJITPolicyTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    func testPreflightResolverIncludesCliEnabledPasswordSubtreeItems() throws {
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "",
                    folderPath: "Team/API",
                    isFolderScoped: true
                ),
            ]
        )

        let scopes = try AgentJITPreflightResolver().resolvedScopes(from: payload, list: listPayload())

        XCTAssertEqual(scopes.map(\.scope), [.folder("Team/API")])
        XCTAssertEqual(scopes.first?.requestedItems.map(\.name).sorted(), ["API", "Nested", "Shared"])
    }

    func testPreflightResolverIncludesCliEnabledAPIKeySubtreeItems() throws {
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(
                    type: "api-key",
                    query: "",
                    folderPath: "Team/API",
                    isFolderScoped: true
                ),
            ]
        )

        let scopes = try AgentJITPreflightResolver().resolvedScopes(from: payload, list: listPayload())

        XCTAssertEqual(scopes.map(\.scope), [.folder("Team/API")])
        XCTAssertEqual(scopes.first?.requestedItems.map(\.type), ["api-key", "api-key", "api-key"])
        XCTAssertEqual(
            scopes.first?.requestedItems.map(\.name).sorted(),
            ["API Key", "Nested API Key", "Shared API Key"]
        )
    }

    func testListPayloadFilterReturnsNoMetadataForAgentNonListCommandWithoutJITGrant() {
        let filtered = BridgeListPayloadFilter.filteredPayload(
            listPayload(),
            for: request(requestedCommand: "load"),
            callerIsAgentic: true,
            activeJITScopes: [],
            automationAuthorization: .notAutomation
        )

        XCTAssertEqual(filtered, emptyPayload())
    }

    func testListPayloadFilterKeepsDirectListBehaviorWithoutJITGrant() {
        let payload = listPayload()

        let filtered = BridgeListPayloadFilter.filteredPayload(
            payload,
            for: request(requestedCommand: "list"),
            callerIsAgentic: true,
            activeJITScopes: [],
            automationAuthorization: .notAutomation
        )

        XCTAssertEqual(filtered, payload)
    }

    func testListPayloadFilterAppliesDefaultNamedAndAllEnvironmentScopes() {
        let defaultEnvironment = BridgePassword(
            id: UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!,
            name: "DATABASE_URL",
            username: "svc",
            website: nil,
            folderPath: "Team/API",
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            createdAt: now,
            updatedAt: now,
            environments: []
        )
        let production = BridgePassword(
            id: UUID(uuidString: "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")!,
            name: "DATABASE_URL",
            username: "svc",
            website: nil,
            folderPath: "Team/API",
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            createdAt: now,
            updatedAt: now,
            environments: ["Production"]
        )
        let allEnvironments = BridgePassword(
            id: UUID(uuidString: "DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD")!,
            name: "DATABASE_URL",
            username: "svc",
            website: nil,
            folderPath: "Team/API",
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            createdAt: now,
            updatedAt: now,
            environments: ["All"]
        )
        let development = BridgePassword(
            id: UUID(uuidString: "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC")!,
            name: "DATABASE_URL",
            username: "svc",
            website: nil,
            folderPath: "Team/API",
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            createdAt: now,
            updatedAt: now,
            environments: ["Development"]
        )
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [defaultEnvironment, allEnvironments, production, development],
            certificates: [],
            notes: [],
            sshKeys: []
        )
        let authorization = AutomationAuthorizationDecision.allowWithoutApproval(scope: .folder("Team/API"))

        let named = BridgeListPayloadFilter.filteredPayload(
            payload,
            for: request(requestedCommand: "list"),
            callerIsAgentic: false,
            activeJITScopes: [],
            automationAuthorization: authorization,
            automationEnvironmentScope: .named("Production")
        )
        let defaultOnly = BridgeListPayloadFilter.filteredPayload(
            payload,
            for: request(requestedCommand: "list"),
            callerIsAgentic: false,
            activeJITScopes: [],
            automationAuthorization: authorization,
            automationEnvironmentScope: .defaultOnly
        )

        XCTAssertEqual(named.passwords.map(\.id), [allEnvironments.id, production.id])
        XCTAssertEqual(defaultOnly.passwords.map(\.id), [defaultEnvironment.id, allEnvironments.id])
    }

    private func request(requestedCommand: String) -> BridgeRequest {
        BridgeRequest(
            id: UUID(),
            type: .list,
            query: "",
            options: .init(field: nil, copy: false),
            context: BridgeContext(
                isTTY: true,
                isPiped: false,
                isSSH: false,
                isCI: false,
                timestamp: now,
                requestedCommand: requestedCommand,
                sessionScope: "tty:/dev/ttys001:sid:123",
                workingDirectory: "/tmp/authsia-test"
            )
        )
    }

    private func emptyPayload() -> BridgeListPayload {
        BridgeListPayload(accounts: [], passwords: [], certificates: [], notes: [], sshKeys: [])
    }

    private func listPayload() -> BridgeListPayload {
        BridgeListPayload(
            accounts: [
                BridgeAccount(
                    id: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
                    issuer: "GitHub",
                    label: "james",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now
                ),
            ],
            passwords: [
                BridgePassword(
                    id: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
                    name: "API",
                    username: "svc",
                    website: nil,
                    folderPath: "Team/API",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now
                ),
                BridgePassword(
                    id: UUID(uuidString: "33333333-3333-3333-3333-333333333333")!,
                    name: "Disabled",
                    username: "svc",
                    website: nil,
                    folderPath: "Team/API",
                    isFavorite: false,
                    isCliEnabled: false,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now
                ),
                BridgePassword(
                    id: UUID(uuidString: "44444444-4444-4444-4444-444444444444")!,
                    name: "Nested",
                    username: "svc",
                    website: nil,
                    folderPath: "Team/API/Prod",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now
                ),
                BridgePassword(
                    id: UUID(uuidString: "55555555-5555-5555-5555-555555555555")!,
                    name: "Shared",
                    username: "svc",
                    website: nil,
                    folderPath: "Team/API",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now
                ),
            ],
            apiKeys: [
                BridgeAPIKey(
                    id: UUID(uuidString: "66666666-6666-6666-6666-666666666666")!,
                    name: "API Key",
                    website: nil,
                    folderPath: "Team/API",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now
                ),
                BridgeAPIKey(
                    id: UUID(uuidString: "77777777-7777-7777-7777-777777777777")!,
                    name: "Disabled API Key",
                    website: nil,
                    folderPath: "Team/API",
                    isFavorite: false,
                    isCliEnabled: false,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now
                ),
                BridgeAPIKey(
                    id: UUID(uuidString: "88888888-8888-8888-8888-888888888888")!,
                    name: "Nested API Key",
                    website: nil,
                    folderPath: "Team/API/Prod",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now
                ),
                BridgeAPIKey(
                    id: UUID(uuidString: "99999999-9999-9999-9999-999999999999")!,
                    name: "Shared API Key",
                    website: nil,
                    folderPath: "Team/API",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now
                ),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )
    }
}
#endif
