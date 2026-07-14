import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData

@MainActor
final class XPCRequestHandlerWorkspaceMetadataTests: XCTestCase {
    private let cliAccessEnabledKey = "cliAccessEnabled"
    private var hadCLISetting = false
    private var previousCLISetting = false

    override func setUp() {
        super.setUp()
        hadCLISetting = BridgeSettings.appDefaults.object(forKey: cliAccessEnabledKey) != nil
        previousCLISetting = BridgeSettings.appDefaults.bool(forKey: cliAccessEnabledKey)
        BridgeSettings.appDefaults.set(true, forKey: cliAccessEnabledKey)
    }

    override func tearDown() {
        if hadCLISetting {
            BridgeSettings.appDefaults.set(previousCLISetting, forKey: cliAccessEnabledKey)
        } else {
            BridgeSettings.appDefaults.removeObject(forKey: cliAccessEnabledKey)
        }
        super.tearDown()
    }

    func testWorkspaceStatusMetadataDoesNotCallApproverOrMintSession() async throws {
        let approver = WorkspaceMetadataApprovalTracker()
        let listProvider = WorkspaceMetadataListProvider()
        let handler = XPCRequestHandler(listProvider: listProvider.fetch, approver: approver)

        let response = try await send(
            handler: handler,
            request: makeRequest(
                command: BridgeContext.workspaceStatusRequestedCommand,
                payload: WorkspaceMetadataRequestPayload(
                    workspaceFolder: "Workspaces/api",
                    mode: .status,
                    references: [
                        WorkspaceMetadataReference(
                            itemType: .password,
                            itemName: "DB_PASSWORD",
                            folderPath: "Workspaces/api"
                        ),
                    ]
                )
            )
        )

        XCTAssertNil(response.error)
        XCTAssertNil(response.sessionToken)
        XCTAssertEqual(response.payload?.passwords.map(\.name), ["DB_PASSWORD"])
        XCTAssertEqual(approver.callCount, 0)
        XCTAssertEqual(listProvider.callCount, 1)
    }

    func testAgentWorkspaceEnvValidationMetadataProbesExactItemsWithoutApproval() async throws {
        let approver = WorkspaceMetadataApprovalTracker()
        let listProvider = WorkspaceMetadataListProvider()
        let handler = XPCRequestHandler(
            listProvider: listProvider.fetch,
            approver: approver,
            passwordSecretExistenceProvider: { $0 == listProvider.passwordID },
            apiKeySecretExistenceProvider: { _ in false }
        )
        let response = try await send(
            handler: handler,
            request: makeRequest(
                command: BridgeContext.workspaceEnvValidateRequestedCommand,
                agentRuntimeContext: AgentRuntimeContext(platform: "codex", agentType: "coding-agent"),
                payload: WorkspaceMetadataRequestPayload(
                    workspaceFolder: "Workspaces/api",
                    mode: .validate,
                    references: [
                        WorkspaceMetadataReference(
                            itemType: .password,
                            itemName: "DB_PASSWORD",
                            folderPath: "Workspaces/api"
                        ),
                        WorkspaceMetadataReference(
                            itemType: .apiKey,
                            itemName: "API_KEY",
                            folderPath: "Workspaces/api"
                        ),
                    ]
                )
            )
        )

        XCTAssertNil(response.error)
        XCTAssertNil(response.sessionToken)
        XCTAssertEqual(response.payload?.passwords.map(\.hasSecret), [true])
        XCTAssertEqual(response.payload?.apiKeys.map(\.hasSecret), [false])
        XCTAssertEqual(approver.callCount, 0)
        XCTAssertEqual(listProvider.callCount, 1)
    }

    func testAgentWorkspaceRunValidationMetadataProbesExactItemsWithoutApproval() async throws {
        let approver = WorkspaceMetadataApprovalTracker()
        let listProvider = WorkspaceMetadataListProvider()
        let handler = XPCRequestHandler(
            listProvider: listProvider.fetch,
            approver: approver,
            passwordSecretExistenceProvider: { _ in false },
            apiKeySecretExistenceProvider: { $0 == listProvider.apiKeyID }
        )
        let response = try await send(
            handler: handler,
            request: makeRequest(
                command: BridgeContext.workspaceRunRequestedCommand,
                agentRuntimeContext: AgentRuntimeContext(platform: "codex", agentType: "coding-agent"),
                payload: WorkspaceMetadataRequestPayload(
                    workspaceFolder: "Workspaces/api",
                    mode: .validate,
                    references: [
                        WorkspaceMetadataReference(
                            itemType: .apiKey,
                            itemName: "API_KEY",
                            folderPath: "Workspaces/api"
                        ),
                    ]
                )
            )
        )

        XCTAssertNil(response.error)
        XCTAssertNil(response.sessionToken)
        XCTAssertEqual(response.payload?.apiKeys.map(\.hasSecret), [true])
        XCTAssertEqual(approver.callCount, 0)
        XCTAssertEqual(listProvider.callCount, 1)
    }

    func testWorkspaceSyncPreviewMetadataDoesNotCallApprover() async throws {
        let approver = WorkspaceMetadataApprovalTracker()
        let listProvider = WorkspaceMetadataListProvider()
        let handler = XPCRequestHandler(listProvider: listProvider.fetch, approver: approver)

        let response = try await send(
            handler: handler,
            request: makeRequest(
                command: BridgeContext.workspaceSyncPreviewRequestedCommand,
                payload: WorkspaceMetadataRequestPayload(
                    workspaceFolder: "Workspaces/api",
                    mode: .syncPreview,
                    references: []
                )
            )
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.passwords.map(\.name), ["DB_PASSWORD"])
        XCTAssertEqual(response.payload?.apiKeys.map(\.name), ["API_KEY"])
        XCTAssertEqual(approver.callCount, 0)
        XCTAssertEqual(listProvider.callCount, 1)
    }

    func testWorkspaceMetadataFailsClosedForMismatchedContext() async throws {
        let approver = WorkspaceMetadataApprovalTracker()
        let listProvider = WorkspaceMetadataListProvider()
        let handler = XPCRequestHandler(listProvider: listProvider.fetch, approver: approver)

        let response = try await send(
            handler: handler,
            request: makeRequest(
                command: BridgeContext.workspaceStatusRequestedCommand,
                workspaceContextFolder: "Workspaces/other",
                payload: WorkspaceMetadataRequestPayload(
                    workspaceFolder: "Workspaces/api",
                    mode: .status,
                    references: []
                )
            )
        )

        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertNil(response.payload)
        XCTAssertEqual(approver.callCount, 0)
        XCTAssertEqual(listProvider.callCount, 1)
    }

    func testWorkspaceMetadataServesScopedMetadataWithoutApproval() async throws {
        let approver = WorkspaceMetadataApprovalTracker()
        let listProvider = WorkspaceMetadataListProvider()
        let handler = XPCRequestHandler(listProvider: listProvider.fetch, approver: approver)
        let response = try await send(
            handler: handler,
            request: makeRequest(
                command: BridgeContext.workspaceSyncPreviewRequestedCommand,
                payload: WorkspaceMetadataRequestPayload(
                    workspaceFolder: "Workspaces/api",
                    mode: .syncPreview,
                    references: []
                )
            )
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.passwords.map(\.name), ["DB_PASSWORD"])
        XCTAssertEqual(response.payload?.apiKeys.map(\.name), ["API_KEY"])
        XCTAssertEqual(approver.callCount, 0)
        XCTAssertEqual(listProvider.callCount, 1)
    }

    func testWorkspaceSyncMetadataUsesPersistedStateWhenRepositoryIsStale() async throws {
        let repository = WorkspaceMetadataStubRepository(
            passwords: [
                Self.passwordMetadata(name: "DB_PASSWORD", folderPath: "Workspaces/api"),
            ],
            hasLoadedVaultState: true
        )
        let metadataProvider = WorkspaceMetadataListProvider(includePasswords: false)
        var accountProviderCallCount = 0
        let handler = XPCRequestHandler(
            accountProvider: {
                accountProviderCallCount += 1
                return []
            },
            approver: WorkspaceMetadataApprovalTracker(),
            repository: repository,
            workspaceMetadataProvider: {
                try BridgeCoder.encode(metadataProvider.fetch())
            }
        )

        let response = try await send(
            handler: handler,
            request: makeRequest(
                command: BridgeContext.workspaceSyncPreviewRequestedCommand,
                payload: WorkspaceMetadataRequestPayload(
                    workspaceFolder: "Workspaces/api",
                    mode: .syncPreview,
                    references: []
                )
            )
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.passwords.map(\.name), [])
        XCTAssertEqual(response.payload?.apiKeys.map(\.name), ["API_KEY"])
        XCTAssertEqual(repository.loadCallCount, 0)
        XCTAssertEqual(accountProviderCallCount, 0)
        XCTAssertEqual(metadataProvider.callCount, 1)
    }

    func testWorkspaceEnvValidationUsesPersistedStateWhenRepositoryIsStale() async throws {
        let repository = WorkspaceMetadataStubRepository(
            passwords: [],
            hasLoadedVaultState: true
        )
        let metadataProvider = WorkspaceMetadataListProvider()
        let handler = XPCRequestHandler(
            approver: WorkspaceMetadataApprovalTracker(),
            repository: repository,
            workspaceMetadataProvider: {
                try BridgeCoder.encode(metadataProvider.fetch())
            },
            passwordSecretExistenceProvider: { $0 == metadataProvider.passwordID },
            apiKeySecretExistenceProvider: { _ in false }
        )

        let response = try await send(
            handler: handler,
            request: makeRequest(
                command: BridgeContext.workspaceEnvValidateRequestedCommand,
                agentRuntimeContext: AgentRuntimeContext(platform: "codex"),
                payload: WorkspaceMetadataRequestPayload(
                    workspaceFolder: "Workspaces/api",
                    mode: .validate,
                    references: [
                        WorkspaceMetadataReference(
                            itemType: .password,
                            itemName: "DB_PASSWORD",
                            folderPath: "Workspaces/api"
                        ),
                    ]
                )
            )
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.passwords.map(\.name), ["DB_PASSWORD"])
        XCTAssertEqual(response.payload?.passwords.map(\.hasSecret), [true])
        XCTAssertEqual(repository.loadCallCount, 0)
        XCTAssertEqual(metadataProvider.callCount, 1)
    }

    func testWorkspaceStatusMetadataUsesWarmRepositoryWithoutPersistedReload() async throws {
        let repository = WorkspaceMetadataStubRepository(
            passwords: [
                Self.passwordMetadata(name: "DB_PASSWORD", folderPath: "Workspaces/api"),
            ],
            hasLoadedVaultState: true
        )
        let metadataProvider = WorkspaceMetadataListProvider(includePasswords: false)
        let handler = XPCRequestHandler(
            approver: WorkspaceMetadataApprovalTracker(),
            repository: repository,
            workspaceMetadataProvider: {
                try BridgeCoder.encode(metadataProvider.fetch())
            }
        )

        let response = try await send(
            handler: handler,
            request: makeRequest(
                command: BridgeContext.workspaceStatusRequestedCommand,
                payload: WorkspaceMetadataRequestPayload(
                    workspaceFolder: "Workspaces/api",
                    mode: .status,
                    references: [
                        WorkspaceMetadataReference(
                            itemType: .password,
                            itemName: "DB_PASSWORD",
                            folderPath: "Workspaces/api"
                        ),
                    ]
                )
            )
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.passwords.map(\.name), ["DB_PASSWORD"])
        XCTAssertEqual(response.payload?.apiKeys.map(\.name), [])
        XCTAssertEqual(repository.loadCallCount, 0)
        XCTAssertEqual(metadataProvider.callCount, 0)
    }

    func testWorkspaceStatusMetadataUsesMetadataOnlyProviderWhenRepositoryIsCold() async throws {
        let repository = WorkspaceMetadataStubRepository(hasLoadedVaultState: false)
        let metadataProvider = WorkspaceMetadataListProvider()
        let handler = XPCRequestHandler(
            accountProvider: {
                throw NSError(domain: "UnexpectedAccountProvider", code: 1)
            },
            approver: WorkspaceMetadataApprovalTracker(),
            repository: repository,
            workspaceMetadataProvider: {
                try BridgeCoder.encode(metadataProvider.fetch())
            }
        )

        let response = try await send(
            handler: handler,
            request: makeRequest(
                command: BridgeContext.workspaceStatusRequestedCommand,
                payload: WorkspaceMetadataRequestPayload(
                    workspaceFolder: "Workspaces/api",
                    mode: .status,
                    references: [
                        WorkspaceMetadataReference(
                            itemType: .password,
                            itemName: "DB_PASSWORD",
                            folderPath: "Workspaces/api"
                        ),
                    ]
                )
            )
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.passwords.map(\.name), ["DB_PASSWORD"])
        XCTAssertEqual(repository.loadCallCount, 0)
        XCTAssertEqual(metadataProvider.callCount, 1)
    }

    private static func passwordMetadata(name: String, folderPath: String) -> PasswordMetadata {
        let now = Date()
        return PasswordMetadata(
            id: UUID(),
            name: name,
            username: "user",
            website: nil,
            notes: nil,
            folderPath: folderPath,
            createdAt: now,
            modifiedAt: now,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false
        )
    }

    private func send(
        handler: XPCRequestHandler,
        request: BridgeRequest
    ) async throws -> BridgeResponse<BridgeListPayload> {
        let expectation = XCTestExpectation(description: "workspace metadata reply")
        var responseData: Data?
        handler.list(try BridgeCoder.encode(request)) { data, _ in
            responseData = data
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)
        return try BridgeCoder.decode(
            BridgeResponse<BridgeListPayload>.self,
            from: try XCTUnwrap(responseData)
        )
    }

    private func makeRequest(
        command: String,
        workspaceContextFolder: String = "Workspaces/api",
        agentRuntimeContext: AgentRuntimeContext? = nil,
        payload: WorkspaceMetadataRequestPayload
    ) throws -> BridgeRequest {
        BridgeRequest(
            id: UUID(),
            type: .workspaceMetadata,
            query: "",
            options: BridgeOptions(field: nil, copy: false),
            context: BridgeContext(
                isTTY: true,
                isPiped: false,
                isSSH: false,
                isCI: false,
                timestamp: Date(),
                requestedCommand: command,
                workingDirectory: "/tmp/api",
                agentRuntimeContext: agentRuntimeContext,
                workspaceContext: WorkspaceRuntimeContext(
                    name: "api",
                    rootLabel: "api",
                    authsiaFolder: workspaceContextFolder
                )
            ),
            body: try BridgeCoder.encode(payload)
        )
    }
}

@MainActor
private final class WorkspaceMetadataStubRepository: VaultRepositoryProviding {
    private(set) var loadCallCount = 0
    private(set) var passwords: [PasswordMetadata]
    private(set) var apiKeys: [APIKeyMetadata]
    private(set) var certificates: [CertificateMetadata]
    private(set) var notes: [SecureNoteMetadata]
    private(set) var sshKeys: [SSHKeyMetadata]
    let hasLoadedVaultState: Bool

    init(
        passwords: [PasswordMetadata] = [],
        apiKeys: [APIKeyMetadata] = [],
        certificates: [CertificateMetadata] = [],
        notes: [SecureNoteMetadata] = [],
        sshKeys: [SSHKeyMetadata] = [],
        hasLoadedVaultState: Bool
    ) {
        self.passwords = passwords
        self.apiKeys = apiKeys
        self.certificates = certificates
        self.notes = notes
        self.sshKeys = sshKeys
        self.hasLoadedVaultState = hasLoadedVaultState
    }

    func load() throws {
        loadCallCount += 1
    }

    func addPassword(_ item: PasswordItem) throws {}
    func updatePassword(_ item: PasswordItem) throws {}
    func deletePassword(id: UUID) throws {}
    func convertPasswordToAPIKey(id: UUID, modifiedAt: Date) throws -> APIKeyItem? { nil }
    func getFullPassword(metadata: PasswordMetadata) throws -> PasswordItem { fatalError("unused") }
    func addAPIKey(_ item: APIKeyItem) throws {}
    func updateAPIKey(_ item: APIKeyItem) throws {}
    func deleteAPIKey(id: UUID) throws {}
    func getFullAPIKey(metadata: APIKeyMetadata) throws -> APIKeyItem { fatalError("unused") }
    func addCertificate(_ item: CertificateItem) throws {}
    func updateCertificate(_ item: CertificateItem) throws {}
    func deleteCertificatePrivateKey(id: UUID) {}
    func deleteCertificate(id: UUID) throws {}
    func getFullCertificate(metadata: CertificateMetadata) throws -> CertificateItem { fatalError("unused") }
    func addNote(_ item: SecureNoteItem) throws {}
    func updateNote(_ item: SecureNoteItem) throws {}
    func deleteNote(id: UUID) throws {}
    func getFullNote(metadata: SecureNoteMetadata) throws -> SecureNoteItem { fatalError("unused") }
    func addSSHKey(_ item: SSHKeyItem) throws {}
    func updateSSHKey(_ item: SSHKeyItem) throws {}
    func deleteSSHKey(id: UUID) throws {}
    func getFullSSHKey(metadata: SSHKeyMetadata) throws -> SSHKeyItem { fatalError("unused") }
    func addFolder(_ path: String, type: VaultItemType) throws {}
}

private final class WorkspaceMetadataApprovalTracker: BridgeApprover {
    private(set) var callCount = 0

    func requestApproval(
        prompt: String,
        command: BridgeRequestType,
        itemLabel: String?,
        field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?
    ) async -> Bool {
        callCount += 1
        return true
    }
}

private final class WorkspaceMetadataListProvider {
    private(set) var callCount = 0
    private let includePasswords: Bool
    let passwordID = UUID()
    let apiKeyID = UUID()

    init(includePasswords: Bool = true) {
        self.includePasswords = includePasswords
    }

    func fetch() throws -> BridgeListPayload {
        callCount += 1
        let now = Date()
        return BridgeListPayload(
            accounts: [],
            passwords: includePasswords ? [
                BridgePassword(
                    id: passwordID,
                    name: "DB_PASSWORD",
                    username: "user",
                    website: nil,
                    folderPath: "Workspaces/api",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now,
                    hasSecret: true
                ),
                BridgePassword(
                    id: UUID(),
                    name: "Other",
                    username: "user",
                    website: nil,
                    folderPath: "Team/other",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now,
                    hasSecret: true
                ),
            ] : [],
            apiKeys: [
                BridgeAPIKey(
                    id: apiKeyID,
                    name: "API_KEY",
                    website: nil,
                    folderPath: "Workspaces/api",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now,
                    hasSecret: true
                ),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )
    }
}
