#if os(macOS)
import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge

final class BridgeWorkspaceMetadataFilterTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)
    private let otherPasswordID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
    private let baselineAPIKeyID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!

    func testStatusReturnsOnlyExactCLIEnabledReferences() throws {
        let request = try makeRequest(
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
                    WorkspaceMetadataReference(
                        itemType: .note,
                        itemName: "Runbook",
                        folderPath: "Workspaces/api"
                    ),
                ]
            )
        )

        let filtered = try BridgeWorkspaceMetadataFilter.filteredPayload(sourcePayload(), for: request)

        XCTAssertEqual(filtered.passwords.map(\.name), ["DB_PASSWORD"])
        XCTAssertEqual(filtered.notes.map(\.title), ["Runbook"])
        XCTAssertTrue(filtered.accounts.isEmpty)
        XCTAssertTrue(filtered.apiKeys.isEmpty)
        XCTAssertTrue(filtered.certificates.isEmpty)
        XCTAssertTrue(filtered.sshKeys.isEmpty)
    }

    func testEnvListReturnsCLIEnabledItemsOnlyFromWorkspaceTree() throws {
        let request = try makeRequest(
            command: BridgeContext.workspaceEnvListRequestedCommand,
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

        let filtered = try BridgeWorkspaceMetadataFilter.filteredPayload(sourcePayload(), for: request)

        XCTAssertEqual(filtered.passwords.map(\.name), ["DB_PASSWORD", "Nested"])
        XCTAssertEqual(filtered.apiKeys.map(\.name), ["API_KEY"])
    }

    func testEnvUseReturnsOnlyExactCLIEnabledReferences() throws {
        let request = try makeRequest(
            command: BridgeContext.workspaceEnvUseRequestedCommand,
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

        let filtered = try BridgeWorkspaceMetadataFilter.filteredPayload(sourcePayload(), for: request)

        XCTAssertEqual(filtered.passwords.map(\.name), ["DB_PASSWORD"])
        XCTAssertTrue(filtered.apiKeys.isEmpty)
    }

    func testWorkspaceEnvListReturnsOnlyExactCLIEnabledReferences() throws {
        let request = try makeRequest(
            command: BridgeContext.workspaceEnvBindingsListRequestedCommand,
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

        let filtered = try BridgeWorkspaceMetadataFilter.filteredPayload(sourcePayload(), for: request)

        XCTAssertTrue(filtered.passwords.isEmpty)
        XCTAssertEqual(filtered.apiKeys.map(\.name), ["API_KEY"])
    }

    func testValidationReturnsOnlyExactCLIEnabledReferences() throws {
        let request = try makeRequest(
            command: BridgeContext.workspaceEnvValidateRequestedCommand,
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

        let filtered = try BridgeWorkspaceMetadataFilter.filteredPayload(sourcePayload(), for: request)

        XCTAssertEqual(filtered.passwords.map(\.name), ["DB_PASSWORD"])
        XCTAssertEqual(filtered.apiKeys.map(\.name), ["API_KEY"])
        XCTAssertTrue(filtered.accounts.isEmpty)
        XCTAssertTrue(filtered.certificates.isEmpty)
        XCTAssertTrue(filtered.notes.isEmpty)
        XCTAssertTrue(filtered.sshKeys.isEmpty)
    }

    func testValidationAllowsExactIDReferenceOutsideWorkspaceFolder() throws {
        let request = try makeRequest(
            command: BridgeContext.workspaceEnvValidateRequestedCommand,
            payload: WorkspaceMetadataRequestPayload(
                workspaceFolder: "Workspaces/api",
                mode: .validate,
                references: [
                    WorkspaceMetadataReference(
                        itemType: .apiKey,
                        itemName: baselineAPIKeyID.uuidString,
                        folderPath: "Workspaces/Baseline"
                    ),
                ]
            )
        )

        let filtered = try BridgeWorkspaceMetadataFilter.filteredPayload(sourcePayload(), for: request)

        XCTAssertEqual(filtered.apiKeys.map(\.id), [baselineAPIKeyID])
        XCTAssertTrue(filtered.passwords.isEmpty)
    }

    func testWorkspaceRunValidationReturnsOnlyExactCLIEnabledReferences() throws {
        let request = try makeRequest(
            command: BridgeContext.workspaceRunRequestedCommand,
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

        let filtered = try BridgeWorkspaceMetadataFilter.filteredPayload(sourcePayload(), for: request)

        XCTAssertEqual(filtered.apiKeys.map(\.name), ["API_KEY"])
        XCTAssertTrue(filtered.passwords.isEmpty)
        XCTAssertTrue(filtered.accounts.isEmpty)
        XCTAssertTrue(filtered.certificates.isEmpty)
        XCTAssertTrue(filtered.notes.isEmpty)
        XCTAssertTrue(filtered.sshKeys.isEmpty)
    }

    func testWorkspaceRunValidationAllowsExactReferenceOutsideWorkspaceFolder() throws {
        let request = try makeRequest(
            command: BridgeContext.workspaceRunRequestedCommand,
            payload: WorkspaceMetadataRequestPayload(
                workspaceFolder: "Workspaces/api",
                mode: .validate,
                references: [
                    WorkspaceMetadataReference(
                        itemType: .apiKey,
                        itemName: "BASELINE_API_KEY",
                        folderPath: "Workspaces/Baseline"
                    ),
                ]
            )
        )

        let filtered = try BridgeWorkspaceMetadataFilter.filteredPayload(sourcePayload(), for: request)

        XCTAssertEqual(filtered.apiKeys.map(\.name), ["BASELINE_API_KEY"])
        XCTAssertTrue(filtered.passwords.isEmpty)
        XCTAssertTrue(filtered.accounts.isEmpty)
        XCTAssertTrue(filtered.certificates.isEmpty)
        XCTAssertTrue(filtered.notes.isEmpty)
        XCTAssertTrue(filtered.sshKeys.isEmpty)
    }

    func testWorkspaceRunValidationAllowsExactIDReferenceOutsideWorkspaceFolder() throws {
        let request = try makeRequest(
            command: BridgeContext.workspaceRunRequestedCommand,
            payload: WorkspaceMetadataRequestPayload(
                workspaceFolder: "Workspaces/api",
                mode: .validate,
                references: [
                    WorkspaceMetadataReference(
                        itemType: .apiKey,
                        itemName: baselineAPIKeyID.uuidString,
                        folderPath: "Workspaces/Baseline"
                    ),
                ]
            )
        )

        let filtered = try BridgeWorkspaceMetadataFilter.filteredPayload(sourcePayload(), for: request)

        XCTAssertEqual(filtered.apiKeys.map(\.id), [baselineAPIKeyID])
        XCTAssertTrue(filtered.passwords.isEmpty)
    }

    func testSyncPreviewReturnsCLIEnabledPasswordAndAPIKeyInWorkspaceTree() throws {
        let request = try makeRequest(
            command: BridgeContext.workspaceSyncPreviewRequestedCommand,
            payload: WorkspaceMetadataRequestPayload(
                workspaceFolder: "Workspaces/api",
                mode: .syncPreview,
                references: []
            )
        )

        let filtered = try BridgeWorkspaceMetadataFilter.filteredPayload(sourcePayload(), for: request)

        XCTAssertEqual(filtered.passwords.map(\.name), ["DB_PASSWORD", "Nested"])
        XCTAssertEqual(filtered.apiKeys.map(\.name), ["API_KEY"])
        XCTAssertTrue(filtered.accounts.isEmpty)
        XCTAssertTrue(filtered.certificates.isEmpty)
        XCTAssertTrue(filtered.notes.isEmpty)
        XCTAssertTrue(filtered.sshKeys.isEmpty)
    }

    func testRejectsMismatchedWorkspaceContext() throws {
        let request = try makeRequest(
            command: BridgeContext.workspaceStatusRequestedCommand,
            workspaceContextFolder: "Workspaces/other",
            payload: WorkspaceMetadataRequestPayload(
                workspaceFolder: "Workspaces/api",
                mode: .status,
                references: []
            )
        )

        XCTAssertThrowsError(try BridgeWorkspaceMetadataFilter.filteredPayload(sourcePayload(), for: request))
    }

    func testRejectsUnsupportedCommandAndModePair() throws {
        let request = try makeRequest(
            command: BridgeContext.workspaceStatusRequestedCommand,
            payload: WorkspaceMetadataRequestPayload(
                workspaceFolder: "Workspaces/api",
                mode: .syncPreview,
                references: []
            )
        )

        XCTAssertThrowsError(try BridgeWorkspaceMetadataFilter.filteredPayload(sourcePayload(), for: request))
    }

    func testStatusAllowsExactReferenceOutsideWorkspaceFolder() throws {
        let request = try makeRequest(
            command: BridgeContext.workspaceStatusRequestedCommand,
            payload: WorkspaceMetadataRequestPayload(
                workspaceFolder: "Workspaces/api",
                mode: .status,
                references: [
                    WorkspaceMetadataReference(
                        itemType: .password,
                        itemName: "Other",
                        folderPath: "Team/other"
                    ),
                ]
            )
        )

        let filtered = try BridgeWorkspaceMetadataFilter.filteredPayload(sourcePayload(), for: request)

        XCTAssertEqual(filtered.passwords.map(\.name), ["Other"])
        XCTAssertTrue(filtered.apiKeys.isEmpty)
    }

    func testStatusAllowsUnscopedExactIDReference() throws {
        let request = try makeRequest(
            command: BridgeContext.workspaceStatusRequestedCommand,
            payload: WorkspaceMetadataRequestPayload(
                workspaceFolder: "Workspaces/api",
                mode: .status,
                references: [
                    WorkspaceMetadataReference(
                        itemType: .password,
                        itemName: otherPasswordID.uuidString,
                        folderPath: nil
                    ),
                ]
            )
        )

        let filtered = try BridgeWorkspaceMetadataFilter.filteredPayload(sourcePayload(), for: request)

        XCTAssertEqual(filtered.passwords.map(\.id), [otherPasswordID])
        XCTAssertTrue(filtered.apiKeys.isEmpty)
    }

    func testRejectsEmptyWorkspaceFolder() throws {
        let request = try makeRequest(
            command: BridgeContext.workspaceStatusRequestedCommand,
            workspaceContextFolder: "   ",
            payload: WorkspaceMetadataRequestPayload(workspaceFolder: "", mode: .status, references: [])
        )

        XCTAssertThrowsError(try BridgeWorkspaceMetadataFilter.filteredPayload(sourcePayload(), for: request))
    }

    private func makeRequest(
        command: String,
        workspaceContextFolder: String = "Workspaces/api",
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
                timestamp: now,
                requestedCommand: command,
                workingDirectory: "/tmp/api",
                workspaceContext: WorkspaceRuntimeContext(
                    name: "api",
                    rootLabel: "api",
                    authsiaFolder: workspaceContextFolder
                )
            ),
            body: try BridgeCoder.encode(payload)
        )
    }

    private func sourcePayload() -> BridgeListPayload {
        BridgeListPayload(
            accounts: [
                BridgeAccount(
                    id: UUID(),
                    issuer: "GitHub",
                    label: "user",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now
                ),
            ],
            passwords: [
                password("DB_PASSWORD", folder: "Workspaces/api", isCliEnabled: true),
                password("Disabled", folder: "Workspaces/api", isCliEnabled: false),
                password("Nested", folder: "Workspaces/api/nested", isCliEnabled: true),
                password("Other", folder: "Team/other", isCliEnabled: true, id: otherPasswordID),
            ],
            apiKeys: [
                apiKey("API_KEY", folder: "Workspaces/api", isCliEnabled: true),
                apiKey(
                    "BASELINE_API_KEY",
                    folder: "Workspaces/Baseline",
                    isCliEnabled: true,
                    id: baselineAPIKeyID
                ),
                apiKey("Disabled API", folder: "Workspaces/api", isCliEnabled: false),
            ],
            certificates: [
                BridgeCertificate(
                    id: UUID(),
                    name: "Certificate",
                    issuer: nil,
                    subject: nil,
                    expirationDate: nil,
                    folderPath: "Workspaces/api",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now
                ),
            ],
            notes: [
                BridgeNote(
                    id: UUID(),
                    title: "Runbook",
                    folderPath: "Workspaces/api",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now
                ),
            ],
            sshKeys: [
                BridgeSSHKey(
                    id: UUID(),
                    name: "Deploy",
                    comment: "",
                    fingerprint: "fp",
                    publicKey: "ssh-ed25519 AAAA",
                    folderPath: "Workspaces/api",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now
                ),
            ]
        )
    }

    private func password(
        _ name: String,
        folder: String,
        isCliEnabled: Bool,
        id: UUID = UUID()
    ) -> BridgePassword {
        BridgePassword(
            id: id,
            name: name,
            username: "user",
            website: nil,
            folderPath: folder,
            isFavorite: false,
            isCliEnabled: isCliEnabled,
            isScraped: false,
            createdAt: now,
            updatedAt: now,
            hasSecret: true
        )
    }

    private func apiKey(
        _ name: String,
        folder: String,
        isCliEnabled: Bool,
        id: UUID = UUID()
    ) -> BridgeAPIKey {
        BridgeAPIKey(
            id: id,
            name: name,
            website: nil,
            folderPath: folder,
            isFavorite: false,
            isCliEnabled: isCliEnabled,
            isScraped: false,
            createdAt: now,
            updatedAt: now,
            hasSecret: true
        )
    }
}
#endif
