import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
import CryptoKit

@MainActor
final class XPCRequestHandlerJITGrantTests: XCTestCase {
    private var isolatedAuditDirectories: [URL] = []

    private let callerIdentity = CallerIdentity(
        pid: 42,
        processName: "authsia",
        bundleIdentifier: "com.authsia.cli",
        signingTeamId: "TEAM",
        signingIdentity: "Developer ID Application",
        parentProcess: ParentProcessInfo(
            pid: 41,
            processName: "Claude",
            bundleIdentifier: "com.anthropic.claude"
        )
    )

    private let humanCallerIdentity = CallerIdentity(
        pid: 42,
        processName: "authsia",
        bundleIdentifier: "com.authsia.cli",
        signingTeamId: "TEAM",
        signingIdentity: "Developer ID Application",
        parentProcess: ParentProcessInfo(
            pid: 41,
            processName: "Terminal",
            bundleIdentifier: "com.apple.Terminal"
        )
    )

    private let vscodeTerminalCallerIdentity = CallerIdentity(
        pid: 42,
        processName: "authsia",
        bundleIdentifier: "com.authsia.cli",
        signingTeamId: "TEAM",
        signingIdentity: "Developer ID Application",
        parentProcess: ParentProcessInfo(
            pid: 41,
            processName: "zsh",
            bundleIdentifier: nil
        ),
        hostProcess: ParentProcessInfo(
            pid: 40,
            processName: "Code Helper",
            bundleIdentifier: "com.microsoft.VSCode"
        )
    )

    private let ideHelperCallerIdentity = CallerIdentity(
        pid: 42,
        processName: "authsia",
        bundleIdentifier: "com.authsia.cli",
        signingTeamId: "TEAM",
        signingIdentity: "Developer ID Application",
        parentProcess: ParentProcessInfo(
            pid: 41,
            processName: "Cursor Helper",
            bundleIdentifier: "com.todesktop.230313mzl4w4u92"
        )
    )

    private let claudeViaVSCodeCallerIdentity = CallerIdentity(
        pid: 42,
        processName: "authsia",
        bundleIdentifier: "com.authsia.cli",
        signingTeamId: "TEAM",
        signingIdentity: "Developer ID Application",
        parentProcess: ParentProcessInfo(
            pid: 41,
            processName: "claude",
            bundleIdentifier: "com.anthropic.claude"
        ),
        hostProcess: ParentProcessInfo(
            pid: 40,
            processName: "Code Helper",
            bundleIdentifier: "com.microsoft.VSCode"
        )
    )

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    override func tearDown() {
        for directory in isolatedAuditDirectories {
            try? FileManager.default.removeItem(at: directory)
        }
        isolatedAuditDirectories.removeAll()
        super.tearDown()
    }

    func testPreflightGroupsRootReferencesIntoOneGrant() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "RootOne", folderPath: nil),
                AgentJITPreflightReference(type: "note", query: "RootNote", folderPath: nil),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.grantIDs.count, 1)
        XCTAssertEqual(store.grants.count, 1)
        XCTAssertEqual(store.grants.first?.folderScope, .root)
        XCTAssertEqual(store.grants.first?.capabilities, [.exec, .list])
        XCTAssertEqual(store.grants.first?.approvedBy, "biometric")
        XCTAssertEqual(store.grants.first?.agentName, "Claude")
        XCTAssertEqual(approver.requests.map(\.command), [.agentJITPreflight])
        XCTAssertEqual(approver.requests.map(\.remoteRequests), [[]])
        XCTAssertEqual(approver.requests.first?.itemLabel, "Root")
        XCTAssertEqual(approver.requests.first?.prompt.contains(
            "Allow Claude temporary access to CLI-enabled password, API key, certificate, and note items in Root only"
        ), true)
        XCTAssertEqual(approver.requests.first?.prompt.contains(
            "plus scoped list access."
        ), true)
        XCTAssertEqual(approver.requests.first?.prompt.contains("all folders"), false)
    }

    func testListPreflightCreatesListOnlyGrant() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "",
                    folderPath: "Team/API",
                    isFolderScoped: true
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            handler,
            body: payload,
            requestedCommand: "list"
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.grantIDs.count, 1)
        XCTAssertEqual(store.grants.count, 1)
        XCTAssertEqual(store.grants.first?.folderScope, .folder("Team/API"))
        XCTAssertEqual(store.grants.first?.capabilities, [.list])
        XCTAssertEqual(store.grants.first?.requestedItems.map(\.name).sorted(), ["API", "API Nested", "Shared"])
        XCTAssertEqual(approver.requests.map(\.command), [.agentJITPreflight])
        XCTAssertEqual(approver.requests.first?.itemLabel, "Team/API")
        XCTAssertEqual(approver.requests.first?.prompt.contains("temporary scoped list access"), true)
    }

    func testBroadListPreflightApprovesOnceForAllResolvedFolderGrants() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "",
                    folderPath: nil,
                    isFolderScoped: false
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            handler,
            body: payload,
            requestedCommand: "list"
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(approver.requests.count, 1)
        XCTAssertEqual(approver.requests.first?.command, .agentJITPreflight)
        XCTAssertEqual(approver.requests.first?.itemLabel, "All folders")
        XCTAssertEqual(
            store.grants.map(\.folderScope),
            [.root, .folder("Team/API"), .folder("Team/Web")]
        )
        XCTAssertEqual(store.grants.map(\.capabilities), Array(repeating: [.list], count: 3))
        XCTAssertEqual(response.payload?.grantIDs.count, 3)
        let apiGrant = try XCTUnwrap(store.grants.first { $0.folderScope == .folder("Team/API") })
        XCTAssertEqual(Set(apiGrant.requestedItems.compactMap(\.folderPath)), ["Team/API", "Team/API/Prod"])
    }

    func testListPreflightSupportsSSHMetadataScope() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [
                AgentJITPreflightReference(
                    type: "ssh",
                    query: "",
                    folderPath: "Team/API",
                    isFolderScoped: true
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            handler,
            body: payload,
            requestedCommand: "list"
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.grantIDs.count, 1)
        XCTAssertEqual(store.grants.first?.capabilities, [.list])
        XCTAssertEqual(store.grants.first?.requestedItems.map(\.name).sorted(), ["API SSH", "Nested SSH"])
    }

    func testListPreflightSupportsAPIKeyMetadataScope() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [
                AgentJITPreflightReference(
                    type: "api-key",
                    query: "",
                    folderPath: "Team/API",
                    isFolderScoped: true
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            handler,
            body: payload,
            requestedCommand: "list"
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.grantIDs.count, 1)
        XCTAssertEqual(store.grants.first?.capabilities, [.list])
        XCTAssertEqual(store.grants.first?.requestedItems.map(\.type), ["api-key"])
        XCTAssertEqual(store.grants.first?.requestedItems.map(\.name), ["API Key"])
    }


    func testPreflightRecordsAuditForCreatedGrant() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let (auditLogger, auditURL, tempDir) = try makeAuditLogger()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let handler = makeHandler(store: store, approver: approver, auditLogger: auditLogger)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
            ],
            environmentScope: .named("Production")
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        let grant = try XCTUnwrap(store.grants.first)
        let records = try auditRecords(at: auditURL)
        XCTAssertNil(response.error)
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].command, .agentJITPreflight)
        XCTAssertEqual(records[0].itemId, grant.id.uuidString)
        XCTAssertEqual(records[0].itemName, "Team/API")
        XCTAssertEqual(records[0].approvedBy, "biometric")
        XCTAssertEqual(records[0].requestedCommand, "exec")
        XCTAssertEqual(records[0].agentJITGrantID, grant.id)
        XCTAssertEqual(records[0].environmentScope, .named("Production"))
        XCTAssertTrue(approver.requests[0].prompt.contains("Environment: Production."))
    }

    func testMacPanelPreflightAttributesStoredGrantAndAudit() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(outcome: .approved(source: .macPanel))
        let (auditLogger, auditURL, tempDir) = try makeAuditLogger()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let handler = makeHandler(store: store, approver: approver, auditLogger: auditLogger)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        let grant = try XCTUnwrap(store.grants.first)
        let records = try auditRecords(at: auditURL)
        XCTAssertNil(response.error)
        XCTAssertEqual(grant.approvedBy, "mac-panel")
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].approvedBy, "mac-panel")
        XCTAssertEqual(records[0].agentJITGrantID, grant.id)
    }

    func testPreflightStoresAgentNameWithIDEHost() async throws {
        let store = MemoryAgentJITGrantStore()
        let handler = makeHandler(
            store: store,
            approver: JITApprovalTracker(result: true),
            callerIdentity: claudeViaVSCodeCallerIdentity
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(store.grants.first?.agentName, "Claude via Visual Studio Code")
    }

    func testPreflightStoresResolvedVaultItemsOnGrant() async throws {
        let store = MemoryAgentJITGrantStore()
        let handler = makeHandler(
            store: store,
            approver: JITApprovalTracker(result: true)
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
                AgentJITPreflightReference(type: "api-key", query: "API Key", folderPath: "Team/API"),
                AgentJITPreflightReference(type: "note", query: "API Note", folderPath: "Team/API"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        let grant = try XCTUnwrap(store.grants.first)
        XCTAssertEqual(grant.requestedItems.map(\.type), ["password", "api-key", "note"])
        XCTAssertEqual(grant.requestedItems.map(\.name), ["API", "API Key", "API Note"])
        XCTAssertEqual(grant.requestedItems.map(\.folderPath), ["Team/API", "Team/API", "Team/API"])
    }

    func testPreflightRecordsAuditForDeniedApproval() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: false)
        let (auditLogger, auditURL, tempDir) = try makeAuditLogger()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let handler = makeHandler(store: store, approver: approver, auditLogger: auditLogger)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        let records = try auditRecords(at: auditURL)
        XCTAssertEqual(response.error?.code, .notAuthorized)
        XCTAssertEqual(store.grants, [])
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].command, .agentJITPreflight)
        XCTAssertEqual(records[0].itemId, "Team/API")
        XCTAssertEqual(records[0].itemName, "Team/API")
        XCTAssertEqual(records[0].approvedBy, "denied:biometric")
        XCTAssertEqual(records[0].requestedCommand, "exec")
        XCTAssertNil(records[0].agentJITGrantID)
    }

    func testPreflightKeepsSiblingScopesSeparate() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
                AgentJITPreflightReference(type: "cert", query: "Web Cert", folderPath: "Team/Web"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.grantIDs.count, 2)
        XCTAssertEqual(Set(store.grants.map(\.folderScope)), [.folder("Team/API"), .folder("Team/Web")])
        XCTAssertEqual(approver.requests.map(\.itemLabel), ["Team/API", "Team/Web"])
        XCTAssertEqual(approver.requests.first?.prompt.contains(
            "Allow Claude temporary access to CLI-enabled password, API key, certificate, and note items " +
                "in folder 'Team/API' and its descendants"
        ), true)
    }

    func testPreflightDisambiguatesDuplicateNamesByRequestedFolder() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "Shared", folderPath: "Team/API"),
                AgentJITPreflightReference(type: "password", query: "Shared", folderPath: "Team/Web"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(Set(store.grants.map(\.folderScope)), [.folder("Team/API"), .folder("Team/Web")])
    }

    func testPreflightRootRequestDoesNotMatchNonRootDuplicate() async throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore())
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "Shared", folderPath: nil),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertEqual(response.error?.code, .notFound)
        XCTAssertNil(response.payload)
    }

    func testPreflightUnscopedRequestGrantsResolvedItemFolder() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "API",
                    folderPath: nil,
                    isFolderScoped: false
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(store.grants.map(\.folderScope), [.folder("Team/API")])
        XCTAssertEqual(approver.requests.map(\.itemLabel), ["Team/API"])
    }

    func testPreflightDescendantReusesActiveAncestorGrantWithoutApproval() async throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec, .list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let store = MemoryAgentJITGrantStore([grant])
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "API Nested",
                    folderPath: nil,
                    isFolderScoped: false
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.grantIDs, [grant.id])
        XCTAssertEqual(store.grants.count, 1)
        XCTAssertEqual(approver.requests, [])
    }

    func testPreflightExplainsSeparateExecCapabilityForCoveredDescendant() async throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder(" Team//API "),
            capabilities: [.list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let store = MemoryAgentJITGrantStore([grant])
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "API Nested",
                    folderPath: "Team/API/Prod"
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        let prompt = try XCTUnwrap(approver.requests.first?.prompt)
        XCTAssertTrue(prompt.contains("Separate approval required"))
        XCTAssertTrue(prompt.contains("allows list access"))
        XCTAssertTrue(prompt.contains("exec capability requires separate approval"))
        XCTAssertTrue(prompt.contains("Team/API and its descendants"))
        XCTAssertFalse(prompt.contains("API Nested"))
    }

    func testPreflightExplainsUnrelatedFolderScope() async throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec, .list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let store = MemoryAgentJITGrantStore([grant])
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "cert", query: "Web Cert", folderPath: "Team/Web"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        let prompt = try XCTUnwrap(approver.requests.first?.prompt)
        XCTAssertTrue(prompt.contains("Separate approval required"))
        XCTAssertTrue(prompt.contains("Team/Web and its descendants"))
        XCTAssertTrue(prompt.contains("Team/API and its descendants"))
        XCTAssertTrue(prompt.contains("unrelated folder trees are isolated"))
        XCTAssertFalse(prompt.contains("Web Cert"))
    }

    func testPreflightExplainsBroaderAncestorScope() async throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API/Prod"),
            capabilities: [.exec, .list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let store = MemoryAgentJITGrantStore([grant])
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "API Nested",
                    folderPath: "Team/API",
                    isFolderScoped: true
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        let prompt = try XCTUnwrap(approver.requests.first?.prompt)
        XCTAssertTrue(prompt.hasPrefix("Separate approval required"))
        XCTAssertTrue(prompt.contains(
            "requested scope Team/API and its descendants is broader than the active grant scope " +
                "Team/API/Prod and its descendants"
        ))
        XCTAssertTrue(prompt.contains("extends access beyond the active subtree to additional descendants"))
        XCTAssertFalse(prompt.contains("unrelated"))
        XCTAssertFalse(prompt.contains("API Nested"))
    }

    func testBroadListPromptExplainsOnlyNewUnrelatedScopes() async throws {
        let caller = callerFingerprint(requestedCommand: "list")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let store = MemoryAgentJITGrantStore([grant])
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "",
                    folderPath: nil,
                    isFolderScoped: false
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            handler,
            body: payload,
            requestedCommand: "list"
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(approver.requests.count, 1)
        let prompt = try XCTUnwrap(approver.requests.first?.prompt)
        XCTAssertTrue(prompt.contains("This request adds folder scopes Root only, Team/Web and its descendants"))
        XCTAssertTrue(prompt.contains("The active grant covers Team/API and its descendants"))
        XCTAssertTrue(prompt.contains("unrelated folder trees are isolated"))
        XCTAssertFalse(prompt.contains("RootOne"))
        XCTAssertFalse(prompt.contains("API Nested"))
        XCTAssertFalse(prompt.contains("Shared"))
        XCTAssertEqual(
            Set(store.grants.map(\.folderScope)),
            [.root, .folder("Team/API"), .folder("Team/Web")]
        )
    }

    func testBroadListPromptDistinguishesBroaderAncestorAndUncoveredScopes() async throws {
        let caller = callerFingerprint(requestedCommand: "list")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API/Prod"),
            capabilities: [.list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let store = MemoryAgentJITGrantStore([grant])
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "",
                    folderPath: nil,
                    isFolderScoped: false
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            handler,
            body: payload,
            requestedCommand: "list"
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(approver.requests.count, 1)
        let prompt = try XCTUnwrap(approver.requests.first?.prompt)
        XCTAssertTrue(prompt.hasPrefix("Separate approval required"))
        XCTAssertTrue(prompt.contains(
            "Broader ancestor expansions Team/API and its descendants extend access beyond active child subtrees " +
                "Team/API/Prod and its descendants to additional descendants"
        ))
        XCTAssertTrue(prompt.contains(
            "Separate uncovered scopes Root only, Team/Web and its descendants require approval because unrelated " +
                "folder trees are isolated"
        ))
        XCTAssertTrue(prompt.contains("The active grant covers Team/API/Prod and its descendants"))
        XCTAssertFalse(prompt.contains("RootOne"))
        XCTAssertFalse(prompt.contains("API Nested"))
        XCTAssertFalse(prompt.contains("Shared"))
    }

    func testExpiredGrantUsesOrdinaryFirstApprovalWording() async throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.list],
            expiresAt: Date().addingTimeInterval(-60)
        )
        let store = MemoryAgentJITGrantStore([grant])
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API Nested", folderPath: "Team/API/Prod"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        let prompt = try XCTUnwrap(approver.requests.first?.prompt)
        XCTAssertTrue(prompt.contains("folder 'Team/API/Prod' and its descendants"))
        XCTAssertFalse(prompt.contains("Separate approval required"))
        XCTAssertFalse(prompt.contains("API Nested"))
    }

    func testPreflightFolderScopeReferenceIncludesDescendantItems() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
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

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(store.grants.map(\.folderScope), [.folder("Team/API")])
        XCTAssertEqual(store.grants.first?.requestedItems.map(\.name).sorted(), ["API", "API Nested", "Shared"])
        XCTAssertEqual(approver.requests.map(\.itemLabel), ["Team/API"])
    }

    func testNamedQueryInDescendantUsesRequestedAncestorScope() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "API Nested",
                    folderPath: "Team/API",
                    isFolderScoped: true
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.grantIDs.count, 1)
        XCTAssertEqual(store.grants.map(\.folderScope), [.folder("Team/API")])
        XCTAssertEqual(store.grants.first?.requestedItems.map(\.name), ["API Nested"])
        XCTAssertEqual(approver.requests.map(\.itemLabel), ["Team/API"])
    }

    func testPreflightMismatchedFolderFailsClosed() async throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore())
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/Web"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertEqual(response.error?.code, .notFound)
        XCTAssertNil(response.payload)
    }

    func testExecGrantMatchesExactFolder() throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            expiresAt: Date().addingTimeInterval(60)
        )
        let handler = makeHandler(store: MemoryAgentJITGrantStore([grant]))
        let request = makeRequest(type: .getPassword, requestedCommand: "exec")

        let result = try handler.agentJITGrant(capability: .exec, itemFolderPath: "Team/API", request: request)

        XCTAssertEqual(result?.id, grant.id)
    }

    func testAgentRuntimeContextDoesNotParticipateInGrantMatching() throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            expiresAt: Date().addingTimeInterval(60)
        )
        let handler = makeHandler(store: MemoryAgentJITGrantStore([grant]))
        let request = makeRequest(
            type: .getPassword,
            requestedCommand: "exec",
            agentRuntimeContext: AgentRuntimeContext(
                platform: "codex",
                sessionID: "new-session",
                turnID: "new-turn",
                agentID: "different-agent",
                agentType: "different",
                toolUseID: nil
            )
        )

        let result = try handler.agentJITGrant(capability: .exec, itemFolderPath: "Team/API", request: request)

        XCTAssertEqual(result?.id, grant.id)
    }


    func testExecGrantAllowsDescendantFolder() throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            expiresAt: Date().addingTimeInterval(60)
        )
        let handler = makeHandler(store: MemoryAgentJITGrantStore([grant]))
        let request = makeRequest(type: .getPassword, requestedCommand: "exec")

        let result = try handler.agentJITGrant(capability: .exec, itemFolderPath: "Team/API/Prod", request: request)

        XCTAssertEqual(result?.id, grant.id)
    }

    func testExecGrantRejectsListRequestedCommand() throws {
        let caller = callerFingerprint(requestedCommand: "list")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            expiresAt: Date().addingTimeInterval(60)
        )
        let handler = makeHandler(store: MemoryAgentJITGrantStore([grant]))
        let request = makeRequest(type: .getPassword, requestedCommand: "list")

        let result = try handler.agentJITGrant(capability: .exec, itemFolderPath: "Team/API", request: request)

        XCTAssertNil(result)
    }

    func testExecSecretReadWithValidInteractiveSessionKeepsSessionBehavior() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore())
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: execContext(requestedCommand: "exec").sessionScope
        )
        let request = makeRequest(type: .getPassword, requestedCommand: "exec", sessionToken: session.sessionToken)

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .allowed(approvedBy: "session", needsApproval: false, agentJITGrantID: nil))
    }

    func testHumanExecSecretReadWithoutJITKeepsSessionBehavior() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: humanCallerIdentity)
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: execContext(requestedCommand: "exec").sessionScope
        )
        let request = makeRequest(type: .getPassword, requestedCommand: "exec", sessionToken: session.sessionToken)

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .allowed(approvedBy: "session", needsApproval: false, agentJITGrantID: nil))
    }

    func testIDEHelperExecSecretReadWithValidSessionKeepsSessionBehavior() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: ideHelperCallerIdentity)
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: execContext(requestedCommand: "exec").sessionScope
        )
        let request = makeRequest(type: .getPassword, requestedCommand: "exec", sessionToken: session.sessionToken)

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .allowed(approvedBy: "session", needsApproval: false, agentJITGrantID: nil))
    }

    func testIDEHelperTTYAncestryWithoutSessionRemainsAgentClassified() {
        let request = makeRequest(type: .getPassword, requestedCommand: "exec")

        XCTAssertTrue(XPCRequestHandler.isAgentJITCaller(
            request: request,
            callerIdentity: ideHelperCallerIdentity
        ))
    }

    func testIDEHelperTTYWithCurrentMatchingSessionIsHumanClassified() throws {
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: execContext(requestedCommand: "exec").sessionScope
        )
        let request = makeRequest(
            type: .getPassword,
            requestedCommand: "exec",
            sessionToken: session.sessionToken
        )

        XCTAssertFalse(XPCRequestHandler.isAgentJITCaller(
            request: request,
            callerIdentity: ideHelperCallerIdentity
        ))
    }

    func testIDEHelperTTYWithCurrentSessionAndRuntimeContextRemainsAgentClassified() throws {
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: execContext(requestedCommand: "exec").sessionScope
        )
        let request = makeRequest(
            type: .getPassword,
            requestedCommand: "exec",
            sessionToken: session.sessionToken,
            agentRuntimeContext: agentRuntimeContext()
        )

        XCTAssertTrue(XPCRequestHandler.isAgentJITCaller(
            request: request,
            callerIdentity: ideHelperCallerIdentity
        ))
    }

    func testIDEHelperNoninteractiveWithCurrentSessionRemainsAgentClassified() throws {
        let context = nonInteractiveExecContext()
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: context.sessionScope
        )
        let request = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "",
            options: .init(field: nil, copy: false),
            context: context,
            sessionToken: session.sessionToken
        )

        XCTAssertTrue(XPCRequestHandler.isAgentJITCaller(
            request: request,
            callerIdentity: ideHelperCallerIdentity
        ))
    }

    func testIDEHelperExecSecretReadWithoutSessionBootstrapsViaBiometric() throws {
        // An IDE-terminal request without a validated session remains agent-classified. Separate
        // bootstrap eligibility lets this stdin-TTY request reach the ordinary biometric gate;
        // it is not a human-session authorization or an auto-allow.
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: ideHelperCallerIdentity)
        let request = makeRequest(type: .getPassword, requestedCommand: "exec")

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .allowed(approvedBy: "biometric", needsApproval: true, agentJITGrantID: nil))
    }

    func testIDEHelperRedirectedStdoutExecSecretReadBootstrapsViaBiometric() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: ideHelperCallerIdentity)
        let request = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "",
            options: .init(field: nil, copy: false),
            context: redirectedExecContext()
        )

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .allowed(approvedBy: "biometric", needsApproval: true, agentJITGrantID: nil))
    }

    func testIDEHelperRedirectedStdoutWithRuntimeContextRemainsJITOnly() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: ideHelperCallerIdentity)
        var context = redirectedExecContext()
        context = BridgeContext(
            isTTY: context.isTTY,
            isPiped: context.isPiped,
            isSSH: context.isSSH,
            isCI: context.isCI,
            timestamp: context.timestamp,
            requestedCommand: context.requestedCommand,
            sessionScope: context.sessionScope,
            workingDirectory: context.workingDirectory,
            agentRuntimeContext: agentRuntimeContext()
        )
        let request = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "",
            options: .init(field: nil, copy: false),
            context: context
        )

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .denied(
            code: .policyDenied,
            message: "Agent exec secret reads require a valid JIT preflight grant for this item scope."
        ))
    }

    func testAgentRuntimeContextExecSecretReadIgnoresSessionOverride() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: ideHelperCallerIdentity)
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: execContext(requestedCommand: "exec").sessionScope
        )
        let request = makeRequest(
            type: .getPassword,
            requestedCommand: "exec",
            sessionToken: session.sessionToken,
            agentRuntimeContext: AgentRuntimeContext(
                platform: "codex",
                sessionID: "s1",
                turnID: nil,
                agentID: nil,
                agentType: nil,
                toolUseID: nil
            )
        )

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .denied(
            code: .policyDenied,
            message: "Agent exec secret reads require a valid JIT preflight grant for this item scope."
        ))
    }

    func testIDEHelperNonInteractiveExecSecretReadFailsClosedEvenWithSession() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: ideHelperCallerIdentity)
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: nonInteractiveExecContext().sessionScope
        )
        let request = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "",
            options: .init(field: nil, copy: false),
            context: nonInteractiveExecContext(),
            sessionToken: session.sessionToken
        )

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .denied(
            code: .policyDenied,
            message: "Agent exec secret reads require a valid JIT preflight grant for this item scope."
        ))
    }

    func testNonInteractiveAgenticExecSecretReadFailsClosed() throws {
        // A piped (non-interactive) agent with agentic ancestry and no JIT grant must fail closed
        // even though it presents no agentRuntimeContext — the isTTY==false path classifies it as agent.
        let handler = makeHandler(store: MemoryAgentJITGrantStore())  // default caller = Claude parent (agentic)
        let request = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "",
            options: .init(field: nil, copy: false),
            context: BridgeContext(
                isTTY: false,
                isPiped: true,
                isSSH: false,
                isCI: false,
                timestamp: now,
                requestedCommand: "exec",
                sessionScope: execContext(requestedCommand: "exec").sessionScope,
                workingDirectory: "/tmp/project"
            )
        )

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .denied(
            code: .policyDenied,
            message: "Agent exec secret reads require a valid JIT preflight grant for this item scope."
        ))
    }

    func testExecSecretReadWithJITGrantCarriesGrantID() throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            expiresAt: Date().addingTimeInterval(60)
        )
        let handler = makeHandler(store: MemoryAgentJITGrantStore([grant]))
        // A confirmed agent (agentRuntimeContext) stays on the JIT path regardless of the TTY, so
        // the grant is consulted and its ID flows through. The runtime context does not participate
        // in grant matching, so the fixture grant still resolves.
        let request = makeRequest(
            type: .getPassword,
            requestedCommand: "exec",
            agentRuntimeContext: agentRuntimeContext()
        )

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .allowed(approvedBy: "jit", needsApproval: false, agentJITGrantID: grant.id))
    }

    func testJITSecretReadAuditInfersEnvironmentFromGrant() throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            expiresAt: Date().addingTimeInterval(60),
            environmentScope: .named("Production")
        )
        let (auditLogger, auditURL, tempDir) = try makeAuditLogger()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let handler = makeHandler(
            store: MemoryAgentJITGrantStore([grant]),
            auditLogger: auditLogger
        )

        handler.recordAudit(
            command: .getPassword,
            itemId: "item-1",
            approvedBy: "jit",
            caller: callerIdentity,
            requestedCommand: "exec",
            agentJITGrantID: grant.id
        )

        XCTAssertEqual(try auditRecords(at: auditURL).first?.environmentScope, .named("Production"))
    }

    func testAPIKeySecretReadUsesPasswordJITDecisionRules() throws {
        let directHandler = makeHandler(store: MemoryAgentJITGrantStore())
        // A confirmed agent (agentRuntimeContext) keeps the direct "get" on the JIT path so the
        // "authsia get is not allowed" denial is still exercised. Without it, ancestry remains
        // agentic, but stdin-TTY/no-runtime separately permits biometric bootstrap; that eligibility
        // is not human-session authorization.
        let directRequest = makeRequest(
            type: .getAPIKey,
            requestedCommand: "get",
            agentRuntimeContext: agentRuntimeContext()
        )

        let directDecision = directHandler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: directRequest,
            bypassApproval: false
        )

        XCTAssertEqual(directDecision, .denied(
            code: .policyDenied,
            message: "Agent JIT grants do not allow authsia get. Use authsia exec with an approved JIT grant to inject secrets into a command."
        ))

        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            expiresAt: Date().addingTimeInterval(60)
        )
        let execHandler = makeHandler(store: MemoryAgentJITGrantStore([grant]))
        let execRequest = makeRequest(
            type: .getAPIKey,
            requestedCommand: "exec",
            agentRuntimeContext: agentRuntimeContext()
        )

        let execDecision = execHandler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: execRequest,
            bypassApproval: false
        )

        XCTAssertEqual(execDecision, .allowed(approvedBy: "jit", needsApproval: false, agentJITGrantID: grant.id))
    }

    func testAgentDirectSecretReadWithValidInteractiveSessionKeepsSessionBehavior() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore())
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: execContext(requestedCommand: "get").sessionScope
        )
        let request = makeRequest(type: .getPassword, requestedCommand: "get", sessionToken: session.sessionToken)

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .allowed(approvedBy: "session", needsApproval: false, agentJITGrantID: nil))
    }

    func testAgentDirectSecretReadWithRuntimeContextFailsClosed() throws {
        // A confirmed agent (agentRuntimeContext) running `authsia get` stays on the JIT path and
        // is denied — direct secret reads are never allowed for agents. Without runtime context,
        // ancestry remains agentic, while stdin-TTY/no-runtime separately allows only biometric
        // bootstrap and does not establish a human session.
        let handler = makeHandler(store: MemoryAgentJITGrantStore())
        let request = makeRequest(
            type: .getPassword,
            requestedCommand: "get",
            agentRuntimeContext: agentRuntimeContext()
        )

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .denied(
            code: .policyDenied,
            message: "Agent JIT grants do not allow authsia get. Use authsia exec with an approved JIT grant to inject secrets into a command."
        ))
    }

    func testHumanDirectSecretReadWithoutJITKeepsSessionBehavior() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: humanCallerIdentity)
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: execContext(requestedCommand: "get").sessionScope
        )
        let request = makeRequest(type: .getPassword, requestedCommand: "get", sessionToken: session.sessionToken)

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .allowed(approvedBy: "session", needsApproval: false, agentJITGrantID: nil))
    }

    func testVSCodeTerminalDirectOTPReadWithoutJITReportsBiometricBootstrap() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: vscodeTerminalCallerIdentity)
        let request = makeRequest(type: .getOTP, requestedCommand: "get")

        let decision = handler.unsupportedAgentJITSecretReadDecision(
            request: request,
            itemKind: "otp"
        )

        XCTAssertEqual(decision, .allowed(approvedBy: "biometric", needsApproval: true, agentJITGrantID: nil))
    }

    func testAgentExecOTPAndSSHReadsFailClosedWithoutJITSupport() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore())
        // A confirmed agent (agentRuntimeContext) stays agentic regardless of the interactive TTY,
        // so exec OTP/SSH reads keep hitting the "not supported" denial. Without runtime context,
        // ancestry remains agentic; stdin-TTY/no-runtime separately permits the biometric bootstrap
        // path and is not session authorization.
        let request = makeRequest(
            type: .getOTP,
            requestedCommand: "exec",
            agentRuntimeContext: agentRuntimeContext()
        )

        let otpDecision = handler.unsupportedAgentJITSecretReadDecision(
            request: request,
            itemKind: "otp"
        )
        let sshDecision = handler.unsupportedAgentJITSecretReadDecision(
            request: makeRequest(
                type: .getSSH,
                requestedCommand: "exec",
                agentRuntimeContext: agentRuntimeContext()
            ),
            itemKind: "ssh key"
        )

        XCTAssertEqual(otpDecision, .denied(
            code: .policyDenied,
            message: "Agent exec JIT does not support otp items."
        ))
        XCTAssertEqual(sshDecision, .denied(
            code: .policyDenied,
            message: "Agent exec JIT does not support ssh key items."
        ))
    }

    func testAutomationBypassStillAllowsExecSecretReadWithoutJIT() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore())
        let request = makeRequest(type: .getPassword, requestedCommand: "exec")

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: true
        )

        XCTAssertEqual(decision, .allowed(approvedBy: "automation", needsApproval: false, agentJITGrantID: nil))
    }

    func testListFilteringUsesActiveSubtreeGrantAndCliEnabledItems() throws {
        let caller = callerFingerprint(requestedCommand: "list")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let handler = makeHandler(store: MemoryAgentJITGrantStore([grant]))
        let request = makeRequest(
            type: .list,
            requestedCommand: "list",
            agentRuntimeContext: agentRuntimeContext()
        )

        let filtered = handler.filteredListPayload(listPayload(), for: request)

        XCTAssertEqual(filtered.accounts, [])
        XCTAssertEqual(filtered.passwords.map(\.name), ["API", "API Nested", "Shared"])
        XCTAssertEqual(filtered.apiKeys.map(\.name), ["API Key"])
        XCTAssertEqual(filtered.certificates.map(\.name), ["API Cert"])
        XCTAssertEqual(filtered.notes.map(\.title), ["API Note"])
        XCTAssertEqual(filtered.sshKeys.map(\.name), ["API SSH", "Nested SSH"])
    }

    func testListWithoutActiveJITGrantKeepsExistingListBehavior() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore())
        let request = makeRequest(type: .list, requestedCommand: "list")
        let payload = listPayload()

        let filtered = handler.filteredListPayload(payload, for: request)

        XCTAssertEqual(filtered, payload)
    }

    func testAgentListWithoutJITGrantRequiresPreflight() async throws {
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), approver: approver)

        // Interactive callers can now bootstrap a session via biometric, so this denial requires a
        // confirmed agent marker (agentRuntimeContext) — the unforgeable "this is really an agent"
        // signal that keeps a real agent on the JIT path regardless of the interactive TTY.
        let response = try await list(
            handler,
            requestedCommand: "list",
            agentRuntimeContext: agentRuntimeContext()
        )

        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertEqual(
            response.error?.message,
            "Agent list requests require a valid JIT preflight grant for a supported Vault scope."
        )
        XCTAssertEqual(approver.requests, [])
        XCTAssertNil(response.payload)
    }

    func testListPathWithActiveJITGrantSkipsApprovalAndReturnsScopedItems() async throws {
        let caller = callerFingerprint(requestedCommand: "list")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: MemoryAgentJITGrantStore([grant]), approver: approver)
        let response = try await list(
            handler,
            requestedCommand: "list",
            agentRuntimeContext: agentRuntimeContext()
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(approver.requests, [])
        XCTAssertEqual(response.payload?.accounts, [])
        XCTAssertEqual(response.payload?.passwords.map(\.name), ["API", "API Nested", "Shared"])
        XCTAssertEqual(response.payload?.apiKeys.map(\.name), ["API Key"])
        XCTAssertEqual(response.payload?.certificates.map(\.name), ["API Cert"])
        XCTAssertEqual(response.payload?.notes.map(\.title), ["API Note"])
        XCTAssertEqual(response.payload?.sshKeys.map(\.name), ["API SSH", "Nested SSH"])
    }

    func testExecInternalListPathWithActiveJITGrantSkipsApprovalAndReturnsScopedItems() async throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: MemoryAgentJITGrantStore([grant]), approver: approver)
        let response = try await list(
            handler,
            requestedCommand: "exec",
            agentRuntimeContext: agentRuntimeContext()
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(approver.requests, [])
        XCTAssertEqual(response.payload?.accounts, [])
        XCTAssertEqual(response.payload?.passwords.map(\.name), ["API", "API Nested", "Shared"])
        XCTAssertEqual(response.payload?.apiKeys.map(\.name), ["API Key"])
        XCTAssertEqual(response.payload?.certificates.map(\.name), ["API Cert"])
        XCTAssertEqual(response.payload?.notes.map(\.title), ["API Note"])
        XCTAssertEqual(response.payload?.sshKeys.map(\.name), ["API SSH", "Nested SSH"])
    }

    func testTTYBootstrapIgnoresMatchingActiveJITGrantAndRequiresBiometric() async throws {
        let caller = callerFingerprint(requestedCommand: "list")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: MemoryAgentJITGrantStore([grant]), approver: approver)

        let response = try await list(handler, requestedCommand: "list")

        XCTAssertNil(response.error)
        XCTAssertEqual(approver.requests.map(\.command), [.list])
        XCTAssertNotNil(response.sessionToken)
        XCTAssertEqual(response.payload?.accounts.map(\.issuer), ["OTP"])
        XCTAssertEqual(
            response.payload?.passwords.map(\.name),
            ["RootOne", "API", "API Nested", "API Disabled", "Web", "Shared", "Shared"]
        )
        XCTAssertEqual(response.payload?.apiKeys.map(\.name), ["API Key", "API Key Disabled", "Web Key"])
        XCTAssertEqual(response.payload?.certificates.map(\.name), ["API Cert", "Web Cert"])
        XCTAssertEqual(response.payload?.notes.map(\.title), ["RootNote", "API Note", "API Disabled Note"])
        XCTAssertEqual(response.payload?.sshKeys.map(\.name), ["API SSH", "Nested SSH"])
    }

    func testAgentExecInternalListWithoutJITGrantReturnsNoVaultMetadata() async throws {
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), approver: approver)

        // A confirmed agent (agentRuntimeContext) stays on the JIT path and is not offered the
        // interactive bootstrap, so its ungranted exec-internal list yields no vault metadata.
        let response = try await list(
            handler,
            requestedCommand: "exec",
            agentRuntimeContext: agentRuntimeContext()
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(approver.requests, [])
        XCTAssertEqual(response.payload, BridgeListPayload(accounts: [], passwords: [], certificates: [], notes: [], sshKeys: []))
    }

    func testAgentLoadInternalListWithoutJITGrantExplainsUnsupportedCommand() async throws {
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), approver: approver)

        let response = try await list(
            handler,
            requestedCommand: "load",
            agentRuntimeContext: agentRuntimeContext()
        )

        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertEqual(
            response.error?.message,
            "Agent JIT grants do not allow authsia load. Use authsia exec with an approved JIT grant to inject secrets into a command."
        )
        XCTAssertEqual(approver.requests, [])
        XCTAssertNil(response.payload)
    }

    func testAgentRuntimeLoadInternalListWithoutJITGrantExplainsUnsupportedCommand() async throws {
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(
            store: MemoryAgentJITGrantStore(),
            approver: approver,
            callerIdentity: humanCallerIdentity
        )

        let response = try await list(
            handler,
            requestedCommand: "load",
            agentRuntimeContext: agentRuntimeContext()
        )

        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertEqual(
            response.error?.message,
            "Agent JIT grants do not allow authsia load. Use authsia exec with an approved JIT grant to inject secrets into a command."
        )
        XCTAssertEqual(approver.requests, [])
        XCTAssertNil(response.payload)
    }

    func testAutomationCredentialLoadInternalListFromAgentBypassesJITDenial() async throws {
        let credentialID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        let credential = AutomationCredentialLookup.CredentialRecord(
            id: credentialID,
            scope: "Team/API",
            expiresAt: Date().addingTimeInterval(60),
            revokedAt: nil,
            machineId: "machine-1",
            allowedCommands: [.load]
        )
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(
            store: MemoryAgentJITGrantStore(),
            approver: approver,
            automationCredentialLookupProvider: { id in
                id == credentialID ? .found(credential) : .credentialNotFound
            },
            currentMachineIdProvider: { "machine-1" }
        )

        let response = try await list(
            handler,
            requestedCommand: "load",
            automationCredentialID: credentialID.uuidString
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(approver.requests, [])
        XCTAssertEqual(response.payload?.accounts, [])
        XCTAssertEqual(response.payload?.passwords.map(\.name), ["API", "API Nested", "Shared"])
        XCTAssertEqual(response.payload?.certificates.map(\.name), ["API Cert"])
        XCTAssertEqual(response.payload?.notes.map(\.title), ["API Note"])
        XCTAssertEqual(response.payload?.sshKeys.map(\.name), ["API SSH", "Nested SSH"])
    }

    func testAgentGetInternalListWithoutJITGrantExplainsUnsupportedCommand() async throws {
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), approver: approver)

        let response = try await list(
            handler,
            requestedCommand: "get",
            agentRuntimeContext: agentRuntimeContext()
        )

        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertEqual(
            response.error?.message,
            "Agent JIT grants do not allow authsia get. Use authsia exec with an approved JIT grant to inject secrets into a command."
        )
        XCTAssertEqual(approver.requests, [])
        XCTAssertNil(response.payload)
    }

    func testAutomationCredentialSkipsJITOnlySSHReadDenial() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore())
        let request = makeRequest(
            type: .getSSH,
            requestedCommand: "get",
            automationCredentialID: UUID().uuidString
        )

        let decision = handler.unsupportedAgentJITSecretReadDecision(
            request: request,
            itemKind: "ssh key"
        )

        XCTAssertEqual(decision, .allowed(approvedBy: "automation", needsApproval: false, agentJITGrantID: nil))
    }

    func testAgentRuntimeDirectSecretReadWithSessionButNoJITGrantFailsClosed() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: humanCallerIdentity)
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: execContext(requestedCommand: "get").sessionScope
        )
        let request = makeRequest(
            type: .getPassword,
            requestedCommand: "get",
            sessionToken: session.sessionToken,
            agentRuntimeContext: agentRuntimeContext()
        )

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .denied(
            code: .policyDenied,
            message: "Agent JIT grants do not allow authsia get. Use authsia exec with an approved JIT grant to inject secrets into a command."
        ))
    }

    func testAgentRuntimeUnlockIsDeniedBeforeApproval() async throws {
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(
            store: MemoryAgentJITGrantStore(),
            approver: approver,
            callerIdentity: humanCallerIdentity
        )
        let request = makeRequest(
            type: .unlock,
            requestedCommand: nil,
            agentRuntimeContext: agentRuntimeContext()
        )

        let response: BridgeResponse<UnlockPayload> = try await bridgeResponse(
            for: request,
            description: "unlock reply"
        ) { requestData, reply in
            handler.unlock(requestData, reply)
        }

        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertEqual(
            response.error?.message,
            "Agent JIT grants do not allow authsia unlock. JIT grants only permit authsia list and authsia exec."
        )
        XCTAssertEqual(approver.requests, [])
        XCTAssertNil(response.payload)
    }

    func testIDEHelperTTYUnlockWithoutSessionReachesBiometricApproval() async throws {
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(
            store: MemoryAgentJITGrantStore(),
            approver: approver,
            callerIdentity: ideHelperCallerIdentity
        )
        let request = makeRequest(type: .unlock, requestedCommand: nil)

        let response: BridgeResponse<UnlockPayload> = try await bridgeResponse(
            for: request,
            description: "bootstrap unlock reply"
        ) { requestData, reply in
            handler.unlock(requestData, reply)
        }

        XCTAssertNil(response.error)
        XCTAssertNotNil(response.payload?.sessionToken)
        XCTAssertEqual(approver.requests.map(\.command), [.unlock])
    }

    func testAgentRuntimeWriteAndExportCommandsAreDeniedBeforeApproval() async throws {
        let password = passwordMetadata(name: "API")
        let repository = EmptyVaultRepository(passwords: [password])
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(
            store: MemoryAgentJITGrantStore(),
            approver: approver,
            repository: repository,
            callerIdentity: humanCallerIdentity
        )
        let cases: [(BridgeRequestType, String?, String, String, Data?, (Data, @escaping (Data?, NSError?) -> Void) -> Void)] = [
            (
                .addPassword,
                nil,
                "add",
                "",
                try BridgeCoder.encode(PasswordWritePayload(
                    name: "New",
                    username: "user",
                    password: "secret",
                    website: nil,
                    notes: nil
                )),
                { requestData, reply in handler.addItem(requestData, reply) }
            ),
            (
                .updatePassword,
                nil,
                "edit",
                "API",
                try BridgeCoder.encode(PasswordWritePayload(
                    name: "Renamed",
                    username: nil,
                    password: nil,
                    website: nil,
                    notes: nil
                )),
                { requestData, reply in handler.updateItem(requestData, reply) }
            ),
            (
                .deletePassword,
                nil,
                "delete",
                "API",
                nil,
                { requestData, reply in handler.deleteItem(requestData, reply) }
            ),
            (
                .exportAccounts,
                nil,
                "export",
                "",
                try BridgeCoder.encode(ExportAccountsRequestPayload(password: nil)),
                { requestData, reply in handler.exportAccounts(requestData, reply) }
            ),
        ]

        for (type, requestedCommand, expectedCommand, query, body, route) in cases {
            let request = makeRequest(
                type: type,
                query: query,
                requestedCommand: requestedCommand,
                body: body,
                agentRuntimeContext: agentRuntimeContext()
            )
            let response: BridgeResponse<WriteResultPayload> = try await bridgeResponse(
                for: request,
                description: "\(expectedCommand) reply",
                route: route
            )

            XCTAssertEqual(response.error?.code, .policyDenied, "expected policy denial for \(expectedCommand)")
            XCTAssertEqual(
                response.error?.message,
                "Agent JIT grants do not allow authsia \(expectedCommand). JIT grants only permit authsia list and authsia exec."
            )
            XCTAssertNil(response.payload)
        }
        XCTAssertEqual(approver.requests, [])
    }

    func testAgentRuntimeCreateAccessIsDeniedBeforeApproval() async throws {
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(
            store: MemoryAgentJITGrantStore(),
            approver: approver,
            callerIdentity: humanCallerIdentity
        )
        let payload = AccessCreateApprovalPayload(
            name: "Agent",
            scope: "Team/API",
            ttlSeconds: 900,
            expiresAt: now.addingTimeInterval(900),
            machineId: "machine",
            machineName: "Mac",
            allowedCommands: ["exec"]
        )
        let request = makeRequest(
            type: .createAccess,
            query: "Team/API",
            requestedCommand: "access",
            body: try BridgeCoder.encode(payload),
            agentRuntimeContext: agentRuntimeContext()
        )

        let response: BridgeResponse<WriteResultPayload> = try await bridgeResponse(
            for: request,
            description: "create access reply"
        ) { requestData, reply in
            handler.addItem(requestData, reply)
        }

        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertEqual(
            response.error?.message,
            "Agent JIT grants do not allow authsia access. JIT grants only permit authsia list and authsia exec."
        )
        XCTAssertEqual(approver.requests, [])
        XCTAssertNil(response.payload)
    }

    func testListPathFailsClosedWhenActiveJITScopeLookupThrows() async throws {
        let store = MemoryAgentJITGrantStore()
        store.markUsedScopesError = AgentJITGrantStoreError.corruptedStore
        let handler = makeHandler(store: store)

        let response = try await list(
            handler,
            requestedCommand: "list",
            agentRuntimeContext: agentRuntimeContext()
        )

        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertNil(response.payload)
    }

    func testPreflightDoesNotSavePartialGrantWhenLaterScopeDenied() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(results: [true, false])
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
                AgentJITPreflightReference(type: "cert", query: "Web Cert", folderPath: "Team/Web"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertEqual(response.error?.code, .notAuthorized)
        XCTAssertEqual(store.grants, [])
        XCTAssertEqual(approver.requests.map(\.itemLabel), ["Team/API", "Team/Web"])
    }

    private func makeHandler(
        store: MemoryAgentJITGrantStore,
        approver: JITApprovalTracker = JITApprovalTracker(result: true),
        repository: VaultRepositoryProviding? = nil,
        automationCredentialLookupProvider: @escaping XPCRequestHandler.AutomationCredentialLookupProvider = {
            _ in .fileMissing
        },
        currentMachineIdProvider: @escaping XPCRequestHandler.CurrentMachineIdProvider = {
            nil
        },
        auditLogger: BridgeAuditLogger? = nil,
        callerIdentity: CallerIdentity? = nil
    ) -> XPCRequestHandler {
        XPCRequestHandler(
            listProvider: listPayload,
            approver: approver,
            repository: repository ?? EmptyVaultRepository(),
            automationCredentialLookupProvider: automationCredentialLookupProvider,
            currentMachineIdProvider: currentMachineIdProvider,
            agentJITGrantStore: store,
            callerIdentityProvider: { callerIdentity ?? self.callerIdentity },
            auditLogger: auditLogger ?? makeIsolatedAuditLogger()
        )
    }

    private func makeIsolatedAuditLogger() -> BridgeAuditLogger {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        isolatedAuditDirectories.append(tempDir)
        return BridgeAuditLogger(
            fileURL: tempDir.appendingPathComponent("bridge_audit.log"),
            hmacKeyProvider: { SymmetricKey(data: Data(repeating: 0xA5, count: 32)) }
        )
    }

    private func makeAuditLogger() throws -> (BridgeAuditLogger, URL, URL) {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent("bridge_audit.log")
        return (
            BridgeAuditLogger(
                fileURL: fileURL,
                hmacKeyProvider: { SymmetricKey(data: Data(repeating: 0xA5, count: 32)) }
            ),
            fileURL,
            tempDir
        )
    }

    private func auditRecords(at fileURL: URL) throws -> [BridgeAuditRecord] {
        let data = try Data(contentsOf: fileURL)
        return try data.split(separator: 0x0A).map { line in
            try BridgeCoder.decode(AuditLineFixture.self, from: Data(line)).record
        }
    }

    private func addItem<T: Codable & Equatable>(
        _ handler: XPCRequestHandler,
        body: T,
        requestedCommand: String = "exec"
    ) async throws -> BridgeResponse<AgentJITPreflightResultPayload> {
        let request = BridgeRequest(
            id: UUID(),
            type: .agentJITPreflight,
            query: "",
            options: .init(field: nil, copy: false),
            context: execContext(requestedCommand: requestedCommand),
            body: try BridgeCoder.encode(body)
        )
        let requestData = try BridgeCoder.encode(request)
        let expectation = XCTestExpectation(description: "preflight reply")
        var responseData: Data?
        handler.addItem(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)
        return try BridgeCoder.decode(
            BridgeResponse<AgentJITPreflightResultPayload>.self,
            from: try XCTUnwrap(responseData)
        )
    }

    private func list(
        _ handler: XPCRequestHandler,
        requestedCommand: String,
        automationCredentialID: String? = nil,
        agentRuntimeContext: AgentRuntimeContext? = nil
    ) async throws -> BridgeResponse<BridgeListPayload> {
        let request = makeRequest(
            type: .list,
            requestedCommand: requestedCommand,
            automationCredentialID: automationCredentialID,
            agentRuntimeContext: agentRuntimeContext
        )
        let requestData = try BridgeCoder.encode(request)
        let expectation = XCTestExpectation(description: "list reply")
        var responseData: Data?
        handler.list(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)
        return try BridgeCoder.decode(
            BridgeResponse<BridgeListPayload>.self,
            from: try XCTUnwrap(responseData)
        )
    }

    private func bridgeResponse<T: Codable & Equatable>(
        for request: BridgeRequest,
        description: String,
        route: (_ requestData: Data, _ reply: @escaping (Data?, NSError?) -> Void) -> Void
    ) async throws -> BridgeResponse<T> {
        let requestData = try BridgeCoder.encode(request)
        let expectation = XCTestExpectation(description: description)
        var responseData: Data?
        route(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)
        return try BridgeCoder.decode(
            BridgeResponse<T>.self,
            from: try XCTUnwrap(responseData)
        )
    }

    private func makeRequest(
        type: BridgeRequestType,
        query: String = "",
        requestedCommand: String?,
        body: Data? = nil,
        sessionToken: String? = nil,
        automationCredentialID: String? = nil,
        agentRuntimeContext: AgentRuntimeContext? = nil
    ) -> BridgeRequest {
        BridgeRequest(
            id: UUID(),
            type: type,
            query: query,
            options: .init(field: nil, copy: false),
            context: execContext(
                requestedCommand: requestedCommand,
                automationCredentialID: automationCredentialID,
                agentRuntimeContext: agentRuntimeContext
            ),
            body: body,
            sessionToken: sessionToken
        )
    }

    private func execContext(
        requestedCommand: String? = "exec",
        automationCredentialID: String? = nil,
        agentRuntimeContext: AgentRuntimeContext? = nil
    ) -> BridgeContext {
        BridgeContext(
            isTTY: true,
            isPiped: false,
            isSSH: false,
            isCI: false,
            timestamp: now,
            automationCredentialID: automationCredentialID,
            requestedCommand: requestedCommand,
            sessionScope: "tty:/dev/ttys001",
            workingDirectory: "/repo",
            agentRuntimeContext: agentRuntimeContext
        )
    }

    private func nonInteractiveExecContext(requestedCommand: String? = "exec") -> BridgeContext {
        BridgeContext(
            isTTY: false,
            isPiped: true,
            isSSH: false,
            isCI: false,
            timestamp: now,
            requestedCommand: requestedCommand,
            sessionScope: execContext(requestedCommand: requestedCommand).sessionScope,
            workingDirectory: "/tmp/project"
        )
    }

    private func redirectedExecContext(requestedCommand: String? = "exec") -> BridgeContext {
        BridgeContext(
            isTTY: true,
            isPiped: true,
            isSSH: false,
            isCI: false,
            timestamp: now,
            requestedCommand: requestedCommand,
            sessionScope: execContext(requestedCommand: requestedCommand).sessionScope,
            workingDirectory: "/tmp/project"
        )
    }

    private func agentRuntimeContext() -> AgentRuntimeContext {
        AgentRuntimeContext(
            platform: "claude-code",
            sessionID: "session",
            turnID: "turn",
            agentID: "agent",
            agentType: "assistant",
            toolUseID: "tool-use"
        )
    }

    private func callerFingerprint(requestedCommand: String) -> AgentJITCallerFingerprint {
        let context = execContext(requestedCommand: requestedCommand)
        return AgentJITCallerFingerprint(
            processName: callerIdentity.processName,
            bundleIdentifier: callerIdentity.bundleIdentifier,
            signingTeamId: callerIdentity.signingTeamId,
            signingIdentity: callerIdentity.signingIdentity,
            parentProcessName: callerIdentity.parentProcess?.processName,
            parentBundleIdentifier: callerIdentity.parentProcess?.bundleIdentifier,
            hostProcessName: callerIdentity.hostProcess?.processName,
            hostBundleIdentifier: callerIdentity.hostProcess?.bundleIdentifier,
            sessionScope: context.sessionScope,
            workingDirectory: context.workingDirectory
        )
    }

    private func listPayload() -> BridgeListPayload {
        BridgeListPayload(
            accounts: [
                BridgeAccount(
                    id: UUID(),
                    issuer: "OTP",
                    label: "otp",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now
                ),
            ],
            passwords: [
                password("RootOne", folderPath: nil),
                password("API", folderPath: "Team/API"),
                password("API Nested", folderPath: "Team/API/Prod"),
                password("API Disabled", folderPath: "Team/API", isCliEnabled: false),
                password("Web", folderPath: "Team/Web"),
                password("Shared", folderPath: "Team/API"),
                password("Shared", folderPath: "Team/Web"),
            ],
            apiKeys: [
                apiKey("API Key", folderPath: "Team/API"),
                apiKey("API Key Disabled", folderPath: "Team/API", isCliEnabled: false),
                apiKey("Web Key", folderPath: "Team/Web"),
            ],
            certificates: [
                certificate("API Cert", folderPath: "Team/API"),
                certificate("Web Cert", folderPath: "Team/Web"),
            ],
            notes: [
                note("RootNote", folderPath: nil),
                note("API Note", folderPath: "Team/API"),
                note("API Disabled Note", folderPath: "Team/API", isCliEnabled: false),
            ],
            sshKeys: [
                sshKey("API SSH", folderPath: "Team/API"),
                sshKey("Nested SSH", folderPath: "Team/API/Prod"),
            ]
        )
    }

    private func password(
        _ name: String,
        folderPath: String?,
        isCliEnabled: Bool = true
    ) -> BridgePassword {
        BridgePassword(
            id: UUID(),
            name: name,
            username: "user",
            website: nil,
            folderPath: folderPath,
            isFavorite: false,
            isCliEnabled: isCliEnabled,
            isScraped: false,
            createdAt: now,
            updatedAt: now
        )
    }

    private func apiKey(
        _ name: String,
        folderPath: String?,
        isCliEnabled: Bool = true
    ) -> BridgeAPIKey {
        BridgeAPIKey(
            id: UUID(),
            name: name,
            website: nil,
            folderPath: folderPath,
            isFavorite: false,
            isCliEnabled: isCliEnabled,
            isScraped: false,
            createdAt: now,
            updatedAt: now
        )
    }

    private func passwordMetadata(name: String, folderPath: String? = nil) -> PasswordMetadata {
        PasswordMetadata(
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

    private func certificate(_ name: String, folderPath: String?) -> BridgeCertificate {
        BridgeCertificate(
            id: UUID(),
            name: name,
            issuer: nil,
            subject: nil,
            expirationDate: nil,
            folderPath: folderPath,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            createdAt: now,
            updatedAt: now
        )
    }

    private func note(
        _ title: String,
        folderPath: String?,
        isCliEnabled: Bool = true
    ) -> BridgeNote {
        BridgeNote(
            id: UUID(),
            title: title,
            folderPath: folderPath,
            isFavorite: false,
            isCliEnabled: isCliEnabled,
            isScraped: false,
            createdAt: now,
            updatedAt: now
        )
    }

    private func sshKey(_ name: String, folderPath: String?) -> BridgeSSHKey {
        BridgeSSHKey(
            id: UUID(),
            name: name,
            comment: "",
            fingerprint: "SHA256:\(name)",
            publicKey: "ssh-ed25519 AAAA",
            folderPath: folderPath,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            createdAt: now,
            updatedAt: now
        )
    }
}

private struct AuditLineFixture: Decodable {
    let record: BridgeAuditRecord
}

private final class MemoryAgentJITGrantStore: AgentJITGrantStoring {
    var grants: [AgentJITGrant]
    var markUsedScopesError: Error?

    init(_ grants: [AgentJITGrant] = []) {
        self.grants = grants
    }

    func loadAll() throws -> [AgentJITGrant] {
        grants
    }

    func save(_ grant: AgentJITGrant) throws {
        try saveAll([grant])
    }

    func saveAll(_ newGrants: [AgentJITGrant]) throws {
        var updatedGrants = grants
        for grant in newGrants {
            if let index = updatedGrants.firstIndex(where: { $0.id == grant.id }) {
                updatedGrants[index] = grant
            } else {
                updatedGrants.append(grant)
            }
        }
        grants = updatedGrants
    }

    func markUsed(id: UUID, at date: Date) throws -> AgentJITGrant {
        guard let index = grants.firstIndex(where: { $0.id == id }) else {
            throw AgentJITGrantStoreError.notFound(id)
        }
        let updated = grants[index].copy(lastUsedAt: date)
        grants[index] = updated
        return updated
    }

    func revoke(id: UUID, revokedAt date: Date) throws -> AgentJITGrant {
        guard let index = grants.firstIndex(where: { $0.id == id }) else {
            throw AgentJITGrantStoreError.notFound(id)
        }
        let updated = grants[index].copy(revokedAt: date)
        grants[index] = updated
        return updated
    }

    func revokeClosedTerminalGrants(now: Date) throws -> [AgentJITGrant] {
        []
    }

    func markUsedIfAllowed(
        capability: AgentJITCapability,
        itemFolderPath: String?,
        itemEnvironments: [String],
        caller: AgentJITCallerFingerprint,
        now: Date
    ) throws -> AgentJITGrant? {
        guard let grant = grants.first(where: {
            $0.allows(
                capability: capability,
                itemFolderPath: itemFolderPath,
                caller: caller,
                now: now
            )
        }) else {
            return nil
        }
        return try markUsed(id: grant.id, at: now)
    }

    func markUsedScopes(
        capability: AgentJITCapability,
        caller: AgentJITCallerFingerprint,
        now: Date
    ) throws -> [AgentJITFolderScope] {
        if let markUsedScopesError {
            throw markUsedScopesError
        }
        let matchingIDs = grants.filter {
            $0.status(asOf: now) == .active
                && $0.capabilities.contains(capability)
                && $0.callerFingerprint.matches(caller)
        }.map(\.id)

        for id in matchingIDs {
            _ = try markUsed(id: id, at: now)
        }

        return grants.filter { matchingIDs.contains($0.id) }.map(\.folderScope)
    }
}

private final class JITApprovalTracker: BridgeApprover {
    struct Request: Equatable {
        let prompt: String
        let command: BridgeRequestType
        let itemLabel: String?
        let field: String?
        let remoteRequests: [RemoteJITApprovalRequest]
    }

    private var results: [RemoteJITApprovalOutcome]
    private(set) var requests: [Request] = []

    init(result: Bool) {
        self.results = [Self.outcome(for: result)]
    }

    init(results: [Bool]) {
        self.results = results.map(Self.outcome(for:))
    }

    init(outcome: RemoteJITApprovalOutcome) {
        self.results = [outcome]
    }

    init(outcomes: [RemoteJITApprovalOutcome]) {
        self.results = outcomes
    }

    func requestApproval(
        prompt: String,
        command: BridgeRequestType,
        itemLabel: String?,
        field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?,
        remoteRequests: [RemoteJITApprovalRequest]
    ) async -> RemoteJITApprovalOutcome {
        requests.append(
            Request(
                prompt: prompt,
                command: command,
                itemLabel: itemLabel,
                field: field,
                remoteRequests: remoteRequests
            )
        )
        if results.count > 1 {
            return results.removeFirst()
        }
        return results.first ?? .denied(source: .macBiometric)
    }

    private static func outcome(for result: Bool) -> RemoteJITApprovalOutcome {
        result ? .approved(source: .macBiometric) : .denied(source: .macBiometric)
    }
}

@MainActor
private final class EmptyVaultRepository: VaultRepositoryProviding {
    var passwords: [PasswordMetadata]
    var apiKeys: [APIKeyMetadata] { [] }
    var certificates: [CertificateMetadata] { [] }
    var notes: [SecureNoteMetadata] { [] }
    var sshKeys: [SSHKeyMetadata] { [] }
    var hasLoadedVaultState = false

    init(passwords: [PasswordMetadata] = []) {
        self.passwords = passwords
    }

    func load() throws {}
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

private extension AgentJITGrant {
    static func fixture(
        id: UUID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
        callerFingerprint: AgentJITCallerFingerprint,
        folderScope: AgentJITFolderScope,
        capabilities: Set<AgentJITCapability>,
        createdAt: Date = Date(timeIntervalSince1970: 1_700_000_000),
        expiresAt: Date,
        revokedAt: Date? = nil,
        lastUsedAt: Date? = nil,
        environmentScope: EnvironmentAccessScope? = nil
    ) -> AgentJITGrant {
        AgentJITGrant(
            id: id,
            agentName: "Codex",
            callerFingerprint: callerFingerprint,
            folderScope: folderScope,
            capabilities: capabilities,
            createdAt: createdAt,
            expiresAt: expiresAt,
            revokedAt: revokedAt,
            lastUsedAt: lastUsedAt,
            requestedItems: [],
            agentRuntimeContext: nil,
            approvedBy: "biometric",
            environmentScope: environmentScope
        )
    }

    func copy(revokedAt: Date? = nil, lastUsedAt: Date? = nil) -> AgentJITGrant {
        AgentJITGrant(
            id: id,
            agentName: agentName,
            callerFingerprint: callerFingerprint,
            folderScope: folderScope,
            capabilities: capabilities,
            createdAt: createdAt,
            expiresAt: expiresAt,
            revokedAt: revokedAt ?? self.revokedAt,
            lastUsedAt: lastUsedAt ?? self.lastUsedAt,
            requestedItems: requestedItems,
            agentRuntimeContext: agentRuntimeContext,
            approvedBy: approvedBy
        )
    }
}
