import XCTest
import Security
@testable import AuthsiaBridgeHost
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData

@MainActor
final class XPCRequestHandlerListApprovalTests: XCTestCase {
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

    func testListCreatesSessionAfterApproval() async {
        let approver = ApprovalTracker(result: true)
        let listProvider = ListProvider()
        let handler = XPCRequestHandler(
            listProvider: listProvider.fetch,
            approver: approver
        )

        let firstRequestData = makeListRequest()
        let first = XCTestExpectation(description: "first list reply")
        var firstResponseData: Data?
        handler.list(firstRequestData) { data, _ in
            firstResponseData = data
            first.fulfill()
        }
        await fulfillment(of: [first], timeout: 1)

        let firstResponse = try? BridgeCoder.decode(BridgeResponse<BridgeListPayload>.self, from: firstResponseData ?? Data())
        let sessionToken = firstResponse?.sessionToken
        XCTAssertNotNil(sessionToken)

        let secondRequestData = makeListRequest(sessionToken: sessionToken)
        let second = XCTestExpectation(description: "second list reply")
        handler.list(secondRequestData) { _, _ in
            second.fulfill()
        }
        await fulfillment(of: [second], timeout: 1)

        XCTAssertEqual(approver.callCount, 1)
        XCTAssertEqual(approver.remoteRequests, [[]])
        XCTAssertEqual(listProvider.callCount, 2)
    }

    func testListFailsClosedWhenGlobalCLIAccessIsDisabled() async throws {
        BridgeSettings.appDefaults.set(false, forKey: cliAccessEnabledKey)
        let approver = ApprovalTracker(result: true)
        let listProvider = ListProvider()
        let handler = XPCRequestHandler(
            listProvider: listProvider.fetch,
            approver: approver
        )
        let expectation = XCTestExpectation(description: "disabled CLI reply")
        var responseData: Data?

        handler.list(makeListRequest()) { data, _ in
            responseData = data
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        let response = try BridgeCoder.decode(
            BridgeResponse<BridgeListPayload>.self,
            from: try XCTUnwrap(responseData)
        )
        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertEqual(approver.callCount, 0)
        XCTAssertEqual(listProvider.callCount, 0)
    }

    func testListFailsClosedWhenApprovalCallbackIsUnavailable() async throws {
        let approver = CallbackRequiredApprover()
        let listProvider = ListProvider()
        let handler = XPCRequestHandler(
            listProvider: listProvider.fetch,
            approver: approver
        )
        let expectation = XCTestExpectation(description: "missing callback reply")
        var responseData: Data?

        handler.list(makeListRequest()) { data, _ in
            responseData = data
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        let response = try BridgeCoder.decode(
            BridgeResponse<BridgeListPayload>.self,
            from: try XCTUnwrap(responseData)
        )
        XCTAssertEqual(response.error?.code, .notAuthorized)
        XCTAssertEqual(approver.callCount, 1)
        XCTAssertFalse(approver.receivedCallback)
        XCTAssertEqual(listProvider.callCount, 0)
    }

    func testListSessionDoesNotAuthorizeDifferentTerminalScope() async {
        let approver = ApprovalTracker(result: true)
        let listProvider = ListProvider()
        let handler = XPCRequestHandler(
            listProvider: listProvider.fetch,
            approver: approver
        )

        let firstRequestData = makeListRequest(sessionScope: "tty:/dev/ttys001")
        let first = XCTestExpectation(description: "first scoped list reply")
        var firstResponseData: Data?
        handler.list(firstRequestData) { data, _ in
            firstResponseData = data
            first.fulfill()
        }
        await fulfillment(of: [first], timeout: 1)

        let firstResponse = try? BridgeCoder.decode(BridgeResponse<BridgeListPayload>.self, from: firstResponseData ?? Data())
        let sessionToken = firstResponse?.sessionToken
        XCTAssertNotNil(sessionToken)

        let secondRequestData = makeListRequest(sessionToken: sessionToken, sessionScope: "tty:/dev/ttys002")
        let second = XCTestExpectation(description: "second scoped list reply")
        handler.list(secondRequestData) { _, _ in
            second.fulfill()
        }
        await fulfillment(of: [second], timeout: 1)

        XCTAssertEqual(approver.callCount, 2)
        XCTAssertEqual(listProvider.callCount, 2)
    }

    func testCompletionListRequestsApprovalWithoutSession() async throws {
        let approver = ApprovalTracker(result: true)
        let listProvider = ListProvider()
        let handler = XPCRequestHandler(
            listProvider: listProvider.fetch,
            approver: approver
        )

        let requestData = makeListRequest(requestedCommand: "completion")
        let expectation = XCTestExpectation(description: "completion list reply")
        var responseData: Data?
        handler.list(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }

        await fulfillment(of: [expectation], timeout: 1)
        let response = try BridgeCoder.decode(
            BridgeResponse<BridgeListPayload>.self,
            from: try XCTUnwrap(responseData)
        )

        XCTAssertEqual(approver.callCount, 1)
        XCTAssertEqual(listProvider.callCount, 1)
        XCTAssertNotNil(response.sessionToken)
        XCTAssertNil(response.error)
    }

    func testRedirectedStdoutExecBootstrapListMintsSessionForIDECaller() async throws {
        let approver = ApprovalTracker(result: true)
        // A NON-EMPTY provider so we can prove the just-bootstrapped human sees the full payload.
        // The empty-payload regression (folder-scoped refs failing on first run) would otherwise go
        // uncaught: before the fix, filteredListPayload treated this interactive caller as agentic
        // and returned an empty payload even though the session was minted.
        let listProvider = NonEmptyListProvider()
        let ideCaller = CallerIdentity(
            pid: 42,
            processName: "authsia",
            bundleIdentifier: "com.authsia.cli",
            signingTeamId: "TEAM",
            signingIdentity: "Developer ID Application",
            parentProcess: ParentProcessInfo(pid: 41, processName: "zsh", bundleIdentifier: nil),
            hostProcess: ParentProcessInfo(pid: 40, processName: "Code Helper", bundleIdentifier: "com.microsoft.VSCode")
        )
        let handler = XPCRequestHandler(
            listProvider: listProvider.fetch,
            approver: approver,
            callerIdentityProvider: { ideCaller }
        )

        // Bootstrap list carrying the real verb "exec", stdin TTY, redirected stdout, no session.
        // Ancestry still classifies this caller as agentic; separate bootstrap eligibility must
        // allow the biometric path and keep its approved list payload intact.
        let requestData = makeListRequest(isPiped: true, requestedCommand: "exec")
        let expectation = XCTestExpectation(description: "bootstrap list reply")
        var responseData: Data?
        handler.list(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        let response = try BridgeCoder.decode(
            BridgeResponse<BridgeListPayload>.self,
            from: try XCTUnwrap(responseData)
        )
        XCTAssertNil(response.error)
        XCTAssertNotNil(response.sessionToken)      // biometric bootstrap minted a session
        XCTAssertEqual(approver.callCount, 1)
        // The bootstrapped human must see the real payload, not an empty one.
        XCTAssertEqual(response.payload?.passwords.map(\.name), ["Bootstrap PW"])
        XCTAssertEqual(response.payload?.sshKeys.map(\.name), ["Bootstrap SSH"])
    }

    func testInteractiveCodexBootstrapListMintsSession() async throws {
        let approver = ApprovalTracker(result: true)
        let listProvider = NonEmptyListProvider()
        // A human typing in a Codex integrated terminal has agentic ancestry. With no session yet
        // and no confirmed agentRuntimeContext, it remains agent-classified, but its stdin TTY is
        // separately bootstrap-eligible and must still reach biometric before receiving data.
        let codexCaller = CallerIdentity(
            pid: 42,
            processName: "authsia",
            bundleIdentifier: "com.authsia.cli",
            signingTeamId: "TEAM",
            signingIdentity: "Developer ID Application",
            parentProcess: ParentProcessInfo(pid: 41, processName: "codex", bundleIdentifier: nil)
        )
        let handler = XPCRequestHandler(
            listProvider: listProvider.fetch,
            approver: approver,
            callerIdentityProvider: { codexCaller }
        )

        // Bootstrap list carrying the real verb "exec", interactive TTY, no session yet.
        let requestData = makeListRequest(requestedCommand: "exec")
        let expectation = XCTestExpectation(description: "codex bootstrap list reply")
        var responseData: Data?
        handler.list(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)

        let response = try BridgeCoder.decode(
            BridgeResponse<BridgeListPayload>.self,
            from: try XCTUnwrap(responseData)
        )
        XCTAssertNil(response.error)
        XCTAssertNotNil(response.sessionToken)      // biometric bootstrap minted a session
        XCTAssertEqual(approver.callCount, 1)
        // The bootstrapped human must see the real payload, not an empty one.
        XCTAssertEqual(response.payload?.passwords.map(\.name), ["Bootstrap PW"])
        XCTAssertEqual(response.payload?.sshKeys.map(\.name), ["Bootstrap SSH"])
    }

    func testStatusReportsCurrentTerminalScopeOnly() async throws {
        let scope = "tty:/dev/ttys-status-\(UUID().uuidString)"
        let otherScope = "tty:/dev/ttys-status-\(UUID().uuidString)"
        let approver = ApprovalTracker(result: true)
        let handler = XPCRequestHandler(approver: approver)

        let unlock = XCTestExpectation(description: "unlock reply")
        var unlockResponseData: Data?
        handler.unlock(makeRequest(type: .unlock, sessionScope: scope)) { data, _ in
            unlockResponseData = data
            unlock.fulfill()
        }
        await fulfillment(of: [unlock], timeout: 1)

        let unlockResponse = try BridgeCoder.decode(
            BridgeResponse<TestUnlockPayload>.self,
            from: try XCTUnwrap(unlockResponseData)
        )
        let token = try XCTUnwrap(unlockResponse.payload?.sessionToken)

        let matchingStatus = XCTestExpectation(description: "matching status reply")
        var matchingStatusData: Data?
        handler.status(makeRequest(type: .status, sessionScope: scope)) { data, _ in
            matchingStatusData = data
            matchingStatus.fulfill()
        }
        await fulfillment(of: [matchingStatus], timeout: 1)

        let matchingResponse = try BridgeCoder.decode(
            BridgeResponse<BridgePingPayload>.self,
            from: try XCTUnwrap(matchingStatusData)
        )
        XCTAssertEqual(matchingResponse.payload?.sessionActive, true)
        XCTAssertNotNil(matchingResponse.payload?.sessionExpiresAt)

        let otherStatus = XCTestExpectation(description: "other status reply")
        var otherStatusData: Data?
        handler.status(makeRequest(type: .status, sessionScope: otherScope)) { data, _ in
            otherStatusData = data
            otherStatus.fulfill()
        }
        await fulfillment(of: [otherStatus], timeout: 1)

        let otherResponse = try BridgeCoder.decode(
            BridgeResponse<BridgePingPayload>.self,
            from: try XCTUnwrap(otherStatusData)
        )
        XCTAssertEqual(otherResponse.payload?.sessionActive, false)
        XCTAssertNil(otherResponse.payload?.sessionExpiresAt)

        let lock = XCTestExpectation(description: "lock reply")
        handler.lock(makeRequest(type: .lock, sessionToken: token, sessionScope: scope)) { _, _ in
            lock.fulfill()
        }
        await fulfillment(of: [lock], timeout: 1)
    }

    func testListPayloadIncludesSSHAndScraped() async throws {
        let listProvider = {
            BridgeListPayload(
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
                passwords: [],
                certificates: [],
                notes: [],
                sshKeys: [
                    BridgeSSHKey(
                        id: UUID(),
                        name: "Work",
                        comment: "laptop",
                        fingerprint: "SHA256:abc",
                        publicKey: "ssh-ed25519 AAAA",
                        isFavorite: false,
                        isCliEnabled: true,
                        isScraped: true,
                        createdAt: Date(),
                        updatedAt: Date()
                    )
                ]
            )
        }
        let handler = XPCRequestHandler(listProvider: listProvider, approver: ApprovalTracker(result: true))
        let requestData = makeListRequest()

        let expectation = XCTestExpectation(description: "list reply")
        var responseData: Data?
        handler.list(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }

        await fulfillment(of: [expectation], timeout: 1)
        let response = try BridgeCoder.decode(BridgeResponse<BridgeListPayload>.self, from: responseData ?? Data())
        XCTAssertNotNil(response.payload?.sshKeys)
    }

    func testListMetadataUsesSnapshotOnlyWhenLoadedMetadataIsEmpty() {
        XCTAssertEqual(
            BridgeListPayloadFactory.metadataWithSnapshotFallback(
                loaded: [String](),
                snapshot: [42],
                mapLoaded: { "loaded:\($0)" },
                mapSnapshot: { "snapshot:\($0)" }
            ),
            ["snapshot:42"]
        )
        XCTAssertEqual(
            BridgeListPayloadFactory.metadataWithSnapshotFallback(
                loaded: ["current"],
                snapshot: [42],
                mapLoaded: { "loaded:\($0)" },
                mapSnapshot: { "snapshot:\($0)" }
            ),
            ["loaded:current"]
        )
    }

    func testPasswordGetMetadataUsesSnapshotForLoadedMetadataMisses() {
        let snapshotID = UUID()
        let snapshotSource = PasswordMetadata(
            id: snapshotID,
            name: "SERVICE_ACCESS_KEY_ID",
            username: "value",
            website: nil,
            notes: "snapshot must not carry note bodies",
            folderPath: "Authsia",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_001),
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false
        )
        let snapshot = VaultCLIMetadataSnapshot(
            passwords: [snapshotSource],
            certificates: [],
            notes: [],
            sshKeys: [],
            folders: [:]
        )
        let loaded = PasswordMetadata(
            id: UUID(),
            name: "Loaded",
            username: "value",
            website: nil,
            notes: "live metadata",
            createdAt: Date(timeIntervalSince1970: 1_700_000_002),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_003),
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false
        )

        let fallback = BridgeListPayloadFactory.passwordMetadataForLookup(
            loaded: [],
            snapshot: snapshot.passwords
        )
        XCTAssertEqual(fallback.first?.id, snapshotID)
        XCTAssertEqual(fallback.first?.folderPath, "Authsia")
        XCTAssertNil(fallback.first?.notes)

        let merged = BridgeListPayloadFactory.passwordMetadataForLookup(
            loaded: [loaded],
            snapshot: snapshot.passwords
        )
        XCTAssertEqual(merged.map { $0.id }, [loaded.id, snapshotID])
        XCTAssertNil(merged.last?.notes)
    }

    func testAPIKeyGetMetadataUsesSnapshotForLoadedMetadataMisses() {
        let snapshotID = UUID()
        let snapshotSource = APIKeyMetadata(
            id: snapshotID,
            name: "STRIPE_API_KEY",
            website: nil,
            notes: "snapshot must not carry note bodies",
            folderPath: "Authsia",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_001),
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false
        )
        let snapshot = VaultCLIMetadataSnapshot(
            passwords: [],
            apiKeys: [snapshotSource],
            certificates: [],
            notes: [],
            sshKeys: [],
            folders: [:]
        )
        let loaded = APIKeyMetadata(
            id: UUID(),
            name: "Loaded",
            website: nil,
            notes: "live metadata",
            createdAt: Date(timeIntervalSince1970: 1_700_000_002),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_003),
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false
        )

        let fallback = BridgeListPayloadFactory.apiKeyMetadataForLookup(
            loaded: [],
            snapshot: snapshot.apiKeys
        )
        XCTAssertEqual(fallback.first?.id, snapshotID)
        XCTAssertEqual(fallback.first?.folderPath, "Authsia")
        XCTAssertNil(fallback.first?.notes)

        let merged = BridgeListPayloadFactory.apiKeyMetadataForLookup(
            loaded: [loaded],
            snapshot: snapshot.apiKeys
        )
        XCTAssertEqual(merged.map { $0.id }, [loaded.id, snapshotID])
        XCTAssertNil(merged.last?.notes)
    }

    @MainActor
    func testDefaultListPayloadUsesInjectedVaultRepository() async throws {
        let suffix = UUID().uuidString
        let passwordName = "ImportedPassword-\(suffix)"
        let sshName = "ImportedSSH-\(suffix)"
        let repository = ListVaultRepository(
            passwords: [
                PasswordMetadata(
                    id: UUID(),
                    name: passwordName,
                    username: "imported",
                    website: nil,
                    notes: nil,
                    createdAt: Date(),
                    modifiedAt: Date(),
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false
                ),
            ],
            sshKeys: [
                SSHKeyMetadata(
                    id: UUID(),
                    name: sshName,
                    publicKey: "ssh-ed25519 AAAA",
                    comment: "imported",
                    fingerprint: "SHA256:imported",
                    createdAt: Date(),
                    modifiedAt: Date(),
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false
                ),
            ]
        )
        let handler = XPCRequestHandler(
            accountProvider: { [] },
            approver: ApprovalTracker(result: true),
            repository: repository
        )
        let requestData = makeListRequest()

        let expectation = XCTestExpectation(description: "list reply")
        var responseData: Data?
        handler.list(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }

        await fulfillment(of: [expectation], timeout: 1)
        let response = try BridgeCoder.decode(BridgeResponse<BridgeListPayload>.self, from: responseData ?? Data())

        XCTAssertTrue(response.payload?.passwords.contains { $0.name == passwordName } == true)
        XCTAssertTrue(response.payload?.sshKeys.contains { $0.name == sshName } == true)
    }

    @MainActor
    func testDefaultListPayloadReloadsVaultRepositoryBeforeListing() async throws {
        let passwordID = UUID()
        let passwordName = "MovedPassword-\(UUID().uuidString)"
        let createdAt = Date(timeIntervalSince1970: 1_800_000_000)
        let oldMetadata = PasswordMetadata(
            id: passwordID,
            name: passwordName,
            username: "imported",
            website: nil,
            notes: nil,
            folderPath: "Old",
            createdAt: createdAt,
            modifiedAt: createdAt,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false
        )
        let newMetadata = PasswordMetadata(
            id: passwordID,
            name: passwordName,
            username: "imported",
            website: nil,
            notes: nil,
            folderPath: "New",
            createdAt: createdAt,
            modifiedAt: createdAt.addingTimeInterval(1),
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false
        )
        let repository = ListVaultRepository(passwords: [oldMetadata])
        repository.onLoad = {
            repository.replacePasswords([newMetadata])
        }
        let handler = XPCRequestHandler(
            accountProvider: { [] },
            approver: ApprovalTracker(result: true),
            repository: repository
        )

        let expectation = XCTestExpectation(description: "list reply")
        var responseData: Data?
        handler.list(makeListRequest()) { data, _ in
            responseData = data
            expectation.fulfill()
        }

        await fulfillment(of: [expectation], timeout: 1)
        let response = try BridgeCoder.decode(BridgeResponse<BridgeListPayload>.self, from: responseData ?? Data())

        XCTAssertEqual(repository.loadCallCount, 1)
        XCTAssertEqual(response.payload?.passwords.first { $0.id == passwordID }?.folderPath, "New")
    }

    func testListReturnsAllItemsIncludingCLIDisabled() async throws {
        let listProvider = {
            BridgeListPayload(
                accounts: [
                    BridgeAccount(
                        id: UUID(),
                        issuer: "A",
                        label: "enabled",
                        isFavorite: false,
                        isCliEnabled: true,
                        isScraped: false,
                        createdAt: Date(),
                        updatedAt: Date()
                    ),
                    BridgeAccount(
                        id: UUID(),
                        issuer: "B",
                        label: "disabled",
                        isFavorite: false,
                        isCliEnabled: false,
                        isScraped: false,
                        createdAt: Date(),
                        updatedAt: Date()
                    ),
                ],
                passwords: [
                    BridgePassword(
                        id: UUID(),
                        name: "pw-enabled",
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
                        name: "pw-disabled",
                        username: "u",
                        website: nil,
                        folderPath: nil,
                        isFavorite: false,
                        isCliEnabled: false,
                        isScraped: false,
                        createdAt: Date(),
                        updatedAt: Date()
                    ),
                ],
                certificates: [
                    BridgeCertificate(
                        id: UUID(),
                        name: "cert-enabled",
                        issuer: nil,
                        subject: nil,
                        expirationDate: nil,
                        folderPath: nil,
                        isFavorite: false,
                        isCliEnabled: true,
                        isScraped: false,
                        createdAt: Date(),
                        updatedAt: Date()
                    ),
                    BridgeCertificate(
                        id: UUID(),
                        name: "cert-disabled",
                        issuer: nil,
                        subject: nil,
                        expirationDate: nil,
                        folderPath: nil,
                        isFavorite: false,
                        isCliEnabled: false,
                        isScraped: false,
                        createdAt: Date(),
                        updatedAt: Date()
                    ),
                ],
                notes: [
                    BridgeNote(
                        id: UUID(),
                        title: "note-enabled",
                        folderPath: nil,
                        isFavorite: false,
                        isCliEnabled: true,
                        isScraped: false,
                        createdAt: Date(),
                        updatedAt: Date()
                    ),
                    BridgeNote(
                        id: UUID(),
                        title: "note-disabled",
                        folderPath: nil,
                        isFavorite: false,
                        isCliEnabled: false,
                        isScraped: false,
                        createdAt: Date(),
                        updatedAt: Date()
                    ),
                ],
                sshKeys: [
                    BridgeSSHKey(
                        id: UUID(),
                        name: "ssh-enabled",
                        comment: "c",
                        fingerprint: "fp1",
                        publicKey: "pk1",
                        folderPath: nil,
                        isFavorite: false,
                        isCliEnabled: true,
                        isScraped: false,
                        createdAt: Date(),
                        updatedAt: Date()
                    ),
                    BridgeSSHKey(
                        id: UUID(),
                        name: "ssh-disabled",
                        comment: "c",
                        fingerprint: "fp2",
                        publicKey: "pk2",
                        folderPath: nil,
                        isFavorite: false,
                        isCliEnabled: false,
                        isScraped: false,
                        createdAt: Date(),
                        updatedAt: Date()
                    ),
                ]
            )
        }
        let handler = XPCRequestHandler(listProvider: listProvider, approver: ApprovalTracker(result: true))
        let requestData = makeListRequest()

        let expectation = XCTestExpectation(description: "list reply filtered")
        var responseData: Data?
        handler.list(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }

        await fulfillment(of: [expectation], timeout: 1)
        let response = try BridgeCoder.decode(BridgeResponse<BridgeListPayload>.self, from: responseData ?? Data())

        // List returns ALL items — no secrets are exposed.
        // The CLI shows the isCliEnabled column so users can see which items are accessible.
        XCTAssertEqual(response.payload?.accounts.count, 2)
        XCTAssertEqual(response.payload?.passwords.count, 2)
        XCTAssertEqual(response.payload?.certificates.count, 2)
        XCTAssertEqual(response.payload?.notes.count, 2)
        XCTAssertEqual(response.payload?.sshKeys.count, 2)
    }

    func testListDeniedInCIContextWithoutApproval() async throws {
        let approver = ApprovalTracker(result: true)
        let listProvider = ListProvider()
        let handler = XPCRequestHandler(
            listProvider: listProvider.fetch,
            approver: approver
        )
        let requestData = makeListRequest(isCI: true)

        let expectation = XCTestExpectation(description: "list ci denied")
        var responseData: Data?
        handler.list(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }

        await fulfillment(of: [expectation], timeout: 1)
        let response = try BridgeCoder.decode(BridgeResponse<String>.self, from: responseData ?? Data())
        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertEqual(approver.callCount, 0)
        XCTAssertEqual(listProvider.callCount, 0)
    }

    func testListFailureReturnsAppUnavailable() async throws {
        let listProvider: XPCRequestHandler.ListProvider = {
            throw KeychainError.unknown(errSecInteractionNotAllowed)
        }
        let handler = XPCRequestHandler(
            listProvider: listProvider,
            approver: ApprovalTracker(result: true)
        )
        let requestData = makeListRequest()

        let expectation = XCTestExpectation(description: "list failure reply")
        var responseData: Data?
        handler.list(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }

        await fulfillment(of: [expectation], timeout: 1)
        let response = try BridgeCoder.decode(BridgeResponse<String>.self, from: responseData ?? Data())
        XCTAssertEqual(response.error?.code, .appUnavailable)
        XCTAssertTrue(response.error?.message.contains("not authorized to read the keychain") == true)
    }

    func testListMetadataLoadFailureReturnsAppUnavailableWithoutGenericPrefix() async throws {
        let listProvider: XPCRequestHandler.ListProvider = {
            throw MetadataLoadError.keychainUnavailable(errSecMissingEntitlement)
        }
        let handler = XPCRequestHandler(
            listProvider: listProvider,
            approver: ApprovalTracker(result: true)
        )
        let requestData = makeListRequest()

        let expectation = XCTestExpectation(description: "metadata load failure reply")
        var responseData: Data?
        handler.list(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }

        await fulfillment(of: [expectation], timeout: 1)
        let response = try BridgeCoder.decode(BridgeResponse<String>.self, from: responseData ?? Data())
        XCTAssertEqual(response.error?.code, .appUnavailable)
        XCTAssertEqual(response.error?.message, MetadataLoadError.keychainUnavailable(errSecMissingEntitlement).localizedDescription)
    }

    func testListAllowsPipedOutputAfterApproval() async throws {
        let approver = ApprovalTracker(result: true)
        let listProvider = ListProvider()
        let handler = XPCRequestHandler(
            listProvider: listProvider.fetch,
            approver: approver
        )
        let requestData = makeListRequest(isPiped: true)

        let expectation = XCTestExpectation(description: "list piped allowed")
        var responseData: Data?
        handler.list(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }

        await fulfillment(of: [expectation], timeout: 1)
        let response = try BridgeCoder.decode(BridgeResponse<BridgeListPayload>.self, from: responseData ?? Data())
        XCTAssertNotNil(response.payload)
        XCTAssertEqual(approver.callCount, 1)
        XCTAssertEqual(listProvider.callCount, 1)
    }

    func testAutomationListBypassesApprovalAndFiltersToScope() async throws {
        let approver = ApprovalTracker(result: true)
        let listProvider = {
            BridgeListPayload(
                accounts: [
                    BridgeAccount(
                        id: UUID(),
                        issuer: "GitHub",
                        label: "otp",
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
                        name: "api-prod",
                        username: "svc",
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
                        name: "other",
                        username: "svc",
                        website: nil,
                        folderPath: "Team/Other",
                        isFavorite: false,
                        isCliEnabled: true,
                        isScraped: false,
                        createdAt: Date(),
                        updatedAt: Date()
                    )
                ],
                certificates: [],
                notes: [
                    BridgeNote(
                        id: UUID(),
                        title: "prod-note",
                        folderPath: "Team/API/Prod",
                        isFavorite: false,
                        isCliEnabled: true,
                        isScraped: false,
                        createdAt: Date(),
                        updatedAt: Date()
                    )
                ],
                sshKeys: [
                    BridgeSSHKey(
                        id: UUID(),
                        name: "no-folder",
                        comment: "laptop",
                        fingerprint: "fp",
                        publicKey: "ssh-ed25519 AAAA",
                        folderPath: nil,
                        isFavorite: false,
                        isCliEnabled: true,
                        isScraped: false,
                        createdAt: Date(),
                        updatedAt: Date()
                    )
                ]
            )
        }
        let credentialID = UUID()
        let credential = AutomationCredentialLookup.CredentialRecord(
            id: credentialID,
            scope: "Team/API",
            expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
            revokedAt: nil,
            machineId: "machine-1",
            allowedCommands: [.list]
        )
        let token = "authsia_ac1_synthetic"
        let handler = XPCRequestHandler(
            listProvider: listProvider,
            approver: approver,
            automationCredentialValidationProvider: { suppliedToken, command, _ in
                XCTAssertEqual(suppliedToken, token)
                XCTAssertEqual(command, .list)
                return .found(credential)
            },
            currentMachineIdProvider: { "machine-1" }
        )
        let requestData = makeListRequest(
            automationCredentialID: credentialID.uuidString,
            automationCredentialToken: token,
            automationScope: "Team/Forged",
            requestedCommand: "list"
        )

        let expectation = XCTestExpectation(description: "automation list reply")
        var responseData: Data?
        handler.list(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }

        await fulfillment(of: [expectation], timeout: 1)
        let response = try BridgeCoder.decode(BridgeResponse<BridgeListPayload>.self, from: responseData ?? Data())

        XCTAssertEqual(approver.callCount, 0)
        XCTAssertNil(response.sessionToken)
        XCTAssertEqual(response.payload?.accounts.count, 0)
        XCTAssertEqual(response.payload?.passwords.map(\.name), ["api-prod"])
        XCTAssertEqual(response.payload?.notes.map(\.title), ["prod-note"])
        XCTAssertEqual(response.payload?.sshKeys.count, 0)
    }

    func testAutomationListAllowsAllNonOTPItemsForGlobalScope() async throws {
        let approver = ApprovalTracker(result: true)
        let listProvider = {
            BridgeListPayload(
                accounts: [
                    BridgeAccount(
                        id: UUID(),
                        issuer: "GitHub",
                        label: "otp",
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
                        name: "root",
                        username: "svc",
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
                        name: "nested",
                        username: "svc",
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
        }
        let credentialID = UUID()
        let credential = AutomationCredentialLookup.CredentialRecord(
            id: credentialID,
            scope: nil,
            expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
            revokedAt: nil,
            machineId: "machine-1",
            allowedCommands: [.list]
        )
        let token = "authsia_ac1_synthetic"
        let handler = XPCRequestHandler(
            listProvider: listProvider,
            approver: approver,
            automationCredentialValidationProvider: { suppliedToken, command, _ in
                XCTAssertEqual(suppliedToken, token)
                XCTAssertEqual(command, .list)
                return .found(credential)
            },
            currentMachineIdProvider: { "machine-1" }
        )
        let requestData = makeListRequest(
            automationCredentialID: credentialID.uuidString,
            automationCredentialToken: token,
            automationScope: nil,
            requestedCommand: "list"
        )

        let expectation = XCTestExpectation(description: "global automation list reply")
        var responseData: Data?
        handler.list(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }

        await fulfillment(of: [expectation], timeout: 1)
        let response = try BridgeCoder.decode(BridgeResponse<BridgeListPayload>.self, from: responseData ?? Data())

        XCTAssertEqual(approver.callCount, 0)
        XCTAssertEqual(response.payload?.accounts.count, 0)
        XCTAssertEqual(response.payload?.passwords.map(\.name), ["root", "nested"])
    }

    private func makeListRequest(
        isPiped: Bool = false,
        isSSH: Bool = false,
        isCI: Bool = false,
        sessionToken: String? = nil,
        automationCredentialID: String? = nil,
        automationCredentialToken: String? = nil,
        automationScope: String? = nil,
        requestedCommand: String? = nil,
        sessionScope: String? = nil
    ) -> Data {
        let request = BridgeRequest(
            id: UUID(),
            type: .list,
            query: "",
            options: BridgeOptions(field: nil, copy: false),
            context: BridgeContext(
                isTTY: true,
                isPiped: isPiped,
                isSSH: isSSH,
                isCI: isCI,
                timestamp: Date(),
                automationCredentialID: automationCredentialID,
                automationCredentialToken: automationCredentialToken,
                automationScope: automationScope,
                requestedCommand: requestedCommand,
                sessionScope: sessionScope
            ),
            sessionToken: sessionToken
        )
        return (try? BridgeCoder.encode(request)) ?? Data()
    }

    private func makeRequest(
        type: BridgeRequestType,
        sessionToken: String? = nil,
        sessionScope: String? = nil
    ) -> Data {
        let request = BridgeRequest(
            id: UUID(),
            type: type,
            query: "",
            options: BridgeOptions(field: nil, copy: false),
            context: BridgeContext(
                isTTY: true,
                isPiped: false,
                isSSH: false,
                isCI: false,
                timestamp: Date(),
                sessionScope: sessionScope
            ),
            sessionToken: sessionToken
        )
        return (try? BridgeCoder.encode(request)) ?? Data()
    }
}

private final class ApprovalTracker: BridgeApprover {
    private(set) var callCount = 0
    private(set) var remoteRequests: [[RemoteJITApprovalRequest]] = []
    private let outcome: RemoteJITApprovalOutcome

    init(result: Bool) {
        self.outcome = result
            ? .approved(source: .macBiometric)
            : .denied(source: .macBiometric)
    }

    func requestApproval(
        prompt: String,
        command: BridgeRequestType,
        itemLabel: String?,
        field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?,
        remoteRequests: [RemoteJITApprovalRequest]
    ) async -> RemoteJITApprovalOutcome {
        callCount += 1
        self.remoteRequests.append(remoteRequests)
        return outcome
    }
}

private final class CallbackRequiredApprover: BridgeApprover {
    private(set) var callCount = 0
    private(set) var receivedCallback = false
    private(set) var remoteRequests: [[RemoteJITApprovalRequest]] = []

    func requestApproval(
        prompt: String,
        command: BridgeRequestType,
        itemLabel: String?,
        field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?,
        remoteRequests: [RemoteJITApprovalRequest]
    ) async -> RemoteJITApprovalOutcome {
        callCount += 1
        receivedCallback = callback != nil
        self.remoteRequests.append(remoteRequests)
        return receivedCallback
            ? .approved(source: .macPanel)
            : .denied(source: .macPanel)
    }
}

private struct TestUnlockPayload: Codable, Equatable {
    let expiresAt: Date
    let ttlSeconds: Int
    let sessionToken: String
}

private final class ListProvider {
    private(set) var callCount = 0

    func fetch() throws -> BridgeListPayload {
        callCount += 1
        return BridgeListPayload(accounts: [], passwords: [], certificates: [], notes: [], sshKeys: [])
    }
}

private final class NonEmptyListProvider {
    private(set) var callCount = 0

    func fetch() throws -> BridgeListPayload {
        callCount += 1
        return BridgeListPayload(
            accounts: [],
            passwords: [
                BridgePassword(
                    id: UUID(),
                    name: "Bootstrap PW",
                    username: "u",
                    website: nil,
                    folderPath: "Team/API",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: Date(),
                    updatedAt: Date()
                ),
            ],
            certificates: [],
            notes: [],
            sshKeys: [
                BridgeSSHKey(
                    id: UUID(),
                    name: "Bootstrap SSH",
                    comment: "c",
                    fingerprint: "fp",
                    publicKey: "ssh-ed25519 AAAA",
                    folderPath: "Team/API",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: Date(),
                    updatedAt: Date()
                ),
            ]
        )
    }
}

@MainActor
private final class ListVaultRepository: VaultRepositoryProviding {
    var onLoad: (() -> Void)?
    private(set) var loadCallCount = 0
    var hasLoadedVaultState = false
    private(set) var passwords: [PasswordMetadata]
    private(set) var apiKeys: [APIKeyMetadata]
    private(set) var certificates: [CertificateMetadata]
    private(set) var notes: [SecureNoteMetadata]
    private(set) var sshKeys: [SSHKeyMetadata]

    init(
        passwords: [PasswordMetadata] = [],
        apiKeys: [APIKeyMetadata] = [],
        certificates: [CertificateMetadata] = [],
        notes: [SecureNoteMetadata] = [],
        sshKeys: [SSHKeyMetadata] = []
    ) {
        self.passwords = passwords
        self.apiKeys = apiKeys
        self.certificates = certificates
        self.notes = notes
        self.sshKeys = sshKeys
    }

    func load() throws {
        loadCallCount += 1
        onLoad?()
    }

    func replacePasswords(_ passwords: [PasswordMetadata]) {
        self.passwords = passwords
    }

    func addPassword(_ item: PasswordItem) throws {}
    func updatePassword(_ item: PasswordItem) throws {}
    func deletePassword(id: UUID) throws {}
    func convertPasswordToAPIKey(id: UUID, modifiedAt: Date) throws -> APIKeyItem? { nil }
    func getFullPassword(metadata: PasswordMetadata) throws -> PasswordItem {
        throw ListVaultRepositoryError.unsupported
    }

    func addAPIKey(_ item: APIKeyItem) throws {}
    func updateAPIKey(_ item: APIKeyItem) throws {}
    func deleteAPIKey(id: UUID) throws {}
    func getFullAPIKey(metadata: APIKeyMetadata) throws -> APIKeyItem {
        throw ListVaultRepositoryError.unsupported
    }

    func addCertificate(_ item: CertificateItem) throws {}
    func updateCertificate(_ item: CertificateItem) throws {}
    func deleteCertificatePrivateKey(id: UUID) {}
    func deleteCertificate(id: UUID) throws {}
    func getFullCertificate(metadata: CertificateMetadata) throws -> CertificateItem {
        throw ListVaultRepositoryError.unsupported
    }

    func addNote(_ item: SecureNoteItem) throws {}
    func updateNote(_ item: SecureNoteItem) throws {}
    func deleteNote(id: UUID) throws {}
    func getFullNote(metadata: SecureNoteMetadata) throws -> SecureNoteItem {
        throw ListVaultRepositoryError.unsupported
    }

    func addSSHKey(_ item: SSHKeyItem) throws {}
    func updateSSHKey(_ item: SSHKeyItem) throws {}
    func deleteSSHKey(id: UUID) throws {}
    func getFullSSHKey(metadata: SSHKeyMetadata) throws -> SSHKeyItem {
        throw ListVaultRepositoryError.unsupported
    }
    func addFolder(_ path: String, type: VaultItemType) throws {}
}

private enum ListVaultRepositoryError: Error {
    case unsupported
}
