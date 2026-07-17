import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge

final class AgentJITGrantAuthorizerTests: XCTestCase {
    func testActiveNamedFolderGrantFindsMatchingFolderAndMarksUsed() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let caller = AgentJITCallerFingerprint.fixture(parentProcessName: "Claude")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            expiresAt: now.addingTimeInterval(60)
        )
        let store = MemoryAgentJITGrantStore([grant])
        let authorizer = AgentJITGrantAuthorizer(store: store)

        let result = try authorizer.activeGrant(
            capability: .exec,
            itemFolderPath: " Team / API ",
            caller: caller,
            now: now
        )

        XCTAssertEqual(result?.id, grant.id)
        XCTAssertEqual(result?.lastUsedAt, now)
        XCTAssertEqual(store.grants.first?.lastUsedAt, now)
    }

    func testActiveGrantAllowsDescendantButRejectsSibling() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let caller = AgentJITCallerFingerprint.fixture()
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            expiresAt: now.addingTimeInterval(60)
        )
        let authorizer = AgentJITGrantAuthorizer(store: MemoryAgentJITGrantStore([grant]))

        let descendantResult = try authorizer.activeGrant(
            capability: .exec,
            itemFolderPath: "Team/API/Prod",
            caller: caller,
            now: now
        )
        let siblingResult = try authorizer.activeGrant(
            capability: .exec,
            itemFolderPath: "Team/Web",
            caller: caller,
            now: now
        )

        XCTAssertEqual(descendantResult?.id, grant.id)
        XCTAssertNil(siblingResult)
    }

    func testActiveGrantRejectsItemOutsideEnvironmentScopeWithoutMarkingUsed() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let caller = AgentJITCallerFingerprint.fixture()
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            expiresAt: now.addingTimeInterval(60),
            environmentScope: .named("production")
        )
        let store = MemoryAgentJITGrantStore([grant])
        let authorizer = AgentJITGrantAuthorizer(store: store)

        let rejected = try authorizer.activeGrant(
            capability: .exec,
            itemFolderPath: "Team/API",
            itemEnvironments: ["staging"],
            caller: caller,
            now: now
        )
        let shared = try authorizer.activeGrant(
            capability: .exec,
            itemFolderPath: "Team/API",
            itemEnvironments: [],
            caller: caller,
            now: now
        )

        XCTAssertNil(rejected)
        XCTAssertEqual(shared?.id, grant.id)
        XCTAssertEqual(store.grants.first?.lastUsedAt, now)
    }

    func testActiveGrantRejectsDifferentCallerParent() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let storedCaller = AgentJITCallerFingerprint.fixture(parentProcessName: "Claude")
        let currentCaller = AgentJITCallerFingerprint.fixture(parentProcessName: "Terminal")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: storedCaller,
            folderScope: .folder("Team/API"),
            expiresAt: now.addingTimeInterval(60)
        )
        let authorizer = AgentJITGrantAuthorizer(store: MemoryAgentJITGrantStore([grant]))

        let result = try authorizer.activeGrant(
            capability: .exec,
            itemFolderPath: "Team/API",
            caller: currentCaller,
            now: now
        )

        XCTAssertNil(result)
    }

    func testActiveGrantAllowsExtensionHostCallerWithoutTerminalSessionScope() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let caller = AgentJITCallerFingerprint(
            processName: "authsia",
            bundleIdentifier: "authsia",
            signingTeamId: nil,
            signingIdentity: nil,
            parentProcessName: "claude",
            parentBundleIdentifier: "com.anthropic.claude-code",
            hostProcessName: "Code Helper (Plugin)",
            hostBundleIdentifier: "com.microsoft.VSCode.helper",
            sessionScope: nil,
            workingDirectory: "/Users/example/Projects/ExampleProject"
        )
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Authsia"),
            capabilities: [.exec, .list],
            expiresAt: now.addingTimeInterval(60)
        )
        let store = MemoryAgentJITGrantStore([grant])
        let authorizer = AgentJITGrantAuthorizer(store: store)

        let result = try authorizer.activeGrant(
            capability: .exec,
            itemFolderPath: "Authsia",
            caller: caller,
            now: now
        )

        XCTAssertEqual(result?.id, grant.id)
        XCTAssertEqual(store.grants.first?.lastUsedAt, now)
    }

    func testActiveGrantRejectsSessionScopedCallerForExtensionHostGrantWithoutSessionScope() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let storedCaller = AgentJITCallerFingerprint.fixture(sessionScope: nil)
        let currentCaller = AgentJITCallerFingerprint.fixture(sessionScope: "tty:/dev/ttys001:sid:10")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: storedCaller,
            folderScope: .folder("Authsia"),
            capabilities: [.exec],
            expiresAt: now.addingTimeInterval(60)
        )
        let authorizer = AgentJITGrantAuthorizer(store: MemoryAgentJITGrantStore([grant]))

        let result = try authorizer.activeGrant(
            capability: .exec,
            itemFolderPath: "Authsia",
            caller: currentCaller,
            now: now
        )

        XCTAssertNil(result)
    }

    func testActiveGrantFailsClosedWhenGrantIsRevokedDuringAtomicCheck() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let caller = AgentJITCallerFingerprint.fixture()
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            expiresAt: now.addingTimeInterval(60)
        )
        let authorizer = AgentJITGrantAuthorizer(store: RevokingAtomicGrantStore(grant: grant))

        let result = try authorizer.activeGrant(
            capability: .exec,
            itemFolderPath: "Team/API",
            caller: caller,
            now: now
        )

        XCTAssertNil(result)
    }

    func testActiveScopesFiltersByCallerCapabilityStatusAndMarksUsed() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let caller = AgentJITCallerFingerprint.fixture(parentProcessName: "Claude")
        let matchingRoot = AgentJITGrant.fixture(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
            callerFingerprint: caller,
            folderScope: .root,
            capabilities: [.exec],
            expiresAt: now.addingTimeInterval(60)
        )
        let matchingFolder = AgentJITGrant.fixture(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!,
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec, .list],
            expiresAt: now.addingTimeInterval(60)
        )
        let wrongCapability = AgentJITGrant.fixture(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000003")!,
            callerFingerprint: caller,
            folderScope: .folder("Team/Web"),
            capabilities: [.list],
            expiresAt: now.addingTimeInterval(60)
        )
        let expired = AgentJITGrant.fixture(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000004")!,
            callerFingerprint: caller,
            folderScope: .folder("Team/Expired"),
            capabilities: [.exec],
            expiresAt: now.addingTimeInterval(-1)
        )
        let wrongCaller = AgentJITGrant.fixture(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000005")!,
            callerFingerprint: AgentJITCallerFingerprint.fixture(parentProcessName: "Terminal"),
            folderScope: .folder("Team/Other"),
            capabilities: [.exec],
            expiresAt: now.addingTimeInterval(60)
        )
        let store = MemoryAgentJITGrantStore([
            matchingRoot,
            matchingFolder,
            wrongCapability,
            expired,
            wrongCaller,
        ])
        let authorizer = AgentJITGrantAuthorizer(store: store)

        let scopes = try authorizer.activeScopes(capability: .exec, caller: caller, now: now)

        XCTAssertEqual(scopes, [.root, .folder("Team/API")])
        XCTAssertEqual(store.grants[0].lastUsedAt, now)
        XCTAssertEqual(store.grants[1].lastUsedAt, now)
        XCTAssertNil(store.grants[2].lastUsedAt)
        XCTAssertNil(store.grants[3].lastUsedAt)
        XCTAssertNil(store.grants[4].lastUsedAt)
    }

    func testActiveScopesUsesAtomicBatchStoreMethod() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let caller = AgentJITCallerFingerprint.fixture()
        let store = BatchOnlyScopeStore(scopes: [.root, .folder("Team/API")])
        let authorizer = AgentJITGrantAuthorizer(store: store)

        let scopes = try authorizer.activeScopes(capability: .exec, caller: caller, now: now)

        XCTAssertEqual(scopes, [.root, .folder("Team/API")])
        XCTAssertEqual(store.batchCallCount, 1)
    }

    func testFileBackedStoreSaveLoadRoundTripAndPermissions() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let fileURL = tempDir.appendingPathComponent("agent-jit-grants.json")
        let store = AgentJITGrantStore(fileURL: fileURL)
        let grant = AgentJITGrant.fixture(folderScope: .folder("Team/API"))

        try store.save(grant)
        let loaded = try store.loadAll()

        XCTAssertEqual(loaded, [grant])
        let fileMode = try mode(at: fileURL)
        let directoryMode = try mode(at: tempDir)
        XCTAssertEqual(fileMode & 0o777, 0o600)
        XCTAssertEqual(directoryMode & 0o777, 0o700)
    }

    func testFileBackedStoreReturnsEmptyArrayForMissingFile() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = AgentJITGrantStore(fileURL: tempDir.appendingPathComponent("agent-jit-grants.json"))

        XCTAssertEqual(try store.loadAll(), [])
    }

    func testFileBackedStoreReturnsEmptyArrayForEmptyFile() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent("agent-jit-grants.json")
        try Data().write(to: fileURL)
        let store = AgentJITGrantStore(fileURL: fileURL)

        XCTAssertEqual(try store.loadAll(), [])
    }

    func testFileBackedStoreThrowsCorruptedStoreForInvalidJSON() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent("agent-jit-grants.json")
        try Data("not json".utf8).write(to: fileURL)
        let store = AgentJITGrantStore(fileURL: fileURL)

        XCTAssertThrowsError(try store.loadAll()) { error in
            XCTAssertEqual(error as? AgentJITGrantStoreError, .corruptedStore)
        }
    }

    func testFileBackedStoreSaveUpsertsByID() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = AgentJITGrantStore(fileURL: tempDir.appendingPathComponent("agent-jit-grants.json"))
        let id = UUID(uuidString: "00000000-0000-0000-0000-000000000099")!
        let original = AgentJITGrant.fixture(id: id, folderScope: .folder("Team/API"))
        let updated = AgentJITGrant.fixture(id: id, folderScope: .folder("Team/Web"))

        try store.save(original)
        try store.save(updated)

        XCTAssertEqual(try store.loadAll(), [updated])
    }

    func testFileBackedStoreThrowsNotFoundForMissingGrantUpdates() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = AgentJITGrantStore(fileURL: tempDir.appendingPathComponent("agent-jit-grants.json"))
        let missingID = UUID(uuidString: "00000000-0000-0000-0000-000000000404")!

        XCTAssertThrowsError(try store.markUsed(id: missingID, at: Date())) { error in
            XCTAssertEqual(error as? AgentJITGrantStoreError, .notFound(missingID))
        }
        XCTAssertThrowsError(try store.revoke(id: missingID, revokedAt: Date())) { error in
            XCTAssertEqual(error as? AgentJITGrantStoreError, .notFound(missingID))
        }
    }

    func testFileBackedStoreLoadsAndRevokesClosedTerminalGrantsAtomically() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = AgentJITGrantStore(
            fileURL: tempDir.appendingPathComponent("agent-jit-grants.json"),
            terminalSessionLiveness: { _ in .closed }
        )
        let caller = AgentJITCallerFingerprint.fixture(sessionScope: "tty:/dev/ttys001:sid:10")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            expiresAt: now.addingTimeInterval(60)
        )
        try store.save(grant)

        let loaded = try store.loadAllRevokingClosedTerminalGrants(now: now)

        XCTAssertEqual(loaded.count, 1)
        XCTAssertEqual(loaded.first?.revokedAt, now)
        XCTAssertEqual(try store.loadAll().first?.revokedAt, now)
    }

    func testFileBackedStoreRevokesClosedTerminalGrantBeforeUse() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = AgentJITGrantStore(
            fileURL: tempDir.appendingPathComponent("agent-jit-grants.json"),
            terminalSessionLiveness: { _ in .closed }
        )
        let caller = AgentJITCallerFingerprint.fixture(sessionScope: "tty:/dev/ttys001:sid:10")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            expiresAt: now.addingTimeInterval(60)
        )

        try store.save(grant)
        let result = try store.markUsedIfAllowed(
            capability: .exec,
            itemFolderPath: "Team/API",
            itemEnvironments: [],
            caller: caller,
            now: now
        )

        let storedGrant = try XCTUnwrap(try store.loadAll().first)
        XCTAssertNil(result)
        XCTAssertEqual(storedGrant.revokedAt, now)
        XCTAssertNil(storedGrant.lastUsedAt)
    }

    private func mode(at url: URL) throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        return (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0
    }
}

private final class MemoryAgentJITGrantStore: AgentJITGrantStoring {
    var grants: [AgentJITGrant]

    init(_ grants: [AgentJITGrant]) {
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
            ) && ($0.environmentScope?.allows(itemEnvironments: itemEnvironments) ?? true)
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

private final class RevokingAtomicGrantStore: AgentJITGrantStoring {
    private let grant: AgentJITGrant

    init(grant: AgentJITGrant) {
        self.grant = grant
    }

    func loadAll() throws -> [AgentJITGrant] {
        [grant]
    }

    func save(_ grant: AgentJITGrant) throws {}

    func saveAll(_ grants: [AgentJITGrant]) throws {}

    func markUsed(id: UUID, at date: Date) throws -> AgentJITGrant {
        grant.copy(lastUsedAt: date)
    }

    func revoke(id: UUID, revokedAt date: Date) throws -> AgentJITGrant {
        grant.copy(revokedAt: date)
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
        let revoked = grant.copy(revokedAt: now)
        guard revoked.allows(
            capability: capability,
            itemFolderPath: itemFolderPath,
            caller: caller,
            now: now
        ) else {
            return nil
        }
        return revoked.copy(lastUsedAt: now)
    }

    func markUsedScopes(
        capability: AgentJITCapability,
        caller: AgentJITCallerFingerprint,
        now: Date
    ) throws -> [AgentJITFolderScope] {
        []
    }
}

private final class BatchOnlyScopeStore: AgentJITGrantStoring {
    private let scopes: [AgentJITFolderScope]
    var batchCallCount = 0

    init(scopes: [AgentJITFolderScope]) {
        self.scopes = scopes
    }

    func loadAll() throws -> [AgentJITGrant] {
        []
    }

    func save(_ grant: AgentJITGrant) throws {}

    func saveAll(_ grants: [AgentJITGrant]) throws {}

    func markUsed(id: UUID, at date: Date) throws -> AgentJITGrant {
        throw AgentJITGrantStoreError.notFound(id)
    }

    func revoke(id: UUID, revokedAt date: Date) throws -> AgentJITGrant {
        throw AgentJITGrantStoreError.notFound(id)
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
        nil
    }

    func markUsedScopes(
        capability: AgentJITCapability,
        caller: AgentJITCallerFingerprint,
        now: Date
    ) throws -> [AgentJITFolderScope] {
        batchCallCount += 1
        return scopes
    }
}

private extension AgentJITGrant {
    static func fixture(
        id: UUID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
        callerFingerprint: AgentJITCallerFingerprint = .fixture(),
        folderScope: AgentJITFolderScope = .folder("Team/API"),
        capabilities: Set<AgentJITCapability> = [.exec],
        createdAt: Date = Date(timeIntervalSince1970: 1_700_000_000),
        expiresAt: Date = Date(timeIntervalSince1970: 1_700_000_300),
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
            approvedBy: "user",
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
            approvedBy: approvedBy,
            environmentScope: environmentScope
        )
    }
}

private extension AgentJITCallerFingerprint {
    static func fixture(
        processName: String = "authsia",
        bundleIdentifier: String? = nil,
        signingTeamId: String? = "TEAM",
        signingIdentity: String? = "Developer ID Application",
        parentProcessName: String? = "Claude",
        parentBundleIdentifier: String? = "com.anthropic.claude",
        sessionScope: String? = "tty:/dev/ttys001:sid:10",
        workingDirectory: String? = "/repo"
    ) -> AgentJITCallerFingerprint {
        AgentJITCallerFingerprint(
            processName: processName,
            bundleIdentifier: bundleIdentifier,
            signingTeamId: signingTeamId,
            signingIdentity: signingIdentity,
            parentProcessName: parentProcessName,
            parentBundleIdentifier: parentBundleIdentifier,
            sessionScope: sessionScope,
            workingDirectory: workingDirectory
        )
    }
}
