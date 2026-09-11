import Foundation
import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge

#if os(macOS)
final class AgentJITGrantStoreTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    func testSaveAllPersistsAcrossStoreRestart() throws {
        let authority = KeychainAuthorityStore(blobStore: JITTestAuthorityBlobStore())
        let legacyURL = temporaryDirectory().appendingPathComponent("agent-jit-grants.json")
        defer { try? FileManager.default.removeItem(at: legacyURL.deletingLastPathComponent()) }
        let first = grant(id: "00000000-0000-0000-0000-000000000001", folder: "Team/One")
        let second = grant(id: "00000000-0000-0000-0000-000000000002", folder: "Team/Two")
        try AgentJITGrantStore(authorityStore: authority, legacyFileURL: legacyURL).saveAll([first, second])

        let restarted = AgentJITGrantStore(authorityStore: authority, legacyFileURL: legacyURL)

        XCTAssertEqual(try restarted.loadAll(), [first, second])
    }

    func testSaveRetainsSingleGrantUpsertCompatibility() throws {
        let store = makeStore()
        let original = grant(id: "00000000-0000-0000-0000-000000000001", folder: "Team/One")
        let updated = grant(id: "00000000-0000-0000-0000-000000000001", folder: "Team/Updated")

        try store.save(original)
        try store.save(updated)

        XCTAssertEqual(try store.loadAll(), [updated])
    }

    func testLegacyJSONCannotCreateAuthorityAndIsRenamed() throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let legacyURL = directory.appendingPathComponent("agent-jit-grants.json")
        let forged = grant(id: "00000000-0000-0000-0000-000000000001", folder: "Forged")
        try JSONEncoder().encode([forged]).write(to: legacyURL)
        let store = AgentJITGrantStore(
            authorityStore: KeychainAuthorityStore(blobStore: JITTestAuthorityBlobStore()),
            legacyFileURL: legacyURL
        )

        XCTAssertFalse(FileManager.default.fileExists(atPath: legacyURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: legacyURL.appendingPathExtension("legacy").path))
        XCTAssertEqual(try store.loadAll(), [])
    }

    func testRevokeAndRevokeAllPersistHistory() throws {
        let store = makeStore()
        let first = grant(id: "00000000-0000-0000-0000-000000000001", folder: "Team/One")
        let second = grant(id: "00000000-0000-0000-0000-000000000002", folder: "Team/Two")
        try store.saveAll([first, second])

        let revoked = try store.revoke(id: first.id, revokedAt: now)
        let allRevoked = try store.revokeAll(revokedAt: now.addingTimeInterval(1))

        XCTAssertEqual(revoked.revokedAt, now)
        XCTAssertEqual(allRevoked.map(\.id), [second.id])
        let history = try store.loadAll()
        XCTAssertEqual(history.first(where: { $0.id == first.id })?.revokedAt, now)
        XCTAssertEqual(
            history.first(where: { $0.id == second.id })?.revokedAt,
            now.addingTimeInterval(1)
        )
    }

    func testCoveringGrantLookupReuses21ItemsAfter19AndPreservesAuthorityBoundaries() throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = AgentJITGrantStore(
            authorityStore: KeychainAuthorityStore(blobStore: JITTestAuthorityBlobStore()),
            legacyFileURL: directory.appendingPathComponent("agent-jit-grants.json"),
            terminalSessionLiveness: { _ in .active }
        )
        let authorizer = AgentJITGrantAuthorizer(store: store)
        let caller = grant(id: "00000000-0000-0000-0000-000000000001", folder: "Team/API").callerFingerprint
        let runtime = AgentRuntimeContext(sessionID: "mcp:store-reuse", agentType: "authsia-mcp")
        let items = (1...21).map {
            AgentJITItemIdentity(type: "api-key", id: UUID(uuidString: String(
                format: "00000000-0000-0000-0000-%012d", $0
            ))!)
        }
        func approvedGrant(_ count: Int) -> AgentJITGrant {
            AgentJITGrant(
                id: UUID(), agentName: "Synthetic agent", callerFingerprint: caller,
                folderScope: .folder("Team/API"), resourceScope: .items(Set(items.prefix(count))),
                capabilities: [.exec], createdAt: now.addingTimeInterval(Double(count - 60)),
                expiresAt: now.addingTimeInterval(300), revokedAt: nil, lastUsedAt: nil,
                agentRuntimeContext: runtime, approvedBy: "macBiometric", environmentScope: .named("dev")
            )
        }
        let older = approvedGrant(19)
        let covering = approvedGrant(21)
        try store.save(older)

        XCTAssertNil(try authorizer.activeGrant(
            capability: .exec, itemIdentities: Set(items), itemFolderPath: "Team/API",
            itemEnvironments: ["dev"], caller: caller, agentRuntimeContext: runtime, now: now
        ))
        XCTAssertNil(try store.loadAll().first?.lastUsedAt)
        try store.save(covering)
        XCTAssertEqual(try store.loadAll().map(\.id), [older.id, covering.id])
        for offset in 0..<2 {
            let usedAt = now.addingTimeInterval(Double(offset))
            let reused = try authorizer.activeGrant(
                capability: .exec, itemIdentities: Set(items), itemFolderPath: "Team/API",
                itemEnvironments: ["dev"], caller: caller, agentRuntimeContext: runtime, now: usedAt
            )
            XCTAssertEqual(reused?.id, covering.id)
            XCTAssertEqual(reused?.lastUsedAt, usedAt)
        }
        XCTAssertNil(try store.loadAll().first(where: { $0.id == older.id })?.lastUsedAt)
        XCTAssertEqual(try store.loadAll().count, 2)

        let cases: [(String, Set<AgentJITItemIdentity>, AgentJITCapability, [String], AgentRuntimeContext?, Date)] = [
            ("empty items", [], .exec, ["dev"], runtime, now),
            ("same UUID with another type", [AgentJITItemIdentity(type: "password", id: items[0].id)], .exec, ["dev"], runtime, now),
            ("unapproved UUID", [AgentJITItemIdentity(type: "api-key", id: UUID())], .exec, ["dev"], runtime, now),
            ("capability", Set(items), .list, ["dev"], runtime, now),
            ("environment", Set(items), .exec, ["prod"], runtime, now),
            ("missing session", Set(items), .exec, ["dev"], nil, now),
            ("another session", Set(items), .exec, ["dev"], AgentRuntimeContext(sessionID: "mcp:other", agentType: "authsia-mcp"), now),
            ("expired", Set(items), .exec, ["dev"], runtime, covering.expiresAt),
        ]
        let beforeDenied = try store.loadAll()
        for (label, identities, capability, environments, context, date) in cases {
            XCTAssertNil(try authorizer.activeGrant(
                capability: capability, itemIdentities: identities, itemFolderPath: "Team/API",
                itemEnvironments: environments, caller: caller, agentRuntimeContext: context, now: date
            ), label)
        }
        XCTAssertEqual(try store.loadAll(), beforeDenied)

        let otherCaller = AgentJITCallerFingerprint(
            processName: "another-client", bundleIdentifier: caller.bundleIdentifier,
            signingTeamId: caller.signingTeamId, signingIdentity: caller.signingIdentity,
            parentProcessName: caller.parentProcessName, parentBundleIdentifier: caller.parentBundleIdentifier,
            sessionScope: caller.sessionScope, workingDirectory: caller.workingDirectory
        )
        XCTAssertNil(try authorizer.activeGrant(
            capability: .exec, itemIdentities: Set(items), itemFolderPath: "Team/API",
            itemEnvironments: ["dev"], caller: otherCaller, agentRuntimeContext: runtime, now: now
        ))
        XCTAssertEqual(try store.loadAll(), beforeDenied)

        _ = try store.revoke(id: covering.id, revokedAt: now)
        XCTAssertNil(try authorizer.activeGrant(
            capability: .exec, itemIdentities: Set(items), itemFolderPath: "Team/API",
            itemEnvironments: ["dev"], caller: caller, agentRuntimeContext: runtime, now: now
        ))
    }

    func testCommandConstrainedLookupSelectsOnlyExactBoundGrantAtomically() throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = AgentJITGrantStore(
            authorityStore: KeychainAuthorityStore(blobStore: JITTestAuthorityBlobStore()),
            legacyFileURL: directory.appendingPathComponent("agent-jit-grants.json"),
            terminalSessionLiveness: { _ in .active }
        )
        let caller = grant(
            id: "00000000-0000-0000-0000-000000000001",
            folder: "Team/API"
        ).callerFingerprint
        let runtime = AgentRuntimeContext(
            sessionID: "mcp:command-bound-store",
            agentID: "proxy:fixture",
            agentType: "authsia-mcp"
        )
        func boundGrant(id: String, command: String?) -> AgentJITGrant {
            AgentJITGrant(
                id: UUID(uuidString: id)!,
                agentName: "Codex",
                callerFingerprint: caller,
                folderScope: .folder("Team/API"),
                capabilities: [.exec],
                createdAt: now.addingTimeInterval(-60),
                expiresAt: now.addingTimeInterval(300),
                revokedAt: nil,
                lastUsedAt: nil,
                agentRuntimeContext: runtime,
                approvedBy: "macBiometric",
                mcpUpstreamCommand: command
            )
        }
        let mismatched = boundGrant(
            id: "00000000-0000-0000-0000-000000000001",
            command: "tools/fixture-mcp-changed"
        )
        let matching = boundGrant(
            id: "00000000-0000-0000-0000-000000000002",
            command: "tools/fixture-mcp"
        )
        let legacy = boundGrant(
            id: "00000000-0000-0000-0000-000000000003",
            command: nil
        )
        try store.saveAll([mismatched, matching, legacy])
        let authorizer = AgentJITGrantAuthorizer(store: store)

        let reused = try authorizer.activeGrant(
            capability: .exec,
            itemFolderPath: "Team/API",
            caller: caller,
            agentRuntimeContext: runtime,
            mcpUpstreamCommand: "tools/fixture-mcp",
            now: now
        )

        XCTAssertEqual(reused?.id, matching.id)
        XCTAssertNil(try store.loadAll().first(where: { $0.id == mismatched.id })?.lastUsedAt)
        XCTAssertNil(try store.loadAll().first(where: { $0.id == legacy.id })?.lastUsedAt)
        let beforeDenied = try store.loadAll()
        XCTAssertNil(try authorizer.activeGrant(
            capability: .exec,
            itemFolderPath: "Team/API",
            caller: caller,
            agentRuntimeContext: runtime,
            mcpUpstreamCommand: "tools/fixture-mcp-other",
            now: now
        ))
        XCTAssertEqual(try store.loadAll(), beforeDenied)

        let unconstrained = try authorizer.activeGrant(
            capability: .exec,
            itemFolderPath: "Team/API",
            caller: caller,
            agentRuntimeContext: runtime,
            now: now
        )
        XCTAssertEqual(unconstrained?.id, mismatched.id)
    }

    func testMissingPayloadFailsClosed() throws {
        let authority = KeychainAuthorityStore(blobStore: JITTestAuthorityBlobStore())
        try authority.insert(
            AuthorityRecord(
                type: .agentJITGrant,
                id: UUID(),
                createdAt: now.addingTimeInterval(-60),
                expiresAt: now.addingTimeInterval(300),
                revokedAt: nil,
                maximumUses: .max,
                consumedUses: 0,
                bindingDigest: Data(repeating: 0x11, count: 32),
                displayMetadata: [:]
            )
        )

        XCTAssertThrowsError(
            try AgentJITGrantStore(authorityStore: authority).loadAll()
        ) {
            XCTAssertEqual($0 as? AgentJITGrantStoreError, .corruptedStore)
        }
    }

    private func makeStore() -> AgentJITGrantStore {
        AgentJITGrantStore(
            authorityStore: KeychainAuthorityStore(blobStore: JITTestAuthorityBlobStore()),
            legacyFileURL: temporaryDirectory().appendingPathComponent("agent-jit-grants.json")
        )
    }

    private func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    }

    private func grant(id: String, folder: String) -> AgentJITGrant {
        AgentJITGrant(
            id: UUID(uuidString: id)!,
            agentName: "Codex",
            callerFingerprint: AgentJITCallerFingerprint(
                processName: "authsia",
                bundleIdentifier: "com.example.authsia",
                signingTeamId: "EXAMPLETEAM",
                signingIdentity: "Synthetic Developer",
                parentProcessName: "Codex",
                parentBundleIdentifier: "com.example.codex",
                sessionScope: "tty:/dev/ttys001:sid:10",
                workingDirectory: "/synthetic/repository"
            ),
            folderScope: .folder(folder),
            capabilities: [.exec],
            createdAt: now.addingTimeInterval(-60),
            expiresAt: now.addingTimeInterval(300),
            revokedAt: nil,
            lastUsedAt: nil,
            approvedBy: "macBiometric"
        )
    }
}

private final class JITTestAuthorityBlobStore: AuthorityBlobStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?

    func load() throws -> Data? {
        lock.withLock { data }
    }

    func save(_ data: Data) throws {
        lock.withLock {
            self.data = data
        }
    }
}
#endif
