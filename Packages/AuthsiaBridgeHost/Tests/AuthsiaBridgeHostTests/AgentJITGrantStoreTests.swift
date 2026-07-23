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
