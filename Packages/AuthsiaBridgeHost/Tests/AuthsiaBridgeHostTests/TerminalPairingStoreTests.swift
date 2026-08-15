#if os(macOS)
import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge

final class TerminalPairingStoreTests: XCTestCase {
    private var directory: URL!
    private var legacyFileURL: URL!
    private var authorityStore: TestAuthorityStore!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-terminal-pairing-tests-\(UUID().uuidString)", isDirectory: true)
        legacyFileURL = directory.appendingPathComponent("terminal-pairings.json")
        authorityStore = TestAuthorityStore()
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    func testRoundTripAndRevoke() throws {
        let pairing = makePairing()
        let store = makeStore(startTime: pairing.anchorShellStartTime)

        try store.save(pairing)
        XCTAssertEqual(try store.loadAll(), [pairing])
        XCTAssertEqual(try store.revoke(id: pairing.id), pairing)
        XCTAssertEqual(try store.loadAll(), [])
    }

    func testPrunesExpiredExitedAndReusedAnchors() throws {
        let now = Date()
        let valid = makePairing(anchorPID: 11, startTime: 100, expiresAt: now.addingTimeInterval(60))
        let expired = makePairing(anchorPID: 12, startTime: 200, expiresAt: now)
        let exited = makePairing(anchorPID: 13, startTime: 300, expiresAt: now.addingTimeInterval(60))
        let reused = makePairing(anchorPID: 14, startTime: 400, expiresAt: now.addingTimeInterval(60))
        let store = TerminalPairingStore(
            authorityStore: authorityStore,
            legacyFileURL: legacyFileURL
        ) { pid in
            switch pid {
            case 11: 100
            case 12: 200
            case 14: 401
            default: nil
            }
        }
        try store.saveAll([valid, expired, exited, reused])

        let result = try store.loadAllPruningInvalid(now: now)
        XCTAssertEqual(result.valid.map(\.id), [valid.id])
        // The prune reports its own drops, so the audit needs no second read that
        // a concurrent request could also see and double-log.
        XCTAssertEqual(Set(result.pruned.map(\.id)), [expired.id, exited.id, reused.id])
        XCTAssertEqual(try store.loadAll().map(\.id), [valid.id])
        XCTAssertEqual(try store.loadAllPruningInvalid(now: now).pruned, [])
    }

    func testRenewedPairingKeepsAnchorBindingsAndExtendsExpiry() throws {
        let pairing = makePairing()
        let store = makeStore(startTime: pairing.anchorShellStartTime)
        try store.save(pairing)

        let renewed = pairing.renewed(expiresAt: pairing.expiresAt.addingTimeInterval(1_800))
        try store.save(renewed)

        let stored = try XCTUnwrap(try store.loadAll().first)
        XCTAssertEqual(try store.loadAll().count, 1)
        XCTAssertEqual(stored.id, pairing.id)
        XCTAssertEqual(stored.controllingTerminal, pairing.controllingTerminal)
        XCTAssertEqual(stored.anchorShellPID, pairing.anchorShellPID)
        XCTAssertEqual(stored.anchorShellStartTime, pairing.anchorShellStartTime)
        XCTAssertEqual(stored.workspaceRoot, pairing.workspaceRoot)
        XCTAssertEqual(stored.createdAt, pairing.createdAt)
        XCTAssertEqual(stored.expiresAt, renewed.expiresAt)
    }

    /// The binding digest covers only the payload, so an authority record whose
    /// envelope extends the lifetime must fail closed rather than grant the
    /// longer pairing.
    func testEnvelopeLifetimeExtensionFailsClosed() throws {
        let pairing = makePairing()
        let store = makeStore(startTime: pairing.anchorShellStartTime)
        try store.save(pairing)

        let record = try XCTUnwrap(authorityStore.allRecords().first)
        authorityStore.upsert(AuthorityRecord(
            type: record.type,
            id: record.id,
            createdAt: record.createdAt,
            expiresAt: record.expiresAt.addingTimeInterval(3_600),
            revokedAt: record.revokedAt,
            maximumUses: record.maximumUses,
            consumedUses: record.consumedUses,
            bindingDigest: record.bindingDigest,
            displayMetadata: record.displayMetadata,
            payload: record.payload
        ))

        XCTAssertThrowsError(try store.loadAll()) { error in
            XCTAssertEqual(error as? TerminalPairingStoreError, .corruptedStore)
        }
    }

    /// Plaintext pairings from the file-backed store were forgeable by any
    /// same-user process, so they are quarantined instead of trusted.
    func testLegacyPlaintextFileIsQuarantinedNotLoaded() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try JSONEncoder().encode([makePairing()]).write(to: legacyFileURL)

        let store = makeStore(startTime: 100)

        XCTAssertEqual(try store.loadAll(), [])
        XCTAssertFalse(FileManager.default.fileExists(atPath: legacyFileURL.path))
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: legacyFileURL.appendingPathExtension("legacy").path
            )
        )
    }

    private func makeStore(startTime: UInt64) -> TerminalPairingStore {
        TerminalPairingStore(
            authorityStore: authorityStore,
            legacyFileURL: legacyFileURL
        ) { _ in startTime }
    }

    /// Whole-second dates: the store encodes payloads as ISO-8601, which drops
    /// sub-second precision on round trip.
    private func makePairing(
        anchorPID: Int32 = 11,
        startTime: UInt64 = 100,
        expiresAt: Date = Date(timeIntervalSince1970: 2_000)
    ) -> TerminalPairing {
        TerminalPairing(
            id: UUID(),
            controllingTerminal: "ttys004",
            anchorShellPID: anchorPID,
            anchorShellStartTime: startTime,
            workspaceRoot: "/tmp/project",
            createdAt: Date(timeIntervalSince1970: 1_000),
            expiresAt: expiresAt
        )
    }
}
#endif
