#if os(macOS)
import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge

final class TerminalPairingStoreTests: XCTestCase {
    private var directory: URL!
    private var fileURL: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-terminal-pairing-tests-\(UUID().uuidString)", isDirectory: true)
        fileURL = directory.appendingPathComponent("pairings.json")
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
        let store = TerminalPairingStore(fileURL: fileURL) { pid in
            switch pid {
            case 11: 100
            case 12: 200
            case 14: 401
            default: nil
            }
        }
        try store.saveAll([valid, expired, exited, reused])

        XCTAssertEqual(try store.loadAllPruningInvalid(now: now).map(\.id), [valid.id])
        XCTAssertEqual(try store.loadAll().map(\.id), [valid.id])
    }

    func testCorruptStoreFailsClosed() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data("not-json".utf8).write(to: fileURL)
        let store = makeStore(startTime: 100)

        XCTAssertThrowsError(try store.loadAll()) { error in
            XCTAssertEqual(error as? TerminalPairingStoreError, .corruptedStore)
        }
    }

    private func makeStore(startTime: UInt64) -> TerminalPairingStore {
        TerminalPairingStore(fileURL: fileURL) { _ in startTime }
    }

    private func makePairing(
        anchorPID: Int32 = 11,
        startTime: UInt64 = 100,
        expiresAt: Date = Date().addingTimeInterval(60)
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
