import Foundation
import Testing
@testable import AuthenticatorBridge

@Suite("Bridge session status")
struct BridgeSessionStatusTests {
    @Test("store clears only the requested terminal scope")
    func storeClearsOnlyRequestedTerminalScope() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-bridge-session-status-\(UUID().uuidString)")
        let fileURL = tempDir.appendingPathComponent("cli-session-status.json")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        try BridgeSessionStatusStore.save(
            BridgeSessionStatusSnapshot(
                bridgePID: 42,
                sessions: [
                    BridgeSessionStatusRecord(scope: "tty:/dev/ttys001:sid:1001", expiresAt: Date().addingTimeInterval(60)),
                    BridgeSessionStatusRecord(scope: "tty:/dev/ttys002:sid:1002", expiresAt: Date().addingTimeInterval(60)),
                ],
                updatedAt: Date()
            ),
            fileURL: fileURL
        )

        let didClear = BridgeSessionStatusStore.clearSessionScope(
            "tty:/dev/ttys001:sid:1001",
            fileURL: fileURL
        )

        let reloaded = try #require(BridgeSessionStatusStore.load(fileURL: fileURL))
        #expect(didClear)
        #expect(reloaded.sessions.map(\.scope) == ["tty:/dev/ttys002:sid:1002"])
    }

    @Test("snapshot filters expired and dead bridge sessions")
    func snapshotFiltersExpiredAndDeadBridgeSessions() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let snapshot = BridgeSessionStatusSnapshot(
            bridgePID: 42,
            sessions: [
                BridgeSessionStatusRecord(scope: "tty:/dev/ttys001:sid:1001", expiresAt: now.addingTimeInterval(-1)),
                BridgeSessionStatusRecord(scope: "tty:/dev/ttys002:sid:1002", expiresAt: now.addingTimeInterval(60)),
            ],
            updatedAt: now
        )

        #expect(snapshot.activeSessions(currentDate: now) { _ in false }.isEmpty)
        #expect(snapshot.activeSessions(currentDate: now) { $0 == 42 }.map(\.scope) == ["tty:/dev/ttys002:sid:1002"])
    }

    @Test("status record decodes optional working directory for Access Center")
    func statusRecordDecodesOptionalWorkingDirectory() throws {
        let json = """
        {
          "scope": "tty:/dev/ttys001:sid:1001",
          "expiresAt": "2026-06-14T00:00:00Z",
          "workingDirectory": "/Users/example/project"
        }
        """
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let record = try decoder.decode(BridgeSessionStatusRecord.self, from: Data(json.utf8))
        let workingDirectory = Mirror(reflecting: record)
            .children
            .first { $0.label == "workingDirectory" }?
            .value as? String

        #expect(workingDirectory == "/Users/example/project")
    }

    @Test("status record preserves optional session origin for menu activation")
    func statusRecordPreservesOptionalSessionOrigin() throws {
        let origin = BridgeSessionOrigin(
            processIdentifier: 1234,
            processName: "Ghostty",
            bundleIdentifier: "com.mitchellh.ghostty"
        )
        let snapshot = BridgeSessionStatusSnapshot(
            bridgePID: 42,
            sessions: [
                BridgeSessionStatusRecord(
                    scope: "tty:/dev/ttys001:sid:1001",
                    expiresAt: Date().addingTimeInterval(60),
                    workingDirectory: "/Users/example/project",
                    origin: origin
                ),
            ],
            updatedAt: Date()
        )
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-bridge-session-origin-\(UUID().uuidString)")
        let fileURL = tempDir.appendingPathComponent("cli-session-status.json")
        defer { try? FileManager.default.removeItem(at: tempDir) }

        try BridgeSessionStatusStore.save(snapshot, fileURL: fileURL)

        let reloaded = try #require(BridgeSessionStatusStore.load(fileURL: fileURL))
        #expect(reloaded.sessions.first?.origin == origin)
    }
}
