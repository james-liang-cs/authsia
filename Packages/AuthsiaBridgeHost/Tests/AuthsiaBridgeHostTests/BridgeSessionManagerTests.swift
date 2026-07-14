import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge

final class BridgeSessionManagerTests: XCTestCase {
    private var tempDir: URL!
    private var statusFileURL: URL!

    override func setUp() {
        super.setUp()
        tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-bridge-session-\(UUID().uuidString)")
        statusFileURL = tempDir.appendingPathComponent("cli-session-status.json")
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: tempDir)
        super.tearDown()
    }

    func testActiveSessionsExposeScopeAndExpiryWithoutToken() throws {
        let scope = "tty:/dev/ttys001:sid:123"
        let manager = makeManager()
        let session = try manager.createSession(ttlSeconds: 60, scope: scope)

        let activeSessions = manager.activeSessions()

        XCTAssertEqual(activeSessions.count, 1)
        XCTAssertEqual(activeSessions.first?.scope, scope)
        XCTAssertEqual(activeSessions.first?.expiresAt.timeIntervalSince1970 ?? 0, session.expiresAt.timeIntervalSince1970, accuracy: 1)
    }

    func testActiveSessionsPruneExpiredSessions() throws {
        let manager = makeManager()
        _ = try manager.createSession(ttlSeconds: -1, scope: "tty:/dev/ttys001:sid:123")

        XCTAssertEqual(manager.activeSessions(), [])
    }

    func testActiveSessionsLoadFromSharedStatusStoreWithoutInMemorySession() throws {
        let scope = "tty:/dev/ttys001:sid:123"
        let expiresAt = Date().addingTimeInterval(60)
        try BridgeSessionStatusStore.save(
            BridgeSessionStatusSnapshot(
                bridgePID: getpid(),
                sessions: [BridgeSessionStatusRecord(scope: scope, expiresAt: expiresAt)],
                updatedAt: Date()
            ),
            fileURL: statusFileURL
        )
        let manager = makeManager()

        let activeSessions = manager.activeSessions()

        XCTAssertEqual(activeSessions.count, 1)
        XCTAssertEqual(activeSessions.first?.scope, scope)
        XCTAssertEqual(activeSessions.first?.expiresAt.timeIntervalSince1970 ?? 0, expiresAt.timeIntervalSince1970, accuracy: 1)
    }

    func testActiveSessionsExposeWorkingDirectoryWhenStatusStoreCapturesIt() throws {
        let scope = "tty:/dev/ttys001:sid:123"
        let expiresAt = Date().addingTimeInterval(60)
        let json = """
        {
          "bridgePID": \(getpid()),
          "sessions": [
            {
              "scope": "\(scope)",
              "expiresAt": "\(Self.iso8601.string(from: expiresAt))",
              "workingDirectory": "/Users/example/project"
            }
          ],
          "updatedAt": "\(Self.iso8601.string(from: Date()))"
        }
        """
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        try Data(json.utf8).write(to: statusFileURL)
        let manager = makeManager()

        let activeSession = try XCTUnwrap(manager.activeSessions().first)
        let workingDirectory = Mirror(reflecting: activeSession)
            .children
            .first { $0.label == "workingDirectory" }?
            .value as? String

        XCTAssertEqual(workingDirectory, "/Users/example/project")
    }

    func testActiveSessionsExposeOriginWhenStatusStoreCapturesIt() throws {
        let scope = "tty:/dev/ttys001:sid:123"
        let expiresAt = Date().addingTimeInterval(60)
        let origin = BridgeSessionOrigin(
            processIdentifier: 1234,
            processName: "Codex",
            bundleIdentifier: "com.openai.codex"
        )
        try BridgeSessionStatusStore.save(
            BridgeSessionStatusSnapshot(
                bridgePID: getpid(),
                sessions: [
                    BridgeSessionStatusRecord(
                        scope: scope,
                        expiresAt: expiresAt,
                        workingDirectory: "/Users/example/project",
                        origin: origin
                    ),
                ],
                updatedAt: Date()
            ),
            fileURL: statusFileURL
        )
        let manager = makeManager()

        let activeSession = try XCTUnwrap(manager.activeSessions().first)

        XCTAssertEqual(activeSession.origin, origin)
    }

    func testCreateSessionPersistsTokenFreeStatusForAccessCenter() throws {
        let scope = "tty:/dev/ttys001:sid:123"
        let manager = makeManager()
        let session = try manager.createSession(ttlSeconds: 60, scope: scope)

        let snapshot = try XCTUnwrap(BridgeSessionStatusStore.load(fileURL: statusFileURL))

        XCTAssertEqual(snapshot.sessions.count, 1)
        XCTAssertEqual(snapshot.sessions.first?.scope, scope)
        XCTAssertEqual(snapshot.sessions.first?.expiresAt.timeIntervalSince1970 ?? 0, session.expiresAt.timeIntervalSince1970, accuracy: 1)
    }

    func testCreateSessionPersistsOriginForDeveloperControlCenterActivation() throws {
        let scope = "tty:/dev/ttys001:sid:123"
        let origin = BridgeSessionOrigin(
            processIdentifier: 1234,
            processName: "iTerm2",
            bundleIdentifier: "com.googlecode.iterm2"
        )
        let manager = makeManager()
        _ = try manager.createSession(ttlSeconds: 60, scope: scope, origin: origin)

        let snapshot = try XCTUnwrap(BridgeSessionStatusStore.load(fileURL: statusFileURL))

        XCTAssertEqual(snapshot.sessions.first?.origin, origin)
    }

    func testClearingSharedStatusRevokesInMemorySession() throws {
        let scope = "tty:/dev/ttys001:sid:123"
        let manager = makeManager()
        let session = try manager.createSession(ttlSeconds: 60, scope: scope)
        XCTAssertNotNil(manager.currentSession(scope: scope))

        XCTAssertTrue(BridgeSessionStatusStore.clearSessionScope(scope, fileURL: statusFileURL))

        XCTAssertNil(manager.currentSession(scope: scope))
        XCTAssertFalse(manager.validateRequestId(UUID(), sessionToken: session.sessionToken, scope: scope))
    }

    func testInvalidateScopeClearsSharedStatusWithoutLocalSession() throws {
        let scope = "tty:/dev/ttys001:sid:123"
        try BridgeSessionStatusStore.save(
            BridgeSessionStatusSnapshot(
                bridgePID: getpid(),
                sessions: [BridgeSessionStatusRecord(scope: scope, expiresAt: Date().addingTimeInterval(60))],
                updatedAt: Date()
            ),
            fileURL: statusFileURL
        )
        let manager = makeManager()

        XCTAssertTrue(manager.invalidate(scope: scope))
        XCTAssertNil(BridgeSessionStatusStore.load(fileURL: statusFileURL))
    }

    private func makeManager() -> BridgeSessionManager {
        BridgeSessionManager(sessionStatusFileURL: statusFileURL, terminalScopeIsUsable: { _ in true })
    }

    private nonisolated(unsafe) static let iso8601: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()
}
