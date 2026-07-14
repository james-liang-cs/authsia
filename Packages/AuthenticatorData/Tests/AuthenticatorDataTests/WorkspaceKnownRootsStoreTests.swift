import XCTest
@testable import AuthenticatorData

final class WorkspaceKnownRootsStoreTests: XCTestCase {
    func testRecordLoadAndForgetWorkspaceRoots() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = WorkspaceKnownRootsStore(applicationSupportDirectory: tempDir)
        let first = tempDir.appendingPathComponent("api", isDirectory: true)
        let second = tempDir.appendingPathComponent("web", isDirectory: true)

        try store.record(first.path)
        try store.record("  \(second.path)  ")
        try store.record(first.path)

        XCTAssertEqual(try store.load(), [first.standardizedFileURL.path, second.standardizedFileURL.path])

        try store.forget(first.path)

        XCTAssertEqual(try store.load(), [second.standardizedFileURL.path])
    }

    func testRecordKeepsMostRecentlyTouchedRootFirstWithoutBulkRefreshReordering() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = WorkspaceKnownRootsStore(applicationSupportDirectory: tempDir)
        let first = tempDir.appendingPathComponent("api", isDirectory: true).standardizedFileURL.path
        let second = tempDir.appendingPathComponent("web", isDirectory: true).standardizedFileURL.path

        try store.record(first)
        try store.record(second)

        XCTAssertEqual(try store.load(), [second, first])

        try store.record([first, second])

        XCTAssertEqual(try store.load(), [second, first])

        try store.record(first)

        XCTAssertEqual(try store.load(), [first, second])
    }

    func testWorkspaceRootsFileContainsOnlyPaths() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = WorkspaceKnownRootsStore(applicationSupportDirectory: tempDir)

        try store.record("/tmp/authsia-workspace")

        let data = try Data(contentsOf: knownRootsFileURL(in: tempDir))
        let json = try XCTUnwrap(String(data: data, encoding: .utf8))
        XCTAssertTrue(json.contains("/tmp/authsia-workspace"))
        XCTAssertFalse(json.contains("authsia://"))
        XCTAssertFalse(json.contains("API_KEY"))
        XCTAssertFalse(json.contains("password"))
    }

    func testNewerSchemaIsNotOverwrittenByOlderStore() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = WorkspaceKnownRootsStore(applicationSupportDirectory: tempDir)
        let fileURL = knownRootsFileURL(in: tempDir)
        try FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let futureSnapshot = WorkspaceKnownRootsSnapshot(
            schemaVersion: WorkspaceKnownRootsStore.currentSchemaVersion + 1,
            roots: ["/tmp/future-workspace"]
        )
        try JSONEncoder().encode(futureSnapshot).write(to: fileURL)

        XCTAssertThrowsError(try store.load())
        XCTAssertThrowsError(try store.record("/tmp/current-workspace"))

        let stored = try JSONDecoder().decode(
            WorkspaceKnownRootsSnapshot.self,
            from: try Data(contentsOf: fileURL)
        )
        XCTAssertEqual(stored.schemaVersion, WorkspaceKnownRootsStore.currentSchemaVersion + 1)
        XCTAssertEqual(stored.roots, ["/tmp/future-workspace"])
    }

    func testRecordSkipsRewriteWhenRootsUnchanged() throws {
        let tempDir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = WorkspaceKnownRootsStore(applicationSupportDirectory: tempDir)
        let fileURL = knownRootsFileURL(in: tempDir)

        try store.record("/tmp/authsia-workspace")
        let initialDate = try XCTUnwrap(
            FileManager.default.attributesOfItem(atPath: fileURL.path)[.modificationDate] as? Date
        )

        Thread.sleep(forTimeInterval: 0.02)
        try store.record("/tmp/authsia-workspace")
        try store.record(["/tmp/authsia-workspace", "/tmp/authsia-workspace/"])

        let finalDate = try XCTUnwrap(
            FileManager.default.attributesOfItem(atPath: fileURL.path)[.modificationDate] as? Date
        )
        XCTAssertEqual(initialDate, finalDate)
    }

    private func makeTemporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func knownRootsFileURL(in applicationSupportDirectory: URL) -> URL {
        applicationSupportDirectory
            .appendingPathComponent("Authsia", isDirectory: true)
            .appendingPathComponent("Workspace", isDirectory: true)
            .appendingPathComponent("known_roots.json")
    }
}
