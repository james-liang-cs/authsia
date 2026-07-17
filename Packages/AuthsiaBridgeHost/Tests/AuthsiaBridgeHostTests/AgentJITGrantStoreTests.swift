import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge

#if os(macOS)
final class AgentJITGrantStoreTests: XCTestCase {
    func testSaveAllEmptyBatchDoesNotCreateStoreOrCallWriter() throws {
        let tempDir = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let fileURL = tempDir.appendingPathComponent("agent-jit-grants.json")
        var writeCount = 0
        let store = AgentJITGrantStore(fileURL: fileURL, atomicWriter: { _ in
            writeCount += 1
        })

        try store.saveAll([])

        XCTAssertEqual(writeCount, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: fileURL.path))
    }

    func testSaveAllReplacesInPlaceAndAppendsInBatchOrder() throws {
        let tempDir = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = AgentJITGrantStore(fileURL: tempDir.appendingPathComponent("agent-jit-grants.json"))
        let first = grant(id: "00000000-0000-0000-0000-000000000001", folder: "Team/One")
        let second = grant(id: "00000000-0000-0000-0000-000000000002", folder: "Team/Two")
        let appendedFirst = grant(id: "00000000-0000-0000-0000-000000000003", folder: "Team/Three")
        let updatedFirst = grant(id: "00000000-0000-0000-0000-000000000001", folder: "Team/Updated")
        let appendedSecond = grant(id: "00000000-0000-0000-0000-000000000004", folder: "Team/Four")
        try store.saveAll([first, second])

        try store.saveAll([appendedFirst, updatedFirst, appendedSecond])

        XCTAssertEqual(try store.loadAll(), [updatedFirst, second, appendedFirst, appendedSecond])
    }

    func testSaveRetainsSingleGrantUpsertCompatibility() throws {
        let tempDir = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = AgentJITGrantStore(fileURL: tempDir.appendingPathComponent("agent-jit-grants.json"))
        let original = grant(id: "00000000-0000-0000-0000-000000000001", folder: "Team/One")
        let updated = grant(id: "00000000-0000-0000-0000-000000000001", folder: "Team/Updated")

        try store.save(original)
        try store.save(updated)

        XCTAssertEqual(try store.loadAll(), [updated])
    }

    func testSaveAllWriteFailureLeavesPriorContentsUnchanged() throws {
        let tempDir = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let fileURL = tempDir.appendingPathComponent("agent-jit-grants.json")
        let persistedStore = AgentJITGrantStore(fileURL: fileURL)
        let first = grant(id: "00000000-0000-0000-0000-000000000001", folder: "Team/One")
        let second = grant(id: "00000000-0000-0000-0000-000000000002", folder: "Team/Two")
        try persistedStore.saveAll([first, second])
        let updatedFirst = grant(id: "00000000-0000-0000-0000-000000000001", folder: "Team/Updated")
        let appended = grant(id: "00000000-0000-0000-0000-000000000003", folder: "Team/Three")
        let failingStore = AgentJITGrantStore(fileURL: fileURL, atomicWriter: { _ in
            throw InjectedWriteError.failed
        })

        XCTAssertThrowsError(try failingStore.saveAll([updatedFirst, appended])) { error in
            XCTAssertEqual(error as? InjectedWriteError, .failed)
        }
        XCTAssertEqual(try persistedStore.loadAll(), [first, second])
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
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresAt: Date(timeIntervalSince1970: 1_700_000_300),
            revokedAt: nil,
            lastUsedAt: nil,
            approvedBy: "macBiometric"
        )
    }
}

private enum InjectedWriteError: Error, Equatable {
    case failed
}
#endif
