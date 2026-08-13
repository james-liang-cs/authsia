#if os(macOS)
import XCTest
@testable import AuthenticatorBridge

final class AccessCenterActivityNotificationTests: XCTestCase {
    func testAccessCenterChangeSignalsDeliverImmediately() throws {
        let sourceURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources/AuthenticatorBridge/AccessCenterActivityNotification.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)

        // Queued (deliverImmediately: false) posts wait until the Bridge run loop is
        // idle, so Access Center can miss grant/session rows until the 30s safety poll.
        XCTAssertTrue(source.contains("deliverImmediately: true"))
        XCTAssertTrue(source.contains("func postGrantDidChange()"))
    }

    func testActivityStoresBroadcastAfterSuccessfulMutations() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-access-center-events-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        try expectActivityChange {
            try BridgeSessionStatusStore.save(
                BridgeSessionStatusSnapshot(
                    bridgePID: 42,
                    sessions: [
                        BridgeSessionStatusRecord(
                            scope: "tty:/dev/ttys001:sid:1001",
                            expiresAt: Date().addingTimeInterval(60)
                        ),
                    ],
                    updatedAt: Date()
                ),
                fileURL: directory.appendingPathComponent("sessions.json")
            )
        }

        try expectActivityChange {
            try AgentFileActivityStore(
                fileURL: directory.appendingPathComponent("files.jsonl")
            ).record(AgentFileActivityEvent(
                recordedAt: Date(),
                agentPlatform: "codex",
                captureSource: .hook,
                workingDirectory: "/tmp/project",
                workspaceRoot: "/tmp/project",
                path: "/tmp/project/Package.swift",
                kind: .file,
                action: .read,
                status: .succeeded,
                confidence: .direct
            ))
        }

        try expectActivityChange {
            let run = InjectedProcessTreeMerger.openRun(
                rootPID: 42,
                rootExecutable: "swift",
                rootArguments: ["swift", "test"],
                startedAt: Date()
            )
            try InjectedProcessTreeStore(
                fileURL: directory.appendingPathComponent("process-trees.jsonl")
            ).upsert(run)
        }

        let networkStore = AgentNetworkActivityStore(
            historyFileURL: directory.appendingPathComponent("network-history.jsonl"),
            activeFileURL: directory.appendingPathComponent("network-active.jsonl")
        )
        let networkSnapshot = AgentNetworkActivityRunSnapshot(
            runID: UUID(),
            grantIDs: [UUID()],
            coverage: .observed,
            updatedAt: Date(),
            records: []
        )
        try expectActivityChange {
            try networkStore.checkpoint(networkSnapshot)
        }
        try expectActivityChange {
            try networkStore.finalize(networkSnapshot)
        }
    }

    private func expectActivityChange(_ mutation: () throws -> Void) throws {
        let expected = expectation(description: "Access Center activity change was broadcast")
        let center = DistributedNotificationCenter.default()
        let observer = center.addObserver(
            forName: Notification.Name("com.authsia.accessCenter.activityDidChange"),
            object: "app.authsia.access-center",
            queue: .main
        ) { notification in
            if let sourcePID = notification.userInfo?["pid"] as? Int,
               sourcePID == ProcessInfo.processInfo.processIdentifier {
                expected.fulfill()
            }
        }
        defer { center.removeObserver(observer) }

        try mutation()
        wait(for: [expected], timeout: 1)
    }
}
#endif
