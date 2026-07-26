import XCTest
@testable import AuthenticatorBridge

final class AgentNetworkActivityTests: XCTestCase {
    func testDestinationZoneClassifiesLoopbackPrivatePublicAndUnknown() {
        XCTAssertEqual(AgentNetworkDestinationZone.classify("127.0.0.1"), .loopback)
        XCTAssertEqual(AgentNetworkDestinationZone.classify("::1"), .loopback)
        XCTAssertEqual(AgentNetworkDestinationZone.classify("10.0.0.4"), .privateNetwork)
        XCTAssertEqual(AgentNetworkDestinationZone.classify("172.16.10.2"), .privateNetwork)
        XCTAssertEqual(AgentNetworkDestinationZone.classify("192.168.1.4"), .privateNetwork)
        XCTAssertEqual(AgentNetworkDestinationZone.classify("169.254.1.1"), .privateNetwork)
        XCTAssertEqual(AgentNetworkDestinationZone.classify("fc00::1"), .privateNetwork)
        XCTAssertEqual(AgentNetworkDestinationZone.classify("fe80::1"), .privateNetwork)
        XCTAssertEqual(AgentNetworkDestinationZone.classify("203.0.113.8"), .publicInternet)
        XCTAssertEqual(AgentNetworkDestinationZone.classify("2001:db8::1"), .publicInternet)
        XCTAssertEqual(AgentNetworkDestinationZone.classify("invalid"), .unknown)
    }

    func testAccumulatorMergesRepeatedSocketAndCountsDistinctConnections() {
        let runID = UUID()
        let grantID = UUID()
        var accumulator = AgentNetworkActivityAccumulator(
            runID: runID,
            grantIDs: [grantID]
        )

        accumulator.apply([
            observation(connectionID: "socket-a", port: 443, observedAt: 10),
            observation(connectionID: "socket-a", port: 443, observedAt: 11),
            observation(connectionID: "socket-b", port: 443, observedAt: 12),
            observation(connectionID: "socket-c", port: 8443, observedAt: 12),
        ])

        XCTAssertEqual(accumulator.records.count, 2)
        let https = accumulator.records.first { $0.remotePort == 443 }
        XCTAssertEqual(https?.runID, runID)
        XCTAssertEqual(https?.grantIDs, [grantID])
        XCTAssertEqual(https?.connectionCount, 2)
        XCTAssertEqual(https?.firstSeenAt, Date(timeIntervalSince1970: 10))
        XCTAssertEqual(https?.lastSeenAt, Date(timeIntervalSince1970: 12))
        XCTAssertEqual(https?.destinationZone, .publicInternet)
    }

    func testStoreReplacesActiveCheckpointAndMovesFinalRunToHistory() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let historyURL = directory.appendingPathComponent("history.jsonl")
        let activeURL = directory.appendingPathComponent("active.jsonl")
        let store = AgentNetworkActivityStore(
            historyFileURL: historyURL,
            activeFileURL: activeURL
        )
        let runID = UUID()
        let grantID = UUID()

        try store.checkpoint(snapshot(runID: runID, grantID: grantID, updatedAt: 10))
        try store.checkpoint(snapshot(runID: runID, grantID: grantID, updatedAt: 20))

        XCTAssertEqual(try store.loadAll().map(\.updatedAt), [
            Date(timeIntervalSince1970: 20),
        ])
        XCTAssertTrue(FileManager.default.fileExists(atPath: activeURL.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: historyURL.path))

        try store.finalize(
            snapshot(runID: runID, grantID: grantID, updatedAt: 30),
            now: Date(timeIntervalSince1970: 30)
        )

        let finalized = try XCTUnwrap(
            try store.loadAll(now: Date(timeIntervalSince1970: 30)).first
        )
        XCTAssertEqual(finalized.runID, runID)
        XCTAssertEqual(finalized.endedAt, Date(timeIntervalSince1970: 30))
        XCTAssertFalse(FileManager.default.fileExists(atPath: activeURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: historyURL.path))

        let directoryAttributes = try FileManager.default.attributesOfItem(
            atPath: directory.path
        )
        let fileAttributes = try FileManager.default.attributesOfItem(
            atPath: historyURL.path
        )
        XCTAssertEqual(
            (directoryAttributes[.posixPermissions] as? NSNumber)?.intValue,
            0o700
        )
        XCTAssertEqual(
            (fileAttributes[.posixPermissions] as? NSNumber)?.intValue,
            0o600
        )
    }

    func testStorePrunesExpiredAndOldestAggregateRows() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let store = AgentNetworkActivityStore(
            historyFileURL: directory.appendingPathComponent("history.jsonl"),
            activeFileURL: directory.appendingPathComponent("active.jsonl"),
            retentionInterval: 30 * 24 * 60 * 60,
            aggregateLimit: 2
        )
        let now = Date(timeIntervalSince1970: 4_000_000)
        let oldDate = now.addingTimeInterval(-(31 * 24 * 60 * 60))
        let recentDates = [
            now.addingTimeInterval(-30),
            now.addingTimeInterval(-20),
            now.addingTimeInterval(-10),
        ]

        try store.finalize(
            snapshot(runID: UUID(), grantID: UUID(), updatedAt: oldDate.timeIntervalSince1970),
            now: oldDate
        )
        for date in recentDates {
            try store.finalize(
                snapshot(runID: UUID(), grantID: UUID(), updatedAt: date.timeIntervalSince1970),
                now: date
            )
        }

        let loaded = try store.loadAll(now: now)
        XCTAssertEqual(loaded.flatMap(\.records).count, 2)
        XCTAssertEqual(loaded.map(\.updatedAt), Array(recentDates.suffix(2)))
    }

    func testStoreSkipsCorruptHistoryLinesAndQueryUsesDirectGrantID() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let historyURL = directory.appendingPathComponent("history.jsonl")
        let store = AgentNetworkActivityStore(
            historyFileURL: historyURL,
            activeFileURL: directory.appendingPathComponent("active.jsonl")
        )
        let matchingGrant = makeGrant()
        let matching = snapshot(
            runID: UUID(),
            grantID: matchingGrant.id,
            updatedAt: 10
        )
        let unrelated = snapshot(runID: UUID(), grantID: UUID(), updatedAt: 20)
        try store.finalize(matching, now: matching.updatedAt)
        try store.finalize(unrelated, now: unrelated.updatedAt)

        let handle = try FileHandle(forWritingTo: historyURL)
        try handle.seekToEnd()
        try handle.write(contentsOf: Data("not-json\n".utf8))
        try handle.close()

        let loaded = try store.loadAll(now: Date(timeIntervalSince1970: 20))
        XCTAssertEqual(loaded.count, 2)
        XCTAssertEqual(
            AgentNetworkActivityQuery.snapshots(
                for: matchingGrant,
                from: loaded
            ).map(\.runID),
            [matching.runID]
        )
    }

    private func observation(
        connectionID: String,
        port: UInt16,
        observedAt: TimeInterval
    ) -> AgentNetworkSocketObservation {
        AgentNetworkSocketObservation(
            connectionID: connectionID,
            observedAt: Date(timeIntervalSince1970: observedAt),
            pid: 42,
            processStartTime: 100,
            executable: "synthetic-client",
            depth: 1,
            remoteAddress: "203.0.113.8",
            remotePort: port,
            networkProtocol: .tcp,
            sentBytes: nil,
            receivedBytes: nil
        )
    }

    private func snapshot(
        runID: UUID,
        grantID: UUID,
        updatedAt: TimeInterval
    ) -> AgentNetworkActivityRunSnapshot {
        var accumulator = AgentNetworkActivityAccumulator(
            runID: runID,
            grantIDs: [grantID]
        )
        accumulator.apply([
            observation(
                connectionID: runID.uuidString,
                port: 443,
                observedAt: updatedAt
            ),
        ])
        return AgentNetworkActivityRunSnapshot(
            runID: runID,
            grantIDs: [grantID],
            coverage: .observed,
            updatedAt: Date(timeIntervalSince1970: updatedAt),
            records: accumulator.records
        )
    }

    private func makeGrant() -> AgentJITGrant {
        AgentJITGrant(
            id: UUID(),
            agentName: "Codex",
            callerFingerprint: AgentJITCallerFingerprint(
                processName: "authsia",
                bundleIdentifier: nil,
                signingTeamId: nil,
                signingIdentity: nil,
                parentProcessName: "codex",
                parentBundleIdentifier: nil,
                sessionScope: "synthetic-session",
                workingDirectory: "/tmp/project"
            ),
            folderScope: .folder("Synthetic"),
            capabilities: [.exec],
            createdAt: Date(timeIntervalSince1970: 1),
            expiresAt: Date(timeIntervalSince1970: 100),
            revokedAt: nil,
            lastUsedAt: nil,
            approvedBy: "test"
        )
    }
}
