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

    func testInspectorConvertsTCPAndConnectedUDPAndExcludesUnsupportedSockets() {
        let sample = processSample(pid: 42, ppid: 1, startTime: 100)
        let result = AgentNetworkSocketInspector.inspect(
            samples: [sample],
            observedAt: Date(timeIntervalSince1970: 50),
            socketProvider: { _, _ in
                AgentNetworkSocketBatch(
                    sockets: [
                        socket(
                            fd: 3,
                            transport: .tcp,
                            address: .ipv4([203, 0, 113, 8]),
                            port: 443
                        ),
                        socket(
                            fd: 4,
                            transport: .udp,
                            address: .ipv6([
                                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 1,
                            ]),
                            port: 53
                        ),
                        socket(
                            fd: 5,
                            transport: .tcp,
                            address: .ipv4([127, 0, 0, 1]),
                            port: 8080,
                            isListening: true
                        ),
                        socket(
                            fd: 6,
                            transport: .udp,
                            address: .ipv4([127, 0, 0, 1]),
                            port: 0
                        ),
                        socket(
                            fd: 7,
                            transport: .unsupported,
                            address: .unsupported,
                            port: 1
                        ),
                    ],
                    wasTruncated: false
                )
            }
        )

        XCTAssertEqual(result.coverage, .observed)
        XCTAssertEqual(result.observations.map(\.networkProtocol), [.tcp, .udp])
        XCTAssertEqual(
            result.observations.map(\.remoteAddress),
            ["203.0.113.8", "2001:db8::1"]
        )
        XCTAssertEqual(result.observations.map(\.remotePort), [443, 53])
        XCTAssertTrue(result.failedProcessIdentityKeys.isEmpty)
    }

    func testInspectorCapsProcessesAndDescriptorsAndNeverReadsUnrelatedSamples() {
        var samples: [InjectedProcessTreeSample] = []
        for index in 0..<257 {
            let pid = Int32(index + 1)
            let parentPID: Int32 = index == 0 ? 0 : 1
            samples.append(
                processSample(
                    pid: pid,
                    ppid: parentPID,
                    startTime: UInt64(index + 100)
                )
            )
        }
        var inspectedPIDs: [Int32] = []

        let result = AgentNetworkSocketInspector.inspect(
            samples: samples,
            observedAt: Date(timeIntervalSince1970: 50),
            processLimit: 256,
            descriptorLimit: 4_096,
            socketProvider: { sample, remainingDescriptorCount in
                inspectedPIDs.append(sample.pid)
                return AgentNetworkSocketBatch(
                    sockets: [
                        self.socket(
                            fd: sample.pid,
                            transport: .tcp,
                            address: .ipv4([203, 0, 113, 8]),
                            port: 443
                        ),
                    ],
                    wasTruncated: remainingDescriptorCount == 0
                )
            }
        )

        XCTAssertEqual(result.coverage, .partial)
        XCTAssertEqual(inspectedPIDs.count, 256)
        XCTAssertFalse(inspectedPIDs.contains(257))
        XCTAssertEqual(result.observations.count, 256)

        let descriptorLimited = AgentNetworkSocketInspector.inspect(
            samples: Array(samples.prefix(2)),
            observedAt: Date(timeIntervalSince1970: 50),
            processLimit: 256,
            descriptorLimit: 1,
            socketProvider: { sample, remainingDescriptorCount in
                XCTAssertEqual(remainingDescriptorCount, 1)
                return AgentNetworkSocketBatch(
                    sockets: [
                        self.socket(
                            fd: sample.pid,
                            transport: .tcp,
                            address: .ipv4([203, 0, 113, 8]),
                            port: 443
                        ),
                    ],
                    wasTruncated: true
                )
            }
        )
        XCTAssertEqual(descriptorLimited.coverage, .partial)
        XCTAssertEqual(descriptorLimited.observations.count, 1)
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

    private func processSample(
        pid: Int32,
        ppid: Int32,
        startTime: UInt64
    ) -> InjectedProcessTreeSample {
        InjectedProcessTreeSample(
            pid: pid,
            ppid: ppid,
            startTime: startTime,
            executable: "synthetic-client",
            arguments: ["synthetic-client"]
        )
    }

    private func socket(
        fd: Int32,
        transport: AgentNetworkSocketTransport,
        address: AgentNetworkIPAddress,
        port: UInt16,
        isListening: Bool = false
    ) -> AgentNetworkSocketMetadata {
        AgentNetworkSocketMetadata(
            fileDescriptor: fd,
            socketGeneration: UInt64(fd),
            transport: transport,
            remoteAddress: address,
            remotePort: port,
            isListening: isListening
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
