import XCTest
@testable import AuthenticatorBridge
#if os(macOS)
import Darwin
#endif

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

    func testDomainExtractorKeepsOnlyNormalizedHostnamesFromCommandArguments() {
        let samples = [
            InjectedProcessTreeSample(
                pid: 42,
                ppid: 1,
                startTime: 100,
                executable: "sh",
                arguments: [
                    "sh",
                    "-c",
                    "curl 'https://user:synthetic-password@API.Example.COM:8443/v1/items?token=synthetic#part'",
                ]
            ),
            InjectedProcessTreeSample(
                pid: 43,
                ppid: 42,
                startTime: 101,
                executable: "npm",
                arguments: [
                    "npm",
                    "install",
                    "--registry=https://Registry.NPMJS.org/private/path",
                ]
            ),
            InjectedProcessTreeSample(
                pid: 44,
                ppid: 42,
                startTime: 102,
                executable: "git",
                arguments: ["git", "fetch", "git@GitHub.com:synthetic/project.git"]
            ),
        ]

        let evidence = AgentNetworkDomainExtractor.evidence(
            from: samples,
            observedAt: Date(timeIntervalSince1970: 10)
        )

        XCTAssertEqual(evidence.map(\.hostname).sorted(), [
            "api.example.com",
            "github.com",
            "registry.npmjs.org",
        ])
        XCTAssertTrue(evidence.allSatisfy { $0.source == .commandArgument })
        XCTAssertTrue(evidence.allSatisfy { $0.confidence == .inferred })
        XCTAssertFalse(
            evidence.map(\.hostname).joined().contains("synthetic-password")
        )
    }

    func testDomainExtractorRejectsEnvironmentValuesAndIPLiterals() {
        let samples = [
            InjectedProcessTreeSample(
                pid: 42,
                ppid: 1,
                startTime: 100,
                executable: "env",
                arguments: [
                    "env",
                    "TOKEN=secret.example.com",
                    "curl",
                    "https://203.0.113.8/private",
                ]
            ),
            InjectedProcessTreeSample(
                pid: 43,
                ppid: 42,
                startTime: 101,
                executable: "curl",
                arguments: [
                    "curl",
                    "--header",
                    "Authorization: Bearer secret.example.com",
                    "--password=https://password.example.com/private",
                ]
            ),
        ]

        XCTAssertTrue(
            AgentNetworkDomainExtractor.evidence(
                from: samples,
                observedAt: Date(timeIntervalSince1970: 10)
            ).isEmpty
        )
    }

    func testAccumulatorDeduplicatesDomainEvidenceByProcessAndHostname() {
        let runID = UUID()
        let grantID = UUID()
        let sample = InjectedProcessTreeSample(
            pid: 42,
            ppid: 1,
            startTime: 100,
            executable: "curl",
            arguments: ["curl", "https://example.com/one", "https://example.com/two"]
        )
        var accumulator = AgentNetworkActivityAccumulator(
            runID: runID,
            grantIDs: [grantID]
        )

        accumulator.applyDomainEvidence(
            from: [sample],
            observedAt: Date(timeIntervalSince1970: 10)
        )
        accumulator.applyDomainEvidence(
            from: [sample],
            observedAt: Date(timeIntervalSince1970: 11)
        )

        XCTAssertEqual(accumulator.domainEvidence.count, 1)
        XCTAssertEqual(accumulator.domainEvidence[0].runID, runID)
        XCTAssertEqual(accumulator.domainEvidence[0].grantIDs, [grantID])
        XCTAssertEqual(accumulator.domainEvidence[0].hostname, "example.com")
        XCTAssertEqual(accumulator.domainEvidence[0].observationCount, 2)
        XCTAssertEqual(
            accumulator.domainEvidence[0].lastSeenAt,
            Date(timeIntervalSince1970: 11)
        )
    }

    func testSnapshotDecodesLegacyPayloadWithoutDomainEvidence() throws {
        let runID = UUID()
        let grantID = UUID()
        let payload = """
        {
          "runID":"\(runID.uuidString)",
          "grantIDs":["\(grantID.uuidString)"],
          "coverage":"observed",
          "updatedAt":"1970-01-01T00:00:00Z",
          "survivingDescendantIdentityKeys":[],
          "records":[]
        }
        """
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let snapshot = try decoder.decode(
            AgentNetworkActivityRunSnapshot.self,
            from: Data(payload.utf8)
        )

        XCTAssertTrue(snapshot.domainEvidence.isEmpty)
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

    func testAccumulatorBoundsRunRecordsAndConnectionTracking() {
        let runID = UUID()
        var accumulator = AgentNetworkActivityAccumulator(
            runID: runID,
            grantIDs: [UUID()],
            recordLimit: 2,
            connectionLimit: 3
        )

        let wasComplete = accumulator.apply([
            observation(connectionID: "socket-a", port: 443, observedAt: 10),
            observation(connectionID: "socket-b", port: 443, observedAt: 11),
            observation(connectionID: "socket-c", port: 8443, observedAt: 12),
            observation(connectionID: "socket-d", port: 9443, observedAt: 13),
        ])

        XCTAssertFalse(wasComplete)
        XCTAssertEqual(accumulator.records.count, 2)
        XCTAssertEqual(
            accumulator.records.first { $0.remotePort == 443 }?.connectionCount,
            2
        )
    }

    func testAccumulatorDefaultLimitsKeepStressFixtureBelowMemoryBudget() throws {
        let observations = (0..<5_000).map { index in
            observation(
                connectionID: "socket-\(index)",
                port: UInt16(index + 1),
                observedAt: TimeInterval(index)
            )
        }
        var accumulator = AgentNetworkActivityAccumulator(
            runID: UUID(),
            grantIDs: [UUID()]
        )
        let memoryBefore = try residentMemoryBytes()

        let wasComplete = accumulator.apply(observations)

        let memoryDelta = max(0, try residentMemoryBytes() - memoryBefore)
        print("Network accumulator incremental memory: \(memoryDelta) bytes")
        XCTAssertFalse(wasComplete)
        XCTAssertEqual(accumulator.records.count, 2_048)
        XCTAssertLessThan(memoryDelta, 10 * 1_024 * 1_024)
    }

    func testLiveInspectorP95LatencyStaysBelowBudget() {
        #if os(macOS)
        let sample = processSample(
            pid: getpid(),
            ppid: getppid(),
            startTime: 1
        )
        var durations: [TimeInterval] = []

        for _ in 0..<40 {
            let startedAt = ProcessInfo.processInfo.systemUptime
            _ = AgentNetworkSocketInspector.liveInspection(
                samples: [sample],
                observedAt: Date()
            )
            durations.append(ProcessInfo.processInfo.systemUptime - startedAt)
        }

        let ordered = durations.sorted()
        let p95 = ordered[Int(Double(ordered.count - 1) * 0.95)]
        print("Network inspector p95 sample latency: \(p95) seconds")
        XCTAssertLessThan(p95, 0.2)
        #endif
    }

    func testInspectorCapStressP95LatencyStaysBelowBudget() {
        let samples = (1...256).map { index in
            processSample(
                pid: Int32(index),
                ppid: index == 1 ? 0 : 1,
                startTime: UInt64(index)
            )
        }
        var durations: [TimeInterval] = []

        for _ in 0..<20 {
            let startedAt = ProcessInfo.processInfo.systemUptime
            let result = AgentNetworkSocketInspector.inspect(
                samples: samples,
                observedAt: Date(),
                socketProvider: { sample, _ in self.stressSocketBatch(for: sample) }
            )
            XCTAssertEqual(result.observations.count, 4_096)
            durations.append(ProcessInfo.processInfo.systemUptime - startedAt)
        }

        let ordered = durations.sorted()
        let p95 = ordered[Int(Double(ordered.count - 1) * 0.95)]
        print("Network inspector capped-fixture p95 sample latency: \(p95) seconds")
        XCTAssertLessThan(p95, 0.2)
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

    func testStoreReusesUnchangedHistoryWhileActiveCheckpointChanges() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let historyURL = directory.appendingPathComponent("history.jsonl")
        let activeURL = directory.appendingPathComponent("active.jsonl")
        let writer = AgentNetworkActivityStore(
            historyFileURL: historyURL,
            activeFileURL: activeURL
        )
        try writer.finalize(
            snapshot(runID: UUID(), grantID: UUID(), updatedAt: 10),
            now: Date(timeIntervalSince1970: 10)
        )

        let counter = NetworkDataLoadCounter()
        let reader = AgentNetworkActivityStore(
            historyFileURL: historyURL,
            activeFileURL: activeURL,
            dataLoader: { url in
                if url == historyURL {
                    counter.increment()
                }
                return try Data(contentsOf: url)
            }
        )

        _ = try reader.loadAll(now: Date(timeIntervalSince1970: 10))
        try reader.checkpoint(
            snapshot(runID: UUID(), grantID: UUID(), updatedAt: 20)
        )
        _ = try reader.loadAll(now: Date(timeIntervalSince1970: 20))

        XCTAssertEqual(counter.value, 1)
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

    func testFindingsReviewGrantEndedSurvivorsUnavailableAndCleartextTraffic() {
        let grant = makeGrant(expiresAt: Date(timeIntervalSince1970: 100))
        let cleartextPorts: [UInt16] = [20, 21, 23, 80, 110, 143, 389]
        let snapshot = networkSnapshot(
            grantID: grant.id,
            coverage: .unavailable,
            updatedAt: 101,
            survivingDescendants: ["42:100"],
            endpoints: cleartextPorts.map { ("203.0.113.8", $0) }
        )

        let findings = AgentCommandFindingDetector.findings(
            for: grant,
            events: [],
            fileEvents: [],
            networkSnapshots: [snapshot],
            auditRecords: []
        )

        XCTAssertEqual(
            Set(findings.map(\.type)),
            [
                .networkAfterGrantEnded,
                .networkDescendantSurvived,
                .networkInspectionUnavailable,
                .potentialCleartextNetwork,
            ]
        )
        XCTAssertTrue(findings.allSatisfy { $0.severity == .review })
        XCTAssertEqual(
            findings.filter { $0.type == .potentialCleartextNetwork }.count,
            cleartextPorts.count
        )
        XCTAssertTrue(
            findings
                .filter { $0.type == .potentialCleartextNetwork }
                .allSatisfy { $0.networkEvidenceRecordIDs.count == 1 }
        )
    }

    func testFindingsReportPartialInspectionAsInfo() {
        let grant = makeGrant()
        let snapshot = networkSnapshot(
            grantID: grant.id,
            coverage: .partial,
            updatedAt: 50,
            endpoints: [("203.0.113.8", 443)]
        )

        let findings = AgentCommandFindingDetector.findings(
            for: grant,
            events: [],
            fileEvents: [],
            networkSnapshots: [snapshot],
            auditRecords: []
        )

        XCTAssertEqual(findings.map(\.type), [.networkInspectionPartial])
        XCTAssertEqual(findings.map(\.severity), [.info])
    }

    func testFindingsIgnoreNormalTLSAndLoopbackTraffic() {
        let grant = makeGrant()
        let snapshot = networkSnapshot(
            grantID: grant.id,
            coverage: .observed,
            updatedAt: 50,
            endpoints: [
                ("127.0.0.1", 80),
                ("192.168.1.4", 443),
                ("203.0.113.8", 443),
            ]
        )

        let findings = AgentCommandFindingDetector.findings(
            for: grant,
            events: [],
            fileEvents: [],
            networkSnapshots: [snapshot],
            auditRecords: []
        )

        XCTAssertTrue(findings.isEmpty)
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

    private func stressSocketBatch(
        for sample: InjectedProcessTreeSample
    ) -> AgentNetworkSocketBatch {
        var sockets: [AgentNetworkSocketMetadata] = []
        for index in 0..<16 {
            let port = UInt16(10_000 + (Int(sample.pid) * 16) + index)
            sockets.append(AgentNetworkSocketMetadata(
                fileDescriptor: Int32(index),
                socketGeneration: UInt64(index),
                transport: .tcp,
                remoteAddress: .ipv4([203, 0, 113, 8]),
                remotePort: port,
                isListening: false
            ))
        }
        return AgentNetworkSocketBatch(sockets: sockets, wasTruncated: false)
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

    private func networkSnapshot(
        grantID: UUID,
        coverage: AgentNetworkCaptureCoverage,
        updatedAt: TimeInterval,
        survivingDescendants: [String] = [],
        endpoints: [(String, UInt16)]
    ) -> AgentNetworkActivityRunSnapshot {
        let runID = UUID()
        var accumulator = AgentNetworkActivityAccumulator(
            runID: runID,
            grantIDs: [grantID]
        )
        accumulator.apply(
            endpoints.enumerated().map { index, endpoint in
                AgentNetworkSocketObservation(
                    connectionID: "socket-\(index)",
                    observedAt: Date(timeIntervalSince1970: updatedAt),
                    pid: 42,
                    processStartTime: 100,
                    executable: "synthetic-client",
                    depth: 1,
                    remoteAddress: endpoint.0,
                    remotePort: endpoint.1,
                    networkProtocol: .tcp,
                    sentBytes: nil,
                    receivedBytes: nil
                )
            }
        )
        return AgentNetworkActivityRunSnapshot(
            runID: runID,
            grantIDs: [grantID],
            coverage: coverage,
            updatedAt: Date(timeIntervalSince1970: updatedAt),
            endedAt: Date(timeIntervalSince1970: updatedAt),
            survivingDescendantIdentityKeys: survivingDescendants,
            records: accumulator.records
        )
    }

    private func makeGrant(
        expiresAt: Date = Date(timeIntervalSince1970: 100)
    ) -> AgentJITGrant {
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
            expiresAt: expiresAt,
            revokedAt: nil,
            lastUsedAt: nil,
            approvedBy: "test"
        )
    }

    private func residentMemoryBytes() throws -> Int64 {
        #if os(macOS)
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(
            MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size
        )
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(
                to: integer_t.self,
                capacity: Int(count)
            ) {
                task_info(
                    mach_task_self_,
                    task_flavor_t(MACH_TASK_BASIC_INFO),
                    $0,
                    &count
                )
            }
        }
        guard result == KERN_SUCCESS else {
            throw NSError(domain: NSMachErrorDomain, code: Int(result))
        }
        return Int64(info.resident_size)
        #else
        return 0
        #endif
    }
}

private final class NetworkDataLoadCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0

    var value: Int {
        lock.withLock { count }
    }

    func increment() {
        lock.withLock {
            count += 1
        }
    }
}
