import XCTest
@testable import AuthenticatorBridge

final class InjectedProcessTreeTests: XCTestCase {
    func testSamplerReturnsRootAndDescendantsWithDepth() {
        let table = [
            InjectedProcessTreeSample(pid: 10, ppid: 1, startTime: 100, executable: "root", arguments: ["root"]),
            InjectedProcessTreeSample(pid: 11, ppid: 10, startTime: 101, executable: "child", arguments: ["child", "a"]),
            InjectedProcessTreeSample(pid: 12, ppid: 11, startTime: 102, executable: "grandchild", arguments: ["grandchild"]),
            InjectedProcessTreeSample(pid: 99, ppid: 1, startTime: 103, executable: "other", arguments: ["other"]),
        ]

        let ranked = InjectedProcessTreeSampler.samples(rootPID: 10, from: table)

        XCTAssertEqual(ranked.map(\.sample.pid), [10, 11, 12])
        XCTAssertEqual(ranked.map(\.depth), [0, 1, 2])
    }

    func testSamplerReadsProcessDetailsOnlyForRootAndDescendants() {
        let topology = [
            InjectedProcessTopologySample(pid: 10, ppid: 1, startTime: 100),
            InjectedProcessTopologySample(pid: 11, ppid: 10, startTime: 101),
            InjectedProcessTopologySample(pid: 12, ppid: 11, startTime: 102),
            InjectedProcessTopologySample(pid: 99, ppid: 1, startTime: 103),
        ]
        var detailedPIDs: [Int32] = []

        let samples = InjectedProcessTreeSampler.samples(
            rootPID: 10,
            topology: topology,
            detailProvider: { pid in
                detailedPIDs.append(pid)
                return InjectedProcessDetail(
                    executable: "process-\(pid)",
                    arguments: ["process-\(pid)"]
                )
            }
        )

        XCTAssertEqual(samples.map(\.pid), [10, 11, 12])
        XCTAssertEqual(detailedPIDs, [10, 11, 12])
        XCTAssertFalse(detailedPIDs.contains(99))
    }

    func testMergerDedupesByPidAndStartTimeAndMarksExited() throws {
        let opened = InjectedProcessTreeMerger.openRun(
            rootPID: 10,
            rootExecutable: "root",
            rootArguments: ["root"],
            startedAt: Date(timeIntervalSince1970: 1),
            rootStartTime: 100
        )
        let first = InjectedProcessTreeMerger.apply(
            samples: [
                (InjectedProcessTreeSample(pid: 10, ppid: 1, startTime: 100, executable: "root", arguments: ["root"]), 0),
                (InjectedProcessTreeSample(pid: 11, ppid: 10, startTime: 101, executable: "child", arguments: ["child"]), 1),
            ],
            to: opened,
            at: Date(timeIntervalSince1970: 2)
        )

        XCTAssertEqual(first.newlySeenNodes.map(\.pid), [11])
        XCTAssertEqual(first.run.nodes.count, 2)

        let second = InjectedProcessTreeMerger.apply(
            samples: [
                (InjectedProcessTreeSample(pid: 10, ppid: 1, startTime: 100, executable: "root", arguments: ["root"]), 0),
            ],
            to: first.run,
            at: Date(timeIntervalSince1970: 3)
        )

        XCTAssertTrue(second.newlySeenNodes.isEmpty)
        let child = try XCTUnwrap(second.run.nodes.first(where: { $0.pid == 11 }))
        XCTAssertEqual(child.exitStatus, 0)
        XCTAssertEqual(child.lastSeenAt, Date(timeIntervalSince1970: 3))
    }

    func testMergerDoesNotDuplicateRootWhenStartTimeBecomesKnown() {
        let opened = InjectedProcessTreeMerger.openRun(
            rootPID: 10,
            rootExecutable: "root",
            rootArguments: ["root"],
            startedAt: Date(timeIntervalSince1970: 1),
            rootStartTime: 0
        )
        let applied = InjectedProcessTreeMerger.apply(
            samples: [
                (InjectedProcessTreeSample(pid: 10, ppid: 1, startTime: 55, executable: "root", arguments: ["root"]), 0),
            ],
            to: opened,
            at: Date(timeIntervalSince1970: 2)
        )

        XCTAssertEqual(applied.run.nodes.count, 1)
        XCTAssertEqual(applied.run.nodes[0].startTime, 55)
        XCTAssertTrue(applied.newlySeenNodes.isEmpty)
    }

    func testStoreRoundTripAndRedactsArguments() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let store = InjectedProcessTreeStore(
            fileURL: directory.appendingPathComponent("trees.jsonl")
        )
        var run = InjectedProcessTreeMerger.openRun(
            rootPID: 42,
            rootExecutable: "env",
            rootArguments: ["env", "TOKEN=super-secret-value"],
            agentJITGrantID: UUID(),
            startedAt: Date(timeIntervalSince1970: 10)
        )
        run = InjectedProcessTreeMerger.finish(run, exitStatus: 0, at: Date(timeIntervalSince1970: 11))
        try store.upsert(run)

        let loaded = try store.loadAll()
        XCTAssertEqual(loaded.count, 1)
        XCTAssertEqual(loaded[0].id, run.id)
        XCTAssertEqual(loaded[0].rootExitStatus, 0)
        XCTAssertFalse(loaded[0].rootArguments.joined(separator: " ").contains("super-secret-value"))
    }

    func testWatcherRecordsInjectedTreeCommandEventsForNewNodes() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let grantID = UUID()
        let treeStore = InjectedProcessTreeStore(fileURL: directory.appendingPathComponent("trees.jsonl"))
        let commandStore = AgentCommandHistoryStore(fileURL: directory.appendingPathComponent("commands.jsonl"))
        let samples = [
            InjectedProcessTreeSample(pid: 10, ppid: 1, startTime: 100, executable: "root", arguments: ["root"]),
            InjectedProcessTreeSample(pid: 11, ppid: 10, startTime: 101, executable: "curl", arguments: ["curl", "https://example.com"]),
        ]
        let watcher = InjectedProcessTreeWatcher(
            store: treeStore,
            commandHistoryStore: commandStore,
            sampleProvider: { _ in samples },
            pollInterval: 60,
            context: InjectedProcessTreeWatchContext(
                agentJITGrantIDs: [grantID],
                agentPlatform: "codex",
                terminalSessionScope: "tty:/dev/ttys001:sid:1",
                workingDirectory: "/tmp/project"
            )
        )

        watcher.start(rootPID: 10, rootExecutable: "root", rootArguments: ["root"], now: Date(timeIntervalSince1970: 5))
        watcher.stop(exitStatus: 0, now: Date(timeIntervalSince1970: 6))

        let runs = try treeStore.loadAll()
        XCTAssertEqual(runs.count, 1)
        XCTAssertEqual(runs[0].nodes.map(\.pid).sorted(), [10, 11])
        XCTAssertEqual(runs[0].rootExitStatus, 0)

        let events = try commandStore.loadAll()
        XCTAssertTrue(events.contains { $0.captureSource == .injectedTree && $0.executable == "curl" })
        XCTAssertTrue(events.allSatisfy { $0.agentJITGrantID == grantID || $0.captureSource != .injectedTree || $0.executable == "curl" || $0.executable == "root" })
        XCTAssertTrue(events.filter { $0.captureSource == .injectedTree }.allSatisfy { $0.agentJITGrantID == grantID })
    }

    func testWatcherUsesSharedSamplesCheckpointsAndFinalizesNetworkActivity() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let treeStore = InjectedProcessTreeStore(
            fileURL: directory.appendingPathComponent("trees.jsonl")
        )
        let commandStore = AgentCommandHistoryStore(
            fileURL: directory.appendingPathComponent("commands.jsonl")
        )
        let networkStore = AgentNetworkActivityStore(
            historyFileURL: directory.appendingPathComponent("network.jsonl"),
            activeFileURL: directory.appendingPathComponent("network-active.jsonl")
        )
        let grantID = UUID()
        let sampleCalls = CallCounter()
        let inspectionCalls = CallCounter()
        let samples = [
            InjectedProcessTreeSample(
                pid: 10,
                ppid: 1,
                startTime: 100,
                executable: "root",
                arguments: ["root"]
            ),
            InjectedProcessTreeSample(
                pid: 11,
                ppid: 10,
                startTime: 101,
                executable: "curl",
                arguments: ["curl", "https://packages.example.com/archive.tgz"]
            ),
        ]
        let watcher = InjectedProcessTreeWatcher(
            store: treeStore,
            commandHistoryStore: commandStore,
            networkActivityStore: networkStore,
            sampleProvider: { _ in
                sampleCalls.increment()
                return samples
            },
            networkInspectionProvider: { receivedSamples, observedAt in
                inspectionCalls.increment()
                XCTAssertEqual(receivedSamples.map(\.pid), [10, 11])
                return AgentNetworkInspectionResult(
                    observations: [
                        AgentNetworkSocketObservation(
                            connectionID: "synthetic-socket",
                            observedAt: observedAt,
                            pid: 11,
                            processStartTime: 101,
                            executable: "helper",
                            depth: 1,
                            remoteAddress: "203.0.113.8",
                            remotePort: 443,
                            networkProtocol: .tcp,
                            sentBytes: nil,
                            receivedBytes: nil
                        ),
                    ],
                    coverage: .observed,
                    failedProcessIdentityKeys: []
                )
            },
            pollInterval: 60,
            networkCheckpointInterval: 2,
            context: InjectedProcessTreeWatchContext(
                agentJITGrantIDs: [grantID],
                agentPlatform: "codex"
            )
        )

        watcher.start(
            rootPID: 10,
            rootExecutable: "root",
            rootArguments: ["root"],
            now: Date(timeIntervalSince1970: 0)
        )
        XCTAssertEqual(
            try networkStore.loadAll(now: Date(timeIntervalSince1970: 0))
                .first?.domainEvidence.map(\.hostname),
            ["packages.example.com"]
        )
        watcher.sampleNow(now: Date(timeIntervalSince1970: 1))
        XCTAssertEqual(
            try networkStore.loadAll(now: Date(timeIntervalSince1970: 1))
                .first?.updatedAt,
            Date(timeIntervalSince1970: 0)
        )
        watcher.sampleNow(now: Date(timeIntervalSince1970: 2))
        XCTAssertEqual(
            try networkStore.loadAll(now: Date(timeIntervalSince1970: 2))
                .first?.updatedAt,
            Date(timeIntervalSince1970: 2)
        )
        watcher.stop(exitStatus: 0, now: Date(timeIntervalSince1970: 3))

        XCTAssertEqual(sampleCalls.value, 4)
        XCTAssertEqual(inspectionCalls.value, 4)
        let snapshot = try XCTUnwrap(
            try networkStore.loadAll(now: Date(timeIntervalSince1970: 3)).first
        )
        XCTAssertEqual(snapshot.endedAt, Date(timeIntervalSince1970: 3))
        XCTAssertEqual(snapshot.records.count, 1)
        XCTAssertEqual(snapshot.records[0].connectionCount, 1)
        XCTAssertEqual(snapshot.domainEvidence.map(\.hostname), ["packages.example.com"])
        XCTAssertEqual(snapshot.domainEvidence.first?.confidence, .inferred)
        XCTAssertEqual(snapshot.survivingDescendantIdentityKeys, ["11:101"])
    }

    func testWatcherIgnoresNetworkStoreFailureAndStillFinalizesProcessTree() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        let treeStore = InjectedProcessTreeStore(
            fileURL: directory.appendingPathComponent("trees.jsonl")
        )
        let watcher = InjectedProcessTreeWatcher(
            store: treeStore,
            commandHistoryStore: AgentCommandHistoryStore(
                fileURL: directory.appendingPathComponent("commands.jsonl")
            ),
            networkActivityStore: AgentNetworkActivityStore(
                historyFileURL: directory,
                activeFileURL: directory
            ),
            sampleProvider: { _ in
                [
                    InjectedProcessTreeSample(
                        pid: 10,
                        ppid: 1,
                        startTime: 100,
                        executable: "root",
                        arguments: ["root"]
                    ),
                ]
            },
            networkInspectionProvider: { _, _ in
                AgentNetworkInspectionResult(
                    observations: [],
                    coverage: .partial,
                    failedProcessIdentityKeys: ["10:100"]
                )
            },
            pollInterval: 60,
            context: InjectedProcessTreeWatchContext(
                agentJITGrantIDs: [UUID()]
            )
        )

        watcher.start(
            rootPID: 10,
            rootExecutable: "root",
            rootArguments: ["root"],
            now: Date(timeIntervalSince1970: 0)
        )
        watcher.stop(exitStatus: 7, now: Date(timeIntervalSince1970: 1))

        XCTAssertEqual(try treeStore.loadAll().first?.rootExitStatus, 7)
    }

    func testFindingsDoNotTreatInjectedTreeAsProcessOnlyCapture() {
        let grantID = UUID()
        let grant = AgentJITGrant(
            id: grantID,
            agentName: "Codex",
            callerFingerprint: AgentJITCallerFingerprint(
                processName: "authsia",
                bundleIdentifier: nil,
                signingTeamId: nil,
                signingIdentity: nil,
                parentProcessName: "codex",
                parentBundleIdentifier: nil,
                sessionScope: "tty:/dev/ttys002:sid:84",
                workingDirectory: "/tmp/project"
            ),
            folderScope: .folder("Team/API"),
            capabilities: [.exec, .list],
            createdAt: Date(timeIntervalSince1970: 50),
            expiresAt: Date(timeIntervalSince1970: 500),
            revokedAt: nil,
            lastUsedAt: nil,
            requestedItems: [],
            agentRuntimeContext: AgentRuntimeContext(
                platform: "codex",
                sessionID: "s1",
                turnID: nil,
                agentID: nil,
                agentType: nil,
                toolUseID: nil
            ),
            approvedBy: "biometric"
        )
        let event = AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 100),
            agentPlatform: "codex",
            agentJITGrantID: grantID,
            captureSource: .injectedTree,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            executable: "curl",
            arguments: ["curl", "https://example.com"],
            command: "curl https://example.com",
            exitStatus: nil
        )

        // Pin `now` inside the grant window; otherwise the recency filter drops this
        // epoch-dated grant before any finding is derived and the assertions pass vacuously.
        let findings = AgentCommandFindingDetector.findings(
            for: [grant],
            events: [event],
            auditRecords: [],
            now: Date(timeIntervalSince1970: 200)
        )

        XCTAssertFalse(findings.contains { $0.type == .processOnlyCapture })
        XCTAssertFalse(findings.contains { $0.type == .processFallbackUsed })
        XCTAssertTrue(findings.contains { $0.type == .injectedTreeCapture })
    }

    // MARK: - Durable write throttling

    /// The watcher samples twice a second, but each `upsert` rewrites the whole store.
    /// These cover the rule that only structural change (or a checkpoint) reaches disk.

    private func makeThrottledWatcher(
        directory: URL,
        samples: @escaping @Sendable () -> [InjectedProcessTreeSample],
        treeCheckpointInterval: TimeInterval = 30
    ) -> (watcher: InjectedProcessTreeWatcher, treeURL: URL) {
        let treeURL = directory.appendingPathComponent("trees.jsonl")
        let watcher = InjectedProcessTreeWatcher(
            store: InjectedProcessTreeStore(fileURL: treeURL),
            commandHistoryStore: AgentCommandHistoryStore(
                fileURL: directory.appendingPathComponent("commands.jsonl")
            ),
            networkActivityStore: AgentNetworkActivityStore(
                historyFileURL: directory.appendingPathComponent("network.jsonl"),
                activeFileURL: directory.appendingPathComponent("network-active.jsonl")
            ),
            sampleProvider: { _ in samples() },
            networkInspectionProvider: { _, _ in
                AgentNetworkInspectionResult(
                    observations: [],
                    coverage: .observed,
                    failedProcessIdentityKeys: []
                )
            },
            // Long enough that the repeating timer never fires inside a test.
            pollInterval: 3600,
            treeCheckpointInterval: treeCheckpointInterval
        )
        return (watcher, treeURL)
    }

    private static let throttleRoot = InjectedProcessTreeSample(
        pid: 10, ppid: 1, startTime: 100, executable: "root", arguments: ["root"]
    )
    private static let throttleChild = InjectedProcessTreeSample(
        pid: 11, ppid: 10, startTime: 101, executable: "aws", arguments: ["aws", "dynamodb", "scan"]
    )

    func testWatcherSkipsPersistWhenOnlySeenTimestampsAdvance() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let (watcher, treeURL) = makeThrottledWatcher(directory: directory) {
            [Self.throttleRoot, Self.throttleChild]
        }
        let start = Date(timeIntervalSince1970: 1_000_000)
        watcher.start(rootPID: 10, rootExecutable: "root", rootArguments: ["root"], now: start)
        let afterStart = try Data(contentsOf: treeURL)

        // An unchanged tree, sampled repeatedly: only lastSeenAt would move.
        watcher.sampleNow(now: start.addingTimeInterval(1))
        watcher.sampleNow(now: start.addingTimeInterval(2))
        watcher.sampleNow(now: start.addingTimeInterval(3))

        XCTAssertEqual(try Data(contentsOf: treeURL), afterStart)
    }

    func testWatcherPersistsWhenADescendantAppears() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let visible = VisibleSamples(samples: [Self.throttleRoot])
        let (watcher, treeURL) = makeThrottledWatcher(directory: directory) { visible.value }
        let start = Date(timeIntervalSince1970: 1_000_000)
        watcher.start(rootPID: 10, rootExecutable: "root", rootArguments: ["root"], now: start)
        let afterStart = try Data(contentsOf: treeURL)

        visible.value = [Self.throttleRoot, Self.throttleChild]
        watcher.sampleNow(now: start.addingTimeInterval(1))

        let afterChild = try Data(contentsOf: treeURL)
        XCTAssertNotEqual(afterChild, afterStart)
        XCTAssertTrue(String(decoding: afterChild, as: UTF8.self).contains("dynamodb"))
    }

    func testWatcherPersistsWhenADescendantExits() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let visible = VisibleSamples(samples: [Self.throttleRoot, Self.throttleChild])
        let (watcher, treeURL) = makeThrottledWatcher(directory: directory) { visible.value }
        let start = Date(timeIntervalSince1970: 1_000_000)
        watcher.start(rootPID: 10, rootExecutable: "root", rootArguments: ["root"], now: start)
        watcher.sampleNow(now: start.addingTimeInterval(1))
        let beforeExit = try Data(contentsOf: treeURL)

        visible.value = [Self.throttleRoot]
        watcher.sampleNow(now: start.addingTimeInterval(2))

        XCTAssertNotEqual(try Data(contentsOf: treeURL), beforeExit)
    }

    func testWatcherPersistsUnchangedTreeOnceTheCheckpointIntervalElapses() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let (watcher, treeURL) = makeThrottledWatcher(
            directory: directory,
            samples: { [Self.throttleRoot, Self.throttleChild] },
            treeCheckpointInterval: 30
        )
        let start = Date(timeIntervalSince1970: 1_000_000)
        watcher.start(rootPID: 10, rootExecutable: "root", rootArguments: ["root"], now: start)
        let afterStart = try Data(contentsOf: treeURL)

        watcher.sampleNow(now: start.addingTimeInterval(29))
        XCTAssertEqual(try Data(contentsOf: treeURL), afterStart, "before the checkpoint is due")

        watcher.sampleNow(now: start.addingTimeInterval(31))
        XCTAssertNotEqual(try Data(contentsOf: treeURL), afterStart, "after the checkpoint is due")
    }

    func testWatcherAlwaysPersistsOnStop() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let (watcher, treeURL) = makeThrottledWatcher(directory: directory) {
            [Self.throttleRoot, Self.throttleChild]
        }
        let start = Date(timeIntervalSince1970: 1_000_000)
        watcher.start(rootPID: 10, rootExecutable: "root", rootArguments: ["root"], now: start)

        watcher.stop(exitStatus: 0, now: start.addingTimeInterval(2))

        let runs = try InjectedProcessTreeStore(fileURL: treeURL).loadAll()
        XCTAssertEqual(runs.count, 1)
        XCTAssertNotNil(runs.first?.endedAt)
        XCTAssertEqual(runs.first?.rootExitStatus, 0)
    }

    // MARK: - Store retention

    private func makeRun(startedAt: Date, endedAt: Date?) -> InjectedProcessTreeRun {
        InjectedProcessTreeRun(
            startedAt: startedAt,
            endedAt: endedAt,
            rootPID: 10,
            rootExecutable: "root",
            rootArguments: ["root"]
        )
    }

    func testStoreDropsRunsPastTheRetentionWindow() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let store = InjectedProcessTreeStore(
            fileURL: directory.appendingPathComponent("trees.jsonl"),
            retentionInterval: 60,
            runLimit: 100
        )
        let now = Date(timeIntervalSince1970: 1_000_000)
        let stale = makeRun(startedAt: now.addingTimeInterval(-600), endedAt: now.addingTimeInterval(-500))
        let fresh = makeRun(startedAt: now.addingTimeInterval(-30), endedAt: now.addingTimeInterval(-10))

        try store.upsert(stale, now: now.addingTimeInterval(-500))
        try store.upsert(fresh, now: now)

        XCTAssertEqual(try store.loadAll().map(\.id), [fresh.id])
    }

    func testStoreKeepsOnlyTheNewestRunsUpToTheLimit() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let store = InjectedProcessTreeStore(
            fileURL: directory.appendingPathComponent("trees.jsonl"),
            retentionInterval: 30 * 24 * 60 * 60,
            runLimit: 3
        )
        let now = Date(timeIntervalSince1970: 1_000_000)
        var written: [InjectedProcessTreeRun] = []
        for offset in 0..<6 {
            let run = makeRun(
                startedAt: now.addingTimeInterval(TimeInterval(offset)),
                endedAt: now.addingTimeInterval(TimeInterval(offset))
            )
            written.append(run)
            try store.upsert(run, now: now.addingTimeInterval(TimeInterval(offset)))
        }

        XCTAssertEqual(try store.loadAll().map(\.id), written.suffix(3).map(\.id))
    }

    func testStoreNeverPrunesTheRunItIsWriting() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let store = InjectedProcessTreeStore(
            fileURL: directory.appendingPathComponent("trees.jsonl"),
            retentionInterval: 60,
            runLimit: 2
        )
        let now = Date(timeIntervalSince1970: 1_000_000)
        // A long-running run started before the retention window opened must survive
        // its own checkpoints rather than prune itself away.
        let longRunning = makeRun(startedAt: now.addingTimeInterval(-600), endedAt: nil)
        try store.upsert(longRunning, now: now)
        try store.upsert(makeRun(startedAt: now, endedAt: now), now: now)
        try store.upsert(makeRun(startedAt: now.addingTimeInterval(1), endedAt: now.addingTimeInterval(1)), now: now)
        try store.upsert(longRunning, now: now.addingTimeInterval(2))

        XCTAssertTrue(try store.loadAll().contains { $0.id == longRunning.id })
    }
}

private final class VisibleSamples: @unchecked Sendable {
    private let lock = NSLock()
    private var samples: [InjectedProcessTreeSample]

    init(samples: [InjectedProcessTreeSample]) {
        self.samples = samples
    }

    var value: [InjectedProcessTreeSample] {
        get { lock.withLock { samples } }
        set { lock.withLock { samples = newValue } }
    }
}


private final class CallCounter: @unchecked Sendable {
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
