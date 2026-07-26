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

        let findings = AgentCommandFindingDetector.findings(
            for: [grant],
            events: [event],
            auditRecords: []
        )

        XCTAssertFalse(findings.contains { $0.type == .processOnlyCapture })
        XCTAssertFalse(findings.contains { $0.type == .processFallbackUsed })
        XCTAssertTrue(findings.contains { $0.type == .injectedTreeCapture })
    }
}
