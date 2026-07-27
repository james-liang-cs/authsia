import Foundation
#if os(macOS)
import Darwin
#endif

public struct InjectedProcessTreeSample: Equatable, Sendable {
    public let pid: Int32
    public let ppid: Int32
    public let startTime: UInt64
    public let executable: String
    public let arguments: [String]

    public init(
        pid: Int32,
        ppid: Int32,
        startTime: UInt64,
        executable: String,
        arguments: [String]
    ) {
        self.pid = pid
        self.ppid = ppid
        self.startTime = startTime
        self.executable = executable
        self.arguments = arguments
    }

    public var identityKey: String {
        "\(pid):\(startTime)"
    }
}

public struct InjectedProcessTopologySample: Equatable, Sendable {
    public let pid: Int32
    public let ppid: Int32
    public let startTime: UInt64

    public init(pid: Int32, ppid: Int32, startTime: UInt64) {
        self.pid = pid
        self.ppid = ppid
        self.startTime = startTime
    }
}

public struct InjectedProcessDetail: Equatable, Sendable {
    public let executable: String
    public let arguments: [String]

    public init(executable: String, arguments: [String]) {
        self.executable = executable
        self.arguments = arguments
    }
}

public struct InjectedProcessTreeNode: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let runID: UUID
    public let pid: Int32
    public let ppid: Int32
    public let startTime: UInt64
    public let executable: String?
    public let arguments: [String]
    public let depth: Int
    public let firstSeenAt: Date
    public var lastSeenAt: Date
    public var exitStatus: Int32?

    public init(
        id: UUID = UUID(),
        runID: UUID,
        pid: Int32,
        ppid: Int32,
        startTime: UInt64,
        executable: String?,
        arguments: [String],
        depth: Int,
        firstSeenAt: Date,
        lastSeenAt: Date,
        exitStatus: Int32? = nil
    ) {
        self.id = id
        self.runID = runID
        self.pid = pid
        self.ppid = ppid
        self.startTime = startTime
        self.executable = AgentCommandRedactor.sanitized(executable, maxLength: 1024)
        self.arguments = AgentCommandRedactor.redactedArguments(arguments)
        self.depth = depth
        self.firstSeenAt = firstSeenAt
        self.lastSeenAt = lastSeenAt
        self.exitStatus = exitStatus
    }

    public var identityKey: String {
        "\(pid):\(startTime)"
    }
}

public struct InjectedProcessTreeRun: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let startedAt: Date
    public var endedAt: Date?
    public let rootPID: Int32
    public let rootExecutable: String?
    public let rootArguments: [String]
    public let agentJITGrantID: UUID?
    public let terminalSessionScope: String?
    public let workingDirectory: String?
    public let agentPlatform: String?
    public var rootExitStatus: Int32?
    public var nodes: [InjectedProcessTreeNode]

    public init(
        id: UUID = UUID(),
        startedAt: Date,
        endedAt: Date? = nil,
        rootPID: Int32,
        rootExecutable: String?,
        rootArguments: [String],
        agentJITGrantID: UUID? = nil,
        terminalSessionScope: String? = nil,
        workingDirectory: String? = nil,
        agentPlatform: String? = nil,
        rootExitStatus: Int32? = nil,
        nodes: [InjectedProcessTreeNode] = []
    ) {
        self.id = id
        self.startedAt = startedAt
        self.endedAt = endedAt
        self.rootPID = rootPID
        self.rootExecutable = AgentCommandRedactor.sanitized(rootExecutable, maxLength: 1024)
        self.rootArguments = AgentCommandRedactor.redactedArguments(rootArguments)
        self.agentJITGrantID = agentJITGrantID
        self.terminalSessionScope = AgentCommandRedactor.sanitized(terminalSessionScope, maxLength: 1024)
        self.workingDirectory = AgentCommandRedactor.sanitized(workingDirectory, maxLength: 2048)
        self.agentPlatform = AgentCommandRedactor.sanitized(agentPlatform)
        self.rootExitStatus = rootExitStatus
        self.nodes = nodes
    }
}

public enum InjectedProcessTreeQuery {
    public static func runs(for grant: AgentJITGrant, from runs: [InjectedProcessTreeRun]) -> [InjectedProcessTreeRun] {
        runs
            .filter { run in
                if let grantID = run.agentJITGrantID, grantID == grant.id {
                    return true
                }
                return matchesTerminalScope(run: run, grant: grant)
            }
            .sorted { $0.startedAt < $1.startedAt }
    }

    private static func matchesTerminalScope(run: InjectedProcessTreeRun, grant: AgentJITGrant) -> Bool {
        guard AgentGrantActivityAttribution.matchesAgentPlatform(
            run.agentPlatform,
            grant: grant
        ) else {
            return false
        }
        guard let runScope = normalized(run.terminalSessionScope),
              let grantScope = normalized(grant.callerFingerprint.sessionScope),
              runScope == grantScope else {
            return false
        }
        guard let runWorkingDirectory = normalizedPath(run.workingDirectory),
              let grantWorkingDirectory = normalizedPath(grant.callerFingerprint.workingDirectory) else {
            return true
        }
        return runWorkingDirectory == grantWorkingDirectory
    }

    private static func normalizedPath(_ value: String?) -> String? {
        guard let value = normalized(value) else { return nil }
        return URL(fileURLWithPath: value).standardizedFileURL.path
    }

    private static func normalized(_ value: String?) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}

public enum InjectedProcessTreeSampler {
    public typealias DetailProvider = (Int32) -> InjectedProcessDetail?

    /// Returns the root and its descendants from a flat process table, with depth from root.
    public static func samples(
        rootPID: Int32,
        from table: [InjectedProcessTreeSample]
    ) -> [(sample: InjectedProcessTreeSample, depth: Int)] {
        guard let root = table.first(where: { $0.pid == rootPID }) else { return [] }

        var childrenByParent: [Int32: [InjectedProcessTreeSample]] = [:]
        for sample in table where sample.pid != rootPID {
            childrenByParent[sample.ppid, default: []].append(sample)
        }

        var result: [(InjectedProcessTreeSample, Int)] = [(root, 0)]
        var queue: [(pid: Int32, depth: Int)] = [(rootPID, 0)]
        var seen = Set<String>([root.identityKey])

        while let current = queue.first {
            queue.removeFirst()
            for child in childrenByParent[current.pid] ?? [] {
                guard !seen.contains(child.identityKey) else { continue }
                seen.insert(child.identityKey)
                let depth = current.depth + 1
                result.append((child, depth))
                queue.append((child.pid, depth))
            }
        }

        return result
    }

    public static func samples(
        rootPID: Int32,
        topology: [InjectedProcessTopologySample],
        detailProvider: DetailProvider
    ) -> [InjectedProcessTreeSample] {
        let topologyTable = topology.map {
            InjectedProcessTreeSample(
                pid: $0.pid,
                ppid: $0.ppid,
                startTime: $0.startTime,
                executable: "unknown",
                arguments: []
            )
        }
        return samples(rootPID: rootPID, from: topologyTable).map { ranked in
            let detail = detailProvider(ranked.sample.pid)
            return InjectedProcessTreeSample(
                pid: ranked.sample.pid,
                ppid: ranked.sample.ppid,
                startTime: ranked.sample.startTime,
                executable: detail?.executable ?? "unknown",
                arguments: detail?.arguments ?? []
            )
        }
    }

    public static func liveSamples(rootPID: Int32) -> [InjectedProcessTreeSample] {
        #if os(macOS)
        return samples(
            rootPID: rootPID,
            topology: allLiveTopology(),
            detailProvider: processDetail
        )
        #else
        _ = rootPID
        return []
        #endif
    }

    #if os(macOS)
    private static func allLiveTopology() -> [InjectedProcessTopologySample] {
        processIDs().compactMap { pid in
            var info = proc_bsdinfo()
            let size = Int32(MemoryLayout<proc_bsdinfo>.size)
            let result = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size)
            guard result == size else { return nil }
            return InjectedProcessTopologySample(
                pid: pid,
                ppid: Int32(info.pbi_ppid),
                startTime: info.pbi_start_tvsec
            )
        }
    }

    private static func processDetail(for pid: Int32) -> InjectedProcessDetail? {
        let arguments = processArguments(for: pid)
        return InjectedProcessDetail(
            executable: processExecutableName(arguments: arguments) ?? "unknown",
            arguments: arguments
        )
    }

    private static func processIDs() -> [pid_t] {
        let count = Int(proc_listallpids(nil, 0))
        guard count > 0 else { return [] }

        var pids = [pid_t](repeating: 0, count: count)
        let byteCount = pids.withUnsafeMutableBytes { buffer in
            proc_listallpids(buffer.baseAddress, Int32(buffer.count))
        }
        guard byteCount > 0 else { return [] }

        let processCount = min(Int(byteCount) / MemoryLayout<pid_t>.size, pids.count)
        return Array(pids.prefix(processCount)).filter { $0 > 0 }
    }

    private static func processArguments(for pid: pid_t) -> [String] {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0 else { return [] }

        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0,
              size > MemoryLayout<Int32>.size else {
            return []
        }

        let argc = buffer.withUnsafeBytes { $0.load(as: Int32.self) }
        guard argc > 0 else { return [] }

        var offset = MemoryLayout<Int32>.size
        while offset < size && buffer[offset] != 0 { offset += 1 }
        while offset < size && buffer[offset] == 0 { offset += 1 }
        guard offset < size else { return [] }

        var arguments: [String] = []
        for _ in 0..<argc {
            guard offset < size else { break }
            let start = offset
            while offset < size && buffer[offset] != 0 { offset += 1 }
            if start < offset,
               let argument = String(bytes: buffer[start..<offset], encoding: .utf8) {
                arguments.append(argument)
            }
            while offset < size && buffer[offset] == 0 { offset += 1 }
        }
        return arguments
    }

    private static func processExecutableName(arguments: [String]) -> String? {
        guard let first = arguments.first else { return nil }
        return URL(fileURLWithPath: first).lastPathComponent
    }
    #endif
}

public struct InjectedProcessTreeApplyResult: Equatable, Sendable {
    public let run: InjectedProcessTreeRun
    public let newlySeenNodes: [InjectedProcessTreeNode]

    public init(run: InjectedProcessTreeRun, newlySeenNodes: [InjectedProcessTreeNode]) {
        self.run = run
        self.newlySeenNodes = newlySeenNodes
    }
}

public enum InjectedProcessTreeMerger {
    public static func openRun(
        rootPID: Int32,
        rootExecutable: String?,
        rootArguments: [String],
        agentJITGrantID: UUID? = nil,
        terminalSessionScope: String? = nil,
        workingDirectory: String? = nil,
        agentPlatform: String? = nil,
        startedAt: Date = Date(),
        rootStartTime: UInt64 = 0
    ) -> InjectedProcessTreeRun {
        let runID = UUID()
        let rootNode = InjectedProcessTreeNode(
            runID: runID,
            pid: rootPID,
            ppid: 0,
            startTime: rootStartTime,
            executable: rootExecutable,
            arguments: rootArguments,
            depth: 0,
            firstSeenAt: startedAt,
            lastSeenAt: startedAt
        )
        return InjectedProcessTreeRun(
            id: runID,
            startedAt: startedAt,
            rootPID: rootPID,
            rootExecutable: rootExecutable,
            rootArguments: rootArguments,
            agentJITGrantID: agentJITGrantID,
            terminalSessionScope: terminalSessionScope,
            workingDirectory: workingDirectory,
            agentPlatform: agentPlatform,
            nodes: [rootNode]
        )
    }

    public static func apply(
        samples: [(sample: InjectedProcessTreeSample, depth: Int)],
        to run: InjectedProcessTreeRun,
        at now: Date = Date()
    ) -> InjectedProcessTreeApplyResult {
        var nodesByKey = Dictionary(uniqueKeysWithValues: run.nodes.map { ($0.identityKey, $0) })
        var newlySeen: [InjectedProcessTreeNode] = []
        let seenKeys = Set(samples.map { $0.sample.identityKey })

        for entry in samples {
            let sample = entry.sample
            let depth = entry.depth

            if let existingKey = matchingKey(for: sample, depth: depth, rootPID: run.rootPID, in: nodesByKey) {
                var existing = nodesByKey[existingKey]!
                // Migrate placeholder root (startTime 0) to the observed identity key.
                if existingKey != sample.identityKey {
                    nodesByKey.removeValue(forKey: existingKey)
                    existing = InjectedProcessTreeNode(
                        id: existing.id,
                        runID: existing.runID,
                        pid: sample.pid,
                        ppid: sample.ppid,
                        startTime: sample.startTime,
                        executable: sample.executable,
                        arguments: sample.arguments,
                        depth: depth,
                        firstSeenAt: existing.firstSeenAt,
                        lastSeenAt: now,
                        exitStatus: nil
                    )
                } else {
                    existing.lastSeenAt = now
                    existing.exitStatus = nil
                }
                nodesByKey[sample.identityKey] = existing
                continue
            }

            let node = InjectedProcessTreeNode(
                runID: run.id,
                pid: sample.pid,
                ppid: sample.ppid,
                startTime: sample.startTime,
                executable: sample.executable,
                arguments: sample.arguments,
                depth: depth,
                firstSeenAt: now,
                lastSeenAt: now
            )
            nodesByKey[sample.identityKey] = node
            newlySeen.append(node)
        }

        for key in Array(nodesByKey.keys) {
            guard !seenKeys.contains(key) else { continue }
            // Keep placeholder root visible until a live sample remaps it.
            if let node = nodesByKey[key],
               node.pid == run.rootPID,
               node.depth == 0,
               node.startTime == 0,
               samples.contains(where: { $0.sample.pid == run.rootPID }) {
                continue
            }
            guard var node = nodesByKey[key], node.exitStatus == nil else { continue }
            node.exitStatus = 0
            node.lastSeenAt = now
            nodesByKey[key] = node
        }

        var updated = run
        updated.nodes = nodesByKey.values.sorted { lhs, rhs in
            if lhs.depth == rhs.depth {
                if lhs.firstSeenAt == rhs.firstSeenAt {
                    return lhs.pid < rhs.pid
                }
                return lhs.firstSeenAt < rhs.firstSeenAt
            }
            return lhs.depth < rhs.depth
        }
        return InjectedProcessTreeApplyResult(run: updated, newlySeenNodes: newlySeen)
    }

    public static func finish(
        _ run: InjectedProcessTreeRun,
        exitStatus: Int32?,
        at endedAt: Date = Date()
    ) -> InjectedProcessTreeRun {
        var updated = run
        updated.endedAt = endedAt
        updated.rootExitStatus = exitStatus
        if let index = updated.nodes.firstIndex(where: { $0.pid == run.rootPID && $0.depth == 0 }) {
            updated.nodes[index].exitStatus = exitStatus
            updated.nodes[index].lastSeenAt = endedAt
        }
        return updated
    }

    private static func matchingKey(
        for sample: InjectedProcessTreeSample,
        depth: Int,
        rootPID: Int32,
        in nodesByKey: [String: InjectedProcessTreeNode]
    ) -> String? {
        if nodesByKey[sample.identityKey] != nil {
            return sample.identityKey
        }
        if sample.pid == rootPID, depth == 0 {
            return nodesByKey.first(where: { $0.value.pid == rootPID && $0.value.depth == 0 })?.key
        }
        return nil
    }
}

public struct InjectedProcessTreeWatchContext: Equatable, Sendable {
    public let agentJITGrantIDs: [UUID]
    public let agentPlatform: String?
    public let terminalSessionScope: String?
    public let workingDirectory: String?

    public init(
        agentJITGrantIDs: [UUID] = [],
        agentPlatform: String? = nil,
        terminalSessionScope: String? = nil,
        workingDirectory: String? = nil
    ) {
        self.agentJITGrantIDs = agentJITGrantIDs
        self.agentPlatform = agentPlatform
        self.terminalSessionScope = terminalSessionScope
        self.workingDirectory = workingDirectory
    }

    public var isEnabled: Bool {
        true
    }
}

public final class InjectedProcessTreeStore: @unchecked Sendable {
    private static let directoryPermissions: NSNumber = 0o700
    private static let filePermissions: NSNumber = 0o600
    private static let mutationLock = NSLock()

    public static var defaultFileURL: URL {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first ?? FileManager.default.temporaryDirectory
        return base
            .appendingPathComponent("Authsia", isDirectory: true)
            .appendingPathComponent("injected-process-trees.jsonl")
    }

    private let fileURL: URL
    private let fileManager: FileManager

    public init(fileURL: URL = InjectedProcessTreeStore.defaultFileURL, fileManager: FileManager = .default) {
        self.fileURL = fileURL
        self.fileManager = fileManager
    }

    public func upsert(_ run: InjectedProcessTreeRun) throws {
        try Self.mutationLock.withLock {
            var runs = try loadAllUnlocked()
            if let index = runs.firstIndex(where: { $0.id == run.id }) {
                runs[index] = run
            } else {
                runs.append(run)
            }
            try writeUnlocked(runs.sorted { $0.startedAt < $1.startedAt })
        }
    }

    public func loadAll() throws -> [InjectedProcessTreeRun] {
        try Self.mutationLock.withLock {
            try loadAllUnlocked()
        }
    }

    public func runs(for grant: AgentJITGrant) throws -> [InjectedProcessTreeRun] {
        try InjectedProcessTreeQuery.runs(for: grant, from: loadAll())
    }

    private func loadAllUnlocked() throws -> [InjectedProcessTreeRun] {
        guard fileManager.fileExists(atPath: fileURL.path) else { return [] }
        try enforceFilePermissions()
        let data = try Data(contentsOf: fileURL)
        return try data.split(separator: 0x0A)
            .map { try JSONDecoder.injectedProcessTree.decode(InjectedProcessTreeRun.self, from: Data($0)) }
            .sorted { $0.startedAt < $1.startedAt }
    }

    private func writeUnlocked(_ runs: [InjectedProcessTreeRun]) throws {
        try ensureDirectory()
        var data = Data()
        for run in runs {
            var line = try JSONEncoder.injectedProcessTreeLine.encode(run)
            line.append(0x0A)
            data.append(line)
        }
        try data.write(to: fileURL, options: .atomic)
        try enforceFilePermissions()
    }

    private func ensureDirectory() throws {
        let directory = fileURL.deletingLastPathComponent()
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: Self.directoryPermissions]
        )
        try fileManager.setAttributes([.posixPermissions: Self.directoryPermissions], ofItemAtPath: directory.path)
    }

    private func enforceFilePermissions() throws {
        try fileManager.setAttributes([.posixPermissions: Self.filePermissions], ofItemAtPath: fileURL.path)
    }
}

public final class InjectedProcessTreeWatcher: @unchecked Sendable {
    public typealias SampleProvider = @Sendable (Int32) -> [InjectedProcessTreeSample]
    public typealias NetworkInspectionProvider = @Sendable (
        [InjectedProcessTreeSample],
        Date
    ) -> AgentNetworkInspectionResult

    private let store: InjectedProcessTreeStore
    private let commandHistoryStore: AgentCommandHistoryStore
    private let networkActivityStore: AgentNetworkActivityStore
    private let sampleProvider: SampleProvider
    private let networkInspectionProvider: NetworkInspectionProvider
    private let pollInterval: TimeInterval
    private let networkCheckpointInterval: TimeInterval
    private let context: InjectedProcessTreeWatchContext
    private let lock = NSLock()
    private let samplingSemaphore = DispatchSemaphore(value: 1)
    private var run: InjectedProcessTreeRun?
    private var timer: DispatchSourceTimer?
    private var recordedCommandKeys = Set<String>()
    private var networkAccumulator: AgentNetworkActivityAccumulator?
    private var networkCoverage: AgentNetworkCaptureCoverage = .observed
    private var lastNetworkCheckpointAt: Date?
    private var lastSurvivingDescendantIdentityKeys: [String] = []

    public init(
        store: InjectedProcessTreeStore = InjectedProcessTreeStore(),
        commandHistoryStore: AgentCommandHistoryStore = AgentCommandHistoryStore(),
        networkActivityStore: AgentNetworkActivityStore = AgentNetworkActivityStore(),
        sampleProvider: @escaping SampleProvider = { InjectedProcessTreeSampler.liveSamples(rootPID: $0) },
        networkInspectionProvider: @escaping NetworkInspectionProvider = {
            AgentNetworkSocketInspector.liveInspection(samples: $0, observedAt: $1)
        },
        pollInterval: TimeInterval = 0.5,
        networkCheckpointInterval: TimeInterval = 2,
        context: InjectedProcessTreeWatchContext = InjectedProcessTreeWatchContext()
    ) {
        self.store = store
        self.commandHistoryStore = commandHistoryStore
        self.networkActivityStore = networkActivityStore
        self.sampleProvider = sampleProvider
        self.networkInspectionProvider = networkInspectionProvider
        self.pollInterval = pollInterval
        self.networkCheckpointInterval = max(0, networkCheckpointInterval)
        self.context = context
    }

    public func start(
        rootPID: Int32,
        rootExecutable: String?,
        rootArguments: [String],
        now: Date = Date()
    ) {
        let grantID = context.agentJITGrantIDs.first
        let opened = InjectedProcessTreeMerger.openRun(
            rootPID: rootPID,
            rootExecutable: rootExecutable,
            rootArguments: rootArguments,
            agentJITGrantID: grantID,
            terminalSessionScope: context.terminalSessionScope,
            workingDirectory: context.workingDirectory,
            agentPlatform: context.agentPlatform,
            startedAt: now
        )
        lock.lock()
        run = opened
        recordedCommandKeys.removeAll()
        networkAccumulator = context.agentJITGrantIDs.isEmpty
            ? nil
            : AgentNetworkActivityAccumulator(
                runID: opened.id,
                grantIDs: context.agentJITGrantIDs
            )
        networkCoverage = .observed
        lastNetworkCheckpointAt = nil
        lastSurvivingDescendantIdentityKeys = []
        lock.unlock()
        try? store.upsert(opened)
        recordCommandEvents(for: opened.nodes, grantIDs: context.agentJITGrantIDs, now: now)
        performSample(now: now, waitForActiveSample: true)

        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + pollInterval, repeating: pollInterval)
        timer.setEventHandler { [weak self] in
            self?.performSample(now: Date(), waitForActiveSample: false)
        }
        self.timer = timer
        timer.resume()
    }

    public func stop(exitStatus: Int32?, now: Date = Date()) {
        timer?.cancel()
        timer = nil
        performSample(now: now, waitForActiveSample: true)
        lock.lock()
        guard let current = run else {
            lock.unlock()
            return
        }
        let finished = InjectedProcessTreeMerger.finish(current, exitStatus: exitStatus, at: now)
        run = finished
        let accumulator = networkAccumulator
        let coverage = networkCoverage
        let survivingDescendants = lastSurvivingDescendantIdentityKeys
        lock.unlock()
        try? store.upsert(finished)
        if let accumulator {
            let snapshot = AgentNetworkActivityRunSnapshot(
                runID: accumulator.runID,
                grantIDs: accumulator.grantIDs,
                coverage: coverage,
                updatedAt: now,
                endedAt: now,
                survivingDescendantIdentityKeys: survivingDescendants,
                records: accumulator.records,
                domainEvidence: accumulator.domainEvidence
            )
            try? networkActivityStore.finalize(snapshot, now: now)
        }
    }

    func sampleNow(now: Date = Date()) {
        performSample(now: now, waitForActiveSample: true)
    }

    private func performSample(now: Date, waitForActiveSample: Bool) {
        let timeout: DispatchTime = waitForActiveSample ? .distantFuture : .now()
        guard samplingSemaphore.wait(timeout: timeout) == .success else { return }
        defer { samplingSemaphore.signal() }
        sampleOnce(now: now)
    }

    private func sampleOnce(now: Date) {
        lock.lock()
        guard let current = run else {
            lock.unlock()
            return
        }
        let rootPID = current.rootPID
        var sampledAccumulator = networkAccumulator
        let sampledCoverage = networkCoverage
        lock.unlock()

        let table = sampleProvider(rootPID)
        let ranked = InjectedProcessTreeSampler.samples(rootPID: rootPID, from: table)
        let result = InjectedProcessTreeMerger.apply(samples: ranked, to: current, at: now)
        let verifiedSamples = ranked.map(\.sample)
        let survivingDescendants = ranked
            .filter { $0.depth > 0 }
            .map(\.sample.identityKey)
            .sorted()
        let updatedCoverage: AgentNetworkCaptureCoverage?
        if var accumulator = sampledAccumulator {
            let inspection = networkInspectionProvider(verifiedSamples, now)
            let socketAggregationWasComplete = accumulator.apply(inspection.observations)
            let domainAggregationWasComplete = accumulator.applyDomainEvidence(
                from: verifiedSamples,
                observedAt: now
            )
            let aggregationWasComplete = socketAggregationWasComplete
                && domainAggregationWasComplete
            sampledAccumulator = accumulator
            let aggregationCoverage: AgentNetworkCaptureCoverage = aggregationWasComplete
                ? .observed
                : .partial
            updatedCoverage = mergedCoverage(
                mergedCoverage(sampledCoverage, inspection.coverage),
                aggregationCoverage
            )
        } else {
            updatedCoverage = nil
        }

        var networkSnapshot: AgentNetworkActivityRunSnapshot?
        lock.lock()
        if let accumulator = sampledAccumulator, let updatedCoverage {
            networkAccumulator = accumulator
            networkCoverage = updatedCoverage
            if lastNetworkCheckpointAt.map({
                now.timeIntervalSince($0) >= networkCheckpointInterval
            }) ?? true {
                lastNetworkCheckpointAt = now
                networkSnapshot = AgentNetworkActivityRunSnapshot(
                    runID: accumulator.runID,
                    grantIDs: accumulator.grantIDs,
                    coverage: networkCoverage,
                    updatedAt: now,
                    records: accumulator.records,
                    domainEvidence: accumulator.domainEvidence
                )
            }
        }
        lastSurvivingDescendantIdentityKeys = survivingDescendants
        run = result.run
        lock.unlock()

        try? store.upsert(result.run)
        if let networkSnapshot {
            try? networkActivityStore.checkpoint(networkSnapshot)
        }
        recordCommandEvents(for: result.newlySeenNodes, grantIDs: context.agentJITGrantIDs, now: now)
    }

    private func mergedCoverage(
        _ current: AgentNetworkCaptureCoverage,
        _ next: AgentNetworkCaptureCoverage
    ) -> AgentNetworkCaptureCoverage {
        if current == .unavailable || next == .unavailable {
            return .unavailable
        }
        if current == .partial || next == .partial {
            return .partial
        }
        return .observed
    }

    private func recordCommandEvents(for nodes: [InjectedProcessTreeNode], grantIDs: [UUID], now: Date) {
        let historyGrantIDs: [UUID?] = grantIDs.isEmpty ? [nil] : grantIDs.map(Optional.some)
        for node in nodes {
            let command = node.arguments.isEmpty
                ? node.executable
                : node.arguments.joined(separator: " ")
            let keyBase = "\(node.runID.uuidString):\(node.identityKey)"
            for grantID in historyGrantIDs {
                let key = "\(keyBase):\(grantID?.uuidString ?? "nil")"
                lock.lock()
                let alreadyRecorded = recordedCommandKeys.contains(key)
                if !alreadyRecorded {
                    recordedCommandKeys.insert(key)
                }
                lock.unlock()
                guard !alreadyRecorded else { continue }

                let event = AgentCommandEvent(
                    recordedAt: now,
                    agentPlatform: context.agentPlatform,
                    agentJITGrantID: grantID,
                    captureSource: .injectedTree,
                    workingDirectory: context.workingDirectory,
                    terminalSessionScope: context.terminalSessionScope,
                    executable: node.executable,
                    arguments: node.arguments,
                    command: command,
                    exitStatus: node.exitStatus
                )
                try? commandHistoryStore.record(event)
            }
        }
    }
}

public extension JSONEncoder {
    static var injectedProcessTree: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }

    static var injectedProcessTreeLine: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }
}

public extension JSONDecoder {
    static var injectedProcessTree: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}
