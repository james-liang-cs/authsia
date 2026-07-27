import Foundation
#if canImport(Darwin)
import Darwin
#endif

public enum AgentNetworkDestinationZone: String, Codable, CaseIterable, Equatable, Sendable {
    case loopback
    case privateNetwork
    case publicInternet
    case unknown

    public static func classify(_ address: String) -> Self {
        #if canImport(Darwin)
        var ipv4 = in_addr()
        if address.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            let value = UInt32(bigEndian: ipv4.s_addr)
            if value & 0xff00_0000 == 0x7f00_0000 {
                return .loopback
            }
            if value & 0xff00_0000 == 0x0a00_0000
                || value & 0xfff0_0000 == 0xac10_0000
                || value & 0xffff_0000 == 0xc0a8_0000
                || value & 0xffff_0000 == 0xa9fe_0000 {
                return .privateNetwork
            }
            return .publicInternet
        }

        var ipv6 = in6_addr()
        if address.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            let bytes = withUnsafeBytes(of: &ipv6) { Array($0) }
            if bytes.dropLast().allSatisfy({ $0 == 0 }), bytes.last == 1 {
                return .loopback
            }
            if bytes[0] & 0xfe == 0xfc
                || (bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80) {
                return .privateNetwork
            }
            return .publicInternet
        }
        #endif
        return .unknown
    }
}

public enum AgentNetworkProtocol: String, Codable, CaseIterable, Equatable, Sendable {
    case tcp
    case udp
}

public enum AgentNetworkCaptureCoverage: String, Codable, CaseIterable, Equatable, Sendable {
    case observed
    case partial
    case unavailable
}

public struct AgentNetworkSocketObservation: Equatable, Sendable {
    public let connectionID: String
    public let observedAt: Date
    public let pid: Int32
    public let processStartTime: UInt64
    public let executable: String?
    public let depth: Int
    public let remoteAddress: String
    public let remotePort: UInt16
    public let networkProtocol: AgentNetworkProtocol
    public let sentBytes: UInt64?
    public let receivedBytes: UInt64?

    public init(
        connectionID: String,
        observedAt: Date,
        pid: Int32,
        processStartTime: UInt64,
        executable: String?,
        depth: Int,
        remoteAddress: String,
        remotePort: UInt16,
        networkProtocol: AgentNetworkProtocol,
        sentBytes: UInt64?,
        receivedBytes: UInt64?
    ) {
        self.connectionID = connectionID
        self.observedAt = observedAt
        self.pid = pid
        self.processStartTime = processStartTime
        self.executable = AgentCommandRedactor.sanitized(executable, maxLength: 1024)
        self.depth = max(0, depth)
        self.remoteAddress = AgentCommandRedactor.sanitized(
            remoteAddress,
            maxLength: 256
        ) ?? "unknown"
        self.remotePort = remotePort
        self.networkProtocol = networkProtocol
        self.sentBytes = sentBytes
        self.receivedBytes = receivedBytes
    }
}

public struct AgentNetworkActivityRecord: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let runID: UUID
    public let grantIDs: [UUID]
    public let pid: Int32
    public let processStartTime: UInt64
    public let executable: String?
    public let depth: Int
    public let remoteAddress: String
    public let remotePort: UInt16
    public let networkProtocol: AgentNetworkProtocol
    public let destinationZone: AgentNetworkDestinationZone
    public private(set) var firstSeenAt: Date
    public private(set) var lastSeenAt: Date
    public private(set) var connectionCount: Int
    public private(set) var sentBytes: UInt64?
    public private(set) var receivedBytes: UInt64?

    public init(
        id: UUID = UUID(),
        runID: UUID,
        grantIDs: [UUID],
        observation: AgentNetworkSocketObservation
    ) {
        self.id = id
        self.runID = runID
        self.grantIDs = Array(Set(grantIDs)).sorted { $0.uuidString < $1.uuidString }
        self.pid = observation.pid
        self.processStartTime = observation.processStartTime
        self.executable = observation.executable
        self.depth = observation.depth
        self.remoteAddress = observation.remoteAddress
        self.remotePort = observation.remotePort
        self.networkProtocol = observation.networkProtocol
        self.destinationZone = AgentNetworkDestinationZone.classify(observation.remoteAddress)
        self.firstSeenAt = observation.observedAt
        self.lastSeenAt = observation.observedAt
        self.connectionCount = 1
        self.sentBytes = observation.sentBytes
        self.receivedBytes = observation.receivedBytes
    }

    mutating func apply(
        _ observation: AgentNetworkSocketObservation,
        isNewConnection: Bool,
        sentByteDelta: UInt64?,
        receivedByteDelta: UInt64?
    ) {
        firstSeenAt = min(firstSeenAt, observation.observedAt)
        lastSeenAt = max(lastSeenAt, observation.observedAt)
        if isNewConnection {
            connectionCount += 1
        }
        sentBytes = Self.add(sentByteDelta, to: sentBytes)
        receivedBytes = Self.add(receivedByteDelta, to: receivedBytes)
    }

    private static func add(_ delta: UInt64?, to total: UInt64?) -> UInt64? {
        guard let delta else { return total }
        return (total ?? 0) &+ delta
    }
}

public struct AgentNetworkActivityRunSnapshot: Codable, Equatable, Sendable {
    public let runID: UUID
    public let grantIDs: [UUID]
    public let coverage: AgentNetworkCaptureCoverage
    public let updatedAt: Date
    public let endedAt: Date?
    public let survivingDescendantIdentityKeys: [String]
    public let records: [AgentNetworkActivityRecord]
    public let domainEvidence: [AgentNetworkDomainEvidence]

    public init(
        runID: UUID,
        grantIDs: [UUID],
        coverage: AgentNetworkCaptureCoverage,
        updatedAt: Date,
        endedAt: Date? = nil,
        survivingDescendantIdentityKeys: [String] = [],
        records: [AgentNetworkActivityRecord],
        domainEvidence: [AgentNetworkDomainEvidence] = []
    ) {
        self.runID = runID
        self.grantIDs = Array(Set(grantIDs)).sorted { $0.uuidString < $1.uuidString }
        self.coverage = coverage
        self.updatedAt = updatedAt
        self.endedAt = endedAt
        self.survivingDescendantIdentityKeys = survivingDescendantIdentityKeys.sorted()
        self.records = records.sorted {
            if $0.lastSeenAt == $1.lastSeenAt {
                return $0.id.uuidString < $1.id.uuidString
            }
            return $0.lastSeenAt < $1.lastSeenAt
        }
        self.domainEvidence = domainEvidence.sorted {
            if $0.lastSeenAt == $1.lastSeenAt {
                return $0.id.uuidString < $1.id.uuidString
            }
            return $0.lastSeenAt < $1.lastSeenAt
        }
    }

    private enum CodingKeys: String, CodingKey {
        case runID
        case grantIDs
        case coverage
        case updatedAt
        case endedAt
        case survivingDescendantIdentityKeys
        case records
        case domainEvidence
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            runID: try container.decode(UUID.self, forKey: .runID),
            grantIDs: try container.decode([UUID].self, forKey: .grantIDs),
            coverage: try container.decode(
                AgentNetworkCaptureCoverage.self,
                forKey: .coverage
            ),
            updatedAt: try container.decode(Date.self, forKey: .updatedAt),
            endedAt: try container.decodeIfPresent(Date.self, forKey: .endedAt),
            survivingDescendantIdentityKeys: try container.decodeIfPresent(
                [String].self,
                forKey: .survivingDescendantIdentityKeys
            ) ?? [],
            records: try container.decode(
                [AgentNetworkActivityRecord].self,
                forKey: .records
            ),
            domainEvidence: try container.decodeIfPresent(
                [AgentNetworkDomainEvidence].self,
                forKey: .domainEvidence
            ) ?? []
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(runID, forKey: .runID)
        try container.encode(grantIDs, forKey: .grantIDs)
        try container.encode(coverage, forKey: .coverage)
        try container.encode(updatedAt, forKey: .updatedAt)
        try container.encodeIfPresent(endedAt, forKey: .endedAt)
        try container.encode(
            survivingDescendantIdentityKeys,
            forKey: .survivingDescendantIdentityKeys
        )
        try container.encode(records, forKey: .records)
        try container.encode(domainEvidence, forKey: .domainEvidence)
    }
}

public struct AgentNetworkActivityAccumulator: Sendable {
    public let runID: UUID
    public let grantIDs: [UUID]

    private let recordLimit: Int
    private let connectionLimit: Int
    private let domainEvidenceLimit: Int
    private var recordsByKey: [String: AgentNetworkActivityRecord] = [:]
    private var connectionIDsByKey: [String: Set<String>] = [:]
    private var byteCountsByConnectionID: [String: (sent: UInt64?, received: UInt64?)] = [:]
    private var domainEvidenceByKey: [String: AgentNetworkDomainEvidence] = [:]

    public init(
        runID: UUID,
        grantIDs: [UUID],
        recordLimit: Int = 2_048,
        connectionLimit: Int = 4_096,
        domainEvidenceLimit: Int = 512
    ) {
        self.runID = runID
        self.grantIDs = Array(Set(grantIDs)).sorted { $0.uuidString < $1.uuidString }
        self.recordLimit = max(1, recordLimit)
        self.connectionLimit = max(1, connectionLimit)
        self.domainEvidenceLimit = max(1, domainEvidenceLimit)
    }

    public var records: [AgentNetworkActivityRecord] {
        recordsByKey.values.sorted {
            if $0.lastSeenAt == $1.lastSeenAt {
                return $0.id.uuidString < $1.id.uuidString
            }
            return $0.lastSeenAt < $1.lastSeenAt
        }
    }

    public var domainEvidence: [AgentNetworkDomainEvidence] {
        domainEvidenceByKey.values.sorted {
            if $0.lastSeenAt == $1.lastSeenAt {
                return $0.id.uuidString < $1.id.uuidString
            }
            return $0.lastSeenAt < $1.lastSeenAt
        }
    }

    @discardableResult
    public mutating func applyDomainEvidence(
        from samples: [InjectedProcessTreeSample],
        observedAt: Date
    ) -> Bool {
        var wasComplete = true
        for observation in AgentNetworkDomainExtractor.evidence(
            from: samples,
            observedAt: observedAt
        ) {
            let key = [
                String(observation.pid),
                String(observation.processStartTime),
                observation.hostname,
                observation.source.rawValue,
            ].joined(separator: ":")
            guard domainEvidenceByKey[key] != nil
                    || domainEvidenceByKey.count < domainEvidenceLimit else {
                wasComplete = false
                continue
            }
            if var evidence = domainEvidenceByKey[key] {
                evidence.apply(observation)
                domainEvidenceByKey[key] = evidence
            } else {
                domainEvidenceByKey[key] = AgentNetworkDomainEvidence(
                    runID: runID,
                    grantIDs: grantIDs,
                    observation: observation
                )
            }
        }
        return wasComplete
    }

    @discardableResult
    public mutating func apply(_ observations: [AgentNetworkSocketObservation]) -> Bool {
        var wasComplete = true
        for observation in observations {
            let key = Self.recordKey(for: observation)
            guard recordsByKey[key] != nil || recordsByKey.count < recordLimit else {
                wasComplete = false
                continue
            }

            let isTrackedConnection = byteCountsByConnectionID[observation.connectionID] != nil
            guard isTrackedConnection || byteCountsByConnectionID.count < connectionLimit else {
                wasComplete = false
                if var record = recordsByKey[key] {
                    record.apply(
                        observation,
                        isNewConnection: false,
                        sentByteDelta: nil,
                        receivedByteDelta: nil
                    )
                    recordsByKey[key] = record
                } else {
                    recordsByKey[key] = AgentNetworkActivityRecord(
                        runID: runID,
                        grantIDs: grantIDs,
                        observation: observation
                    )
                }
                continue
            }

            let previousBytes = byteCountsByConnectionID[observation.connectionID]
            let sentDelta = Self.delta(current: observation.sentBytes, previous: previousBytes?.sent)
            let receivedDelta = Self.delta(
                current: observation.receivedBytes,
                previous: previousBytes?.received
            )
            byteCountsByConnectionID[observation.connectionID] = (
                observation.sentBytes,
                observation.receivedBytes
            )

            var connectionIDs = connectionIDsByKey[key, default: []]
            let isNewConnection = connectionIDs.insert(observation.connectionID).inserted
            connectionIDsByKey[key] = connectionIDs

            if var record = recordsByKey[key] {
                record.apply(
                    observation,
                    isNewConnection: isNewConnection,
                    sentByteDelta: sentDelta,
                    receivedByteDelta: receivedDelta
                )
                recordsByKey[key] = record
            } else {
                recordsByKey[key] = AgentNetworkActivityRecord(
                    runID: runID,
                    grantIDs: grantIDs,
                    observation: observation
                )
            }
        }
        return wasComplete
    }

    private static func recordKey(for observation: AgentNetworkSocketObservation) -> String {
        [
            String(observation.pid),
            String(observation.processStartTime),
            observation.remoteAddress,
            String(observation.remotePort),
            observation.networkProtocol.rawValue,
        ].joined(separator: ":")
    }

    private static func delta(current: UInt64?, previous: UInt64?) -> UInt64? {
        guard let current else { return nil }
        guard let previous else { return current }
        return current >= previous ? current - previous : current
    }
}

public enum AgentNetworkActivityQuery {
    public static func snapshots(
        for grant: AgentJITGrant,
        from snapshots: [AgentNetworkActivityRunSnapshot]
    ) -> [AgentNetworkActivityRunSnapshot] {
        snapshots
            .filter { $0.grantIDs.contains(grant.id) }
            .sorted { $0.updatedAt < $1.updatedAt }
    }

    public static func records(
        for grant: AgentJITGrant,
        from snapshots: [AgentNetworkActivityRunSnapshot]
    ) -> [AgentNetworkActivityRecord] {
        self.snapshots(for: grant, from: snapshots)
            .flatMap(\.records)
            .sorted { $0.lastSeenAt < $1.lastSeenAt }
    }
}

public final class AgentNetworkActivityStore: @unchecked Sendable {
    private static let directoryPermissions: NSNumber = 0o700
    private static let filePermissions: NSNumber = 0o600
    private static let mutationLock = NSLock()

    public static var defaultHistoryFileURL: URL {
        defaultDirectoryURL.appendingPathComponent("agent-network-activity.jsonl")
    }

    public static var defaultActiveFileURL: URL {
        defaultDirectoryURL.appendingPathComponent("agent-network-active.jsonl")
    }

    private static var defaultDirectoryURL: URL {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first ?? FileManager.default.temporaryDirectory
        return base.appendingPathComponent("Authsia", isDirectory: true)
    }

    private struct FileFingerprint: Equatable {
        let size: UInt64
        let modificationDate: Date?
    }

    private struct HistoryCache {
        let fingerprint: FileFingerprint?
        let snapshots: [AgentNetworkActivityRunSnapshot]
    }

    private let historyFileURL: URL
    private let activeFileURL: URL
    private let fileManager: FileManager
    private let retentionInterval: TimeInterval
    private let aggregateLimit: Int
    private let dataLoader: @Sendable (URL) throws -> Data
    private var historyCache: HistoryCache?

    public init(
        historyFileURL: URL = AgentNetworkActivityStore.defaultHistoryFileURL,
        activeFileURL: URL = AgentNetworkActivityStore.defaultActiveFileURL,
        fileManager: FileManager = .default,
        retentionInterval: TimeInterval = 30 * 24 * 60 * 60,
        aggregateLimit: Int = 10_000
    ) {
        self.historyFileURL = historyFileURL
        self.activeFileURL = activeFileURL
        self.fileManager = fileManager
        self.retentionInterval = retentionInterval
        self.aggregateLimit = max(1, aggregateLimit)
        self.dataLoader = { try Data(contentsOf: $0) }
    }

    init(
        historyFileURL: URL,
        activeFileURL: URL,
        fileManager: FileManager = .default,
        retentionInterval: TimeInterval = 30 * 24 * 60 * 60,
        aggregateLimit: Int = 10_000,
        dataLoader: @escaping @Sendable (URL) throws -> Data
    ) {
        self.historyFileURL = historyFileURL
        self.activeFileURL = activeFileURL
        self.fileManager = fileManager
        self.retentionInterval = retentionInterval
        self.aggregateLimit = max(1, aggregateLimit)
        self.dataLoader = dataLoader
    }

    public func checkpoint(_ snapshot: AgentNetworkActivityRunSnapshot) throws {
        try Self.mutationLock.withLock {
            var active = try loadFile(activeFileURL)
            active.removeAll { $0.runID == snapshot.runID }
            active.append(snapshot)
            try write(active, to: activeFileURL)
        }
    }

    public func finalize(
        _ snapshot: AgentNetworkActivityRunSnapshot,
        now: Date = Date()
    ) throws {
        try Self.mutationLock.withLock {
            let finalized = AgentNetworkActivityRunSnapshot(
                runID: snapshot.runID,
                grantIDs: snapshot.grantIDs,
                coverage: snapshot.coverage,
                updatedAt: snapshot.updatedAt,
                endedAt: snapshot.endedAt ?? now,
                survivingDescendantIdentityKeys: snapshot.survivingDescendantIdentityKeys,
                records: snapshot.records,
                domainEvidence: snapshot.domainEvidence
            )

            var active = try loadFile(activeFileURL)
            active.removeAll { $0.runID == snapshot.runID }
            if active.isEmpty {
                try removeFileIfPresent(activeFileURL)
            } else {
                try write(active, to: activeFileURL)
            }

            var history = try loadHistoryFile()
            history.removeAll { $0.runID == snapshot.runID }
            history.append(finalized)
            let retained = pruned(history, now: now)
            try write(retained, to: historyFileURL)
            historyCache = HistoryCache(
                fingerprint: fileFingerprint(for: historyFileURL),
                snapshots: retained
            )
        }
    }

    public func loadAll(now: Date = Date()) throws -> [AgentNetworkActivityRunSnapshot] {
        try Self.mutationLock.withLock {
            let history = pruned(try loadHistoryFile(), now: now)
            let active = try loadFile(activeFileURL)
            var byRunID = Dictionary(uniqueKeysWithValues: history.map { ($0.runID, $0) })
            for snapshot in active {
                byRunID[snapshot.runID] = snapshot
            }
            return byRunID.values.sorted { $0.updatedAt < $1.updatedAt }
        }
    }

    private func loadHistoryFile() throws -> [AgentNetworkActivityRunSnapshot] {
        if fileManager.fileExists(atPath: historyFileURL.path) {
            try requireRegularFile(historyFileURL)
            try enforceFilePermissions(historyFileURL)
        }
        let fingerprint = fileFingerprint(for: historyFileURL)
        if let historyCache, historyCache.fingerprint == fingerprint {
            return historyCache.snapshots
        }
        let snapshots = try loadFile(historyFileURL)
        historyCache = HistoryCache(
            fingerprint: fileFingerprint(for: historyFileURL),
            snapshots: snapshots
        )
        return snapshots
    }

    private func loadFile(_ fileURL: URL) throws -> [AgentNetworkActivityRunSnapshot] {
        guard fileManager.fileExists(atPath: fileURL.path) else { return [] }
        try requireRegularFile(fileURL)
        try enforceFilePermissions(fileURL)
        let data = try dataLoader(fileURL)
        return data.split(separator: 0x0A)
            .compactMap {
                try? Self.decoder.decode(
                    AgentNetworkActivityRunSnapshot.self,
                    from: Data($0)
                )
            }
            .sorted { $0.updatedAt < $1.updatedAt }
    }

    private func write(
        _ snapshots: [AgentNetworkActivityRunSnapshot],
        to fileURL: URL
    ) throws {
        if fileManager.fileExists(atPath: fileURL.path) {
            try requireRegularFile(fileURL)
        }
        try ensureDirectory(for: fileURL)
        var data = Data()
        for snapshot in snapshots.sorted(by: { $0.updatedAt < $1.updatedAt }) {
            var line = try Self.encoder.encode(snapshot)
            line.append(0x0A)
            data.append(line)
        }
        try data.write(to: fileURL, options: .atomic)
        try enforceFilePermissions(fileURL)
    }

    private func fileFingerprint(for fileURL: URL) -> FileFingerprint? {
        guard let attributes = try? fileManager.attributesOfItem(atPath: fileURL.path),
              let size = (attributes[.size] as? NSNumber)?.uint64Value else {
            return nil
        }
        return FileFingerprint(
            size: size,
            modificationDate: attributes[.modificationDate] as? Date
        )
    }

    private func pruned(
        _ snapshots: [AgentNetworkActivityRunSnapshot],
        now: Date
    ) -> [AgentNetworkActivityRunSnapshot] {
        let cutoff = now.addingTimeInterval(-retentionInterval)
        let retained = snapshots
            .filter { ($0.endedAt ?? $0.updatedAt) >= cutoff }
            .sorted { $0.updatedAt > $1.updatedAt }
        var remainingRows = aggregateLimit
        var result: [AgentNetworkActivityRunSnapshot] = []

        for snapshot in retained {
            let hasActivity = !snapshot.records.isEmpty || !snapshot.domainEvidence.isEmpty
            guard !hasActivity || remainingRows > 0 else { continue }
            let records = Array(snapshot.records.suffix(remainingRows))
            remainingRows -= records.count
            let domainEvidence = Array(snapshot.domainEvidence.suffix(remainingRows))
            remainingRows -= domainEvidence.count
            if hasActivity, records.isEmpty, domainEvidence.isEmpty {
                continue
            }
            result.append(
                AgentNetworkActivityRunSnapshot(
                    runID: snapshot.runID,
                    grantIDs: snapshot.grantIDs,
                    coverage: snapshot.coverage,
                    updatedAt: snapshot.updatedAt,
                    endedAt: snapshot.endedAt,
                    survivingDescendantIdentityKeys: snapshot.survivingDescendantIdentityKeys,
                    records: records,
                    domainEvidence: domainEvidence
                )
            )
        }
        return result.sorted { $0.updatedAt < $1.updatedAt }
    }

    private func ensureDirectory(for fileURL: URL) throws {
        let directory = fileURL.deletingLastPathComponent()
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: Self.directoryPermissions]
        )
        try fileManager.setAttributes(
            [.posixPermissions: Self.directoryPermissions],
            ofItemAtPath: directory.path
        )
    }

    private func enforceFilePermissions(_ fileURL: URL) throws {
        try fileManager.setAttributes(
            [.posixPermissions: Self.filePermissions],
            ofItemAtPath: fileURL.path
        )
    }

    private func requireRegularFile(_ fileURL: URL) throws {
        let attributes = try fileManager.attributesOfItem(atPath: fileURL.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular else {
            throw POSIXError(.EINVAL)
        }
    }

    private func removeFileIfPresent(_ fileURL: URL) throws {
        guard fileManager.fileExists(atPath: fileURL.path) else { return }
        try requireRegularFile(fileURL)
        try fileManager.removeItem(at: fileURL)
    }

    private static var encoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = .sortedKeys
        return encoder
    }

    private static var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}
