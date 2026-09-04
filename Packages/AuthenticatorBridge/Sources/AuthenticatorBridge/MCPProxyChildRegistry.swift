#if os(macOS)
import Darwin
import Foundation

/// Sidecar the proxy writes after spawn so Authsia.app can kill an orphaned
/// child process group when the proxy is gone. Revoke-kill is otherwise only
/// the proxy's own poll loop.
public enum MCPProxyChildRegistry {
    public struct Record: Codable, Equatable, Sendable {
        public let grantID: UUID
        public let processGroupID: Int32
        public let childProcessID: Int32
        public let proxyProcessID: Int32
        public let recordedAt: Date

        public init(
            grantID: UUID,
            processGroupID: Int32,
            childProcessID: Int32,
            proxyProcessID: Int32,
            recordedAt: Date = Date()
        ) {
            self.grantID = grantID
            self.processGroupID = processGroupID
            self.childProcessID = childProcessID
            self.proxyProcessID = proxyProcessID
            self.recordedAt = recordedAt
        }
    }

    public static var defaultFileURL: URL {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first ?? FileManager.default.temporaryDirectory
        return base
            .appendingPathComponent("Authsia", isDirectory: true)
            .appendingPathComponent("mcp-proxy-children.json")
    }

    public static func register(
        grantIDs: Set<UUID>,
        processGroupID: pid_t,
        childProcessID: pid_t,
        proxyProcessID: pid_t,
        fileURL: URL = defaultFileURL,
        fileManager: FileManager = .default,
        now: Date = Date()
    ) {
        guard processGroupID > 1, childProcessID > 1, proxyProcessID > 1 else { return }
        mutate(fileURL: fileURL, fileManager: fileManager) { records in
            records.removeAll {
                $0.processGroupID == processGroupID || grantIDs.contains($0.grantID)
            }
            let ids: [UUID] = grantIDs.isEmpty ? [UUID()] : Array(grantIDs)
            for grantID in ids {
                records.append(
                    Record(
                        grantID: grantID,
                        processGroupID: processGroupID,
                        childProcessID: childProcessID,
                        proxyProcessID: proxyProcessID,
                        recordedAt: now
                    )
                )
            }
        }
    }

    public static func unregister(
        grantIDs: Set<UUID>,
        fileURL: URL = defaultFileURL,
        fileManager: FileManager = .default
    ) {
        guard !grantIDs.isEmpty else { return }
        mutate(fileURL: fileURL, fileManager: fileManager) { records in
            records.removeAll { grantIDs.contains($0.grantID) }
        }
    }

    public static func unregister(
        processGroupID: pid_t,
        fileURL: URL = defaultFileURL,
        fileManager: FileManager = .default
    ) {
        guard processGroupID > 1 else { return }
        mutate(fileURL: fileURL, fileManager: fileManager) { records in
            records.removeAll { $0.processGroupID == processGroupID }
        }
    }

    public static func load(
        fileURL: URL = defaultFileURL,
        fileManager: FileManager = .default
    ) -> [Record] {
        locked(fileURL: fileURL, fileManager: fileManager) { handle in
            decodeRecords(from: handle)
        } ?? []
    }

    /// Kill the process group for this grant if the recorded child still owns
    /// that group, then drop the sidecar row. Safe to call when the proxy is
    /// already gone.
    public static func terminate(
        grantID: UUID,
        fileURL: URL = defaultFileURL,
        fileManager: FileManager = .default,
        graceSeconds: TimeInterval = 2
    ) {
        let records = load(fileURL: fileURL, fileManager: fileManager)
            .filter { $0.grantID == grantID }
        for record in records {
            terminateIfCurrent(
                childProcessID: record.childProcessID,
                processGroupID: record.processGroupID,
                graceSeconds: graceSeconds
            )
        }
        unregister(grantIDs: [grantID], fileURL: fileURL, fileManager: fileManager)
    }

    /// Kill children whose proxy pid is already dead. The proxy cannot observe
    /// revoke after `kill -9` / a crash; this is the app-side sweep.
    public static func reapOrphans(
        fileURL: URL = defaultFileURL,
        fileManager: FileManager = .default,
        isProcessAlive: (pid_t) -> Bool = { Darwin.kill($0, 0) == 0 || errno == EPERM },
        graceSeconds: TimeInterval = 2
    ) {
        let records = load(fileURL: fileURL, fileManager: fileManager)
        var dead: Set<UUID> = []
        var deadGroups: Set<pid_t> = []
        for record in records where !isProcessAlive(record.proxyProcessID) {
            terminateIfCurrent(
                childProcessID: record.childProcessID,
                processGroupID: record.processGroupID,
                graceSeconds: graceSeconds
            )
            dead.insert(record.grantID)
            deadGroups.insert(record.processGroupID)
        }
        unregister(grantIDs: dead, fileURL: fileURL, fileManager: fileManager)
        for group in deadGroups {
            unregister(processGroupID: group, fileURL: fileURL, fileManager: fileManager)
        }
    }

    public static func terminateProcessGroup(
        _ processGroupID: pid_t,
        graceSeconds: TimeInterval = 2
    ) {
        guard processGroupID > 1 else { return }
        _ = Darwin.kill(-processGroupID, SIGTERM)
        let deadline = Date().addingTimeInterval(max(0, graceSeconds))
        while Date() < deadline {
            if Darwin.kill(-processGroupID, 0) != 0, errno != EPERM {
                return
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        _ = Darwin.kill(-processGroupID, SIGKILL)
    }

    /// Refuse to signal a process group unless the recorded child still leads
    /// it. Pid/pgid reuse after the child exits would otherwise SIGTERM an
    /// unrelated process.
    public static func terminateIfCurrent(
        childProcessID: pid_t,
        processGroupID: pid_t,
        graceSeconds: TimeInterval = 2
    ) {
        guard childProcessID > 1, processGroupID > 1 else { return }
        guard Darwin.getpgid(childProcessID) == processGroupID else { return }
        terminateProcessGroup(processGroupID, graceSeconds: graceSeconds)
    }

    private static func mutate(
        fileURL: URL,
        fileManager: FileManager,
        _ body: (inout [Record]) -> Void
    ) {
        locked(fileURL: fileURL, fileManager: fileManager) { handle in
            var records = decodeRecords(from: handle)
            body(&records)
            guard let data = try? JSONEncoder().encode(records) else { return }
            do {
                try handle.truncate(atOffset: 0)
                try handle.seek(toOffset: 0)
                try handle.write(contentsOf: data)
            } catch {
                return
            }
            try? fileManager.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: fileURL.path
            )
        }
    }

    @discardableResult
    private static func locked<T>(
        fileURL: URL,
        fileManager: FileManager,
        _ body: (FileHandle) -> T
    ) -> T? {
        let directory = fileURL.deletingLastPathComponent()
        try? fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        if !fileManager.fileExists(atPath: fileURL.path) {
            fileManager.createFile(
                atPath: fileURL.path,
                contents: Data("[]".utf8),
                attributes: [.posixPermissions: 0o600]
            )
        }
        guard let handle = try? FileHandle(forUpdating: fileURL) else { return nil }
        defer { try? handle.close() }
        flock(handle.fileDescriptor, LOCK_EX)
        defer { flock(handle.fileDescriptor, LOCK_UN) }
        return body(handle)
    }

    private static func decodeRecords(from handle: FileHandle) -> [Record] {
        let data = (try? handle.readToEnd()) ?? Data()
        try? handle.seek(toOffset: 0)
        guard !data.isEmpty,
              let records = try? JSONDecoder().decode([Record].self, from: data) else {
            return []
        }
        return records
    }
}
#endif
