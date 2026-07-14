import Foundation
#if os(macOS)
import Darwin
#endif

public struct AgentCommandProcessSnapshot: Equatable, Sendable {
    public let pid: Int32
    public let processName: String
    public let arguments: [String]
    public let workingDirectory: String?
    public let terminalSessionScope: String?
    public let ancestry: [AgenticProcessReference]

    public init(
        pid: Int32,
        processName: String,
        arguments: [String],
        workingDirectory: String?,
        terminalSessionScope: String?,
        ancestry: [AgenticProcessReference]
    ) {
        self.pid = pid
        self.processName = processName
        self.arguments = arguments
        self.workingDirectory = workingDirectory
        self.terminalSessionScope = terminalSessionScope
        self.ancestry = ancestry
    }
}

public struct AgentCommandProcessMonitor: Sendable {
    private let snapshotProvider: @Sendable () -> [AgentCommandProcessSnapshot]

    public init(
        snapshotProvider: @escaping @Sendable () -> [AgentCommandProcessSnapshot] = AgentCommandProcessMonitor.liveSnapshots
    ) {
        self.snapshotProvider = snapshotProvider
    }

    public func events(for grants: [AgentJITGrant], now: Date = Date()) -> [AgentCommandEvent] {
        let activeGrants = grants.filter { $0.status(asOf: now) == .active }
        guard !activeGrants.isEmpty else { return [] }

        return snapshotProvider().compactMap { snapshot in
            guard !AgenticProcessDetector.isAgenticProcess(
                processName: snapshot.processName,
                bundleIdentifier: nil,
                arguments: snapshot.arguments
            ) else {
                return nil
            }
            guard AgenticProcessDetector.containsAgenticProcess(snapshot.ancestry),
                  let grant = Self.matchingGrant(for: snapshot, in: activeGrants) else {
                return nil
            }

            let command = snapshot.arguments.isEmpty
                ? snapshot.processName
                : snapshot.arguments.joined(separator: " ")
            return AgentCommandEvent(
                recordedAt: now,
                agentPlatform: Self.agentPlatform(in: snapshot.ancestry),
                agentJITGrantID: grant.id,
                captureSource: .process,
                contextExpiresAt: grant.expiresAt,
                workingDirectory: snapshot.workingDirectory,
                terminalSessionScope: snapshot.terminalSessionScope,
                executable: snapshot.processName,
                arguments: snapshot.arguments,
                command: command,
                exitStatus: nil
            )
        }
    }

    public static func liveSnapshots() -> [AgentCommandProcessSnapshot] {
        #if os(macOS)
        processIDs().compactMap { pid in
            let ancestry = AgenticProcessDetector.processAncestry(startingAt: pid)
            guard let currentProcess = ancestry.first else { return nil }
            return AgentCommandProcessSnapshot(
                pid: pid,
                processName: currentProcess.processName,
                arguments: currentProcess.arguments,
                workingDirectory: nil,
                terminalSessionScope: TerminalSessionScope.ancestralScope(startingAt: pid),
                ancestry: ancestry
            )
        }
        #else
        []
        #endif
    }

    private static func matchingGrant(
        for snapshot: AgentCommandProcessSnapshot,
        in grants: [AgentJITGrant]
    ) -> AgentJITGrant? {
        guard let snapshotScope = normalized(snapshot.terminalSessionScope) else { return nil }
        return grants.first { grant in
            guard normalized(grant.callerFingerprint.sessionScope) == snapshotScope else { return false }
            guard let snapshotWorkingDirectory = normalizedPath(snapshot.workingDirectory),
                  let grantWorkingDirectory = normalizedPath(grant.callerFingerprint.workingDirectory) else {
                return true
            }
            return snapshotWorkingDirectory == grantWorkingDirectory
        }
    }

    private static func agentPlatform(in ancestry: [AgenticProcessReference]) -> String? {
        guard let agent = ancestry.first(where: {
            AgenticProcessDetector.isAgenticProcess(
                processName: $0.processName,
                bundleIdentifier: $0.bundleIdentifier,
                arguments: $0.arguments
            )
        }) else {
            return nil
        }

        return AgenticProcessDetector.agentPlatform(
            processName: agent.processName,
            bundleIdentifier: agent.bundleIdentifier,
            arguments: agent.arguments
        )
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

    #if os(macOS)
    private static func processIDs() -> [pid_t] {
        let count = Int(proc_listallpids(nil, 0))
        guard count > 0 else { return [] }

        var pids = [pid_t](repeating: 0, count: count)
        let byteCount = pids.withUnsafeMutableBytes { buffer in
            proc_listallpids(buffer.baseAddress, Int32(buffer.count))
        }
        guard byteCount > 0 else { return [] }

        let processCount = min(Int(byteCount) / MemoryLayout<pid_t>.size, pids.count)
        return Array(pids.prefix(processCount)).filter { $0 > 1 }
    }
    #endif
}
