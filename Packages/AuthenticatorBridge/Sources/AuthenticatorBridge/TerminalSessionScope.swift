import Foundation
#if os(macOS)
import Darwin
#endif

public struct TerminalSessionComponents: Equatable, Sendable {
    public let terminalIdentifier: String
    public let processSessionIdentifier: Int32?

    public init(terminalIdentifier: String, processSessionIdentifier: Int32?) {
        self.terminalIdentifier = terminalIdentifier
        self.processSessionIdentifier = processSessionIdentifier
    }
}

public enum TerminalSessionLiveness: Equatable, Sendable {
    case active
    case closed
    case unknown
}

public enum TerminalSessionScope {
    public static func identity(
        terminalIdentifier: String?,
        processSessionIdentifier: Int32?
    ) -> String? {
        guard let terminalIdentifier = nonEmpty(terminalIdentifier) else {
            return nil
        }
        if let processSessionIdentifier {
            return "tty:\(terminalIdentifier):sid:\(processSessionIdentifier)"
        }
        return "tty:\(terminalIdentifier)"
    }

    public static func components(from scope: String?) -> TerminalSessionComponents? {
        guard let scope = nonEmpty(scope), scope.hasPrefix("tty:") else {
            return nil
        }

        let value = String(scope.dropFirst("tty:".count))
        if let sidRange = value.range(of: ":sid:") {
            let terminalIdentifier = String(value[..<sidRange.lowerBound])
            let sessionValue = String(value[sidRange.upperBound...])
            guard let terminalIdentifier = nonEmpty(terminalIdentifier) else {
                return nil
            }
            return TerminalSessionComponents(
                terminalIdentifier: terminalIdentifier,
                processSessionIdentifier: Int32(sessionValue)
            )
        }

        guard let terminalIdentifier = nonEmpty(value) else {
            return nil
        }
        return TerminalSessionComponents(
            terminalIdentifier: terminalIdentifier,
            processSessionIdentifier: nil
        )
    }

    public static func liveness(for scope: String?) -> TerminalSessionLiveness {
        liveness(for: scope, isProcessRunning: processIsRunning(pid:))
    }

    public static func liveness(
        for scope: String?,
        isProcessRunning: (Int32) -> Bool
    ) -> TerminalSessionLiveness {
        guard let sessionID = components(from: scope)?.processSessionIdentifier,
              sessionID > 1 else {
            return .unknown
        }
        return isProcessRunning(sessionID) ? .active : .closed
    }

    public static func currentProcess() -> String? {
        identity(
            terminalIdentifier: currentTerminalIdentifier(),
            processSessionIdentifier: currentProcessSessionIdentifier()
        )
    }

    public static func process(pid: Int32) -> String? {
        identity(
            terminalIdentifier: controllingTerminalPath(pid: pid),
            processSessionIdentifier: processSessionIdentifier(pid: pid)
        )
    }

    public static func currentTerminalIdentifier() -> String? {
        #if os(macOS)
        return currentTerminalIdentifier(
            isTerminal: { isatty($0) != 0 },
            terminalName: { ttyname($0).map { String(cString: $0) } },
            controllingTerminalPath: { controllingTerminalPath(pid: getpid()) }
        )
        #else
        return nil
        #endif
    }

    #if os(macOS)
    static func currentTerminalIdentifier(
        isTerminal: (Int32) -> Bool,
        terminalName: (Int32) -> String?,
        controllingTerminalPath: () -> String?
    ) -> String? {
        let fileDescriptors = [STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO]
        guard fileDescriptors.contains(where: isTerminal) else {
            return nil
        }
        if let concreteTerminal = controllingTerminalPath() {
            return concreteTerminal
        }
        for fileDescriptor in fileDescriptors where isTerminal(fileDescriptor) {
            if let terminalName = terminalName(fileDescriptor) {
                return terminalName
            }
        }
        return nil
    }
    #endif

    public static func currentProcessSessionIdentifier() -> Int32? {
        #if os(macOS)
        return processSessionIdentifier(pid: getpid())
        #else
        return nil
        #endif
    }

    public static func controllingTerminalPath(pid: Int32) -> String? {
        #if os(macOS)
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        let result = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size)
        guard result == size,
              info.e_tdev != 0,
              info.e_tdev != UInt32.max else {
            return nil
        }

        let terminalDevice = dev_t(bitPattern: info.e_tdev)
        guard let terminalName = devname(terminalDevice, mode_t(S_IFCHR)) else {
            return nil
        }
        return "/dev/\(String(cString: terminalName))"
        #else
        return nil
        #endif
    }

    /// Resolves the scope of the nearest process in the ancestry chain (starting at
    /// `pid`) that has a controlling terminal. Mirrors how the SSH agent resolves a
    /// requester's terminal, so CLI commands running without tty stdio (IDE tasks,
    /// agent-driven shells, pipelines) land on the same scope as agent approvals.
    public static func ancestralScope(
        startingAt pid: Int32,
        maxHops: Int = 8,
        parentProcessIdentifier: (Int32) -> Int32? = parentProcessIdentifier,
        scopeForProcess: (Int32) -> String? = { process(pid: $0) }
    ) -> String? {
        var current: Int32? = pid
        var seen = Set<Int32>()
        var hops = 0
        while let pid = current, pid > 1, hops < maxHops, !seen.contains(pid) {
            if let scope = scopeForProcess(pid) {
                return scope
            }
            seen.insert(pid)
            current = parentProcessIdentifier(pid)
            hops += 1
        }
        return nil
    }

    public static func currentAncestralScope() -> String? {
        #if os(macOS)
        return ancestralScope(startingAt: getpid())
        #else
        return nil
        #endif
    }

    public static func parentProcessIdentifier(pid: Int32) -> Int32? {
        #if os(macOS)
        var info = proc_bsdshortinfo()
        let size = Int32(MemoryLayout<proc_bsdshortinfo>.size)
        let result = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &info, size)
        guard result == size else { return nil }
        let parentPID = Int32(info.pbsi_ppid)
        guard parentPID > 0, parentPID != pid else { return nil }
        return parentPID
        #else
        return nil
        #endif
    }

    public static func processSessionIdentifier(pid: Int32) -> Int32? {
        #if os(macOS)
        let sessionID = getsid(pid)
        return sessionID == -1 ? nil : sessionID
        #else
        return nil
        #endif
    }

    private static func nonEmpty(_ value: String?) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private static func processIsRunning(pid: Int32) -> Bool {
        #if os(macOS)
        errno = 0
        if kill(pid, 0) == 0 {
            return true
        }
        return errno == EPERM
        #else
        return false
        #endif
    }
}
