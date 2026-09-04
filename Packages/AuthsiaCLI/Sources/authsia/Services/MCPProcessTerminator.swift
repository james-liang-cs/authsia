import Darwin
import Foundation

final class MCPProcessTerminator: @unchecked Sendable {
    private let lock = NSLock()
    private let process: Process?
    private let knownProcessID: pid_t?
    private let knownProcessGroupID: pid_t?
    private let killGraceSeconds: Double
    private var operation: MCPBlockingOperation<Void>?

    init(process: Process, killGraceSeconds: Double) {
        self.process = process
        self.knownProcessID = nil
        self.knownProcessGroupID = nil
        self.killGraceSeconds = max(0, killGraceSeconds)
    }

    init(processID: pid_t, processGroupID: pid_t? = nil, killGraceSeconds: Double) {
        self.process = nil
        self.knownProcessID = processID
        self.knownProcessGroupID = processGroupID
        self.killGraceSeconds = max(0, killGraceSeconds)
    }

    @discardableResult
    func start() -> Bool {
        let result: (operation: MCPBlockingOperation<Void>?, hasTarget: Bool) = lock.withLock {
            let processID = self.processID
            let processGroupID = self.processGroupID(for: processID)
            if self.operation != nil {
                return (nil, targetExists(processID: processID, processGroupID: processGroupID))
            }
            guard targetExists(processID: processID, processGroupID: processGroupID) else {
                return (nil, false)
            }
            let process = self.process
            let killGraceSeconds = self.killGraceSeconds
            let operation = MCPBlockingOperation<Void> {
                Self.terminateAndWait(
                    process: process,
                    processID: processID,
                    processGroupID: processGroupID,
                    killGraceSeconds: killGraceSeconds
                )
            }
            self.operation = operation
            return (operation, true)
        }
        result.operation?.start()
        return result.hasTarget
    }

    func waitUntilFinished() async {
        let operation = lock.withLock { self.operation }
        if let operation {
            await operation.value()
        }
    }

    var recordedProcessGroupID: pid_t? { knownProcessGroupID }

    private var processID: pid_t {
        if let knownProcessID {
            return knownProcessID
        }
        return process?.processIdentifier ?? 0
    }

    private func processGroupID(for processID: pid_t) -> pid_t? {
        if let knownProcessGroupID {
            return knownProcessGroupID
        }
        return Self.managedProcessGroupID(processID)
    }

    private func targetExists(processID: pid_t, processGroupID: pid_t?) -> Bool {
        if let process {
            return process.isRunning || (processGroupID.map { Self.processGroupExists($0) } ?? false)
        }
        if processID > 0, Self.processExists(processID) {
            return true
        }
        return processGroupID.map { Self.processGroupExists($0) } ?? false
    }

    private static func terminateAndWait(
        process: Process?,
        processID: pid_t,
        processGroupID: pid_t?,
        killGraceSeconds: Double
    ) {
        if let processGroupID {
            Darwin.kill(-processGroupID, SIGTERM)
        } else if let process {
            process.terminate()
        } else if processID > 0 {
            Darwin.kill(processID, SIGTERM)
        }

        let gracefulDeadline = Date().addingTimeInterval(killGraceSeconds)
        while Self.targetStillExists(process: process, processID: processID, processGroupID: processGroupID),
              Date() < gracefulDeadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        guard Self.targetStillExists(process: process, processID: processID, processGroupID: processGroupID) else {
            return
        }

        if let processGroupID {
            Darwin.kill(-processGroupID, SIGKILL)
        } else if processID > 0 {
            Darwin.kill(processID, SIGKILL)
        }

        let forcedDeadline = Date().addingTimeInterval(1)
        while Self.targetStillExists(process: process, processID: processID, processGroupID: processGroupID),
              Date() < forcedDeadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
    }

    private static func targetStillExists(
        process: Process?,
        processID: pid_t,
        processGroupID: pid_t?
    ) -> Bool {
        if let processGroupID {
            return processGroupExists(processGroupID)
        }
        if let process {
            return process.isRunning
        }
        return processID > 0 && processExists(processID)
    }

    private static func processExists(_ processID: pid_t) -> Bool {
        Darwin.kill(processID, 0) == 0 || errno == EPERM
    }

    private static func processGroupExists(_ processGroupID: pid_t) -> Bool {
        Darwin.kill(-processGroupID, 0) == 0 || errno == EPERM
    }

    static func managedProcessGroupID(_ processID: pid_t) -> pid_t? {
        guard processID > 0 else { return nil }
        if Darwin.getpgid(processID) == processID {
            return processID
        }
        return processGroupExists(processID) ? processID : nil
    }
}

final class MCPBlockingOperation<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private let operation: @Sendable () -> Value
    private var result: Value?
    private var continuation: CheckedContinuation<Value, Never>?
    private var started = false

    init(_ operation: @escaping @Sendable () -> Value) {
        self.operation = operation
    }

    func start() {
        lock.lock()
        guard !started else {
            lock.unlock()
            return
        }
        started = true
        lock.unlock()

        Thread.detachNewThread { [self] in
            complete(operation())
        }
    }

    func value() async -> Value {
        await withCheckedContinuation { pending in
            lock.lock()
            if let result {
                lock.unlock()
                pending.resume(returning: result)
            } else {
                continuation = pending
                lock.unlock()
            }
        }
    }

    private func complete(_ value: Value) {
        lock.lock()
        result = value
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: value)
    }
}
