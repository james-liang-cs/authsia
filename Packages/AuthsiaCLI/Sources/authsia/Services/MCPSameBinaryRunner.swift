import Darwin
import Foundation

struct MCPChildResult: Equatable, Sendable {
    let invocationID: UUID
    let exitCode: Int32?
    let stdout: String
    let stderr: String
    let stdoutTruncated: Bool
    let stderrTruncated: Bool
    let cancelled: Bool
    let timedOut: Bool
    let durationMilliseconds: Int
    var launchFailed = false
    var signalled = false
    var failureCode: MCPToolErrorCode? = nil
}

protocol MCPChildRunning: Sendable {
    func run(
        arguments: [String],
        invocation: MCPInvocationContext,
        timeoutSeconds: Int
    ) async -> MCPChildResult
}

struct MCPSameBinaryRunner: MCPChildRunning, Sendable {
    typealias ProcessFactory = @Sendable () -> Process

    static let outputLimit = 65_536

    let executableURL: URL
    let workspaceRoot: URL
    let parentEnvironment: [String: String]
    let killGraceSeconds: Double
    private let processFactory: ProcessFactory

    init(
        executableURL: URL = Authsia.currentExecutableURL(),
        workspaceRoot: URL,
        parentEnvironment: [String: String] = ProcessInfo.processInfo.environment,
        killGraceSeconds: Double = 2,
        processFactory: @escaping ProcessFactory = { Process() }
    ) {
        self.executableURL = executableURL
        self.workspaceRoot = workspaceRoot
        self.parentEnvironment = parentEnvironment
        self.killGraceSeconds = killGraceSeconds
        self.processFactory = processFactory
    }

    func makeProcess(
        arguments: [String],
        invocation: MCPInvocationContext,
        failureReportURL: URL? = nil
    ) -> Process {
        let process = processFactory()
        process.executableURL = executableURL
        process.currentDirectoryURL = workspaceRoot
        process.arguments = arguments

        var environment = MCPInheritedEnvironment.filtered(parentEnvironment)
        for (key, value) in invocation.environment {
            environment[key] = value
        }
        environment[MCPChildProcessGroup.environmentKey] = "1"
        if let failureReportURL {
            environment[MCPChildFailureReporter.environmentKey] = failureReportURL.path
        }
        process.environment = environment
        return process
    }

    func run(
        arguments: [String],
        invocation: MCPInvocationContext,
        timeoutSeconds: Int
    ) async -> MCPChildResult {
        let startedAt = ContinuousClock.now
        let failureReport = MCPChildFailureFile()
        defer { failureReport?.remove() }
        let process = makeProcess(
            arguments: arguments,
            invocation: invocation,
            failureReportURL: failureReport?.url
        )
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        do {
            try process.run()
        } catch {
            return MCPChildResult(
                invocationID: invocation.id,
                exitCode: nil,
                stdout: "",
                stderr: "",
                stdoutTruncated: false,
                stderrTruncated: false,
                cancelled: false,
                timedOut: false,
                durationMilliseconds: elapsedMilliseconds(since: startedAt),
                launchFailed: true
            )
        }

        let stdoutReader = MCPBlockingOperation {
            Self.readBounded(stdoutPipe.fileHandleForReading)
        }
        let stderrReader = MCPBlockingOperation {
            Self.readBounded(stderrPipe.fileHandleForReading)
        }
        stdoutReader.start()
        stderrReader.start()
        let termination = MCPChildTerminationState()
        let processTerminator = MCPProcessTerminator(
            process: process,
            killGraceSeconds: killGraceSeconds
        )
        let processWaiter = MCPBlockingOperation { () -> (Int32, Process.TerminationReason) in
            process.waitUntilExit()
            processTerminator.start()
            return (process.terminationStatus, process.terminationReason)
        }
        processWaiter.start()
        let timeout = MCPChildTimeout(seconds: timeoutSeconds) {
            if processTerminator.start() {
                termination.markTimedOut()
            }
        }
        timeout.start()

        let processOutput = await withTaskCancellationHandler {
            let processTermination = await processWaiter.value()
            await processTerminator.waitUntilFinished()
            let stdout = await stdoutReader.value()
            let stderr = await stderrReader.value()
            return (processTermination, stdout, stderr)
        } onCancel: {
            termination.markCancelled()
            processTerminator.start()
        }
        timeout.cancel()

        let processTermination = processOutput.0
        let stdout = processOutput.1
        let stderr = processOutput.2
        let state = termination.snapshot()
        let exitCode = processTermination.1 == .exit ? processTermination.0 : nil
        return MCPChildResult(
            invocationID: invocation.id,
            exitCode: exitCode,
            stdout: String(decoding: stdout.data, as: UTF8.self),
            stderr: String(decoding: stderr.data, as: UTF8.self),
            stdoutTruncated: stdout.truncated,
            stderrTruncated: stderr.truncated,
            cancelled: state.cancelled,
            timedOut: state.timedOut,
            durationMilliseconds: elapsedMilliseconds(since: startedAt),
            signalled: processTermination.1 == .uncaughtSignal,
            failureCode: failureReport?.readCode()
        )
    }

    private static func readBounded(_ handle: FileHandle) -> (data: Data, truncated: Bool) {
        var retained = Data()
        var truncated = false
        while true {
            let chunk = handle.readData(ofLength: 16_384)
            guard !chunk.isEmpty else { break }
            let remaining = outputLimit - retained.count
            if remaining > 0 {
                retained.append(chunk.prefix(remaining))
            }
            if chunk.count > remaining {
                truncated = true
            }
        }
        return (retained, truncated)
    }

    private func elapsedMilliseconds(since start: ContinuousClock.Instant) -> Int {
        let elapsed = start.duration(to: .now)
        return Int(elapsed.components.seconds * 1_000) +
            Int(elapsed.components.attoseconds / 1_000_000_000_000_000)
    }
}

private struct MCPChildFailureFile {
    let url: URL

    init?() {
        let candidate = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-mcp-failure-\(UUID().uuidString)")
        guard FileManager.default.createFile(
            atPath: candidate.path,
            contents: Data(),
            attributes: [.posixPermissions: 0o600]
        ) else {
            return nil
        }
        url = candidate
    }

    func readCode() -> MCPToolErrorCode? {
        guard let data = try? Data(contentsOf: url),
              data.count <= 64,
              let rawValue = String(data: data, encoding: .utf8) else {
            return nil
        }
        return MCPToolErrorCode(rawValue: rawValue)
    }

    func remove() {
        try? FileManager.default.removeItem(at: url)
    }
}

enum MCPChildProcessGroup {
    static let environmentKey = "AUTHSIA_MCP_PROCESS_GROUP"
}

private final class MCPChildTerminationState: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    private var timedOut = false

    func markCancelled() {
        lock.withLock { cancelled = true }
    }

    func markTimedOut() {
        lock.withLock { timedOut = true }
    }

    func snapshot() -> (cancelled: Bool, timedOut: Bool) {
        lock.withLock { (cancelled, timedOut) }
    }
}

private final class MCPChildTimeout: @unchecked Sendable {
    private let condition = NSCondition()
    private let deadline: Date
    private let action: @Sendable () -> Void
    private var cancelled = false

    init(seconds: Int, action: @escaping @Sendable () -> Void) {
        deadline = Date().addingTimeInterval(TimeInterval(seconds))
        self.action = action
    }

    func start() {
        Thread.detachNewThread { [self] in
            condition.lock()
            let reachedDeadline = !condition.wait(until: deadline)
            let shouldRun = reachedDeadline && !cancelled
            condition.unlock()
            if shouldRun { action() }
        }
    }

    func cancel() {
        condition.lock()
        cancelled = true
        condition.signal()
        condition.unlock()
    }
}
