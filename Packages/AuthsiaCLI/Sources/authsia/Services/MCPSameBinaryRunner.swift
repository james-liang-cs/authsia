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
}

struct MCPSameBinaryRunner: Sendable {
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
        invocation: MCPInvocationContext
    ) -> Process {
        let process = processFactory()
        process.executableURL = executableURL
        process.currentDirectoryURL = workspaceRoot
        process.arguments = arguments

        var environment = parentEnvironment
        Exec.removeAutomationCredentials(from: &environment)
        for (key, value) in invocation.environment {
            environment[key] = value
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
        let process = makeProcess(arguments: arguments, invocation: invocation)
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
                durationMilliseconds: elapsedMilliseconds(since: startedAt)
            )
        }

        let stdoutTask = Task.detached {
            Self.readBounded(stdoutPipe.fileHandleForReading)
        }
        let stderrTask = Task.detached {
            Self.readBounded(stderrPipe.fileHandleForReading)
        }
        let termination = MCPChildTerminationState()
        let waitTask = Task.detached { () -> (Int32, Process.TerminationReason) in
            process.waitUntilExit()
            return (process.terminationStatus, process.terminationReason)
        }
        let timeoutTask = Task {
            do {
                try await Task.sleep(for: .seconds(timeoutSeconds))
                termination.markTimedOut()
                Self.terminate(process, killGraceSeconds: killGraceSeconds)
            } catch {
                return
            }
        }

        let processTermination = await withTaskCancellationHandler {
            await waitTask.value
        } onCancel: {
            termination.markCancelled()
            Self.terminate(process, killGraceSeconds: killGraceSeconds)
        }
        timeoutTask.cancel()

        let stdout = await stdoutTask.value
        let stderr = await stderrTask.value
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
            durationMilliseconds: elapsedMilliseconds(since: startedAt)
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

    private static func terminate(_ process: Process, killGraceSeconds: Double) {
        guard process.isRunning else { return }
        process.terminate()
        Task.detached {
            try? await Task.sleep(for: .seconds(killGraceSeconds))
            if process.isRunning {
                Darwin.kill(process.processIdentifier, SIGKILL)
            }
        }
    }

    private func elapsedMilliseconds(since start: ContinuousClock.Instant) -> Int {
        let elapsed = start.duration(to: .now)
        return Int(elapsed.components.seconds * 1_000) +
            Int(elapsed.components.attoseconds / 1_000_000_000_000_000)
    }
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
