import Darwin
import Foundation
import Testing
@testable import authsia

@Suite("MCP same-binary runner")
struct MCPSameBinaryRunnerTests {
    @Test("process uses the exact binary workspace argv and sanitized environment")
    func exactProcessBoundary() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let executable = URL(fileURLWithPath: "/synthetic/Authsia.app/Contents/MacOS/authsia")
        let invocationID = UUID(uuidString: "2624F49A-65EE-433C-B816-03631A44D1C7")!
        let invocation = MCPInvocationContext(
            id: invocationID,
            environment: [
                "AUTHSIA_AGENT_TYPE": "authsia-mcp",
                "AUTHSIA_AGENT_SESSION_ID": "mcp:test",
            ]
        )
        let runner = MCPSameBinaryRunner(
            executableURL: executable,
            workspaceRoot: root,
            parentEnvironment: [
                "HOME": "/synthetic/home",
                "PATH": "/usr/bin",
                "LANG": "en_US.UTF-8",
                "LC_CTYPE": "UTF-8",
                "GITHUB_TOKEN": "synthetic-token-must-not-survive",
                "AWS_SECRET_ACCESS_KEY": "synthetic-key-must-not-survive",
                "AUTHSIA_AGENT_ID": "stale-agent-must-not-survive",
                AutomationAccessResolver.environmentKey: "must-not-survive",
                AutomationAccessResolver.sshEnvironmentKey: "must-not-survive-either",
            ]
        )

        let process = runner.makeProcess(
            arguments: ["workspace", "run", "--", "printf", "hello world"],
            invocation: invocation
        )

        #expect(process.executableURL == executable)
        #expect(process.currentDirectoryURL == root)
        #expect(process.arguments == ["workspace", "run", "--", "printf", "hello world"])
        #expect(process.environment?["HOME"] == "/synthetic/home")
        #expect(process.environment?["PATH"] == "/usr/bin")
        #expect(process.environment?["LANG"] == "en_US.UTF-8")
        #expect(process.environment?["LC_CTYPE"] == "UTF-8")
        #expect(process.environment?["GITHUB_TOKEN"] == nil)
        #expect(process.environment?["AWS_SECRET_ACCESS_KEY"] == nil)
        #expect(process.environment?["AUTHSIA_AGENT_ID"] == nil)
        #expect(process.environment?[AutomationAccessResolver.environmentKey] == nil)
        #expect(process.environment?[AutomationAccessResolver.sshEnvironmentKey] == nil)
        #expect(process.environment?["AUTHSIA_AGENT_TYPE"] == "authsia-mcp")
        #expect(process.environment?["AUTHSIA_AGENT_SESSION_ID"] == "mcp:test")
    }

    @Test("stdout and stderr are drained concurrently and bounded")
    func outputIsBounded() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let runner = MCPSameBinaryRunner(
            executableURL: URL(fileURLWithPath: "/usr/bin/python3"),
            workspaceRoot: root,
            parentEnvironment: [:]
        )
        let invocation = MCPInvocationContext(id: UUID(), environment: [:])
        let program = "import sys;sys.stdout.write('o'*70000);sys.stderr.write('e'*70000)"

        let result = await runner.run(
            arguments: ["-c", program],
            invocation: invocation,
            timeoutSeconds: 10
        )

        #expect(result.exitCode == 0)
        #expect(result.stdout.utf8.count == 65_536)
        #expect(result.stderr.utf8.count == 65_536)
        #expect(result.stdoutTruncated)
        #expect(result.stderrTruncated)
        #expect(!result.cancelled)
        #expect(!result.timedOut)
        #expect(result.invocationID == invocation.id)
    }

    @Test("task cancellation terminates the child and returns cancellation")
    func cancellationTerminatesChild() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let readyFile = root.appendingPathComponent("synthetic-child.ready")
        let runner = MCPSameBinaryRunner(
            executableURL: URL(fileURLWithPath: "/usr/bin/python3"),
            workspaceRoot: root,
            parentEnvironment: [:],
            killGraceSeconds: 0.05
        )
        let invocation = MCPInvocationContext(id: UUID(), environment: [:])
        let program = #"""
        import os, sys, time
        os.setpgid(0, 0)
        with open(sys.argv[1], "w") as handle:
            handle.write("ready")
        while True:
            time.sleep(1)
        """#
        let task = Task(priority: .high) {
            await runner.run(
                arguments: ["-c", program, readyFile.path],
                invocation: invocation,
                timeoutSeconds: 60
            )
        }

        let cancellation = MCPTestCancellationTrigger(files: [readyFile], task: task)
        cancellation.start()
        let result = await task.value

        #expect(cancellation.observedReadiness)
        #expect(result.cancelled)
        #expect(!result.timedOut)
        #expect(result.invocationID == invocation.id)
    }

    @Test("timeout terminates the child and is distinct from cancellation")
    func timeoutTerminatesChild() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let runner = MCPSameBinaryRunner(
            executableURL: URL(fileURLWithPath: "/bin/sleep"),
            workspaceRoot: root,
            parentEnvironment: [:],
            killGraceSeconds: 0.05
        )
        let invocation = MCPInvocationContext(id: UUID(), environment: [:])

        let result = await runner.run(
            arguments: ["10"],
            invocation: invocation,
            timeoutSeconds: 1
        )

        #expect(result.timedOut)
        #expect(!result.cancelled)
    }

    @Test("timeout terminates stubborn descendants before returning")
    func timeoutTerminatesStubbornDescendants() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let pidFile = root.appendingPathComponent("synthetic-child.pid")
        let runner = MCPSameBinaryRunner(
            executableURL: URL(fileURLWithPath: "/usr/bin/python3"),
            workspaceRoot: root,
            parentEnvironment: [:],
            killGraceSeconds: 0.05
        )
        let program = #"""
        import os, signal, sys, time
        os.setpgid(0, 0)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        child = os.fork()
        if child == 0:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            with open(sys.argv[1], "w") as handle:
                handle.write(str(os.getpid()))
            os.close(1)
            os.close(2)
            while True:
                time.sleep(1)
        while True:
            time.sleep(1)
        """#

        let result = await runner.run(
            arguments: ["-c", program, pidFile.path],
            invocation: MCPInvocationContext(id: UUID(), environment: [:]),
            timeoutSeconds: 1
        )
        let descendantPID = try #require(
            Int32(String(contentsOf: pidFile, encoding: .utf8))
        )
        defer {
            if Self.processExists(descendantPID) {
                Darwin.kill(descendantPID, SIGKILL)
            }
        }

        #expect(result.timedOut)
        #expect(!Self.processExists(descendantPID))
    }

    @Test("normal wrapper exit cleans up remaining descendants")
    func normalExitCleansUpRemainingDescendants() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let pidFile = root.appendingPathComponent("synthetic-background-child.pid")
        let runner = MCPSameBinaryRunner(
            executableURL: URL(fileURLWithPath: "/usr/bin/python3"),
            workspaceRoot: root,
            parentEnvironment: [:],
            killGraceSeconds: 0.05
        )
        let program = #"""
        import os, signal, sys, time
        os.setpgid(0, 0)
        child = os.fork()
        if child == 0:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            with open(sys.argv[1], "w") as handle:
                handle.write(str(os.getpid()))
            os.close(1)
            os.close(2)
            while True:
                time.sleep(1)
        while not os.path.exists(sys.argv[1]):
            time.sleep(0.01)
        """#

        let result = await runner.run(
            arguments: ["-c", program, pidFile.path],
            invocation: MCPInvocationContext(id: UUID(), environment: [:]),
            timeoutSeconds: 10
        )
        let descendantPID = try #require(
            Int32(String(contentsOf: pidFile, encoding: .utf8))
        )
        defer {
            if Self.processExists(descendantPID) {
                Darwin.kill(descendantPID, SIGKILL)
            }
        }

        #expect(result.exitCode == 0)
        #expect(!result.cancelled)
        #expect(!result.timedOut)
        #expect(!Self.processExists(descendantPID))
    }

    @Test("cancellation awaits forced cleanup after the group leader exits")
    func cancellationAwaitsDescendantCleanupAfterLeaderExit() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let descendantPIDFile = root.appendingPathComponent("synthetic-descendant.pid")
        let readyFile = root.appendingPathComponent("synthetic-leader.ready")
        let runner = MCPSameBinaryRunner(
            executableURL: URL(fileURLWithPath: "/usr/bin/python3"),
            workspaceRoot: root,
            parentEnvironment: [:],
            killGraceSeconds: 0.2
        )
        let program = #"""
        import os, signal, sys, time
        os.setpgid(0, 0)
        child = os.fork()
        if child == 0:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            with open(sys.argv[1], "w") as handle:
                handle.write(str(os.getpid()))
            os.close(1)
            os.close(2)
            while True:
                time.sleep(1)
        with open(sys.argv[2], "w") as handle:
            handle.write("ready")
        while True:
            time.sleep(1)
        """#
        let task = Task(priority: .high) {
            await runner.run(
                arguments: ["-c", program, descendantPIDFile.path, readyFile.path],
                invocation: MCPInvocationContext(id: UUID(), environment: [:]),
                timeoutSeconds: 60
            )
        }

        let cancellation = MCPTestCancellationTrigger(
            files: [readyFile, descendantPIDFile],
            task: task
        )
        cancellation.start()
        let result = await task.value
        #expect(cancellation.observedReadiness)
        let descendantPID = try #require(
            Int32(String(contentsOf: descendantPIDFile, encoding: .utf8))
        )
        defer {
            if Self.processExists(descendantPID) {
                Darwin.kill(descendantPID, SIGKILL)
            }
        }

        #expect(result.cancelled)
        #expect(!Self.processExists(descendantPID))
    }

    @Test("child policy failures use the private status channel")
    func childPolicyFailureStatus() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let runner = MCPSameBinaryRunner(
            executableURL: URL(fileURLWithPath: "/usr/bin/python3"),
            workspaceRoot: root,
            parentEnvironment: [:]
        )
        let program = #"""
        import os, sys
        with open(os.environ["AUTHSIA_MCP_FAILURE_FILE"], "w") as handle:
            handle.write("approvalDenied")
        sys.exit(1)
        """#

        let result = await runner.run(
            arguments: ["-c", program],
            invocation: MCPInvocationContext(id: UUID(), environment: [:]),
            timeoutSeconds: 10
        )

        #expect(result.exitCode == 1)
        #expect(result.failureCode == .approvalDenied)
    }

    private static func processExists(_ processID: Int32) -> Bool {
        Darwin.kill(processID, 0) == 0 || errno == EPERM
    }

    fileprivate static func waitForFiles(_ urls: [URL], timeoutSeconds: Double = 30) -> Bool {
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while Date() < deadline {
            if urls.allSatisfy({ FileManager.default.fileExists(atPath: $0.path) }) {
                return true
            }
            Thread.sleep(forTimeInterval: 0.01)
        }
        return false
    }
}

private final class MCPTestCancellationTrigger: @unchecked Sendable {
    private let lock = NSLock()
    private let files: [URL]
    private let task: Task<MCPChildResult, Never>
    private var readiness = false

    init(files: [URL], task: Task<MCPChildResult, Never>) {
        self.files = files
        self.task = task
    }

    var observedReadiness: Bool {
        lock.withLock { readiness }
    }

    func start() {
        let thread = Thread { [self] in
            let observed = MCPSameBinaryRunnerTests.waitForFiles(files)
            lock.withLock { readiness = observed }
            task.cancel()
        }
        thread.qualityOfService = .userInitiated
        thread.start()
    }
}
