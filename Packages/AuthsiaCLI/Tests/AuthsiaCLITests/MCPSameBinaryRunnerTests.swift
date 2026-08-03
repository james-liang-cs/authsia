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
                "PATH": "/usr/bin",
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
        let runner = MCPSameBinaryRunner(
            executableURL: URL(fileURLWithPath: "/bin/sleep"),
            workspaceRoot: root,
            parentEnvironment: [:],
            killGraceSeconds: 0.05
        )
        let invocation = MCPInvocationContext(id: UUID(), environment: [:])
        let task = Task {
            await runner.run(
                arguments: ["10"],
                invocation: invocation,
                timeoutSeconds: 20
            )
        }

        try await Task.sleep(for: .milliseconds(100))
        task.cancel()
        let result = await task.value

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
}
