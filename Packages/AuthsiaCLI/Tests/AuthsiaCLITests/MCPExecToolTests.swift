import Foundation
import AuthenticatorBridge
import MCP
import Testing
@testable import authsia

@Suite("MCP mediated exec tool")
struct MCPExecToolTests {
    @Test("arguments can only construct workspace run argv")
    func exactWorkspaceRunArguments() throws {
        let input = try MCPExecInput(
            argv: ["swift", "test", "--filter", "Safe Test"],
            environment: "Development",
            envFiles: [".env", "config/.env.local"],
            timeoutSeconds: 30,
            workspaceRoot: "/tmp/active-workspace"
        ).validated()

        #expect(AuthsiaMCPServer.execArguments(input) == [
            "workspace", "run",
            "--environment", "Development",
            "--env-file", ".env",
            "--env-file", "config/.env.local",
            "--",
            "swift", "test", "--filter", "Safe Test",
        ])
        #expect(AuthsiaMCPServer.execArguments(
            try MCPExecInput(argv: ["make"], defaultOnly: true).validated()
        ) == ["workspace", "run", "--default-only", "--", "make"])
    }

    @Test("unsafe paths environment combinations and controls are rejected")
    func invalidInputs() {
        for path in ["/tmp/.env", "../.env", "config/../../.env", "linked\0.env"] {
            #expect(throws: MCPToolInputError.self) {
                try MCPExecInput(argv: ["make"], envFiles: [path]).validated()
            }
        }
        #expect(throws: MCPToolInputError.self) {
            try MCPExecInput(argv: ["make"], environment: "bad\nenvironment").validated()
        }
        #expect(throws: MCPToolInputError.self) {
            try MCPExecInput(argv: ["make"], environment: "Development", defaultOnly: true).validated()
        }
    }

    @Test("nonzero execution is a structured success and keeps the invocation id")
    func structuredNonzeroResult() async throws {
        let fixture = try makeServer(
            runner: ImmediateRunner(result: MCPChildResult(
                invocationID: UUID(),
                exitCode: 17,
                stdout: "masked output",
                stderr: "synthetic failure",
                stdoutTruncated: false,
                stderrTruncated: false,
                cancelled: false,
                timedOut: false,
                durationMilliseconds: 42
            ))
        )
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(name: "exec test", version: "1")
        try await fixture.server.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)

        let context: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.exec.rawValue,
            arguments: ["argv": ["make"]]
        )
        let response = try await context.value

        #expect(response.isError != true)
        #expect(response.structuredContent?.objectValue?["exitCode"]?.intValue == 17)
        #expect(response.structuredContent?.objectValue?["termination"]?.stringValue == "exited")
        #expect(response.structuredContent?.objectValue?["stdout"]?.stringValue == "masked output")
        #expect(response.structuredContent?.objectValue?["invocationID"]?.stringValue?.isEmpty == false)

        await client.disconnect()
        await fixture.server.waitUntilCompleted()
    }

    @Test("a concurrent execution returns busy without spawning")
    func concurrentExecutionIsBusy() async throws {
        let runner = ControllableRunner()
        let fixture = try makeServer(runner: runner)
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let transports = await InMemoryTransport.createConnectedPair()
        let client = Client(name: "exec test", version: "1")
        try await fixture.server.start(transport: transports.server)
        _ = try await client.connect(transport: transports.client)

        let first: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.exec.rawValue,
            arguments: ["argv": ["first"]]
        )
        await runner.waitUntilStarted()
        let second: RequestContext<CallTool.Result> = try await client.callTool(
            name: AuthsiaMCPToolName.exec.rawValue,
            arguments: ["argv": ["second"]]
        )
        let busy = try await second.value

        #expect(busy.isError == true)
        #expect(busy.structuredContent?.objectValue?["code"]?.stringValue == "busy")
        #expect(await runner.callCount == 1)

        await runner.finish()
        _ = try await first.value
        await client.disconnect()
        await fixture.server.waitUntilCompleted()
    }

    @Test("adapter timeout cancellation and launch failures are tool errors")
    func adapterFailuresAreToolErrors() async throws {
        let cases: [(MCPChildResult, String)] = [
            (
                MCPChildResult(
                    invocationID: UUID(),
                    exitCode: nil,
                    stdout: "",
                    stderr: "",
                    stdoutTruncated: false,
                    stderrTruncated: false,
                    cancelled: false,
                    timedOut: true,
                    durationMilliseconds: 1
                ),
                "timedOut"
            ),
            (
                MCPChildResult(
                    invocationID: UUID(),
                    exitCode: nil,
                    stdout: "",
                    stderr: "",
                    stdoutTruncated: false,
                    stderrTruncated: false,
                    cancelled: true,
                    timedOut: false,
                    durationMilliseconds: 1
                ),
                "cancelled"
            ),
            (
                MCPChildResult(
                    invocationID: UUID(),
                    exitCode: nil,
                    stdout: "",
                    stderr: "",
                    stdoutTruncated: false,
                    stderrTruncated: false,
                    cancelled: false,
                    timedOut: false,
                    durationMilliseconds: 1,
                    launchFailed: true
                ),
                "executionFailed"
            ),
            (
                MCPChildResult(
                    invocationID: UUID(),
                    exitCode: 1,
                    stdout: "",
                    stderr: "",
                    stdoutTruncated: false,
                    stderrTruncated: false,
                    cancelled: false,
                    timedOut: false,
                    durationMilliseconds: 1,
                    failureCode: .approvalDenied
                ),
                "approvalDenied"
            ),
        ]

        for (childResult, expectedCode) in cases {
            let fixture = try makeServer(runner: ImmediateRunner(result: childResult))
            defer { try? FileManager.default.removeItem(at: fixture.root) }
            let transports = await InMemoryTransport.createConnectedPair()
            let client = Client(name: "exec test", version: "1")
            try await fixture.server.start(transport: transports.server)
            _ = try await client.connect(transport: transports.client)

            let context: RequestContext<CallTool.Result> = try await client.callTool(
                name: AuthsiaMCPToolName.exec.rawValue,
                arguments: ["argv": ["synthetic-command"]]
            )
            let response = try await context.value

            #expect(response.isError == true)
            #expect(response.structuredContent?.objectValue?["code"]?.stringValue == expectedCode)
            #expect(
                response.structuredContent?.objectValue?["invocationID"]?.stringValue?.isEmpty == false
            )

            await client.disconnect()
            await fixture.server.waitUntilCompleted()
        }
    }

    private func makeServer(
        runner: any MCPChildRunning
    ) throws -> (server: AuthsiaMCPServer, root: URL) {
        let root = try makeWorkspaceRoot()
        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                workspace: .init(name: "exec", authsiaFolder: "Workspaces/exec"),
                managedEnvFiles: [],
                agents: nil
            ),
            toWorkspaceRoot: root
        )
        let runtime = MCPRuntimeContext(startingDirectory: root)
        let inspection = MCPWorkspaceInspectionService(
            runtimeContext: runtime,
            bridgeStateProvider: { .ready },
            selectionStore: WorkspaceEnvironmentSelectionStore(
                fileURL: root.appendingPathComponent("selection.json")
            )
        )
        return (
            AuthsiaMCPServer(
                version: "test",
                runtimeContext: runtime,
                workspaceInspection: inspection,
                grantService: MCPGrantService(
                    serverInstanceID: runtime.instanceID,
                    client: ExecToolGrantClient()
                ),
                childRunner: runner,
                mcpAccessEnabled: { true },
                diagnostics: { _ in }
            ),
            root
        )
    }
}

private struct ImmediateRunner: MCPChildRunning {
    let result: MCPChildResult

    func run(
        arguments: [String],
        invocation: MCPInvocationContext,
        timeoutSeconds: Int
    ) async -> MCPChildResult {
        MCPChildResult(
            invocationID: invocation.id,
            exitCode: result.exitCode,
            stdout: result.stdout,
            stderr: result.stderr,
            stdoutTruncated: result.stdoutTruncated,
            stderrTruncated: result.stderrTruncated,
            cancelled: result.cancelled,
            timedOut: result.timedOut,
            durationMilliseconds: result.durationMilliseconds,
            launchFailed: result.launchFailed,
            signalled: result.signalled,
            failureCode: result.failureCode
        )
    }
}

private final class ExecToolGrantClient: MCPGrantClient, @unchecked Sendable {
    func agentJITSnapshot(
        agentRuntimeContext: AgentRuntimeContext
    ) throws -> AgentJITGrantSnapshotPayload {
        .init(active: [], history: [])
    }

    func revokeAgentJITGrant(
        id: UUID,
        agentRuntimeContext: AgentRuntimeContext
    ) throws -> AgentJITGrantMutationPayload {
        .init(revokedGrantIDs: [id])
    }
}

private actor ControllableRunner: MCPChildRunning {
    private(set) var callCount = 0
    private var started = false
    private var startWaiters: [CheckedContinuation<Void, Never>] = []
    private var finishWaiters: [CheckedContinuation<Void, Never>] = []

    func run(
        arguments: [String],
        invocation: MCPInvocationContext,
        timeoutSeconds: Int
    ) async -> MCPChildResult {
        callCount += 1
        started = true
        startWaiters.forEach { $0.resume() }
        startWaiters.removeAll()
        await withCheckedContinuation { finishWaiters.append($0) }
        return MCPChildResult(
            invocationID: invocation.id,
            exitCode: 0,
            stdout: "",
            stderr: "",
            stdoutTruncated: false,
            stderrTruncated: false,
            cancelled: false,
            timedOut: false,
            durationMilliseconds: 1
        )
    }

    func waitUntilStarted() async {
        guard !started else { return }
        await withCheckedContinuation { startWaiters.append($0) }
    }

    func finish() {
        finishWaiters.forEach { $0.resume() }
        finishWaiters.removeAll()
    }
}
