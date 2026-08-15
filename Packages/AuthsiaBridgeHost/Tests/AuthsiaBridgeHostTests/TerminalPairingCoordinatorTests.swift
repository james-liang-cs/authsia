#if os(macOS)
import XCTest
import AuthenticatorBridge
@testable import AuthsiaBridgeHost

@MainActor
final class TerminalPairingCoordinatorTests: XCTestCase {
    func testGeneratedCodesUseFourUnambiguousCharacters() {
        for _ in 0..<100 {
            let code = TerminalPairingCoordinator.generateCode()
            XCTAssertEqual(code.count, 4)
            XCTAssertTrue(code.allSatisfy(TerminalPairingCoordinator.codeAlphabet.contains))
            XCTAssertFalse(code.contains("0"))
            XCTAssertFalse(code.contains("O"))
            XCTAssertFalse(code.contains("1"))
            XCTAssertFalse(code.contains("I"))
        }
    }

    func testExpiryAndSecondWrongAttemptInvalidatePendingPairing() throws {
        let workspace = try makeWorkspace()
        defer { try? FileManager.default.removeItem(at: workspace) }
        let now = Date(timeIntervalSince1970: 10_000)
        let coordinator = TerminalPairingCoordinator(codeProvider: { "7K9M" })

        var pending = begin(coordinator, workspace: workspace.path, now: now)
        XCTAssertTrue(coordinator.markLocallyApproved(id: pending.id))
        XCTAssertEqual(
            complete(coordinator, id: pending.id, code: "NOPE", workspace: workspace, now: now),
            .retryRemaining
        )
        XCTAssertEqual(
            complete(coordinator, id: pending.id, code: "NOPE", workspace: workspace, now: now),
            .invalid
        )
        XCTAssertNil(coordinator.pendingRequest(id: pending.id))

        pending = begin(coordinator, workspace: workspace.path, now: now)
        XCTAssertTrue(coordinator.markLocallyApproved(id: pending.id))
        XCTAssertEqual(
            complete(
                coordinator,
                id: pending.id,
                code: "7K9M",
                workspace: workspace,
                now: now.addingTimeInterval(61)
            ),
            .invalid
        )
    }

    func testSecondRequestSupersedesFirstWithoutOldCodeInvalidatingNewRequest() throws {
        let workspace = try makeWorkspace()
        defer { try? FileManager.default.removeItem(at: workspace) }
        let now = Date(timeIntervalSince1970: 20_000)
        var codes = ["ABCD", "7K9M"]
        let coordinator = TerminalPairingCoordinator(codeProvider: { codes.removeFirst() })

        let first = begin(coordinator, workspace: workspace.path, now: now)
        let secondResult = coordinator.begin(
            workspaceRoot: workspace.path,
            coversSubfolders: false,
            controllingTerminal: "ttys004",
            anchorShellPID: 41,
            anchorShellStartTime: 100,
            fullCommand: "/usr/local/bin/authsia get password deploy",
            now: now
        )
        XCTAssertEqual(secondResult.supersededID, first.id)
        XCTAssertTrue(coordinator.markLocallyApproved(id: secondResult.request.id))

        XCTAssertEqual(
            complete(coordinator, id: first.id, code: "ABCD", workspace: workspace, now: now),
            .invalid
        )
        guard case .paired(let pairing) = complete(
            coordinator,
            id: secondResult.request.id,
            code: "7K9M",
            workspace: workspace,
            now: now
        ) else {
            return XCTFail("expected the replacement pairing to remain valid")
        }
        XCTAssertEqual(pairing.controllingTerminal, "ttys004")
        XCTAssertEqual(pairing.workspaceRoot, workspace.path)
    }

    private func begin(
        _ coordinator: TerminalPairingCoordinator,
        workspace: String,
        now: Date
    ) -> TerminalPairingApprovalRequest {
        coordinator.begin(
            workspaceRoot: workspace,
            coversSubfolders: false,
            controllingTerminal: "ttys004",
            anchorShellPID: 41,
            anchorShellStartTime: 100,
            fullCommand: "/usr/local/bin/authsia get password deploy",
            now: now
        ).request
    }

    private func complete(
        _ coordinator: TerminalPairingCoordinator,
        id: UUID,
        code: String,
        workspace: URL,
        now: Date
    ) -> TerminalPairingCompletionResult {
        coordinator.complete(
            id: id,
            code: code,
            request: BridgeRequest(
                id: UUID(),
                type: .terminalPairingComplete,
                query: "",
                options: BridgeOptions(field: nil, copy: false),
                context: BridgeContext(
                    isTTY: true,
                    isPiped: false,
                    isSSH: false,
                    isCI: false,
                    timestamp: now,
                    requestedCommand: "get password deploy",
                    sessionScope: "tty:/dev/ttys004:sid:40",
                    workingDirectory: workspace.path,
                    workspaceAuthorityPath: workspace.path
                )
            ),
            callerIdentity: caller,
            pairingTTL: 300,
            now: now,
            processStartTime: { _ in 100 }
        )
    }

    private var caller: CallerIdentity {
        let shell = ParentProcessInfo(
            pid: 41,
            processName: "zsh",
            bundleIdentifier: nil,
            startTimeSeconds: 100
        )
        return CallerIdentity(
            pid: 42,
            processName: "authsia",
            bundleIdentifier: "app.authsia.cli",
            signingTeamId: "TEAM",
            signingIdentity: "Developer ID Application",
            parentProcess: shell,
            hostProcess: ParentProcessInfo(
                pid: 40,
                processName: "Code Helper",
                bundleIdentifier: "com.microsoft.VSCode"
            ),
            controllingTerminal: "ttys004",
            shellAncestryPrefix: [shell],
            hostCommand: "/usr/local/bin/authsia get password deploy"
        )
    }

    private func makeWorkspace() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-pairing-coordinator-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url.resolvingSymlinksInPath().standardizedFileURL
    }
}
#endif
