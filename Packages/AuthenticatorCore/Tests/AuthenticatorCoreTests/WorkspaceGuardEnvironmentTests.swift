import Foundation
import XCTest
@testable import AuthenticatorCore

final class WorkspaceGuardEnvironmentTests: XCTestCase {
    func testUnguardedEnvironmentUsesAnyGuardStateAndKeepsWorkspaceContext() {
        let unguarded = WorkspaceGuardEnvironment.unguardedEnvironment([
            "PATH": "/tmp/authsia-guard-NEW:/usr/bin:/bin",
            "HOME": "/Users/example",
            "AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH": "/tmp/authsia-guard-OLD:/usr/bin:/bin",
            "AUTHSIA_WORKSPACE_ROOT": "/tmp/My Project",
        ])

        XCTAssertEqual(unguarded["PATH"], "/usr/bin:/bin")
        XCTAssertEqual(unguarded["HOME"], "/Users/example")
        XCTAssertEqual(unguarded["AUTHSIA_WORKSPACE_ROOT"], "/tmp/My Project")
        XCTAssertNil(unguarded["AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH"])
    }

    func testUnguardedChildCommandCleansStaleGuardStateAndKeepsWorkspaceContext() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = [
            "-c",
            WorkspaceGuardEnvironment.unguardedChildShellCommand(
                agentPlatform: "codex",
                command: "/usr/bin/env"
            ),
        ]
        process.environment = [
            "PATH": "/tmp/authsia-guard-NEW:/usr/bin:/bin",
            "AUTHSIA_WORKSPACE_GUARD": "1",
            "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": "/tmp/authsia-guard-NEW",
            "AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH": "/tmp/authsia-guard-OLD:/usr/bin:/bin",
            "AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION": "1",
            "AUTHSIA_WORKSPACE_ROOT": "/tmp/My Project",
        ]
        let output = Pipe()
        process.standardOutput = output

        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let lines = (String(data: data, encoding: .utf8) ?? "")
            .split(separator: "\n")
            .map(String.init)

        XCTAssertEqual(process.terminationStatus, 0)
        XCTAssertTrue(lines.contains("PATH=/usr/bin:/bin"))
        XCTAssertTrue(lines.contains("AUTHSIA_WORKSPACE_ROOT=/tmp/My Project"))
        XCTAssertTrue(lines.contains("AUTHSIA_AGENT_PLATFORM=codex"))
        XCTAssertTrue(lines.contains("AUTHSIA_AGENT_INVOKES_AUTHSIA=1"))
        XCTAssertFalse(lines.contains { $0.hasPrefix("AUTHSIA_WORKSPACE_GUARD") })
    }
}
