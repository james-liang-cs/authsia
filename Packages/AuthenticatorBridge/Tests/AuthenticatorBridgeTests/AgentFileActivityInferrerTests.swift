import XCTest
@testable import AuthenticatorBridge

final class AgentFileActivityInferrerTests: XCTestCase {
    func testInfersReadPathsFromAllowlistedCommands() {
        let grantID = UUID()
        let command = AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 100),
            agentPlatform: "codex",
            agentJITGrantID: grantID,
            captureSource: .process,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys001:sid:1",
            executable: "cat",
            arguments: ["cat", ".env", "README.md"],
            command: "cat .env README.md",
            exitStatus: 0
        )

        let events = AgentFileActivityInferrer.events(from: [command])

        XCTAssertEqual(events.count, 2)
        XCTAssertTrue(events.allSatisfy { $0.captureSource == .command })
        XCTAssertTrue(events.allSatisfy { $0.confidence == .inferred })
        XCTAssertTrue(events.allSatisfy { $0.action == .read })
        XCTAssertTrue(events.allSatisfy { $0.agentJITGrantID == grantID })
        XCTAssertEqual(
            Set(events.map(\.path)),
            Set(["/tmp/project/.env", "/tmp/project/README.md"])
        )
    }

    func testDoesNotDuplicateNearbyHookFileEvents() {
        let grantID = UUID()
        let command = AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 100),
            agentPlatform: "claude-code",
            agentJITGrantID: grantID,
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            executable: "cat",
            arguments: ["cat", "Secrets/token"],
            command: "cat Secrets/token",
            exitStatus: 0
        )
        let existing = AgentFileActivityEvent(
            recordedAt: Date(timeIntervalSince1970: 101),
            agentPlatform: "claude-code",
            agentJITGrantID: grantID,
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project/Secrets/token",
            kind: .file,
            action: .read,
            status: .succeeded,
            confidence: .direct
        )

        let events = AgentFileActivityInferrer.events(
            from: [command],
            existingFileEvents: [existing]
        )

        XCTAssertTrue(events.isEmpty)
    }

    func testIgnoresCommandsWithoutPathLikeArguments() {
        let command = AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 100),
            agentPlatform: "codex",
            captureSource: .process,
            workingDirectory: "/tmp/project",
            executable: "npm",
            arguments: ["npm", "test"],
            command: "npm test",
            exitStatus: 0
        )

        XCTAssertTrue(AgentFileActivityInferrer.events(from: [command]).isEmpty)
    }

    func testMergingAppendsInferredEvents() {
        let command = AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 100),
            agentPlatform: "codex",
            agentJITGrantID: UUID(),
            captureSource: .injectedTree,
            workingDirectory: "/tmp/project",
            executable: "rm",
            arguments: ["rm", "-f", "./build/tmp.txt"],
            command: "rm -f ./build/tmp.txt",
            exitStatus: 0
        )
        let existing = AgentFileActivityEvent(
            recordedAt: Date(timeIntervalSince1970: 50),
            agentPlatform: "codex",
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project/README.md",
            kind: .file,
            action: .read,
            status: .succeeded,
            confidence: .direct
        )

        let merged = AgentFileActivityInferrer.merging(commands: [command], fileEvents: [existing])

        XCTAssertEqual(merged.count, 2)
        XCTAssertEqual(merged.last?.action, .delete)
        XCTAssertEqual(merged.last?.path, "/tmp/project/build/tmp.txt")
        XCTAssertEqual(merged.last?.captureSource, .command)
    }

    func testInferredEventIDsAreStableAcrossCalls() {
        let command = AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 100),
            agentPlatform: "codex",
            agentJITGrantID: UUID(uuidString: "11111111-1111-1111-1111-111111111111"),
            captureSource: .process,
            workingDirectory: "/tmp/project",
            executable: "cat",
            arguments: ["cat", ".env"],
            command: "cat .env",
            exitStatus: 0
        )

        let first = AgentFileActivityInferrer.events(from: [command])
        let second = AgentFileActivityInferrer.events(from: [command])

        XCTAssertEqual(first.map(\.id), second.map(\.id))
        XCTAssertEqual(first.first?.path, "/tmp/project/.env")
    }
}
