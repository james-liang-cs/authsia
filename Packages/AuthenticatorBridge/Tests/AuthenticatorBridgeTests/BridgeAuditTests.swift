import XCTest
@testable import AuthenticatorBridge

final class BridgeAuditTests: XCTestCase {
    func testAuditRecordSerialization() throws {
        let record = BridgeAuditRecord(command: .getOTP, itemId: "id", approvedBy: "biometric", timestamp: Date())
        let data = try BridgeCoder.encode(record)
        let decoded = try BridgeCoder.decode(BridgeAuditRecord.self, from: data)
        XCTAssertEqual(decoded.command, .getOTP)
    }

    func testCallerIdentitySerialization() throws {
        let caller = CallerIdentity(
            pid: 1234,
            processName: "authsia",
            bundleIdentifier: nil,
            signingTeamId: "ABC123",
            signingIdentity: "Developer ID Application: Test"
        )
        let data = try BridgeCoder.encode(caller)
        let decoded = try BridgeCoder.decode(CallerIdentity.self, from: data)
        XCTAssertEqual(decoded.pid, 1234)
        XCTAssertEqual(decoded.processName, "authsia")
        XCTAssertNil(decoded.bundleIdentifier)
        XCTAssertEqual(decoded.signingTeamId, "ABC123")
        XCTAssertEqual(decoded.signingIdentity, "Developer ID Application: Test")
    }

    func testAuditRecordWithCallerSerialization() throws {
        let caller = CallerIdentity(
            pid: 5678,
            processName: "authsia",
            bundleIdentifier: nil,
            signingTeamId: nil,
            signingIdentity: nil
        )
        let record = BridgeAuditRecord(
            command: .getOTP,
            itemId: "test-id",
            approvedBy: "session",
            timestamp: Date(),
            caller: caller
        )
        let data = try BridgeCoder.encode(record)
        let decoded = try BridgeCoder.decode(BridgeAuditRecord.self, from: data)
        XCTAssertEqual(decoded.caller?.pid, 5678)
        XCTAssertEqual(decoded.caller?.processName, "authsia")
    }

    func testAuditRecordWithoutCallerBackwardCompat() throws {
        let record = BridgeAuditRecord(
            command: .getOTP,
            itemId: "test-id",
            approvedBy: "biometric",
            timestamp: Date()
        )
        let data = try BridgeCoder.encode(record)
        let decoded = try BridgeCoder.decode(BridgeAuditRecord.self, from: data)
        XCTAssertNil(decoded.caller)
        XCTAssertNil(decoded.requestedCommand)
        XCTAssertNil(decoded.fullCommand)
    }

    func testAuditRecordWithRequestedCommandSerialization() throws {
        let record = BridgeAuditRecord(
            command: .getPassword,
            itemId: "test-id",
            approvedBy: "automation",
            timestamp: Date(),
            requestedCommand: "exec"
        )
        let data = try BridgeCoder.encode(record)
        let decoded = try BridgeCoder.decode(BridgeAuditRecord.self, from: data)
        XCTAssertEqual(decoded.requestedCommand, "exec")
    }

    func testAuditRecordWithFullCommandSerialization() throws {
        let record = BridgeAuditRecord(
            command: .getPassword,
            itemId: "test-id",
            approvedBy: "automation",
            timestamp: Date(),
            requestedCommand: "exec",
            fullCommand: "authsia exec password SERVICE_ENDPOINT -- npm start"
        )
        let data = try BridgeCoder.encode(record)
        let decoded = try BridgeCoder.decode(BridgeAuditRecord.self, from: data)
        XCTAssertEqual(decoded.fullCommand, "authsia exec password SERVICE_ENDPOINT -- npm start")
    }

    func testAuditRecordWithAgentJITGrantIDSerialization() throws {
        let grantID = UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!
        let record = BridgeAuditRecord(
            command: .getPassword,
            itemId: "test-id",
            approvedBy: "jit",
            timestamp: Date(),
            requestedCommand: "exec",
            agentJITGrantID: grantID
        )

        let data = try BridgeCoder.encode(record)
        let decoded = try BridgeCoder.decode(BridgeAuditRecord.self, from: data)

        XCTAssertEqual(decoded.agentJITGrantID, grantID)
    }

    func testAuditRecordWithAgentRuntimeContextSerialization() throws {
        let record = BridgeAuditRecord(
            command: .getPassword,
            itemId: "test-id",
            approvedBy: "jit",
            timestamp: Date(),
            requestedCommand: "exec",
            agentRuntimeContext: AgentRuntimeContext(
                platform: "codex",
                sessionID: "session-1",
                turnID: "turn-1",
                agentID: "agent-1",
                agentType: "reviewer",
                toolUseID: "tool-1"
            )
        )

        let data = try BridgeCoder.encode(record)
        let decoded = try BridgeCoder.decode(BridgeAuditRecord.self, from: data)

        XCTAssertEqual(decoded.agentRuntimeContext?.platform, "codex")
        XCTAssertEqual(decoded.agentRuntimeContext?.agentType, "reviewer")
    }

    func testAuditRecordWithWorkspaceContextSerialization() throws {
        let record = BridgeAuditRecord(
            command: .getPassword,
            itemId: "test-id",
            approvedBy: "jit",
            timestamp: Date(),
            requestedCommand: "exec",
            workspaceContext: WorkspaceRuntimeContext(
                name: "selected-api",
                rootLabel: "api",
                authsiaFolder: "Workspaces/selected-api"
            )
        )

        let data = try BridgeCoder.encode(record)
        let decoded = try BridgeCoder.decode(BridgeAuditRecord.self, from: data)

        XCTAssertEqual(decoded.workspaceContext?.name, "selected-api")
        XCTAssertEqual(decoded.workspaceContext?.rootLabel, "api")
        XCTAssertEqual(decoded.workspaceContext?.authsiaFolder, "Workspaces/selected-api")
        XCTAssertEqual(decoded.workspaceContext?.displayName, "selected-api (api)")
    }

    func testAuditRecordWithEnvironmentScopeSerialization() throws {
        let record = BridgeAuditRecord(
            command: .getPassword,
            itemId: "test-id",
            approvedBy: "jit",
            timestamp: Date(),
            requestedCommand: "exec",
            environmentScope: .named("Production")
        )

        let data = try BridgeCoder.encode(record)
        let decoded = try BridgeCoder.decode(BridgeAuditRecord.self, from: data)

        XCTAssertEqual(decoded.environmentScope, .named("Production"))
    }

    func testAuditRecordMissingAgentJITGrantIDDecodesNil() throws {
        let json = """
        {
          "command": "getPassword",
          "itemId": "test-id",
          "approvedBy": "session",
          "timestamp": "2026-06-13T10:00:00Z",
          "requestedCommand": "get"
        }
        """

        let decoded = try BridgeCoder.decode(BridgeAuditRecord.self, from: Data(json.utf8))

        XCTAssertNil(decoded.agentJITGrantID)
        XCTAssertNil(decoded.agentRuntimeContext)
        XCTAssertNil(decoded.fullCommand)
        XCTAssertNil(decoded.workspaceContext)
    }

    func testAuditRecordWithSSHAgentInfoSerialization() throws {
        let peer = SSHAgentProcessRef(pid: 42, name: "ssh", path: "/usr/bin/ssh")
        let instigator = SSHAgentProcessRef(pid: 41, name: "git", path: "/usr/bin/git")
        let sshAgent = SSHAgentAuditInfo(
            peer: peer,
            instigator: instigator,
            ancestry: [peer, instigator],
            targetHost: "github.com"
        )
        let record = BridgeAuditRecord(
            command: .sshAgentSign,
            itemId: "key-id",
            itemName: "github.key",
            approvedBy: "biometric",
            timestamp: Date(),
            sshAgent: sshAgent
        )

        let data = try BridgeCoder.encode(record)
        let decoded = try BridgeCoder.decode(BridgeAuditRecord.self, from: data)

        XCTAssertEqual(decoded.command, .sshAgentSign)
        XCTAssertEqual(decoded.sshAgent?.peer?.name, "ssh")
        XCTAssertEqual(decoded.sshAgent?.instigator?.name, "git")
        XCTAssertEqual(decoded.sshAgent?.ancestry.map(\.name), ["ssh", "git"])
        XCTAssertEqual(decoded.sshAgent?.targetHost, "github.com")
    }
}
