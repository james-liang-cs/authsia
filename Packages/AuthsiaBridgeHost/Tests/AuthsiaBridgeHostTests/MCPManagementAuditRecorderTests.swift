import XCTest
import CryptoKit
import AuthenticatorBridge
@testable import AuthsiaBridgeHost

final class MCPManagementAuditRecorderTests: XCTestCase {
    func testManagementEventsJoinExistingChainAndTamperingFailsVerification() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("audit.log")
        let key = SymmetricKey(size: .bits256)
        let logger = BridgeAuditLogger(fileURL: file, hmacKeyProvider: { key })
        try logger.record(.init(command: .ping, itemId: "fixture", approvedBy: "fixture", timestamp: Date()))
        let journal = MCPManagementAuditStore(fileURL: root.appendingPathComponent("journal.jsonl"))
        let recorder = MCPManagementAuditRecorder(audit: logger, journal: journal)
        let operation = UUID()
        for (phase, result) in [("intent", "pending"), ("outcome", "applied")] {
            try recorder.record(.init(operationID: operation, kind: "policy", phase: phase,
                summary: "Synthetic fixture policy", result: result))
        }
        XCTAssertTrue(try logger.verifyIntegrity())
        let records = try logger.loadRecords()
        XCTAssertEqual(records.count, 3)
        XCTAssertEqual(records.last?.mcpManagementEvent?.operationID, operation)
        XCTAssertEqual(records.last?.mcpManagementEvent?.result, "applied")
        XCTAssertEqual(try journal.load().count, 2)
        let text = try String(contentsOf: file, encoding: .utf8)
        try text.replacingOccurrences(of: "Synthetic fixture policy", with: "Altered fixture policy").write(to: file, atomically: true, encoding: .utf8)
        XCTAssertFalse(try logger.verifyIntegrity())
    }
    func testFailedCanonicalAuditDoesNotWriteProjection() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let logger = BridgeAuditLogger(fileURL: root.appendingPathComponent("audit.log"), hmacKeyProvider: { throw MCPManagementError.auditUnavailable })
        let journal = MCPManagementAuditStore(fileURL: root.appendingPathComponent("journal.jsonl"))
        XCTAssertThrowsError(try MCPManagementAuditRecorder(audit: logger, journal: journal).record(
            .init(operationID: UUID(), kind: "wrap", phase: "intent", summary: "Synthetic fixture", result: "pending")))
        XCTAssertTrue(try journal.load().isEmpty)
    }
    @MainActor
    func testManagementAuditRejectsNonAppCaller() async {
        let handler = XPCRequestHandler(approver: AuditTestApprover(), callerIdentityProvider: {
            CallerIdentity(pid: 42, processName: "fixture", bundleIdentifier: "fixture.untrusted", signingTeamId: nil, signingIdentity: nil)
        })
        let reply = expectation(description: "rejected")
        handler.mcpManagementRecordActivity(Data()) { data, error in
            XCTAssertNil(data); XCTAssertNotNil(error); reply.fulfill()
        }
        await fulfillment(of: [reply], timeout: 2)
    }
}
@MainActor
private final class AuditTestApprover: BridgeApprover {
    func requestApproval(prompt: String, command: BridgeRequestType, itemLabel: String?, field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?, remoteRequests: [RemoteJITApprovalRequest]) async -> RemoteJITApprovalOutcome {
        XCTFail("Audit must not request vault approval")
        return .denied(source: .macPanel)
    }
}
