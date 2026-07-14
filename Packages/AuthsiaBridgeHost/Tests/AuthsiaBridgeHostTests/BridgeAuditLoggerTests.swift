import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge
import CryptoKit

final class BridgeAuditLoggerTests: XCTestCase {
    func testWritesChainedTamperEvidentAuditEntries() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent("bridge_audit.log")
        let logger = makeLogger(fileURL: fileURL)
        let record1 = BridgeAuditRecord(command: .getOTP, itemId: "item-1", approvedBy: "biometric", timestamp: Date())
        let record2 = BridgeAuditRecord(command: .getPassword, itemId: "item-2", approvedBy: "session", timestamp: Date())

        try logger.record(record1)
        try logger.record(record2)

        let data = try Data(contentsOf: fileURL)
        let lines = String(decoding: data, as: UTF8.self).split(separator: "\n")
        XCTAssertEqual(lines.count, 2)

        let first = try decodeAuditLine(from: Data(lines[0].utf8))
        let second = try decodeAuditLine(from: Data(lines[1].utf8))

        XCTAssertEqual(first.record.itemId, "item-1")
        XCTAssertEqual(second.record.itemId, "item-2")
        XCTAssertNil(first.previousHash)
        XCTAssertEqual(second.previousHash, first.entryHash)
        XCTAssertTrue(try logger.verifyIntegrity())
    }

    func testVerifyIntegrityDetectsTamperedEntry() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent("bridge_audit.log")
        let logger = makeLogger(fileURL: fileURL)

        try logger.record(BridgeAuditRecord(command: .getOTP, itemId: "item-1", approvedBy: "biometric", timestamp: Date()))
        var content = try String(contentsOf: fileURL, encoding: .utf8)
        content = content.replacingOccurrences(of: "item-1", with: "item-x")
        try content.write(to: fileURL, atomically: true, encoding: .utf8)

        XCTAssertFalse(try logger.verifyIntegrity())
    }

    func testRecordsWithRequestedCommandRoundTrip() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent("bridge_audit.log")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let logger = makeLogger(fileURL: fileURL)

        try logger.record(BridgeAuditRecord(
            command: .getPassword,
            itemId: "item-1",
            approvedBy: "automation",
            timestamp: Date(),
            requestedCommand: "exec"
        ))

        XCTAssertTrue(try logger.verifyIntegrity())

        let data = try Data(contentsOf: fileURL)
        let lines = data.split(separator: 0x0A)
        XCTAssertEqual(lines.count, 1)
        let entry = try decodeAuditLine(from: Data(lines[0]))
        XCTAssertEqual(entry.record.requestedCommand, "exec")
    }

    func testLoadRecordsReturnsAuditRecordsInTimestampOrder() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent("bridge_audit.log")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let logger = makeLogger(fileURL: fileURL)
        let older = Date(timeIntervalSince1970: 1_700_000_000)
        let newer = older.addingTimeInterval(60)

        try logger.record(BridgeAuditRecord(command: .getPassword, itemId: "newer", approvedBy: "jit", timestamp: newer))
        try logger.record(BridgeAuditRecord(command: .getPassword, itemId: "older", approvedBy: "session", timestamp: older))

        let records = try logger.loadRecords()

        XCTAssertEqual(records.map(\.itemId), ["older", "newer"])
    }

    func testLoadRecordsCanLimitRecentRecordsSinceDate() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent("bridge_audit.log")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let logger = makeLogger(fileURL: fileURL)
        let now = Date(timeIntervalSince1970: 1_700_000_000)

        for index in 0..<5 {
            try logger.record(BridgeAuditRecord(
                command: .getPassword,
                itemId: "item-\(index)",
                approvedBy: "session",
                timestamp: now.addingTimeInterval(TimeInterval(index * 60))
            ))
        }

        let records = try logger.loadRecords(limit: 2, since: now.addingTimeInterval(60))

        XCTAssertEqual(records.map(\.itemId), ["item-3", "item-4"])
    }

    func testMigratesLegacyV6EntriesToCurrentVersion() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent("bridge_audit.log")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let logger = makeLogger(fileURL: fileURL)
        try logger.record(BridgeAuditRecord(
            command: .getPassword,
            itemId: "item-1",
            approvedBy: "session",
            timestamp: Date(),
            requestedCommand: "get",
            agentJITGrantID: UUID(uuidString: "11111111-2222-3333-4444-555555555555")
        ))
        let currentEntry = try decodeOnlyAuditLine(from: fileURL)
        try writeAuditLine(
            AuditLineFixture(
                version: 6,
                record: currentEntry.record,
                previousHash: currentEntry.previousHash,
                entryHash: currentEntry.entryHash
            ),
            to: fileURL
        )

        XCTAssertTrue(try logger.verifyIntegrity())

        let migratedData = try Data(contentsOf: fileURL)
        let migratedLines = migratedData.split(separator: 0x0A)
        XCTAssertEqual(migratedLines.count, 1)
        let migratedEntry = try decodeAuditLine(from: Data(migratedLines[0]))
        XCTAssertEqual(migratedEntry.version, 10)
        XCTAssertEqual(migratedEntry.record.itemId, "item-1")
        XCTAssertEqual(migratedEntry.record.agentJITGrantID, UUID(uuidString: "11111111-2222-3333-4444-555555555555"))
        XCTAssertNil(migratedEntry.record.agentRuntimeContext)
    }

    func testMigratesLegacyV9EntriesToCurrentVersion() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent("bridge_audit.log")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let logger = makeLogger(fileURL: fileURL)
        try logger.record(BridgeAuditRecord(
            command: .getPassword,
            itemId: "item-1",
            approvedBy: "jit",
            timestamp: Date(),
            requestedCommand: "exec"
        ))
        let currentEntry = try decodeOnlyAuditLine(from: fileURL)
        try writeAuditLine(
            AuditLineFixture(
                version: 9,
                record: currentEntry.record,
                previousHash: currentEntry.previousHash,
                entryHash: currentEntry.entryHash
            ),
            to: fileURL
        )

        XCTAssertTrue(try logger.verifyIntegrity())

        let migratedEntry = try decodeOnlyAuditLine(from: fileURL)
        XCTAssertEqual(migratedEntry.version, 10)
        XCTAssertNil(migratedEntry.record.environmentScope)
    }

    func testRejectsTamperedLegacyV6EntriesBeforeMigration() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent("bridge_audit.log")
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let logger = makeLogger(fileURL: fileURL)
        try logger.record(BridgeAuditRecord(
            command: .getPassword,
            itemId: "item-1",
            approvedBy: "session",
            timestamp: Date(),
            requestedCommand: "get",
            agentJITGrantID: UUID(uuidString: "11111111-2222-3333-4444-555555555555")
        ))
        let currentEntry = try decodeOnlyAuditLine(from: fileURL)
        let tamperedRecord = BridgeAuditRecord(
            command: currentEntry.record.command,
            itemId: "item-tampered",
            itemName: currentEntry.record.itemName,
            approvedBy: currentEntry.record.approvedBy,
            timestamp: currentEntry.record.timestamp,
            caller: currentEntry.record.caller,
            requestedCommand: currentEntry.record.requestedCommand,
            fullCommand: currentEntry.record.fullCommand,
            agentJITGrantID: currentEntry.record.agentJITGrantID,
            agentRuntimeContext: nil,
            workspaceContext: currentEntry.record.workspaceContext,
            sshAgent: currentEntry.record.sshAgent
        )
        try writeAuditLine(
            AuditLineFixture(
                version: 6,
                record: tamperedRecord,
                previousHash: currentEntry.previousHash,
                entryHash: currentEntry.entryHash
            ),
            to: fileURL
        )

        XCTAssertFalse(try logger.verifyIntegrity())
    }

    func testAuditLogFileIsCreatedWithStrictPermissions() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent("bridge_audit.log")
        let logger = makeLogger(fileURL: fileURL)

        try logger.record(BridgeAuditRecord(command: .getOTP, itemId: "item-1", approvedBy: "biometric", timestamp: Date()))

        let attributes = try FileManager.default.attributesOfItem(atPath: fileURL.path)
        let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0
        XCTAssertEqual(mode & 0o777, 0o600)
    }

    private func makeLogger(fileURL: URL) -> BridgeAuditLogger {
        BridgeAuditLogger(
            fileURL: fileURL,
            hmacKeyProvider: { SymmetricKey(data: Data(repeating: 0xA5, count: 32)) }
        )
    }

    private func decodeAuditLine(from data: Data) throws -> AuditLineFixture {
        try JSONDecoder.bridge.decode(AuditLineFixture.self, from: data)
    }

    private func decodeOnlyAuditLine(from fileURL: URL) throws -> AuditLineFixture {
        let data = try Data(contentsOf: fileURL)
        let lines = data.split(separator: 0x0A)
        XCTAssertEqual(lines.count, 1)
        return try decodeAuditLine(from: Data(lines[0]))
    }

    private func writeAuditLine(_ entry: AuditLineFixture, to fileURL: URL) throws {
        var line = try JSONEncoder.bridge.encode(entry)
        line.append(0x0A)
        try line.write(to: fileURL)
    }
}

private struct AuditLineFixture: Codable {
    let version: Int
    let record: BridgeAuditRecord
    let previousHash: String?
    let entryHash: String
}
