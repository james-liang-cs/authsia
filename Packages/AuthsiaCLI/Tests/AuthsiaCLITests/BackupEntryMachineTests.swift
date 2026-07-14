// Tests/AuthsiaCLITests/BackupEntryMachineTests.swift
import Testing
import Foundation
@testable import authsia

@Suite("BackupEntry machine identity")
struct BackupEntryMachineTests {

    @Test("BackupEntry encodes hostname and machineId")
    func encodesIdentity() throws {
        let entry = BackupService.BackupEntry(
            id: UUID().uuidString,
            originalPath: "/Users/example/.zshrc",
            folderPath: nil,
            backupNoteId: "note-123",
            backupNoteName: "authsia_backup_zshrc_20260315_143022",
            timestamp: Date(),
            description: "test",
            fileHash: "abc123",
            isRestored: false,
            hostname: "Example-MacBook.local",
            machineId: "AAAABBBB-1234-5678-ABCD-123456789012"
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(entry)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(BackupService.BackupEntry.self, from: data)
        #expect(decoded.hostname == "Example-MacBook.local")
        #expect(decoded.machineId == "AAAABBBB-1234-5678-ABCD-123456789012")
    }

    @Test("BackupEntry decodes legacy entry without hostname gracefully")
    func decodesLegacyEntry() throws {
        let legacyJSON = """
        {
            "id": "some-uuid",
            "originalPath": "/Users/example/.zshrc",
            "backupNoteName": "authsia_backup_zshrc_20260101_120000",
            "timestamp": "2026-01-01T12:00:00Z",
            "description": "old backup",
            "fileHash": "abc123",
            "isRestored": false
        }
        """
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let entry = try decoder.decode(BackupService.BackupEntry.self, from: Data(legacyJSON.utf8))
        #expect(entry.hostname == nil)
        #expect(entry.machineId == nil)
        #expect(entry.folderPath == nil)
        #expect(entry.backupNoteId == nil)
    }

    @Test("BackupEntry infers ssh adoption kind for legacy entries")
    func infersSSHAdoptionKindForLegacyEntry() throws {
        let legacyJSON = """
        {
            "id": "some-uuid",
            "originalPath": "/Users/example/.ssh/id_ed25519",
            "backupNoteName": "authsia_backup_id_ed25519_20260101_120000",
            "timestamp": "2026-01-01T12:00:00Z",
            "description": "Before authsia ssh adopt",
            "fileHash": "abc123",
            "isRestored": false
        }
        """
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let entry = try decoder.decode(BackupService.BackupEntry.self, from: Data(legacyJSON.utf8))
        #expect(entry.kind == .sshAdoption)
    }

    @Test("displayMachine returns displayName when hostname present")
    func displayMachineWithHostname() {
        let entry = BackupService.BackupEntry(
            id: UUID().uuidString,
            originalPath: "/tmp/test",
            folderPath: nil,
            backupNoteId: nil,
            backupNoteName: "test",
            timestamp: Date(),
            description: "",
            fileHash: "x",
            isRestored: false,
            hostname: "My-Mac.local",
            machineId: UUID().uuidString
        )
        #expect(entry.displayMachine == "My-Mac")
    }

    @Test("displayMachine returns 'legacy backup' when hostname nil")
    func displayMachineLegacyFallback() {
        let entry = BackupService.BackupEntry(
            id: UUID().uuidString,
            originalPath: "/tmp/test",
            folderPath: nil,
            backupNoteId: nil,
            backupNoteName: "test",
            timestamp: Date(),
            description: "",
            fileHash: "x",
            isRestored: false,
            hostname: nil,
            machineId: nil
        )
        #expect(entry.displayMachine == "legacy backup")
    }
}
