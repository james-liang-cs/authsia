import Testing
import Foundation
@testable import authsia

@Suite("MachineIdentity")
struct MachineIdentityTests {

    @Test("displayName strips .local suffix")
    func displayNameStripsLocal() {
        let id = MachineIdentity(
            machineId: UUID().uuidString,
            hostname: "Example-MacBook.local"
        )
        #expect(id.displayName == "Example-MacBook")
    }

    @Test("displayName preserves name without .local")
    func displayNameNoLocal() {
        let id = MachineIdentity(
            machineId: UUID().uuidString,
            hostname: "corp-laptop-42"
        )
        #expect(id.displayName == "corp-laptop-42")
    }

    @Test("load creates and persists a new identity when file absent")
    func loadCreatesNewIdentity() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let id1 = MachineIdentity.load(from: tempDir)
        let id2 = MachineIdentity.load(from: tempDir)

        #expect(id1.machineId == id2.machineId)
        #expect(!id1.machineId.isEmpty)
    }

    @Test("load returns same UUID on second call")
    func loadReturnsSameUUID() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let id1 = MachineIdentity.load(from: tempDir)
        let id2 = MachineIdentity.load(from: tempDir)

        #expect(id1.machineId == id2.machineId)
    }

    @Test("load writes machine.json with 0o600 permissions")
    func filePermissions() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        _ = MachineIdentity.load(from: tempDir)

        let fileURL = tempDir.appendingPathComponent("machine.json")
        let attrs = try FileManager.default.attributesOfItem(atPath: fileURL.path)
        let perms = attrs[.posixPermissions] as? Int
        #expect(perms == 0o600)
    }

    @Test("load recovers from corrupted machine.json")
    func recoversFromCorruptedFile() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Write corrupted JSON
        let fileURL = tempDir.appendingPathComponent("machine.json")
        try "not valid json {{{".write(to: fileURL, atomically: true, encoding: .utf8)

        // Should recover and return a valid identity
        let identity = MachineIdentity.load(from: tempDir)
        #expect(!identity.machineId.isEmpty)
        #expect(!identity.hostname.isEmpty)
    }
}
