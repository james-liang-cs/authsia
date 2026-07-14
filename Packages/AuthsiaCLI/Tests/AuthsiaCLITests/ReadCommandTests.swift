import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
@testable import authsia

@Suite("Read command")
struct ReadCommandTests {

    @Test("parseAndValidate accepts valid URI")
    func parseValid() throws {
        let ref = try ReadCmd.parseAndValidate("authsia://password/GitHub/password")
        #expect(ref.type == .password)
        #expect(ref.item == "GitHub")
        #expect(ref.field == "password")
    }

    @Test("parseAndValidate accepts URI without field")
    func parseWithoutField() throws {
        let ref = try ReadCmd.parseAndValidate("authsia://note/MyNote")
        #expect(ref.type == .note)
        #expect(ref.item == "MyNote")
        #expect(ref.field == nil)
    }

    @Test("help covers API key URI type and field")
    func helpCoversAPIKeyURITypeAndField() {
        let help = ReadCmd.helpMessage(columns: 160)

        #expect(help.contains("password, api-key, cert, note, ssh, otp"))
        #expect(help.contains("password/key/certificate/content/privateKey/code"))
        #expect(help.contains("authsia read \"authsia://api-key/Stripe/key\""))
        #expect(help.contains("export API_KEY=$(authsia read \"authsia://api-key/Stripe/key\")"))
    }

    @Test("parseAndValidate rejects non-URI input")
    func rejectNonURI() {
        #expect(throws: (any Error).self) {
            try ReadCmd.parseAndValidate("just-a-name")
        }
    }

    @Test("parseAndValidate rejects wrong scheme")
    func rejectWrongScheme() {
        #expect(throws: (any Error).self) {
            try ReadCmd.parseAndValidate("op://vault/item/field")
        }
    }

    @Test("parseAndValidate rejects unknown type")
    func rejectUnknownType() {
        #expect(throws: (any Error).self) {
            try ReadCmd.parseAndValidate("authsia://database/MySQL/password")
        }
    }

    @Test("writeToFile creates file with 0600 permissions")
    func writeFile() throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("read-test-\(UUID().uuidString).txt").path
        defer { try? FileManager.default.removeItem(atPath: path) }

        try ReadCmd.writeToFile(value: "secret-content", path: path)

        let content = try String(contentsOfFile: path, encoding: .utf8)
        #expect(content == "secret-content")

        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        let perms = (attrs[.posixPermissions] as? NSNumber)?.int16Value
        #expect(perms == 0o600)
    }

    @Test("writeToFile creates parent directories if needed")
    func writeFileCreatesDirectories() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("read-test-dir-\(UUID().uuidString)")
        let path = dir.appendingPathComponent("subdir/secret.pem").path
        defer { try? FileManager.default.removeItem(at: dir) }

        try ReadCmd.writeToFile(value: "pem-content", path: path)
        #expect(FileManager.default.fileExists(atPath: path))
    }

    @Test("writeToFile refuses symlink output paths")
    func writeFileRejectsSymlink() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("read-test-link-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let target = dir.appendingPathComponent("target.txt").path
        let link = dir.appendingPathComponent("secret.txt").path
        try "existing".write(toFile: target, atomically: true, encoding: .utf8)
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)

        #expect(throws: (any Error).self) {
            try ReadCmd.writeToFile(value: "plaintext", path: link)
        }

        let targetContent = try String(contentsOfFile: target, encoding: .utf8)
        #expect(targetContent == "existing")
    }

    @Test("read rejects when credential omits .read")
    func readRejectsWithoutReadCapability() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "read-cap")
        defer { try? FileManager.default.removeItem(at: directory) }

        let credential = try Access.createCredential(
            name: "exec-only",
            scope: "Team/API",
            ttl: "15m",
            store: store,
            machineIdentity: MachineIdentity(machineId: "m", hostname: "h"),
            now: now,
            allowedCommands: [.exec]
        )
        let payload = BridgeListPayload(accounts: [], passwords: [], certificates: [], notes: [], sshKeys: [])
        let ref = try ReadCmd.parseAndValidate("authsia://password/AnyName/password")

        do {
            try ReadCmd.authorizeAutomationAccess(
                ref: ref,
                payload: payload,
                environment: [AutomationAccessResolver.environmentKey: credential.id.uuidString],
                store: store,
                now: now.addingTimeInterval(60),
                currentMachineId: "m"
            )
            Issue.record("expected ValidationError")
        } catch let error as ValidationError {
            #expect(String(describing: error).contains("does not permit 'read'"))
        } catch {
            Issue.record("expected ValidationError, got \(error)")
        }
    }
}
