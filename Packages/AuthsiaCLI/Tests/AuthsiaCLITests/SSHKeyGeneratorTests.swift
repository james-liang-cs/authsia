import Testing
import Foundation
import AuthenticatorCore
@testable import authsia

@Suite("SSHKeyGenerator")
struct SSHKeyGeneratorTests {

    // MARK: - Fake vault client

    final class FakeVaultClient: SSHKeyVaultClient, @unchecked Sendable {
        var existingNames: Set<String> = []
        var addSSHCalls: [AddSSHCall] = []
        var existsError: Error?
        var addError: Error?

        struct AddSSHCall {
            let name: String
            let publicKey: String
            let privateKey: String
            let comment: String
            let fingerprint: String
            let passphrase: String?
            let keyType: SSHKeyType
        }

        func sshKeyExists(named name: String) throws -> Bool {
            if let existsError { throw existsError }
            return existingNames.contains(name)
        }

        func addSSH(
            name: String,
            publicKey: String,
            privateKey: String,
            comment: String,
            fingerprint: String,
            passphrase: String?,
            keyType: SSHKeyType?,
            isScraped: Bool,
            folderPath: String?,
            scrapeMachineName: String?,
            scrapeMachineId: String?
        ) throws -> WriteResult {
            if let addError { throw addError }
            addSSHCalls.append(.init(
                name: name,
                publicKey: publicKey,
                privateKey: privateKey,
                comment: comment,
                fingerprint: fingerprint,
                passphrase: passphrase,
                keyType: keyType ?? .ed25519
            ))
            return WriteResult(id: UUID().uuidString, message: "ok")
        }
    }

    // MARK: - Helpers

    private func makeOutputDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sshgen-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    // MARK: - Validation

    @Test("rejects empty name")
    func rejectsEmptyName() throws {
        let dir = try makeOutputDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        #expect(throws: Error.self) {
            try SSHKeyGenerator.generate(
                name: "  ",
                directory: dir.path,
                type: "ed25519",
                bits: nil,
                vaultClient: FakeVaultClient(),
                keyGenInvocation: { _, _, _, _ in
                    Issue.record("keyGenInvocation must not be called when validation fails")
                }
            )
        }
    }

    @Test("rejects invalid key type")
    func rejectsInvalidType() throws {
        let dir = try makeOutputDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        #expect(throws: Error.self) {
            try SSHKeyGenerator.generate(
                name: "deploy",
                directory: dir.path,
                type: "dsa",
                bits: nil,
                vaultClient: FakeVaultClient(),
                keyGenInvocation: { _, _, _, _ in
                    Issue.record("keyGenInvocation must not be called when validation fails")
                }
            )
        }
    }

    @Test("rejects invalid RSA bit size")
    func rejectsInvalidRSABits() throws {
        let dir = try makeOutputDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        #expect(throws: Error.self) {
            try SSHKeyGenerator.generate(
                name: "corp",
                directory: dir.path,
                type: "rsa",
                bits: 1024,
                vaultClient: FakeVaultClient(),
                keyGenInvocation: { _, _, _, _ in
                    Issue.record("keyGenInvocation must not be called when validation fails")
                }
            )
        }
    }

    // MARK: - Preflight

    @Test("aborts when private key path already exists on disk")
    func abortsWhenPrivatePathExists() throws {
        let dir = try makeOutputDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let privatePath = dir.appendingPathComponent("deploy")
        try "leftover".write(to: privatePath, atomically: true, encoding: .utf8)

        var keyGenCalled = false
        let fake = FakeVaultClient()

        #expect(throws: Error.self) {
            try SSHKeyGenerator.generate(
                name: "deploy",
                directory: dir.path,
                type: "ed25519",
                bits: nil,
                vaultClient: fake,
                keyGenInvocation: { _, _, _, _ in keyGenCalled = true }
            )
        }
        #expect(keyGenCalled == false)
        #expect(fake.addSSHCalls.isEmpty)
    }

    @Test("aborts when public key path already exists on disk")
    func abortsWhenPublicPathExists() throws {
        let dir = try makeOutputDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let publicPath = dir.appendingPathComponent("deploy.pub")
        try "leftover".write(to: publicPath, atomically: true, encoding: .utf8)

        var keyGenCalled = false
        let fake = FakeVaultClient()

        #expect(throws: Error.self) {
            try SSHKeyGenerator.generate(
                name: "deploy",
                directory: dir.path,
                type: "ed25519",
                bits: nil,
                vaultClient: fake,
                keyGenInvocation: { _, _, _, _ in keyGenCalled = true }
            )
        }
        #expect(keyGenCalled == false)
        #expect(fake.addSSHCalls.isEmpty)
    }

    @Test("aborts when name already exists in vault")
    func abortsWhenNameExistsInVault() throws {
        let dir = try makeOutputDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        var keyGenCalled = false
        let fake = FakeVaultClient()
        fake.existingNames = ["deploy"]

        #expect(throws: Error.self) {
            try SSHKeyGenerator.generate(
                name: "deploy",
                directory: dir.path,
                type: "ed25519",
                bits: nil,
                vaultClient: fake,
                keyGenInvocation: { _, _, _, _ in keyGenCalled = true }
            )
        }
        #expect(keyGenCalled == false)
        #expect(fake.addSSHCalls.isEmpty)
        // Nothing left under the output directory
        #expect(FileManager.default.fileExists(atPath: dir.appendingPathComponent("deploy").path) == false)
        #expect(FileManager.default.fileExists(atPath: dir.appendingPathComponent("deploy.pub").path) == false)
    }

    @Test("propagates vault unavailable error")
    func propagatesVaultUnavailableError() throws {
        let dir = try makeOutputDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        struct Boom: Error {}
        var keyGenCalled = false
        let fake = FakeVaultClient()
        fake.existsError = Boom()

        #expect {
            try SSHKeyGenerator.generate(
                name: "deploy",
                directory: dir.path,
                type: "ed25519",
                bits: nil,
                vaultClient: fake,
                keyGenInvocation: { _, _, _, _ in keyGenCalled = true }
            )
        } throws: { error in
            guard case SSHKeyGenerator.GenerationError.vaultUnavailable = error else { return false }
            return true
        }
        #expect(keyGenCalled == false)
    }

    @Test("does not create the output directory when vault preflight aborts")
    func doesNotLeakDirectoryWhenVaultPreflightFails() throws {
        let parent = FileManager.default.temporaryDirectory
            .appendingPathComponent("sshgen-noleak-\(UUID().uuidString)", isDirectory: true)
        let nonExistentSubdir = parent.appendingPathComponent("new-sub-dir", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: parent) }

        let fake = FakeVaultClient()
        fake.existingNames = ["deploy"]  // forces vault preflight to fail

        #expect(throws: Error.self) {
            try SSHKeyGenerator.generate(
                name: "deploy",
                directory: nonExistentSubdir.path,
                type: "ed25519",
                bits: nil,
                vaultClient: fake,
                keyGenInvocation: { _, _, _, _ in
                    Issue.record("keyGenInvocation must not be called when preflight fails")
                }
            )
        }

        // The non-existent subdir must NOT have been created as a side effect of the failed preflight
        #expect(FileManager.default.fileExists(atPath: nonExistentSubdir.path) == false)
        #expect(FileManager.default.fileExists(atPath: parent.path) == false)
    }

    // MARK: - Happy path

    private static let fakeEd25519KeyData = "AAAAC3NzaC1lZDI1NTE5AAAAIAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    private func writeFakeKeypair(at stem: URL, type: String) throws {
        // Private key — opaque bytes; the helper does not parse this.
        try "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEPRIVATEKEYBYTES\n-----END OPENSSH PRIVATE KEY-----\n"
            .write(to: stem, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: stem.path)

        let pubLine: String
        switch type {
        case "ed25519":
            pubLine = "ssh-ed25519 \(Self.fakeEd25519KeyData) authsia:test\n"
        case "rsa":
            pubLine = "ssh-rsa \(Self.fakeEd25519KeyData) authsia:test\n"
        default:
            pubLine = "ssh-unknown \(Self.fakeEd25519KeyData) authsia:test\n"
        }
        let pubURL = stem.deletingLastPathComponent()
            .appendingPathComponent(stem.lastPathComponent + ".pub")
        try pubLine.write(to: pubURL, atomically: true, encoding: .utf8)
    }

    @Test("happy path stores in vault, writes pub and stub, wipes temp dir")
    func happyPathStoresAndWritesLeftovers() throws {
        let dir = try makeOutputDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let fake = FakeVaultClient()
        var observedTempStem: URL?

        let returnedPath = try SSHKeyGenerator.generate(
            name: "deploy",
            directory: dir.path,
            type: "ed25519",
            bits: nil,
            vaultClient: fake,
            keyGenInvocation: { stem, type, _, _ in
                observedTempStem = stem
                try self.writeFakeKeypair(at: stem, type: type)
            }
        )

        // Returned path is the user's intended private key location
        #expect(returnedPath == dir.appendingPathComponent("deploy").path)

        // Vault was called once with correct shape
        #expect(fake.addSSHCalls.count == 1)
        let call = try #require(fake.addSSHCalls.first)
        #expect(call.name == "deploy")
        #expect(call.comment == "authsia:deploy")
        #expect(call.passphrase == nil)
        #expect(call.publicKey.contains("ssh-ed25519"))
        #expect(call.publicKey.contains(Self.fakeEd25519KeyData))
        #expect(call.privateKey.contains("BEGIN OPENSSH PRIVATE KEY"))
        #expect(call.fingerprint.hasPrefix("SHA256:"))
        #expect(call.keyType == .ed25519)

        // Public key file exists at user path with 0644
        let publicPath = dir.appendingPathComponent("deploy.pub").path
        #expect(FileManager.default.fileExists(atPath: publicPath))
        let publicAttrs = try FileManager.default.attributesOfItem(atPath: publicPath)
        #expect((publicAttrs[.posixPermissions] as? Int) == 0o644)
        let publicContent = try String(contentsOfFile: publicPath, encoding: .utf8)
        #expect(publicContent.contains("ssh-ed25519"))

        // Stub file exists at user path with 0600 and Authsia comment
        let stubPath = dir.appendingPathComponent("deploy").path
        #expect(FileManager.default.fileExists(atPath: stubPath))
        let stubAttrs = try FileManager.default.attributesOfItem(atPath: stubPath)
        #expect((stubAttrs[.posixPermissions] as? Int) == 0o600)
        let stubContent = try String(contentsOfFile: stubPath, encoding: .utf8)
        #expect(stubContent.contains("This SSH key is managed by Authsia"))
        #expect(stubContent.contains("eval \"$(authsia init zsh)\""))
        #expect(stubContent.contains("authsia load ssh") == false)
        #expect(stubContent.contains("BEGIN OPENSSH PRIVATE KEY") == false) // not the real key

        // Temp dir was wiped — observedTempStem's parent should not exist
        let tempParent = try #require(observedTempStem).deletingLastPathComponent()
        #expect(FileManager.default.fileExists(atPath: tempParent.path) == false)
    }

    // MARK: - Failure paths

    @Test("keygen failure wipes temp dir and leaves no leftovers")
    func keygenFailureWipesAndLeavesNoLeftovers() throws {
        let dir = try makeOutputDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        struct KeygenBoom: Error {}
        let fake = FakeVaultClient()
        var observedTempStem: URL?

        #expect {
            try SSHKeyGenerator.generate(
                name: "deploy",
                directory: dir.path,
                type: "ed25519",
                bits: nil,
                vaultClient: fake,
                keyGenInvocation: { stem, _, _, _ in
                    observedTempStem = stem
                    throw KeygenBoom()
                }
            )
        } throws: { error in
            guard case SSHKeyGenerator.GenerationError.keyGenFailed = error else { return false }
            return true
        }

        #expect(fake.addSSHCalls.isEmpty)
        let tempParent = try #require(observedTempStem).deletingLastPathComponent()
        #expect(FileManager.default.fileExists(atPath: tempParent.path) == false)
        #expect(FileManager.default.fileExists(atPath: dir.appendingPathComponent("deploy").path) == false)
        #expect(FileManager.default.fileExists(atPath: dir.appendingPathComponent("deploy.pub").path) == false)
    }

    @Test("vault store failure wipes temp dir and leaves no leftovers")
    func storeFailureWipesAndLeavesNoLeftovers() throws {
        let dir = try makeOutputDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        struct StoreBoom: Error {}
        let fake = FakeVaultClient()
        fake.addError = StoreBoom()
        var observedTempStem: URL?

        #expect {
            try SSHKeyGenerator.generate(
                name: "deploy",
                directory: dir.path,
                type: "ed25519",
                bits: nil,
                vaultClient: fake,
                keyGenInvocation: { stem, type, _, _ in
                    observedTempStem = stem
                    try self.writeFakeKeypair(at: stem, type: type)
                }
            )
        } throws: { error in
            guard case SSHKeyGenerator.GenerationError.storeFailed = error else { return false }
            return true
        }

        #expect(fake.addSSHCalls.isEmpty)
        let tempParent = try #require(observedTempStem).deletingLastPathComponent()
        #expect(FileManager.default.fileExists(atPath: tempParent.path) == false)
        #expect(FileManager.default.fileExists(atPath: dir.appendingPathComponent("deploy").path) == false)
        #expect(FileManager.default.fileExists(atPath: dir.appendingPathComponent("deploy.pub").path) == false)
    }

    // MARK: - RSA branch

    @Test("rsa branch passes type and bits through and stores via same flow")
    func rsaBranch() throws {
        let dir = try makeOutputDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let fake = FakeVaultClient()
        var observedType: String?
        var observedBits: Int?

        _ = try SSHKeyGenerator.generate(
            name: "corp",
            directory: dir.path,
            type: "rsa",
            bits: 2048,
            vaultClient: fake,
            keyGenInvocation: { stem, type, bits, _ in
                observedType = type
                observedBits = bits
                try self.writeFakeKeypair(at: stem, type: type)
            }
        )

        #expect(observedType == "rsa")
        #expect(observedBits == 2048)
        #expect(fake.addSSHCalls.count == 1)
        let call = try #require(fake.addSSHCalls.first)
        #expect(call.publicKey.contains("ssh-rsa"))
        #expect(call.comment == "authsia:corp")
        #expect(call.keyType == .rsa2048)
        #expect(FileManager.default.fileExists(atPath: dir.appendingPathComponent("corp.pub").path))
        #expect(FileManager.default.fileExists(atPath: dir.appendingPathComponent("corp").path))
    }
}
