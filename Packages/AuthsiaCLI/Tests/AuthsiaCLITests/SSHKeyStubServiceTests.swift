// Tests/AuthsiaCLITests/SSHKeyStubServiceTests.swift
import Testing
import Foundation
@testable import authsia

struct SSHKeyStubServiceTests {

    // MARK: - stubPrivateKeyFile

    @Test func stubReplacesContentWithStub() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        let keyPath = tmp.appendingPathComponent("id_ed25519").path
        try FileManager.default.createDirectory(atPath: tmp.path, withIntermediateDirectories: true)
        try "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n"
            .write(toFile: keyPath, atomically: true, encoding: .utf8)

        try SSHKeyStubService.stubPrivateKeyFile(at: keyPath, keyName: "deploy")

        let content = try String(contentsOfFile: keyPath, encoding: .utf8)
        #expect(content.contains("managed by Authsia"))
        #expect(content.contains("eval \"$(authsia init zsh)\""))
        #expect(!content.contains("authsia load ssh"))
        #expect(!content.contains("PRIVATE KEY"))
    }

    @Test func stubPreservesPermissions() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        let keyPath = tmp.appendingPathComponent("id_rsa").path
        try FileManager.default.createDirectory(atPath: tmp.path, withIntermediateDirectories: true)
        try "secret".write(toFile: keyPath, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyPath)

        try SSHKeyStubService.stubPrivateKeyFile(at: keyPath, keyName: "deploy")

        let attrs = try FileManager.default.attributesOfItem(atPath: keyPath)
        let perms = attrs[.posixPermissions] as? Int
        #expect(perms == 0o600)
    }

    @Test func stubMissingFileThrows() {
        #expect(throws: (any Error).self) {
            try SSHKeyStubService.stubPrivateKeyFile(at: "/nonexistent/id_ed25519", keyName: "x")
        }
    }

    @Test("stubPrivateKeyFile creates file with explicit permissions when missing")
    func test_stubPrivateKeyFile_createsFileWithExplicitPermissions() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("stub-create-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let keyPath = directory.appendingPathComponent("brand-new-key").path
        #expect(FileManager.default.fileExists(atPath: keyPath) == false)

        try SSHKeyStubService.stubPrivateKeyFile(
            at: keyPath,
            keyName: "deploy",
            permissions: 0o600
        )

        #expect(FileManager.default.fileExists(atPath: keyPath))
        let attrs = try FileManager.default.attributesOfItem(atPath: keyPath)
        #expect((attrs[.posixPermissions] as? Int) == 0o600)
        let content = try String(contentsOfFile: keyPath, encoding: .utf8)
        #expect(content.contains("This SSH key is managed by Authsia"))
        #expect(content.contains("eval \"$(authsia init zsh)\""))
    }

    // MARK: - annotateSSHConfig

    @Test func annotateInsertsCommentAboveIdentityFile() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        let configPath = tmp.appendingPathComponent("config").path
        try FileManager.default.createDirectory(atPath: tmp.path, withIntermediateDirectories: true)

        let original = "Host work\n    IdentityFile ~/.ssh/id_ed25519\n    User james\n"
        try original.write(toFile: configPath, atomically: true, encoding: .utf8)

        SSHKeyStubService.annotateSSHConfig(
            at: configPath,
            forKeyPath: "~/.ssh/id_ed25519",
            keyName: "WorkKey"
        )

        let result = try String(contentsOfFile: configPath, encoding: .utf8)
        #expect(result.contains("Key managed by Authsia"))
        #expect(result.contains("built-in Authsia agent"))
        #expect(result.contains("IdentityFile ~/.ssh/id_ed25519"))

        let commentRange = result.range(of: "Key managed by Authsia")!
        let identityRange = result.range(of: "IdentityFile ~/.ssh/id_ed25519")!
        #expect(commentRange.lowerBound < identityRange.lowerBound)
    }

    @Test func annotateNoMatchingIdentityFileNoChange() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        let configPath = tmp.appendingPathComponent("config").path
        try FileManager.default.createDirectory(atPath: tmp.path, withIntermediateDirectories: true)

        let original = "Host work\n    IdentityFile ~/.ssh/id_other\n"
        try original.write(toFile: configPath, atomically: true, encoding: .utf8)

        SSHKeyStubService.annotateSSHConfig(
            at: configPath,
            forKeyPath: "~/.ssh/id_ed25519",
            keyName: "WorkKey"
        )

        let result = try String(contentsOfFile: configPath, encoding: .utf8)
        #expect(result == original)
    }

    @Test func annotateMissingConfigFileNoThrow() {
        // Should silently skip if .ssh/config doesn't exist
        SSHKeyStubService.annotateSSHConfig(
            at: "/nonexistent/.ssh/config",
            forKeyPath: "~/.ssh/id_ed25519",
            keyName: "x"
        )
    }

    @Test func annotateIdempotentNoDuplicateComment() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        let configPath = tmp.appendingPathComponent("config").path
        try FileManager.default.createDirectory(atPath: tmp.path, withIntermediateDirectories: true)

        let original = "Host work\n    # Key managed by Authsia — served by built-in Authsia agent\n    IdentityFile ~/.ssh/id_ed25519\n"
        try original.write(toFile: configPath, atomically: true, encoding: .utf8)

        SSHKeyStubService.annotateSSHConfig(
            at: configPath,
            forKeyPath: "~/.ssh/id_ed25519",
            keyName: "WorkKey"
        )

        let result = try String(contentsOfFile: configPath, encoding: .utf8)
        let count = result.components(separatedBy: "Key managed by Authsia").count - 1
        #expect(count == 1, "Comment should not be inserted twice")
    }

    @Test func annotateIdempotentWithBlankLineBeforeIdentityFile() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        let configPath = tmp.appendingPathComponent("config").path
        try FileManager.default.createDirectory(atPath: tmp.path, withIntermediateDirectories: true)

        // Authsia comment, blank line, then IdentityFile
        let original = "Host work\n    # Key managed by Authsia — served by built-in Authsia agent\n\n    IdentityFile ~/.ssh/id_ed25519\n"
        try original.write(toFile: configPath, atomically: true, encoding: .utf8)

        SSHKeyStubService.annotateSSHConfig(
            at: configPath,
            forKeyPath: "~/.ssh/id_ed25519",
            keyName: "WorkKey"
        )

        let result = try String(contentsOfFile: configPath, encoding: .utf8)
        let count = result.components(separatedBy: "Key managed by Authsia").count - 1
        #expect(count == 1, "Comment should not be inserted twice even with blank line gap")
    }
}
