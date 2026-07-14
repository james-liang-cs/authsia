import Foundation
import ArgumentParser
import Testing
@testable import authsia

@Suite("SSH command")
struct SSHCommandTests {

    @Test("ssh adopt parses revert all with optional machine")
    func sshAdoptParsesRevertAllWithMachine() throws {
        let command = try SSH.Adopt.parse(["--revert-all", "--machine", "james-macbook"])

        #expect(command.revertAll)
        #expect(command.machine == "james-macbook")
        #expect(command.revert == nil)
    }

    @Test("ssh adopt rejects conflicting revert options")
    func sshAdoptRejectsConflictingRevertOptions() throws {
        let command = try SSH.Adopt.parse(["--revert", "~/.ssh/id_ed25519", "--revert-all"])

        #expect(throws: ValidationError.self) {
            try command.validateRevertOptions()
        }
    }

    @Test("ssh adopt rejects machine outside revert mode")
    func sshAdoptRejectsMachineOutsideRevertMode() throws {
        let command = try SSH.Adopt.parse(["--machine", "james-macbook"])

        #expect(throws: ValidationError.self) {
            try command.validateRevertOptions()
        }
    }

    @Test("ssh adopt revert normalizes relative paths")
    func sshAdoptRevertNormalizesRelativePaths() {
        let path = SSH.Adopt.normalizedRevertPath(
            "id_ed25519",
            currentDirectoryPath: "/Users/example/Projects/ExampleProject",
            homeDirectoryPath: "/Users/example",
            fileExists: { $0 == "/Users/example/Projects/ExampleProject/id_ed25519" }
        )

        #expect(path == "/Users/example/Projects/ExampleProject/id_ed25519")
    }

    @Test("ssh adopt revert treats bare missing key name as default ssh file")
    func sshAdoptRevertTreatsBareMissingKeyNameAsDefaultSSHFile() {
        let path = SSH.Adopt.normalizedRevertPath(
            "id_ed25519",
            currentDirectoryPath: "/Users/example/Projects/ExampleProject",
            homeDirectoryPath: "/Users/example",
            fileExists: { _ in false }
        )

        #expect(path == "/Users/example/.ssh/id_ed25519")
    }

    @Test("ssh adopt summary counts existing vault keys as adopted")
    func sshAdoptSummaryCountsExistingVaultKeysAsAdopted() {
        let summary = SSHAdoptionService.AdoptionSummary(added: 0, managedExisting: 1, skipped: 0)

        let output = SSH.Adopt.renderAdoptionSummary(summary, alreadyManaged: 1)

        #expect(output == "Adopted 1 SSH key for Authsia management. Replaced 1 local key already in the vault. Skipped 0. Already managed 1.")
    }

    @Test("upsertHostEntry creates a config block with authsia guidance")
    func upsertHostEntryCreatesBlock() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ssh-config-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let configPath = directory.appendingPathComponent("config").path
        try SSHConfigWriter.upsertHostEntry(
            host: "github.com",
            keyName: "WorkKey",
            configPath: configPath
        )

        let output = try String(contentsOfFile: configPath, encoding: .utf8)
        #expect(output.contains("Host github.com"))
        #expect(output.contains("IdentityAgent"))
        #expect(output.contains("built-in Authsia agent"))
    }

    @Test("upsertHostEntry supports aliases hostname and username")
    func upsertHostEntrySupportsAliasAndUser() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ssh-config-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let configPath = directory.appendingPathComponent("config").path
        try SSHConfigWriter.upsertHostEntry(
            entry: .init(
                host: "github-work",
                hostname: "github.com",
                user: "git",
                keyName: "WorkKey"
            ),
            configPath: configPath
        )

        let output = try String(contentsOfFile: configPath, encoding: .utf8)
        #expect(output.contains("Host github-work"))
        #expect(output.contains("HostName github.com"))
        #expect(output.contains("User git"))
        #expect(output.contains("built-in Authsia agent"))
    }

    @Test("upsertHostEntry is idempotent for the same host")
    func upsertHostEntryIsIdempotent() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ssh-config-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let configPath = directory.appendingPathComponent("config").path
        try SSHConfigWriter.upsertHostEntry(host: "github.com", keyName: "WorkKey", configPath: configPath)
        try SSHConfigWriter.upsertHostEntry(host: "github.com", keyName: "WorkKey", configPath: configPath)

        let output = try String(contentsOfFile: configPath, encoding: .utf8)
        let count = output.components(separatedBy: "Host github.com").count - 1
        #expect(count == 1)
    }

    @Test("git signing setup writes repo-local config and allowed signers file")
    func gitSigningSetupWritesRepoLocalConfigAndAllowedSigners() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("git-signing-\(UUID().uuidString)", isDirectory: true)
        let repoURL = directory.appendingPathComponent("repo", isDirectory: true)
        let gitDirectoryURL = repoURL.appendingPathComponent(".git", isDirectory: true)
        try FileManager.default.createDirectory(at: gitDirectoryURL, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let publicKeyURL = directory.appendingPathComponent("work.pub")
        try "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey work@example.com\n"
            .write(to: publicKeyURL, atomically: true, encoding: .utf8)

        let result = try GitSigningConfigWriter.configure(
            repositoryPath: repoURL.path,
            principal: "dev@example.com",
            publicKeyPath: publicKeyURL.path
        )

        let config = try String(contentsOf: gitDirectoryURL.appendingPathComponent("config"), encoding: .utf8)
        let allowedSigners = try String(contentsOf: result.allowedSignersURL, encoding: .utf8)

        #expect(config.contains("[gpg]"))
        #expect(config.contains("format = ssh"))
        #expect(config.contains("[commit]"))
        #expect(config.contains("gpgsign = true"))
        #expect(config.contains("[tag]"))
        #expect(config.contains("[user]"))
        #expect(config.contains("signingkey = \(publicKeyURL.path)"))
        #expect(config.contains("[gpg \"ssh\"]"))
        #expect(config.contains("allowedSignersFile = \(result.allowedSignersURL.path)"))
        #expect(allowedSigners.contains("dev@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey work@example.com"))
    }

    @Test("git signing setup rejects repositories without a git directory")
    func gitSigningSetupRejectsMissingGitDirectory() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("git-signing-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let publicKeyURL = directory.appendingPathComponent("work.pub")
        try "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey work@example.com\n"
            .write(to: publicKeyURL, atomically: true, encoding: .utf8)

        #expect(throws: Error.self) {
            _ = try GitSigningConfigWriter.configure(
                repositoryPath: directory.path,
                principal: "dev@example.com",
                publicKeyPath: publicKeyURL.path
            )
        }
    }
}
