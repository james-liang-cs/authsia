import Testing
import Foundation
import AuthenticatorCore
@testable import authsia

@Suite("SSHAdoptionService")
struct SSHAdoptionServiceTests {
    private static let fakeKeyData = "AAAAC3NzaC1lZDI1NTE5AAAAIAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    @Test("discovers private keys and host bindings for dry run")
    func discoversCandidatesAndHostBindings() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ssh-adopt-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let privateKeyPath = directory.appendingPathComponent("id_ed25519").path
        let publicKeyPath = directory.appendingPathComponent("id_ed25519.pub").path
        let configPath = directory.appendingPathComponent("config").path

        try "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n"
            .write(toFile: privateKeyPath, atomically: true, encoding: .utf8)
        try "ssh-ed25519 \(Self.fakeKeyData) github-work\n"
            .write(toFile: publicKeyPath, atomically: true, encoding: .utf8)
        try """
        Host github-work
            HostName github.com
            User git
            IdentityFile \(privateKeyPath)

        Host ignored
            IdentityFile ~/.ssh/id_other
        """.write(toFile: configPath, atomically: true, encoding: .utf8)

        let candidates = try SSHAdoptionService.discover(path: directory.path, configPath: configPath)

        let candidate = try #require(candidates.first)
        #expect(candidates.count == 1)
        #expect(candidate.keyName == "id_ed25519")
        #expect(candidate.privateKeyPath == privateKeyPath)
        #expect(candidate.publicKeyPath == publicKeyPath)
        #expect(candidate.boundHosts == ["github.com"])
        #expect(candidate.hostBindings.map(\.host) == ["github-work"])
        #expect(candidate.hostBindings.map(\.user) == ["git"])
    }

    @Test("discovers host bindings when ssh config uses tabs")
    func discoversHostBindingsWithTabs() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ssh-adopt-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let privateKeyPath = directory.appendingPathComponent("id_ed25519").path
        let publicKeyPath = directory.appendingPathComponent("id_ed25519.pub").path
        let configPath = directory.appendingPathComponent("config").path

        try "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n"
            .write(toFile: privateKeyPath, atomically: true, encoding: .utf8)
        try "ssh-ed25519 \(Self.fakeKeyData) github-work\n"
            .write(toFile: publicKeyPath, atomically: true, encoding: .utf8)
        try """
        Host\tgithub-work
        \tHostName\tgithub.com
        \tUser\tgit
        \tIdentityFile\t\(privateKeyPath)
        """.write(toFile: configPath, atomically: true, encoding: .utf8)

        let candidates = try SSHAdoptionService.discover(path: directory.path, configPath: configPath)

        let candidate = try #require(candidates.first)
        #expect(candidate.boundHosts == ["github.com"])
        #expect(candidate.hostBindings.map(\.host) == ["github-work"])
        #expect(candidate.hostBindings.map(\.user) == ["git"])
    }

    @Test("discovers nonstandard private key filenames with matching public keys")
    func discoversNonstandardPrivateKeyFilenames() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ssh-adopt-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let privateKeyPath = directory.appendingPathComponent("test").path
        let publicKeyPath = directory.appendingPathComponent("test.pub").path
        let knownHostsPath = directory.appendingPathComponent("known_hosts").path

        try "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n"
            .write(toFile: privateKeyPath, atomically: true, encoding: .utf8)
        try "ssh-ed25519 \(Self.fakeKeyData) test-key\n"
            .write(toFile: publicKeyPath, atomically: true, encoding: .utf8)
        try "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAknownhosts\n"
            .write(toFile: knownHostsPath, atomically: true, encoding: .utf8)

        let candidates = try SSHAdoptionService.discover(path: directory.path, configPath: nil)

        let candidate = try #require(candidates.first)
        #expect(candidates.count == 1)
        #expect(candidate.keyName == "test")
        #expect(candidate.privateKeyPath == privateKeyPath)
        #expect(candidate.publicKeyPath == publicKeyPath)
        #expect(candidate.metadata.comment == "test-key")
    }

    @Test("discovers legacy RSA private keys without matching public key files")
    func discoversLegacyRSAPrivateKeysWithoutMatchingPublicKeyFiles() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ssh-adopt-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let privateKeyPath = directory.appendingPathComponent("id_rsa").path
        try Self.generateLegacyRSAKey(at: privateKeyPath, comment: "rsa-work")
        try FileManager.default.removeItem(atPath: "\(privateKeyPath).pub")

        let privateKey = try String(contentsOfFile: privateKeyPath, encoding: .utf8)
        let candidates = try SSHAdoptionService.discover(path: directory.path, configPath: nil)
        let candidate = try #require(candidates.first)

        #expect(candidates.count == 1)
        #expect(privateKey.contains("BEGIN RSA PRIVATE KEY"))
        #expect(candidate.keyName == "id_rsa")
        #expect(candidate.privateKeyPath == privateKeyPath)
        #expect(candidate.metadata.publicKey.hasPrefix("ssh-rsa "))
        #expect(candidate.metadata.comment == "id_rsa")
        #expect(candidate.metadata.keyType == .rsa2048)
    }

    @Test("reports Authsia-managed stubs as already adopted")
    func reportsManagedStubsAsAlreadyAdopted() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ssh-adopt-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let privateKeyPath = directory.appendingPathComponent("test").path
        let publicKeyPath = directory.appendingPathComponent("test.pub").path

        try """
        # This SSH key is managed by Authsia.
        # Migrated: 2026-04-30
        # Served by the built-in Authsia agent.
        # Shell setup: eval "$(authsia init zsh)"
        """.write(toFile: privateKeyPath, atomically: true, encoding: .utf8)
        try "ssh-ed25519 \(Self.fakeKeyData) test-key\n"
            .write(toFile: publicKeyPath, atomically: true, encoding: .utf8)

        let result = try SSHAdoptionService.inspect(path: directory.path, configPath: nil)
        let output = SSHAdoptionService.renderDryRun(
            candidates: result.candidates,
            managedStubPaths: result.managedStubPaths
        )

        #expect(result.candidates.isEmpty)
        #expect(result.managedStubPaths == [privateKeyPath])
        #expect(output.contains("Already managed by Authsia"))
        #expect(output.contains(privateKeyPath))
    }

    @Test("dry run output names the built-in agent setup")
    func dryRunOutputNamesBuiltInAgentSetup() throws {
        let candidate = SSHAdoptionService.Candidate(
            keyName: "id_ed25519",
            privateKeyPath: "/Users/example/.ssh/id_ed25519",
            publicKeyPath: "/Users/example/.ssh/id_ed25519.pub",
            metadata: .init(
                publicKey: "ssh-ed25519 \(Self.fakeKeyData) github-work",
                comment: "github-work",
                fingerprint: "SHA256:test",
                keyType: .ed25519
            ),
            hostBindings: [
                .init(host: "github-work", hostName: "github.com", user: "git")
            ]
        )

        let output = SSHAdoptionService.renderDryRun(candidates: [candidate])

        #expect(output.contains("Would adopt 1 SSH key"))
        #expect(output.contains("github-work -> github.com"))
        #expect(output.contains("eval \"$(authsia init zsh)\""))
        #expect(output.contains("authsia load ssh") == false)
    }

    @Test("existing matching vault key stubs local private key without duplicating a backup note")
    func existingMatchingVaultKeyStubsLocalPrivateKeyWithoutBackup() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ssh-adopt-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let privateKeyPath = directory.appendingPathComponent("deploy").path
        let publicKey = "ssh-ed25519 \(Self.fakeKeyData) deploy"
        let metadata = try SSHKeyMetadataResolver.parsePublicKeyLine(publicKey, fallbackComment: "deploy")
        let privateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n"
        try privateKey
            .write(toFile: privateKeyPath, atomically: true, encoding: .utf8)

        let client = RecordingAdoptionClient(existingKeys: [
            "deploy": .init(publicKey: publicKey, fingerprint: metadata.fingerprint, privateKey: privateKey)
        ])
        let backupService = RecordingAdoptionBackupService()
        let candidate = SSHAdoptionService.Candidate(
            keyName: "deploy",
            privateKeyPath: privateKeyPath,
            publicKeyPath: "\(privateKeyPath).pub",
            metadata: metadata,
            hostBindings: []
        )

        let summary = try await SSHAdoptionService.adopt(
            candidates: [candidate],
            client: client,
            backupService: backupService,
            folderPath: nil,
            configPath: directory.appendingPathComponent("config").path
        )

        let fileContent = try String(contentsOfFile: privateKeyPath, encoding: .utf8)
        let backups = await backupService.backups
        #expect(summary.added == 0)
        #expect(summary.managedExisting == 1)
        #expect(summary.adopted == 1)
        #expect(summary.skipped == 0)
        #expect(client.addedKeys.isEmpty)
        #expect(backups.isEmpty)
        #expect(fileContent.contains("This SSH key is managed by Authsia"))
        #expect(!fileContent.contains("BEGIN OPENSSH PRIVATE KEY"))
    }

    @Test("same-name key in different folder does not block adoption")
    func sameNameKeyInDifferentFolderDoesNotBlockAdoption() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ssh-adopt-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let privateKeyPath = directory.appendingPathComponent("deploy").path
        let publicKey = "ssh-ed25519 \(Self.fakeKeyData) deploy"
        let metadata = try SSHKeyMetadataResolver.parsePublicKeyLine(publicKey, fallbackComment: "deploy")
        try "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n"
            .write(toFile: privateKeyPath, atomically: true, encoding: .utf8)

        let client = RecordingAdoptionClient(existingKeys: [
            .init(
                name: "deploy",
                folderPath: "Team/Other",
                key: .init(publicKey: publicKey, fingerprint: metadata.fingerprint, privateKey: nil)
            )
        ])
        let candidate = SSHAdoptionService.Candidate(
            keyName: "deploy",
            privateKeyPath: privateKeyPath,
            publicKeyPath: "\(privateKeyPath).pub",
            metadata: metadata,
            hostBindings: []
        )

        let summary = try await SSHAdoptionService.adopt(
            candidates: [candidate],
            client: client,
            backupService: nil,
            folderPath: "Team/API",
            configPath: directory.appendingPathComponent("config").path
        )

        #expect(summary.added == 1)
        #expect(summary.managedExisting == 0)
        #expect(summary.adopted == 1)
        #expect(summary.skipped == 0)
        #expect(client.addedKeys.map(\.folderPath) == ["Team/API"])
    }

    @Test("existing matching vault metadata without restorable private key does not stub local private key")
    func existingMatchingVaultMetadataWithoutRestorablePrivateKeyDoesNotStubLocalPrivateKey() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ssh-adopt-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let privateKeyPath = directory.appendingPathComponent("deploy").path
        let publicKey = "ssh-ed25519 \(Self.fakeKeyData) deploy"
        let metadata = try SSHKeyMetadataResolver.parsePublicKeyLine(publicKey, fallbackComment: "deploy")
        let privateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n"
        try privateKey.write(toFile: privateKeyPath, atomically: true, encoding: .utf8)

        let client = RecordingAdoptionClient(existingKeys: [
            "deploy": .init(publicKey: publicKey, fingerprint: metadata.fingerprint, privateKey: nil)
        ])
        let candidate = SSHAdoptionService.Candidate(
            keyName: "deploy",
            privateKeyPath: privateKeyPath,
            publicKeyPath: "\(privateKeyPath).pub",
            metadata: metadata,
            hostBindings: []
        )

        let summary = try await SSHAdoptionService.adopt(
            candidates: [candidate],
            client: client,
            backupService: nil,
            folderPath: nil,
            configPath: directory.appendingPathComponent("config").path
        )

        let fileContent = try String(contentsOfFile: privateKeyPath, encoding: .utf8)
        #expect(summary.added == 0)
        #expect(summary.managedExisting == 0)
        #expect(summary.adopted == 0)
        #expect(summary.skipped == 1)
        #expect(client.addedKeys.isEmpty)
        #expect(fileContent.contains("BEGIN OPENSSH PRIVATE KEY"))
        #expect(!fileContent.contains("This SSH key is managed by Authsia"))
    }

    @Test("newly adopted key stores private key in vault without duplicating a backup note")
    func newlyAdoptedKeyDoesNotDuplicatePrivateKeyInBackup() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ssh-adopt-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let privateKeyPath = directory.appendingPathComponent("deploy").path
        let publicKey = "ssh-ed25519 \(Self.fakeKeyData) deploy"
        let metadata = try SSHKeyMetadataResolver.parsePublicKeyLine(publicKey, fallbackComment: "deploy")
        let privateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n"
        try privateKey.write(toFile: privateKeyPath, atomically: true, encoding: .utf8)

        let client = RecordingAdoptionClient()
        let backupService = RecordingAdoptionBackupService()
        let candidate = SSHAdoptionService.Candidate(
            keyName: "deploy",
            privateKeyPath: privateKeyPath,
            publicKeyPath: "\(privateKeyPath).pub",
            metadata: metadata,
            hostBindings: []
        )

        let summary = try await SSHAdoptionService.adopt(
            candidates: [candidate],
            client: client,
            backupService: backupService,
            folderPath: nil,
            configPath: directory.appendingPathComponent("config").path
        )

        let fileContent = try String(contentsOfFile: privateKeyPath, encoding: .utf8)
        let backups = await backupService.backups
        #expect(summary.added == 1)
        #expect(summary.managedExisting == 0)
        #expect(summary.adopted == 1)
        #expect(summary.skipped == 0)
        #expect(client.addedKeys.map(\.name) == ["deploy"])
        #expect(backups.isEmpty)
        #expect(fileContent.contains("This SSH key is managed by Authsia"))
        #expect(!fileContent.contains("BEGIN OPENSSH PRIVATE KEY"))
    }

    @Test("newly adopted key is not stubbed when vault read-back cannot verify private key")
    func newlyAdoptedKeyDoesNotStubWhenVaultReadBackCannotVerifyPrivateKey() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ssh-adopt-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let privateKeyPath = directory.appendingPathComponent("deploy").path
        let publicKey = "ssh-ed25519 \(Self.fakeKeyData) deploy"
        let metadata = try SSHKeyMetadataResolver.parsePublicKeyLine(publicKey, fallbackComment: "deploy")
        let privateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n"
        try privateKey.write(toFile: privateKeyPath, atomically: true, encoding: .utf8)

        let client = RecordingAdoptionClient(addedKeysAreRestorable: false)
        let candidate = SSHAdoptionService.Candidate(
            keyName: "deploy",
            privateKeyPath: privateKeyPath,
            publicKeyPath: "\(privateKeyPath).pub",
            metadata: metadata,
            hostBindings: []
        )

        await #expect(throws: (any Error).self) {
            try await SSHAdoptionService.adopt(
                candidates: [candidate],
                client: client,
                backupService: nil,
                folderPath: nil,
                configPath: directory.appendingPathComponent("config").path
            )
        }

        let fileContent = try String(contentsOfFile: privateKeyPath, encoding: .utf8)
        #expect(client.addedKeys.map(\.name) == ["deploy"])
        #expect(fileContent.contains("BEGIN OPENSSH PRIVATE KEY"))
        #expect(!fileContent.contains("This SSH key is managed by Authsia"))
    }

    @Test("managed stub restores private key from vault")
    func managedStubRestoresPrivateKeyFromVault() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ssh-adopt-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let privateKeyPath = directory.appendingPathComponent("deploy").path
        let privateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n"
        let publicKey = "ssh-ed25519 \(Self.fakeKeyData) deploy"
        let metadata = try SSHKeyMetadataResolver.parsePublicKeyLine(publicKey, fallbackComment: "deploy")
        try """
        # This SSH key is managed by Authsia.
        # Served by the built-in Authsia agent.
        """.write(toFile: privateKeyPath, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: privateKeyPath)

        let client = RecordingAdoptionClient(existingKeys: [
            "deploy": .init(publicKey: publicKey, fingerprint: metadata.fingerprint, privateKey: privateKey),
        ])

        let restored = try SSHAdoptionService.restoreManagedStub(
            at: privateKeyPath,
            client: client,
            folderPath: nil
        )

        let fileContent = try String(contentsOfFile: privateKeyPath, encoding: .utf8)
        let permissions = try FileManager.default.attributesOfItem(atPath: privateKeyPath)[.posixPermissions] as? Int
        #expect(restored)
        #expect(fileContent == privateKey)
        #expect(permissions == 0o600)
    }

    @Test("existing conflicting vault key does not stub local private key")
    func existingConflictingVaultKeyDoesNotStubLocalPrivateKey() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ssh-adopt-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let privateKeyPath = directory.appendingPathComponent("deploy").path
        let metadata = try SSHKeyMetadataResolver.parsePublicKeyLine(
            "ssh-ed25519 \(Self.fakeKeyData) deploy",
            fallbackComment: "deploy"
        )
        try "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n"
            .write(toFile: privateKeyPath, atomically: true, encoding: .utf8)

        let client = RecordingAdoptionClient(existingKeys: [
            "deploy": .init(
                publicKey: "ssh-ed25519 \(Self.fakeKeyData) other",
                fingerprint: "SHA256:different",
                privateKey: nil
            )
        ])
        let candidate = SSHAdoptionService.Candidate(
            keyName: "deploy",
            privateKeyPath: privateKeyPath,
            publicKeyPath: "\(privateKeyPath).pub",
            metadata: metadata,
            hostBindings: []
        )

        let summary = try await SSHAdoptionService.adopt(
            candidates: [candidate],
            client: client,
            backupService: nil,
            folderPath: nil,
            configPath: directory.appendingPathComponent("config").path
        )

        let fileContent = try String(contentsOfFile: privateKeyPath, encoding: .utf8)
        #expect(summary.added == 0)
        #expect(summary.managedExisting == 0)
        #expect(summary.adopted == 0)
        #expect(summary.skipped == 1)
        #expect(client.addedKeys.isEmpty)
        #expect(fileContent.contains("BEGIN OPENSSH PRIVATE KEY"))
        #expect(!fileContent.contains("This SSH key is managed by Authsia"))
    }

    @Test("latest active adoption backup ignores newer scrape backup")
    func latestActiveAdoptionBackupIgnoresNewerScrapeBackup() throws {
        let path = "/Users/example/.ssh/id_ed25519"
        let adoptionBackup = Self.backupEntry(
            path: path,
            timestamp: Date(timeIntervalSince1970: 100),
            description: SSHAdoptionService.backupDescription
        )
        let scrapeBackup = Self.backupEntry(
            path: path,
            timestamp: Date(timeIntervalSince1970: 200),
            description: "Before authsia scrape"
        )

        let selected = SSHAdoptionService.latestActiveAdoptionBackup(from: [scrapeBackup, adoptionBackup])

        #expect(selected?.id == adoptionBackup.id)
    }

    @Test("latest active adoption backup uses kind instead of description text")
    func latestActiveAdoptionBackupUsesKindInsteadOfDescriptionText() throws {
        let path = "/Users/example/.ssh/id_ed25519"
        let adoptionBackup = Self.backupEntry(
            path: path,
            timestamp: Date(timeIntervalSince1970: 100),
            description: "custom operator note",
            kind: .sshAdoption
        )
        let scrapeBackup = Self.backupEntry(
            path: path,
            timestamp: Date(timeIntervalSince1970: 200),
            description: SSHAdoptionService.backupDescription,
            kind: .scrape
        )

        let selected = SSHAdoptionService.latestActiveAdoptionBackup(from: [scrapeBackup, adoptionBackup])

        #expect(selected?.id == adoptionBackup.id)
    }

    @Test("active adoption backups by path exclude scrape and restored backups")
    func activeAdoptionBackupsByPathExcludeScrapeAndRestoredBackups() throws {
        let olderDeploy = Self.backupEntry(
            path: "/Users/example/.ssh/deploy",
            timestamp: Date(timeIntervalSince1970: 100),
            description: SSHAdoptionService.backupDescription
        )
        let newerDeploy = Self.backupEntry(
            path: "/Users/example/.ssh/deploy",
            timestamp: Date(timeIntervalSince1970: 200),
            description: SSHAdoptionService.backupDescription
        )
        let scrapeBackup = Self.backupEntry(
            path: "/Users/example/.ssh/github",
            timestamp: Date(timeIntervalSince1970: 300),
            description: "Before authsia scrape"
        )
        let restoredBackup = Self.backupEntry(
            path: "/Users/example/.ssh/restored",
            timestamp: Date(timeIntervalSince1970: 400),
            description: SSHAdoptionService.backupDescription,
            isRestored: true
        )

        let selected = SSHAdoptionService.latestActiveAdoptionBackupsByPath(
            from: [olderDeploy, newerDeploy, scrapeBackup, restoredBackup]
        )

        #expect(selected.map(\.id) == [newerDeploy.id])
    }

    private static func generateLegacyRSAKey(at path: String, comment: String) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = ["-q", "-t", "rsa", "-b", "2048", "-m", "PEM", "-N", "", "-C", comment, "-f", path]

        let stderr = Pipe()
        process.standardError = stderr
        process.standardInput = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            let errorOutput = String(
                data: stderr.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8
            ) ?? "ssh-keygen failed"
            throw NSError(
                domain: "SSHAdoptionServiceTests.ssh-keygen",
                code: Int(process.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: errorOutput.trimmingCharacters(in: .whitespacesAndNewlines)]
            )
        }
    }

    private static func backupEntry(
        path: String,
        timestamp: Date,
        description: String,
        kind: BackupService.BackupKind? = nil,
        isRestored: Bool = false
    ) -> BackupService.BackupEntry {
        BackupService.BackupEntry(
            id: UUID().uuidString,
            originalPath: path,
            folderPath: nil,
            backupNoteId: nil,
            backupNoteName: "test-backup",
            timestamp: timestamp,
            description: description,
            kind: kind,
            fileHash: "test",
            isRestored: isRestored,
            hostname: "test-host",
            machineId: "test-machine"
        )
    }
}

private actor RecordingAdoptionBackupService: SSHAdoptionBackuping {
    struct Backup: Equatable {
        let path: String
        let content: String
        let description: String
        let kind: BackupService.BackupKind

        init(
            path: String,
            content: String,
            description: String,
            kind: BackupService.BackupKind = .sshAdoption
        ) {
            self.path = path
            self.content = content
            self.description = description
            self.kind = kind
        }
    }

    private(set) var backups: [Backup] = []

    func createBackup(
        of filePath: String,
        originalContent: String,
        description: String,
        kind: BackupService.BackupKind
    ) async throws -> BackupService.BackupEntry {
        backups.append(.init(path: filePath, content: originalContent, description: description, kind: kind))
        return BackupService.BackupEntry(
            id: UUID().uuidString,
            originalPath: filePath,
            folderPath: nil,
            backupNoteId: nil,
            backupNoteName: "test-backup",
            timestamp: Date(),
            description: description,
            kind: kind,
            fileHash: "test",
            isRestored: false,
            hostname: "test-host",
            machineId: "test-machine"
        )
    }
}

private final class RecordingAdoptionClient: SSHAdoptionVaultClient {
    struct ExistingKey {
        let name: String
        let folderPath: String?
        let key: SSHAdoptionService.ExistingVaultKey
    }

    struct AddedKey {
        let name: String
        let folderPath: String?
        let approvalPolicy: SSHKeyApprovalPolicy?
        let boundHosts: [String]?
        let publicKey: String
        let privateKey: String
        let fingerprint: String
    }

    var existingKeys: [ExistingKey]
    var addedKeysAreRestorable: Bool
    private(set) var addedKeys: [AddedKey] = []

    init(
        existingKeys: [String: SSHAdoptionService.ExistingVaultKey] = [:],
        addedKeysAreRestorable: Bool = true
    ) {
        self.existingKeys = existingKeys.map { name, key in
            ExistingKey(name: name, folderPath: nil, key: key)
        }
        self.addedKeysAreRestorable = addedKeysAreRestorable
    }

    init(existingKeys: [ExistingKey], addedKeysAreRestorable: Bool = true) {
        self.existingKeys = existingKeys
        self.addedKeysAreRestorable = addedKeysAreRestorable
    }

    func existingSSHKey(named name: String, folderPath: String?) throws -> SSHAdoptionService.ExistingVaultKey? {
        if let key = existingKeys.first(where: {
            $0.name == name && normalizeFolderPath($0.folderPath) == normalizeFolderPath(folderPath)
        })?.key {
            return key
        }

        guard addedKeysAreRestorable else { return nil }
        return addedKeys.first {
            $0.name == name && normalizeFolderPath($0.folderPath) == normalizeFolderPath(folderPath)
        }.map {
            SSHAdoptionService.ExistingVaultKey(
                publicKey: $0.publicKey,
                fingerprint: $0.fingerprint,
                privateKey: $0.privateKey
            )
        }
    }

    func addSSH(
        name: String,
        publicKey: String,
        privateKey: String,
        comment: String,
        fingerprint: String,
        passphrase: String?,
        keyType: SSHKeyType?,
        approvalPolicy: SSHKeyApprovalPolicy?,
        boundHosts: [String]?,
        isScraped: Bool,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?
    ) throws -> WriteResult {
        addedKeys.append(.init(
            name: name,
            folderPath: folderPath,
            approvalPolicy: approvalPolicy,
            boundHosts: boundHosts,
            publicKey: publicKey,
            privateKey: privateKey,
            fingerprint: fingerprint
        ))
        return WriteResult(id: UUID().uuidString, message: "ok")
    }
}
