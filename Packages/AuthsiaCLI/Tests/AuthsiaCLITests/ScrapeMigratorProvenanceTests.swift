import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
@testable import authsia

@Suite("ScrapeMigrator provenance notes")
struct ScrapeMigratorProvenanceTests {

    @Test("provenance note includes machine display name")
    func provenanceIncludesMachine() {
        let note = ScrapeMigrator.provenanceNote(
            filePath: "/Users/example/.zshrc",
            lineNumber: 42,
            machineName: "Example-MacBook",
            date: "2026-03-15"
        )
        #expect(note.contains("Example-MacBook"))
        #expect(note.contains(".zshrc"))
        #expect(note.contains("42"))
        #expect(note.contains("2026-03-15"))
    }

    @Test("provenance note format is stable")
    func provenanceFormat() {
        let note = ScrapeMigrator.provenanceNote(
            filePath: "/tmp/test",
            lineNumber: 1,
            machineName: "Mac-Mini",
            date: "2026-01-01"
        )
        #expect(note == "Scraped by authsia\nMachine: Mac-Mini  |  File: /tmp/test  |  Line: 1\nDate: 2026-01-01")
    }

    @Test("api key migration passes structured scrape machine provenance")
    func apiKeyMigrationPassesStructuredProvenance() throws {
        let client = RecordingScrapeVaultClient()
        let migrator = ScrapeMigrator(
            client: client,
            conflictMode: .skip,
            folderPath: "Team/API",
            machineName: "jamess-mac-mini",
            machineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )

        let secret = DetectedSecret(
            filePath: "/Users/example/.zshrc",
            lineNumber: 7,
            originalLine: "export API_KEY=super-secret",
            key: "API_KEY",
            value: "super-secret",
            rawContent: nil,
            confidence: .high,
            type: .apiKey,
            entropy: 4.7,
            description: "api key",
            sshMetadata: nil
        )

        let summary = try migrator.migrate([secret])

        #expect(summary.addedCount == 1)
        #expect(client.addedAPIKeys.first?.name == "API_KEY")
        #expect(client.addedAPIKeys.first?.key == "super-secret")
        #expect(client.addedAPIKeys.first?.scrapeMachineName == "jamess-mac-mini")
        #expect(client.addedAPIKeys.first?.scrapeMachineId == "73C4AEA4-EB11-4AD7-AC14-DA296C404846")
        #expect(client.addedPasswords.isEmpty)
    }

    @Test("password migration ignores same-name items in other folders")
    func passwordMigrationIgnoresSameNameItemsInOtherFolders() throws {
        let client = RecordingScrapeVaultClient(
            passwords: [
                .init(name: "API_KEY", folderPath: "Team/Other")
            ]
        )
        let migrator = ScrapeMigrator(
            client: client,
            conflictMode: .prompt { _ in
                Issue.record("Different-folder item should not prompt for overwrite.")
                return false
            },
            folderPath: "Team/API",
            machineName: "jamess-mac-mini",
            machineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )

        let summary = try migrator.migrate([Self.passwordSecret(key: "API_KEY")])

        #expect(summary.addedCount == 1)
        #expect(summary.skippedCount == 0)
        #expect(client.addedPasswords.count == 1)
        #expect(client.updatedPasswords.isEmpty)
    }

    @Test("password migration prompts for same-name items in the same folder")
    func passwordMigrationPromptsForSameNameItemsInSameFolder() throws {
        var promptCount = 0
        let client = RecordingScrapeVaultClient(
            passwords: [
                .init(id: "password-api", name: "API_KEY", folderPath: "Team/API")
            ]
        )
        let migrator = ScrapeMigrator(
            client: client,
            conflictMode: .prompt { _ in
                promptCount += 1
                return false
            },
            folderPath: "Team/API",
            machineName: "jamess-mac-mini",
            machineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )

        let summary = try migrator.migrate([Self.passwordSecret(key: "API_KEY")])

        #expect(promptCount == 1)
        #expect(summary.addedCount == 0)
        #expect(summary.skippedCount == 1)
        #expect(client.addedPasswords.isEmpty)
        #expect(client.updatedPasswords.isEmpty)
    }

    @Test("password migration overwrites same-folder item by id")
    func passwordMigrationOverwritesSameFolderItemByID() throws {
        let client = RecordingScrapeVaultClient(
            passwords: [
                .init(id: "password-api", name: "API_KEY", folderPath: "Team/API"),
                .init(id: "password-other", name: "API_KEY", folderPath: "Team/Other")
            ]
        )
        let migrator = ScrapeMigrator(
            client: client,
            conflictMode: .overwrite,
            folderPath: "Team/API",
            machineName: "jamess-mac-mini",
            machineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )

        let summary = try migrator.migrate([Self.passwordSecret(key: "API_KEY")])

        #expect(summary.addedCount == 1)
        #expect(summary.skippedCount == 0)
        #expect(client.addedPasswords.isEmpty)
        #expect(client.updatedPasswords.first?.query == "password-api")
    }

    @Test("password migration can reuse same-folder item without vault write")
    func passwordMigrationCanReuseSameFolderItemWithoutVaultWrite() throws {
        let client = RecordingScrapeVaultClient(
            passwords: [
                .init(id: "password-api", name: "API_KEY", folderPath: "Team/API"),
            ]
        )
        let migrator = ScrapeMigrator(
            client: client,
            conflictMode: .choose { _ in .reuse },
            folderPath: "Team/API",
            machineName: "jamess-mac-mini",
            machineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )

        let summary = try migrator.migrate([Self.passwordSecret(key: "API_KEY")])

        #expect(summary.addedCount == 0)
        #expect(summary.skippedCount == 0)
        #expect(summary.results.map(\.outcome) == [.reused])
        #expect(client.addedPasswords.isEmpty)
        #expect(client.updatedPasswords.isEmpty)
    }

    @Test("note migration passes structured scrape machine provenance")
    func noteMigrationPassesStructuredProvenance() throws {
        let client = RecordingScrapeVaultClient()
        let migrator = ScrapeMigrator(
            client: client,
            conflictMode: .skip,
            folderPath: "Team/API",
            machineName: "jamess-mac-mini",
            machineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )

        let secret = DetectedSecret(
            filePath: "/Users/example/.kube/config",
            lineNumber: 1,
            originalLine: "kubeconfig",
            key: "scraped_kube",
            value: "ignored",
            rawContent: "{\"clusters\":[]}",
            confidence: .high,
            type: .certificate,
            entropy: 4.0,
            description: "json note",
            sshMetadata: nil
        )

        let summary = try migrator.migrate([secret])

        #expect(summary.addedCount == 1)
        #expect(client.addedNotes.first?.scrapeMachineName == "jamess-mac-mini")
        #expect(client.addedNotes.first?.scrapeMachineId == "73C4AEA4-EB11-4AD7-AC14-DA296C404846")
    }

    private static func passwordSecret(key: String) -> DetectedSecret {
        DetectedSecret(
            filePath: "/Users/example/.env",
            lineNumber: 7,
            originalLine: "\(key)=super-secret",
            key: key,
            value: "super-secret",
            rawContent: nil,
            confidence: .high,
            type: .password,
            entropy: 4.7,
            description: "password",
            sshMetadata: nil
        )
    }

    @Test("certificate migration does not store PEM as secure note")
    func certificateMigrationDoesNotStorePEMAsNote() throws {
        let client = RecordingScrapeVaultClient()
        let migrator = ScrapeMigrator(
            client: client,
            conflictMode: .skip,
            folderPath: "Team/API",
            machineName: "jamess-mac-mini",
            machineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )

        let secret = DetectedSecret(
            filePath: "/Users/example/certs/server.pem",
            lineNumber: 1,
            originalLine: "TLS_CERT=server.pem",
            key: "TLS_CERT",
            value: "server.pem",
            rawContent: """
            -----BEGIN CERTIFICATE-----
            MIIB
            -----END CERTIFICATE-----
            """,
            confidence: .high,
            type: .certificate,
            entropy: 4.0,
            description: "certificate",
            sshMetadata: nil
        )

        let summary = try migrator.migrate([secret])

        #expect(summary.addedCount == 1)
        #expect(client.addedNotes.isEmpty)
        #expect(client.addedCertificates.first?.certificate.contains("BEGIN CERTIFICATE") == true)
        #expect(client.addedCertificates.first?.privateKey == nil)
        #expect(client.addedCertificates.first?.scrapeMachineName == "jamess-mac-mini")
        #expect(client.addedCertificates.first?.scrapeMachineId == "73C4AEA4-EB11-4AD7-AC14-DA296C404846")
    }

    @Test("certificate migration combines matching public certificate and private key")
    func certificateMigrationCombinesMatchingPublicCertAndPrivateKey() throws {
        let client = RecordingScrapeVaultClient()
        let migrator = ScrapeMigrator(
            client: client,
            conflictMode: .skip,
            folderPath: "Team/API",
            machineName: "jamess-mac-mini",
            machineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )

        let publicCert = DetectedSecret(
            filePath: "/Users/example/certs/server.crt",
            lineNumber: 0,
            originalLine: "",
            key: "server",
            value: "/Users/example/certs/server.crt",
            rawContent: """
            -----BEGIN CERTIFICATE-----
            MIIB
            -----END CERTIFICATE-----
            """,
            confidence: .high,
            type: .certificate,
            entropy: 0,
            description: "certificate",
            sshMetadata: nil
        )
        let privateKey = DetectedSecret(
            filePath: "/Users/example/certs/server.key",
            lineNumber: 0,
            originalLine: "",
            key: "server",
            value: "/Users/example/certs/server.key",
            rawContent: """
            -----BEGIN PRIVATE KEY-----
            MIIE
            -----END PRIVATE KEY-----
            """,
            confidence: .high,
            type: .certificate,
            entropy: 0,
            description: "private key",
            sshMetadata: nil
        )

        let summary = try migrator.migrate([publicCert, privateKey])

        #expect(summary.addedCount == 1)
        #expect(summary.skippedCount == 0)
        #expect(client.addedCertificates.count == 1)
        #expect(client.addedCertificates.first?.certificate.contains("BEGIN CERTIFICATE") == true)
        #expect(client.addedCertificates.first?.privateKey?.contains("BEGIN PRIVATE KEY") == true)
    }

    @Test("certificate migration does not merge same-name pairs from different stems")
    func certificateMigrationDoesNotMergeSameNamePairsFromDifferentStems() throws {
        let client = RecordingScrapeVaultClient()
        let migrator = ScrapeMigrator(
            client: client,
            conflictMode: .skip,
            folderPath: "Team/API",
            machineName: "jamess-mac-mini",
            machineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )

        func certificateSecret(path: String, pem: String) -> DetectedSecret {
            DetectedSecret(
                filePath: path,
                lineNumber: 0,
                originalLine: "",
                key: "server",
                value: path,
                rawContent: pem,
                confidence: .high,
                type: .certificate,
                entropy: 0,
                description: "certificate material",
                sshMetadata: nil
            )
        }

        let prodCert = certificateSecret(
            path: "/tmp/prod/server.crt",
            pem: """
            -----BEGIN CERTIFICATE-----
            PROD_CERT
            -----END CERTIFICATE-----
            """
        )
        let prodKey = certificateSecret(
            path: "/tmp/prod/server.key",
            pem: """
            -----BEGIN PRIVATE KEY-----
            PROD_KEY
            -----END PRIVATE KEY-----
            """
        )
        let oldCert = certificateSecret(
            path: "/tmp/old/server.crt",
            pem: """
            -----BEGIN CERTIFICATE-----
            OLD_CERT
            -----END CERTIFICATE-----
            """
        )
        let oldKey = certificateSecret(
            path: "/tmp/old/server.key",
            pem: """
            -----BEGIN PRIVATE KEY-----
            OLD_KEY
            -----END PRIVATE KEY-----
            """
        )

        let summary = try migrator.migrate([prodCert, prodKey, oldCert, oldKey])
        let added = try #require(client.addedCertificates.first)

        #expect(summary.addedCount == 1)
        #expect(summary.skippedCount == 1)
        #expect(client.addedCertificates.count == 1)
        #expect(added.certificate.contains("PROD_CERT"))
        #expect(added.privateKey?.contains("PROD_KEY") == true)
        #expect(!added.certificate.contains("OLD_CERT"))
        #expect(added.privateKey?.contains("OLD_KEY") != true)
    }

    @Test("certificate migration does not combine duplicate certificate-only items")
    func certificateMigrationDoesNotCombineDuplicateCertificateOnlyItems() throws {
        let client = RecordingScrapeVaultClient()
        let migrator = ScrapeMigrator(
            client: client,
            conflictMode: .skip,
            folderPath: "Team/API",
            machineName: "jamess-mac-mini",
            machineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )

        let firstCert = DetectedSecret(
            filePath: "/Users/example/certs/server-a.crt",
            lineNumber: 0,
            originalLine: "",
            key: "server",
            value: "/Users/example/certs/server-a.crt",
            rawContent: """
            -----BEGIN CERTIFICATE-----
            MIIB
            -----END CERTIFICATE-----
            """,
            confidence: .high,
            type: .certificate,
            entropy: 0,
            description: "certificate",
            sshMetadata: nil
        )
        let secondCert = DetectedSecret(
            filePath: "/Users/example/certs/server-b.crt",
            lineNumber: 0,
            originalLine: "",
            key: "server",
            value: "/Users/example/certs/server-b.crt",
            rawContent: """
            -----BEGIN CERTIFICATE-----
            MIIC
            -----END CERTIFICATE-----
            """,
            confidence: .high,
            type: .certificate,
            entropy: 0,
            description: "certificate",
            sshMetadata: nil
        )

        let summary = try migrator.migrate([firstCert, secondCert])

        #expect(summary.addedCount == 1)
        #expect(summary.skippedCount == 1)
        #expect(client.addedCertificates.count == 1)
        #expect(client.addedCertificates.first?.certificate.contains("MIIB") == true)
        #expect(client.addedCertificates.first?.certificate.contains("MIIC") == false)
    }

    @Test("certificate overwrite preserves private key when new scrape has certificate only")
    func certificateOverwritePreservesPrivateKeyWhenNewScrapeHasCertificateOnly() throws {
        let client = RecordingScrapeVaultClient(
            certificates: [
                .init(id: "cert-server", name: "server", folderPath: "Team/API")
            ]
        )
        let migrator = ScrapeMigrator(
            client: client,
            conflictMode: .overwrite,
            folderPath: "Team/API",
            machineName: "jamess-mac-mini",
            machineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )
        let publicCert = DetectedSecret(
            filePath: "/Users/example/certs/server.crt",
            lineNumber: 0,
            originalLine: "",
            key: "server",
            value: "/Users/example/certs/server.crt",
            rawContent: """
            -----BEGIN CERTIFICATE-----
            NEW_CERT
            -----END CERTIFICATE-----
            """,
            confidence: .high,
            type: .certificate,
            entropy: 0,
            description: "certificate",
            sshMetadata: nil
        )

        let summary = try migrator.migrate([publicCert])

        #expect(summary.addedCount == 1)
        let update = try #require(client.updatedCertificates.first)
        #expect(update.query == "cert-server")
        #expect(update.privateKey == nil)
        #expect(update.clearPrivateKey == false)
    }

    @Test("ssh migration is skipped in favor of ssh adopt")
    func sshMigrationIsSkippedInFavorOfSSHAdopt() throws {
        let client = RecordingScrapeVaultClient()
        let migrator = ScrapeMigrator(
            client: client,
            conflictMode: .skip,
            folderPath: "Team/API",
            machineName: "jamess-mac-mini",
            machineId: "73C4AEA4-EB11-4AD7-AC14-DA296C404846"
        )

        let secret = DetectedSecret(
            filePath: "/Users/example/.ssh/id_ed25519",
            lineNumber: 1,
            originalLine: "private-key",
            key: "WORK_SSH",
            value: "ignored",
            rawContent: "-----BEGIN OPENSSH PRIVATE KEY-----",
            confidence: .high,
            type: .sshKey,
            entropy: 5.0,
            description: "ssh key",
            sshMetadata: .init(
                publicKey: "ssh-ed25519 AAAA",
                comment: "laptop",
                fingerprint: "SHA256:abc"
            )
        )

        let summary = try migrator.migrate([secret])

        #expect(summary.addedCount == 0)
        #expect(summary.skippedCount == 1)
        #expect(client.addedPasswords.isEmpty)
        #expect(client.addedNotes.isEmpty)
    }
}

private final class RecordingScrapeVaultClient: ScrapeVaultClient {
    struct ExistingItem {
        let id: String
        let name: String
        let folderPath: String?

        init(id: String = UUID().uuidString, name: String, folderPath: String?) {
            self.id = id
            self.name = name
            self.folderPath = folderPath
        }
    }

    struct PasswordCall {
        let query: String?
        let scrapeMachineName: String?
        let scrapeMachineId: String?
    }

    struct APIKeyCall {
        let query: String?
        let name: String?
        let key: String?
        let folderPath: String?
        let scrapeMachineName: String?
        let scrapeMachineId: String?
    }

    struct NoteCall {
        let scrapeMachineName: String?
        let scrapeMachineId: String?
    }

    struct CertificateCall {
        let id: String
        let name: String
        let certificate: String
        let privateKey: String?
        let folderPath: String?
        let scrapeMachineName: String?
        let scrapeMachineId: String?
    }

    struct CertificateUpdateCall {
        let query: String
        let privateKey: String?
        let clearPrivateKey: Bool
    }

    private let passwords: [ExistingItem]
    private let apiKeys: [ExistingItem]
    private let certificates: [ExistingItem]
    private let notes: [ExistingItem]
    private(set) var addedPasswords: [PasswordCall] = []
    private(set) var updatedPasswords: [PasswordCall] = []
    private(set) var addedAPIKeys: [APIKeyCall] = []
    private(set) var updatedAPIKeys: [APIKeyCall] = []
    private(set) var addedNotes: [NoteCall] = []
    private(set) var addedCertificates: [CertificateCall] = []
    private(set) var updatedCertificates: [CertificateUpdateCall] = []

    init(
        passwords: [ExistingItem] = [],
        apiKeys: [ExistingItem] = [],
        certificates: [ExistingItem] = [],
        notes: [ExistingItem] = []
    ) {
        self.passwords = passwords
        self.apiKeys = apiKeys
        self.certificates = certificates
        self.notes = notes
    }

    func existingPasswordID(named name: String, folderPath: String?) throws -> String? {
        passwords.first { isSameItem($0, name: name, folderPath: folderPath) }?.id
    }
    func existingAPIKeyID(named name: String, folderPath: String?) throws -> String? {
        apiKeys.first { isSameItem($0, name: name, folderPath: folderPath) }?.id
    }
    func existingCertificateID(named name: String, folderPath: String?) throws -> String? {
        certificates.first { isSameItem($0, name: name, folderPath: folderPath) }?.id ??
            addedCertificates.first {
                isSameName($0.name, name) && normalizeFolderPath($0.folderPath) == normalizeFolderPath(folderPath)
            }?.id
    }
    func existingNoteID(title: String, folderPath: String?) throws -> String? {
        notes.first { isSameItem($0, name: title, folderPath: folderPath) }?.id
    }

    func addPassword(
        name: String,
        username: String,
        password: String,
        website: String?,
        notes: String?,
        isScraped: Bool,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?,
        expiresAt: Date?
    ) throws -> WriteResult {
        addedPasswords.append(.init(query: nil, scrapeMachineName: scrapeMachineName, scrapeMachineId: scrapeMachineId))
        return WriteResult(id: UUID().uuidString, message: "ok")
    }

    func updatePassword(
        query: String,
        name: String?,
        username: String?,
        password: String?,
        website: String?,
        notes: String?,
        isScraped: Bool?,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?,
        expiresAt: Date?,
        clearExpiresAt: Bool
    ) throws -> WriteResult {
        updatedPasswords.append(.init(query: query, scrapeMachineName: scrapeMachineName, scrapeMachineId: scrapeMachineId))
        return WriteResult(id: UUID().uuidString, message: "ok")
    }

    func addAPIKey(
        name: String,
        key: String,
        website: String?,
        notes: String?,
        isScraped: Bool,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?,
        expiresAt: Date?
    ) throws -> WriteResult {
        addedAPIKeys.append(
            .init(
                query: nil,
                name: name,
                key: key,
                folderPath: folderPath,
                scrapeMachineName: scrapeMachineName,
                scrapeMachineId: scrapeMachineId
            )
        )
        return WriteResult(id: UUID().uuidString, message: "ok")
    }

    func updateAPIKey(
        query: String,
        name: String?,
        key: String?,
        website: String?,
        notes: String?,
        isScraped: Bool?,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?,
        expiresAt: Date?,
        clearExpiresAt: Bool
    ) throws -> WriteResult {
        updatedAPIKeys.append(
            .init(
                query: query,
                name: name,
                key: key,
                folderPath: folderPath,
                scrapeMachineName: scrapeMachineName,
                scrapeMachineId: scrapeMachineId
            )
        )
        return WriteResult(id: UUID().uuidString, message: "ok")
    }

    func addCertificate(
        name: String,
        certificate: String,
        privateKey: String?,
        notes: String?,
        folderPath: String?,
        isScraped: Bool,
        scrapeMachineName: String?,
        scrapeMachineId: String?
    ) throws -> WriteResult {
        let id = UUID().uuidString
        addedCertificates.append(
            .init(
                id: id,
                name: name,
                certificate: certificate,
                privateKey: privateKey,
                folderPath: folderPath,
                scrapeMachineName: scrapeMachineName,
                scrapeMachineId: scrapeMachineId
            )
        )
        return WriteResult(id: id, message: "ok")
    }

    func updateCertificate(
        query: String,
        name: String?,
        certificate: String?,
        privateKey: String?,
        clearPrivateKey: Bool,
        notes: String?,
        folderPath: String?,
        isScraped: Bool?,
        scrapeMachineName: String?,
        scrapeMachineId: String?
    ) throws -> WriteResult {
        updatedCertificates.append(
            .init(query: query, privateKey: privateKey, clearPrivateKey: clearPrivateKey)
        )
        return WriteResult(id: query, message: "ok")
    }

    func addNote(
        title: String,
        content: String,
        isScraped: Bool,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?
    ) throws -> WriteResult {
        addedNotes.append(.init(scrapeMachineName: scrapeMachineName, scrapeMachineId: scrapeMachineId))
        return WriteResult(id: UUID().uuidString, message: "ok")
    }

    func updateNote(
        query: String,
        title: String?,
        content: String?,
        isScraped: Bool?,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?
    ) throws -> WriteResult {
        fatalError("not used")
    }

    private func isSameItem(_ item: ExistingItem, name: String, folderPath: String?) -> Bool {
        isSameName(item.name, name) && normalizeFolderPath(item.folderPath) == normalizeFolderPath(folderPath)
    }

    private func isSameName(_ lhs: String, _ rhs: String) -> Bool {
        lhs.trimmingCharacters(in: .whitespacesAndNewlines)
            .caseInsensitiveCompare(rhs.trimmingCharacters(in: .whitespacesAndNewlines)) == .orderedSame
    }
}

@Suite("ScrapeMigrator SSH file stubbing")
struct ScrapeMigratorSSHStubbingTests {

    @Test func skippedSSHSecretDoesNotStubPrivateKeyFile() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        let keyPath = tmp.appendingPathComponent("id_ed25519").path
        try FileManager.default.createDirectory(atPath: tmp.path, withIntermediateDirectories: true)
        try "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n"
            .write(toFile: keyPath, atomically: true, encoding: .utf8)

        let secret = DetectedSecret(
            filePath: keyPath,
            lineNumber: 1,
            originalLine: "",
            key: "deploy",
            value: "",
            rawContent: "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n",
            confidence: .high,
            type: .sshKey,
            entropy: 5.0,
            description: "",
            sshMetadata: DetectedSecret.SSHMetadata(
                publicKey: "ssh-ed25519 AAAA",
                comment: "deploy@prod",
                fingerprint: "SHA256:abc",
                passphrase: nil
            )
        )

        let migrator = ScrapeMigrator(
            client: RecordingScrapeVaultClient(),
            conflictMode: .skip
        )
        let summary = try migrator.migrate([secret])

        let stubContent = try String(contentsOfFile: keyPath, encoding: .utf8)
        #expect(summary.skippedCount == 1)
        #expect(stubContent.contains("PRIVATE KEY"))
        #expect(!stubContent.contains("managed by Authsia"))
    }
}

@Suite("SSH handling defaults and guidance")
struct ScrapeSSHDefaultTests {
    @Test("scrape help covers type-filtered path example")
    func scrapeHelpCoversTypeFilteredPathExample() {
        let help = Scrape.helpMessage(columns: 160)

        #expect(help.contains("authsia scrape --type api-key --path .env"))
        #expect(help.contains("Allowed credential types: api-key, password, json, cert"))
    }

    @Test("scrape parses recursive directory flag")
    func scrapeParsesRecursiveDirectoryFlag() throws {
        let scrape = try Scrape.parse(["--path", "./certs", "--recursive", "--dry-run"])

        #expect(scrape.path == ["./certs"])
        #expect(scrape.recursive)
        #expect(scrape.dryRun)
    }

    @Test("scrape parses credential type filters")
    func scrapeParsesCredentialTypeFilters() throws {
        let scrape = try Scrape.parse(["--type", "api-key", "password", "json", "cert", "--dry-run"])

        #expect(scrape.type == [.apiKey, .password, .json, .cert])
        #expect(scrape.dryRun)
    }

    @Test("scrape parses original backup revert")
    func scrapeParsesOriginalBackupRevert() throws {
        let scrape = try Scrape.parse(["--revert-original", "~/.zshrc", "--machine", "james-macbook"])

        #expect(scrape.revertOriginal == "~/.zshrc")
        #expect(scrape.machine == "james-macbook")
        #expect(scrape.revert == nil)
    }

    @Test("scrape filters detections by credential type")
    func scrapeFiltersDetectionsByCredentialType() {
        var scrape = Scrape()
        scrape.type = [.apiKey]

        let apiKey = detectedSecret(key: "API_KEY", type: .apiKey)
        let token = detectedSecret(key: "API_TOKEN", type: .token)
        let password = detectedSecret(key: "DB_PASSWORD", type: .password)
        let json = detectedSecret(key: "SERVICE_ACCOUNT", type: .jsonCredential)
        let cert = detectedSecret(key: "TLS_CERT", type: .certificate)

        let filtered = scrape.filterSecretsByCredentialType([apiKey, token, password, json, cert])

        #expect(filtered.map(\.key) == ["API_KEY", "API_TOKEN"])
    }

    @Test("default scrape paths do not include ssh directory")
    func defaultPathsSkipSSHDirectory() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("scrape-default-\(UUID().uuidString)", isDirectory: true)
        let current = root.appendingPathComponent("project", isDirectory: true)
        let home = root.appendingPathComponent("home", isDirectory: true)
        try FileManager.default.createDirectory(at: current, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: home.appendingPathComponent(".ssh"), withIntermediateDirectories: true)
        try "".write(to: current.appendingPathComponent(".env"), atomically: true, encoding: .utf8)
        try "".write(to: home.appendingPathComponent(".zshrc"), atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: root) }

        let paths = Scrape.resolveDefaultPaths(
            fileManager: .default,
            homeDirectory: home,
            currentDirectory: current.path
        )

        #expect(paths.contains(current.appendingPathComponent(".env").path))
        #expect(paths.contains(home.appendingPathComponent(".zshrc").path))
        #expect(!paths.contains(home.appendingPathComponent(".ssh").path))
    }

    @Test("scanner detects custom-named ssh key for adoption guidance")
    func scannerDetectsCustomNamedSSHKeyForAdoptionGuidance() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("scrape-ssh-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let keyPath = root.appendingPathComponent("test")
        try "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n"
            .write(to: keyPath, atomically: true, encoding: .utf8)
        try "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa test-key\n"
            .write(to: root.appendingPathComponent("test.pub"), atomically: true, encoding: .utf8)

        let secrets = await FileScannerService().scanPaths([root.path], detectionService: SecretDetectionService())

        #expect(secrets.count == 1)
        #expect(secrets.first?.type == .sshKey)
        #expect(secrets.first?.key == "test")
    }

    @Test("explicit ssh key path is not rewritten by scrape")
    func explicitSSHKeyPathIsNotFileReplacement() {
        let keyPath = "/tmp/id_ed25519"
        var scrape = Scrape()
        scrape.path = [keyPath]
        let ssh = DetectedSecret(
            filePath: keyPath,
            lineNumber: 0,
            originalLine: "",
            key: "id_ed25519",
            value: "",
            rawContent: "-----BEGIN OPENSSH PRIVATE KEY-----",
            confidence: .high,
            type: .sshKey,
            entropy: 0,
            description: "ssh",
            sshMetadata: DetectedSecret.SSHMetadata(
                publicKey: "ssh-ed25519 AAAA",
                comment: "id_ed25519",
                fingerprint: "SHA256:abc"
            )
        )

        let replacements = scrape.fileReplacementSecrets(from: [ssh])

        #expect(replacements.isEmpty)
    }

    @Test("selected shell config secret from default scan is rewritten")
    func defaultScannedShellConfigSecretIsFileReplacement() {
        let zshrcPath = "/tmp/.zshrc"
        var scrape = Scrape()
        scrape.path = []
        scrape.replaceAll = false
        let secret = DetectedSecret(
            filePath: zshrcPath,
            lineNumber: 1,
            originalLine: "export API_KEY=super-secret",
            key: "API_KEY",
            value: "super-secret",
            rawContent: nil,
            confidence: .high,
            type: .apiKey,
            entropy: 4.7,
            description: "api key",
            sshMetadata: nil
        )

        let replacements = scrape.fileReplacementSecrets(from: [secret])

        #expect(replacements == [secret])
    }

    @Test("explicit env suffix path is rewritten by scrape")
    func explicitEnvSuffixPathIsFileReplacement() {
        let envPath = "/tmp/authsia-scrape-validation.env"
        var scrape = Scrape()
        scrape.path = [envPath]
        let secret = DetectedSecret(
            filePath: envPath,
            lineNumber: 1,
            originalLine: "API_KEY=super-secret",
            key: "API_KEY",
            value: "super-secret",
            rawContent: nil,
            confidence: .high,
            type: .apiKey,
            entropy: 4.7,
            description: "api key",
            sshMetadata: nil
        )

        let replacements = scrape.fileReplacementSecrets(from: [secret])

        #expect(replacements == [secret])
    }

    @Test("standalone certificate file is stored without file backup rewrite")
    func standaloneCertificateFileIsNotFileReplacement() {
        let certPath = "/tmp/server.pem"
        var scrape = Scrape()
        scrape.path = [certPath]
        scrape.dryRun = false
        let secret = DetectedSecret(
            filePath: certPath,
            lineNumber: 0,
            originalLine: "",
            key: "server",
            value: certPath,
            rawContent: """
            -----BEGIN CERTIFICATE-----
            MIIB
            -----END CERTIFICATE-----
            -----BEGIN PRIVATE KEY-----
            MIIE
            -----END PRIVATE KEY-----
            """,
            confidence: .high,
            type: .certificate,
            entropy: 0,
            description: "pem certificate with private key",
            sshMetadata: nil
        )

        let replacements = scrape.fileReplacementSecrets(from: [secret])
        let storageSecrets = scrape.nonFileReplacementSecretsForStorage(from: [secret])

        #expect(replacements.isEmpty)
        #expect(storageSecrets == [secret])
    }

    @Test("dry-run does not store standalone credential files")
    func dryRunDoesNotStoreStandaloneCredentialFiles() {
        let json = DetectedSecret(
            filePath: "/tmp/service-account.json",
            lineNumber: 0,
            originalLine: "",
            key: "service-account",
            value: "",
            rawContent: "{}",
            confidence: .high,
            type: .jsonCredential,
            entropy: 0,
            description: "json credential",
            sshMetadata: nil
        )
        var scrape = Scrape()
        scrape.dryRun = true

        let storageSecrets = scrape.nonFileReplacementSecretsForStorage(from: [json])

        #expect(storageSecrets.isEmpty)
    }

    @Test("ssh adoption guidance points to ssh adopt")
    func sshAdoptionGuidancePointsToSSHAdopt() {
        let secret = DetectedSecret(
            filePath: "/Users/example/.ssh/id_ed25519",
            lineNumber: 0,
            originalLine: "",
            key: "id_ed25519",
            value: "",
            rawContent: "-----BEGIN OPENSSH PRIVATE KEY-----",
            confidence: .high,
            type: .sshKey,
            entropy: 0,
            description: "ssh",
            sshMetadata: nil
        )

        let guidance = Scrape.sshAdoptionGuidance(for: [secret])

        #expect(guidance.contains("Skipped 1 SSH private key"))
        #expect(guidance.contains("authsia ssh adopt --path /Users/example/.ssh --dry-run"))
    }

    private func detectedSecret(key: String, type: SecretType) -> DetectedSecret {
        DetectedSecret(
            filePath: "/tmp/.env",
            lineNumber: 1,
            originalLine: "\(key)=value",
            key: key,
            value: "value",
            rawContent: type == .jsonCredential ? "{}" : nil,
            confidence: .high,
            type: type,
            entropy: 4.0,
            description: "test",
            sshMetadata: nil
        )
    }
}

// MARK: - Env file migration stores secrets in the vault

@Suite("Scrape env file migration")
struct ScrapeEnvFileMigrationTests {

    /// Minimal backup vault stub so handleEnvFileMigration can back up the file
    /// without touching a real vault.
    final class BackupStub: BackupVaultClient, @unchecked Sendable {
        var manifestContent = """
        {"version":"1.0","lastUpdated":"2026-01-01T00:00:00Z","backups":[]}
        """
        var manifestExists = false

        func addNote(title: String, content: String, isScraped: Bool, folderPath: String?) throws -> WriteResult {
            if title.hasPrefix("authsia_scrape_backups") {
                manifestContent = content
                manifestExists = true
            }
            return WriteResult(id: "note", message: "added")
        }

        func updateNote(query: String, title: String?, content: String?, isScraped: Bool?, folderPath: String?) throws -> WriteResult {
            if query.hasPrefix("authsia_scrape_backups"), let content {
                manifestContent = content
                manifestExists = true
            }
            return WriteResult(id: query, message: "updated")
        }

        func getNote(query: String) throws -> NoteResult {
            if query.hasPrefix("authsia_scrape_backups"), manifestExists {
                return NoteResult(id: query, title: query, content: manifestContent, createdAt: Date(), modifiedAt: Date(), isFavorite: false)
            }
            throw BridgeClientError.bridgeError(code: "notFound", message: "not found", query: query)
        }

        func deleteNote(query: String) throws -> WriteResult {
            if query.hasPrefix("authsia_scrape_backups") {
                manifestExists = false
            }
            return WriteResult(id: query, message: "deleted")
        }

        func list() throws -> BridgeListPayload {
            BridgeListPayload(accounts: [], passwords: [], certificates: [], notes: [], sshKeys: [])
        }
    }

    /// Regression guard: rewriting a .env file with authsia:// references MUST
    /// also store the secret values in the vault, otherwise `authsia exec
    /// --env-file` cannot resolve them. (Broke in db7ed32.)
    @Test("env file migration stores secrets in the vault")
    func envMigrationStoresSecrets() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("scrape-env-\(UUID().uuidString).env").path
        try "API_KEY=super-secret\n".write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let secret = DetectedSecret(
            filePath: path,
            lineNumber: 1,
            originalLine: "API_KEY=super-secret",
            key: "API_KEY",
            value: "super-secret",
            rawContent: nil,
            confidence: .high,
            type: .apiKey,
            entropy: 4.7,
            description: "api key",
            sshMetadata: nil
        )

        let backupService = BackupService(
            bridgeClient: BackupStub(),
            dateProvider: { Date() },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        let stored = StoredSecretsBox()
        var scrape = Scrape()
        scrape.quiet = true
        scrape.dryRun = false
        scrape.replaceAll = false
        scrape.folder = nil

        let result = try await scrape.handleEnvFileMigration(
            secrets: [secret],
            backupService: backupService,
            confirmApplyChanges: { true },
            storeSecrets: { secrets in
                await stored.record(secrets)
                return storedSummary(for: secrets)
            }
        )

        if case .applied(let appliedSecrets) = result {
            #expect(appliedSecrets == [secret])
        } else {
            Issue.record("Expected env migration to apply")
        }
        let recorded = await stored.value
        #expect(recorded.map(\.authsiaKey) == ["API_KEY"])

        // File was rewritten to the reference that exec will resolve against.
        let rewritten = try String(contentsOfFile: path, encoding: .utf8)
        #expect(rewritten.contains("API_KEY=authsia://api-key/API_KEY/key"))
    }

    /// dry-run must NOT store anything.
    @Test("dry-run env migration stores nothing")
    func dryRunStoresNothing() async throws {
        let secret = DetectedSecret(
            filePath: "/tmp/.env",
            lineNumber: 1,
            originalLine: "API_KEY=super-secret",
            key: "API_KEY",
            value: "super-secret",
            rawContent: nil,
            confidence: .high,
            type: .apiKey,
            entropy: 4.7,
            description: "api key",
            sshMetadata: nil
        )

        let backupService = BackupService(
            bridgeClient: BackupStub(),
            dateProvider: { Date() },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        let stored = StoredSecretsBox()
        var scrape = Scrape()
        scrape.quiet = true
        scrape.replaceAll = false
        scrape.dryRun = true
        scrape.folder = nil

        let result = try await scrape.handleEnvFileMigration(
            secrets: [secret],
            backupService: backupService,
            confirmApplyChanges: { true },
            storeSecrets: { secrets in
                await stored.record(secrets)
                return storedSummary(for: secrets)
            }
        )

        #expect(result == .dryRun)
        let recorded = await stored.value
        #expect(recorded.isEmpty)
    }

    @Test("env migration leaves file unchanged when storage fails")
    func envMigrationLeavesFileUnchangedWhenStorageFails() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("scrape-env-\(UUID().uuidString).env").path
        let originalContent = "API_KEY=super-secret\n"
        try originalContent.write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let secret = DetectedSecret(
            filePath: path,
            lineNumber: 1,
            originalLine: "API_KEY=super-secret",
            key: "API_KEY",
            value: "super-secret",
            rawContent: nil,
            confidence: .high,
            type: .apiKey,
            entropy: 4.7,
            description: "api key",
            sshMetadata: nil
        )

        let backupService = BackupService(
            bridgeClient: BackupStub(),
            dateProvider: { Date() },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        var scrape = Scrape()
        scrape.quiet = true
        scrape.dryRun = false
        scrape.replaceAll = false
        scrape.folder = nil

        await #expect(throws: StorageFailure.self) {
            _ = try await scrape.handleEnvFileMigration(
                secrets: [secret],
                backupService: backupService,
                confirmApplyChanges: { true },
                storeSecrets: { _ in throw StorageFailure() }
            )
        }

        let afterFailure = try String(contentsOfFile: path, encoding: .utf8)
        #expect(afterFailure == originalContent)
        let modifiedFiles = await backupService.listModifiedFiles(activeOnly: true)
        #expect(modifiedFiles.isEmpty)
    }

    @Test("env migration leaves file unchanged when overwrite is declined")
    func envMigrationLeavesFileUnchangedWhenOverwriteDeclined() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("scrape-env-\(UUID().uuidString).env").path
        let originalContent = "PASSWORD=super-secret\n"
        try originalContent.write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let secret = DetectedSecret(
            filePath: path,
            lineNumber: 1,
            originalLine: "PASSWORD=super-secret",
            key: "PASSWORD",
            value: "super-secret",
            rawContent: nil,
            confidence: .high,
            type: .password,
            entropy: 4.7,
            description: "password",
            sshMetadata: nil
        )

        let backupService = BackupService(
            bridgeClient: BackupStub(),
            dateProvider: { Date() },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        var scrape = Scrape()
        scrape.quiet = true
        scrape.dryRun = false
        scrape.replaceAll = false
        scrape.folder = nil

        _ = try await scrape.handleEnvFileMigration(
            secrets: [secret],
            backupService: backupService,
            confirmApplyChanges: { true },
            storeSecrets: { _ in
                skippedSummary(for: secret)
            }
        )

        let afterSkip = try String(contentsOfFile: path, encoding: .utf8)
        #expect(afterSkip == originalContent)
        let modifiedFiles = await backupService.listModifiedFiles(activeOnly: true)
        #expect(modifiedFiles.isEmpty)
    }

    @Test("env migration removes created backup when rewrite fails")
    func envMigrationRemovesCreatedBackupWhenRewriteFails() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("scrape-env-\(UUID().uuidString).env").path
        let currentContent = "API_KEY=changed\n"
        try currentContent.write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let secret = DetectedSecret(
            filePath: path,
            lineNumber: 1,
            originalLine: "API_KEY=old-secret",
            key: "API_KEY",
            value: "old-secret",
            rawContent: nil,
            confidence: .high,
            type: .apiKey,
            entropy: 4.7,
            description: "api key",
            sshMetadata: nil
        )

        let backupService = BackupService(
            bridgeClient: BackupStub(),
            dateProvider: { Date() },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        var scrape = Scrape()
        scrape.quiet = true
        scrape.dryRun = false
        scrape.replaceAll = false
        scrape.folder = nil

        await #expect(throws: (any Error).self) {
            _ = try await scrape.handleEnvFileMigration(
                secrets: [secret],
                backupService: backupService,
                confirmApplyChanges: { true },
                storeSecrets: { storedSummary(for: $0) }
            )
        }

        #expect(try String(contentsOfFile: path, encoding: .utf8) == currentContent)
        let modifiedFiles = await backupService.listModifiedFiles(activeOnly: true)
        #expect(modifiedFiles.isEmpty)
    }

    @Test("shallow directory env migration backs up only direct files")
    func shallowDirectoryEnvMigrationBacksUpOnlyDirectFiles() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("scrape-backup-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let directPath = root.appendingPathComponent(".env")
        let nestedDirectory = root.appendingPathComponent("nested", isDirectory: true)
        try FileManager.default.createDirectory(at: nestedDirectory, withIntermediateDirectories: true)
        let nestedPath = nestedDirectory.appendingPathComponent(".env")
        let directOriginal = "DIRECT_API_KEY=sk_live_DIRECT_1234567890abcdef\n"
        let nestedOriginal = "NESTED_API_KEY=sk_live_NESTED_1234567890abcdef\n"
        try directOriginal.write(to: directPath, atomically: true, encoding: .utf8)
        try nestedOriginal.write(to: nestedPath, atomically: true, encoding: .utf8)

        let scanner = FileScannerService()
        let secrets = await scanner.scanPaths([root.path], detectionService: SecretDetectionService())
        #expect(Set(secrets.map(\.filePath)) == [directPath.path])

        let backupService = BackupService(
            bridgeClient: BackupStub(),
            dateProvider: { Date() },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )
        var scrape = Scrape()
        scrape.quiet = true
        scrape.dryRun = false
        scrape.replaceAll = true
        scrape.folder = nil

        _ = try await scrape.handleEnvFileMigration(
            secrets: secrets,
            backupService: backupService,
            storeSecrets: { storedSummary(for: $0) }
        )

        let modifiedFiles = await backupService.listModifiedFiles(activeOnly: true)
        #expect(modifiedFiles == [directPath.path])
        #expect(try String(contentsOf: nestedPath, encoding: .utf8) == nestedOriginal)
    }

    @Test("recursive directory env migration backs up direct and nested files")
    func recursiveDirectoryEnvMigrationBacksUpDirectAndNestedFiles() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("scrape-backup-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let directPath = root.appendingPathComponent(".env")
        let nestedDirectory = root.appendingPathComponent("nested", isDirectory: true)
        try FileManager.default.createDirectory(at: nestedDirectory, withIntermediateDirectories: true)
        let nestedPath = nestedDirectory.appendingPathComponent(".env")
        try "DIRECT_API_KEY=sk_live_DIRECT_1234567890abcdef\n"
            .write(to: directPath, atomically: true, encoding: .utf8)
        try "NESTED_API_KEY=sk_live_NESTED_1234567890abcdef\n"
            .write(to: nestedPath, atomically: true, encoding: .utf8)

        let scanner = FileScannerService()
        let secrets = await scanner.scanPaths(
            [root.path],
            detectionService: SecretDetectionService(),
            recursive: true
        )
        #expect(Set(secrets.map(\.filePath)) == [directPath.path, nestedPath.path])

        let backupService = BackupService(
            bridgeClient: BackupStub(),
            dateProvider: { Date() },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )
        var scrape = Scrape()
        scrape.quiet = true
        scrape.dryRun = false
        scrape.replaceAll = true
        scrape.folder = nil

        _ = try await scrape.handleEnvFileMigration(
            secrets: secrets,
            backupService: backupService,
            storeSecrets: { storedSummary(for: $0) }
        )

        let modifiedFiles = await backupService.listModifiedFiles(activeOnly: true)
        #expect(modifiedFiles == [directPath.path, nestedPath.path].sorted())
    }

    @Test("shell config migration creates no backup when storage fails")
    func shellConfigMigrationCreatesNoBackupWhenStorageFails() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("scrape-shell-\(UUID().uuidString).zshrc").path
        let originalContent = "export API_KEY=super-secret\n"
        try originalContent.write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let secret = DetectedSecret(
            filePath: path,
            lineNumber: 1,
            originalLine: "export API_KEY=super-secret",
            key: "API_KEY",
            value: "super-secret",
            rawContent: nil,
            confidence: .high,
            type: .apiKey,
            entropy: 4.7,
            description: "api key",
            sshMetadata: nil
        )

        let backupService = BackupService(
            bridgeClient: BackupStub(),
            dateProvider: { Date() },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        var scrape = Scrape()
        scrape.quiet = true
        scrape.dryRun = false
        scrape.replaceAll = false
        scrape.folder = nil

        await #expect(throws: StorageFailure.self) {
            _ = try await scrape.handleShellConfigMigration(
                secrets: [secret],
                shellConfigService: ShellConfigService(),
                backupService: backupService,
                confirmApplyChanges: { true },
                storeSecrets: { _ in throw StorageFailure() }
            )
        }

        let afterFailure = try String(contentsOfFile: path, encoding: .utf8)
        #expect(afterFailure == originalContent)
        let modifiedFiles = await backupService.listModifiedFiles(activeOnly: true)
        #expect(modifiedFiles.isEmpty)
    }

    @Test("shell config migration leaves file unchanged when overwrite is declined")
    func shellConfigMigrationLeavesFileUnchangedWhenOverwriteDeclined() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("scrape-shell-\(UUID().uuidString).zshrc").path
        let originalContent = "PASSWORD=super-secret\n"
        try originalContent.write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let secret = DetectedSecret(
            filePath: path,
            lineNumber: 1,
            originalLine: "PASSWORD=super-secret",
            key: "PASSWORD",
            value: "super-secret",
            rawContent: nil,
            confidence: .high,
            type: .password,
            entropy: 4.7,
            description: "password",
            sshMetadata: nil
        )

        let backupService = BackupService(
            bridgeClient: BackupStub(),
            dateProvider: { Date() },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        var scrape = Scrape()
        scrape.quiet = true
        scrape.dryRun = false
        scrape.replaceAll = false
        scrape.folder = nil

        _ = try await scrape.handleShellConfigMigration(
            secrets: [secret],
            shellConfigService: ShellConfigService(),
            backupService: backupService,
            confirmApplyChanges: { true },
            storeSecrets: { _ in
                skippedSummary(for: secret)
            }
        )

        let afterSkip = try String(contentsOfFile: path, encoding: .utf8)
        #expect(afterSkip == originalContent)
        let modifiedFiles = await backupService.listModifiedFiles(activeOnly: true)
        #expect(modifiedFiles.isEmpty)
    }

    @Test("no-change migration result reports no selected secrets stored")
    func noChangeMigrationResultReportsNoSelectedSecretsStored() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("scrape-env-\(UUID().uuidString).env").path
        try "PASSWORD=super-secret\n".write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let secret = DetectedSecret(
            filePath: path,
            lineNumber: 1,
            originalLine: "PASSWORD=super-secret",
            key: "PASSWORD",
            value: "super-secret",
            rawContent: nil,
            confidence: .high,
            type: .password,
            entropy: 4.7,
            description: "password",
            sshMetadata: nil
        )

        let backupService = BackupService(
            bridgeClient: BackupStub(),
            dateProvider: { Date() },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        var scrape = Scrape()
        scrape.quiet = true
        scrape.dryRun = false
        scrape.replaceAll = false
        scrape.folder = nil

        let result = try await scrape.handleEnvFileMigration(
            secrets: [secret],
            backupService: backupService,
            confirmApplyChanges: { true },
            storeSecrets: { _ in skippedSummary(for: secret) }
        )

        #expect(result == .noChanges)
    }

    @Test("migration completion message distinguishes no changes and dry run")
    func migrationCompletionMessageDistinguishesNoChangesAndDryRun() {
        #expect(Scrape.migrationCompletionMessage(didApplyChanges: false, didDryRun: false) == "No changes applied.")
        #expect(
            Scrape.migrationCompletionMessage(didApplyChanges: false, didDryRun: true) ==
                "🔍 Dry run complete. No changes made."
        )
        #expect(Scrape.migrationCompletionMessage(didApplyChanges: true, didDryRun: true) == "✅ Migration complete!")
    }
}

private func storedSummary(for secrets: [DetectedSecret]) -> ScrapeMigrationSummary {
    ScrapeMigrationSummary(
        addedCount: secrets.count,
        skippedCount: 0,
        failed: [],
        results: secrets.map { ScrapeMigrationResult(secret: $0, outcome: .added) }
    )
}

private func skippedSummary(for secret: DetectedSecret) -> ScrapeMigrationSummary {
    ScrapeMigrationSummary(
        addedCount: 0,
        skippedCount: 1,
        failed: [],
        results: [ScrapeMigrationResult(secret: secret, outcome: .skipped)]
    )
}

private actor StoredSecretsBox {
    private(set) var value: [DetectedSecret] = []
    func record(_ secrets: [DetectedSecret]) { value.append(contentsOf: secrets) }
}

private struct StorageFailure: Error {}
