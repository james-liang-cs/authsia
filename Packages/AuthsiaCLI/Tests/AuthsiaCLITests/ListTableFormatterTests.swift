import Foundation
import Testing
import AuthenticatorBridge
import AuthenticatorCore
@testable import authsia

@Suite("List table formatter")
struct ListTableFormatterTests {
    @Test("OTP table shows ID after Favorite")
    func otpTableShowsIDAfterFavorite() throws {
        let id = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
        let output = TableFormatter.formatOTPItems([
            BridgeAccount(
                id: id,
                issuer: "GitHub",
                label: "alice@example.com",
                isFavorite: true,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 0),
                updatedAt: Date(timeIntervalSince1970: 0)
            ),
        ])

        try assertIDColumnAfterFavorite(in: output, id: id.uuidString)
    }

    @Test("password table shows ID after Favorite")
    func passwordTableShowsIDAfterFavorite() throws {
        let id = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        let output = TableFormatter.formatPasswords([
            BridgePassword(
                id: id,
                name: "API_KEY",
                username: "",
                website: nil,
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 0),
                updatedAt: Date(timeIntervalSince1970: 0)
            ),
        ])

        try assertIDColumnAfterFavorite(in: output, id: id.uuidString)
    }

    @Test("vault tables show default and named environments")
    func vaultTablesShowDefaultAndNamedEnvironments() throws {
        let `default` = TableFormatter.formatPasswords([
            BridgePassword(
                id: UUID(),
                name: "DEFAULT_ITEM",
                username: "",
                website: nil,
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 0),
                updatedAt: Date(timeIntervalSince1970: 0)
            ),
        ])
        let tagged = TableFormatter.formatAPIKeys([
            BridgeAPIKey(
                id: UUID(),
                name: "Tagged",
                website: nil,
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 0),
                updatedAt: Date(timeIntervalSince1970: 0),
                environments: ["Development", "Production"]
            ),
        ])

        #expect(`default`.contains("Environments"))
        #expect(`default`.contains("Default"))
        #expect(tagged.contains("Development, Production"))
    }

    @Test("password table shows item expiry")
    func passwordTableShowsItemExpiry() throws {
        let expiresAt = Date(timeIntervalSince1970: 1_800_000_000)
        let output = TableFormatter.formatPasswords([
            BridgePassword(
                id: UUID(uuidString: "77777777-7777-7777-7777-777777777777")!,
                name: "API_KEY",
                username: "",
                website: nil,
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 0),
                updatedAt: Date(timeIntervalSince1970: 0),
                expiresAt: expiresAt
            ),
        ])

        try assertExpiresColumn(in: output, expectedValue: shortDateString(from: expiresAt))
    }

    @Test("api key table shows ID after Favorite and omits username")
    func apiKeyTableShowsIDAfterFavoriteAndOmitsUsername() throws {
        let id = UUID(uuidString: "88888888-8888-8888-8888-888888888888")!
        let output = TableFormatter.formatAPIKeys([
            BridgeAPIKey(
                id: id,
                name: "Stripe",
                website: nil,
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 0),
                updatedAt: Date(timeIntervalSince1970: 0)
            ),
        ])

        try assertIDColumnAfterFavorite(in: output, id: id.uuidString)
        #expect(!columns(from: output.split(separator: "\n").map(String.init)[1]).contains("Username"))
    }

    @Test("certificate table shows ID after Favorite")
    func certificateTableShowsIDAfterFavorite() throws {
        let id = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
        let output = TableFormatter.formatCertificates([
            BridgeCertificate(
                id: id,
                name: "TLS_CERT",
                issuer: nil,
                subject: nil,
                expirationDate: nil,
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 0),
                updatedAt: Date(timeIntervalSince1970: 0)
            ),
        ])

        try assertIDColumnAfterFavorite(in: output, id: id.uuidString)
    }

    @Test("note table shows ID after Favorite")
    func noteTableShowsIDAfterFavorite() throws {
        let id = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!
        let output = TableFormatter.formatNotes([
            BridgeNote(
                id: id,
                title: "Runbook",
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 0),
                updatedAt: Date(timeIntervalSince1970: 0)
            ),
        ])

        try assertIDColumnAfterFavorite(in: output, id: id.uuidString)
    }

    @Test("SSH table shows ID after Favorite")
    func sshTableShowsIDAfterFavorite() throws {
        let id = UUID(uuidString: "55555555-5555-5555-5555-555555555555")!
        let output = TableFormatter.formatSSHKeys([
            BridgeSSHKey(
                id: id,
                name: "deploy",
                comment: "deploy",
                fingerprint: "SHA256:abc",
                publicKey: "ssh-ed25519 AAAA",
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 0),
                updatedAt: Date(timeIntervalSince1970: 0)
            ),
        ])

        try assertIDColumnAfterFavorite(in: output, id: id.uuidString)
    }

    @Test("SSH table omits public key column")
    func sshTableOmitsPublicKeyColumn() throws {
        let publicKey = "ssh-ed25519 AAAA"
        let output = TableFormatter.formatSSHKeys([
            BridgeSSHKey(
                id: UUID(uuidString: "66666666-6666-6666-6666-666666666666")!,
                name: "deploy",
                comment: "deploy",
                fingerprint: "SHA256:abc",
                publicKey: publicKey,
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: Date(timeIntervalSince1970: 0),
                updatedAt: Date(timeIntervalSince1970: 0)
            ),
        ])

        let lines = output.split(separator: "\n").map(String.init)
        #expect(lines.count >= 4)
        let headers = columns(from: lines[1])

        #expect(!headers.contains("Public Key"))
        #expect(!output.contains(publicKey))
    }

    @Test("backup table shows file and backup note path")
    func backupTableShowsFileAndBackupNotePath() throws {
        let output = TableFormatter.formatBackups([
            BackupService.BackupEntry(
                id: "backup-1",
                originalPath: "/Users/example/.zshrc",
                folderPath: "Team/API/Authsia Backups",
                backupNoteId: "note-1",
                backupNoteName: "authsia_backup_team_api_zshrc_20260612_123000",
                timestamp: Date(timeIntervalSince1970: 0),
                description: "baseline",
                kind: .scrape,
                slot: .baseline,
                fileHash: "abc123",
                isRestored: false,
                hostname: "James-MacBook.local",
                machineId: "MACHINE-A"
            )
        ])

        let lines = output.split(separator: "\n").map(String.init)
        #expect(lines.count >= 4)
        let headers = columns(from: lines[1])
        let row = columns(from: lines[3])

        #expect(headers == ["File", "Machine", "Created", "Status", "Slot", "Backup Note Path"])
        #expect(row[0] == "/Users/example/.zshrc")
        #expect(row[1] == "James-MacBook")
        #expect(row[3] == "active")
        #expect(row[4] == "original")
        #expect(row[5] == "Team/API/Authsia Backups/authsia_backup_team_api_zshrc_20260612_123000")
    }

    private func assertIDColumnAfterFavorite(in output: String, id: String) throws {
        let lines = output.split(separator: "\n").map(String.init)
        #expect(lines.count >= 4)
        let headers = columns(from: lines[1])
        let row = columns(from: lines[3])
        let favoriteIndex = try #require(headers.firstIndex(of: "Favorite"))

        #expect(headers.contains("ID"))
        #expect(headers[favoriteIndex + 1] == "ID")
        #expect(row[favoriteIndex + 1] == id)
    }

    private func assertExpiresColumn(in output: String, expectedValue: String) throws {
        let lines = output.split(separator: "\n").map(String.init)
        #expect(lines.count >= 4)
        let headers = columns(from: lines[1])
        let row = columns(from: lines[3])
        let expiresIndex = try #require(headers.firstIndex(of: "Expires"))

        #expect(row[expiresIndex] == expectedValue)
    }

    private func shortDateString(from date: Date) -> String {
        let dateFormatter = DateFormatter()
        dateFormatter.dateStyle = .short
        return dateFormatter.string(from: date)
    }

    private func columns(from line: String) -> [String] {
        let parts = line
            .split(separator: "|", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        return Array(parts.dropFirst().dropLast())
    }
}
