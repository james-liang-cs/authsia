import Testing
import Foundation
import AuthenticatorBridge
@testable import authsia

@Suite("BackupService machine filtering")
struct BackupServiceFilterTests {

    private func makeEntry(id: String, path: String, machineId: String?, hostname: String?, restored: Bool = false) -> BackupService.BackupEntry {
        BackupService.BackupEntry(
            id: id,
            originalPath: path,
            folderPath: nil,
            backupNoteId: nil,
            backupNoteName: "authsia_backup_test",
            timestamp: Date(),
            description: "",
            fileHash: "hash",
            isRestored: restored,
            hostname: hostname,
            machineId: machineId
        )
    }

    @Test("matchesMachine returns true when machineId matches")
    func matchesByMachineId() {
        let entry = makeEntry(id: "1", path: "/tmp/f", machineId: "MACHINE-A", hostname: "mac-a")
        #expect(entry.matchesMachine(machineId: "MACHINE-A"))
    }

    @Test("matchesMachine returns false when machineId differs")
    func doesNotMatchDifferentMachine() {
        let entry = makeEntry(id: "1", path: "/tmp/f", machineId: "MACHINE-B", hostname: "mac-b")
        #expect(!entry.matchesMachine(machineId: "MACHINE-A"))
    }

    @Test("matchesMachine returns true for legacy entry with nil machineId")
    func legacyEntryAlwaysMatches() {
        // Legacy entries (no machineId) are treated as belonging to current machine
        // to avoid silently hiding pre-existing backups after upgrade.
        let entry = makeEntry(id: "1", path: "/tmp/f", machineId: nil, hostname: nil)
        #expect(entry.matchesMachine(machineId: "MACHINE-A"))
    }
}

// MARK: - Single-backup invariant

@Suite("BackupService backup retention")
struct BackupServiceSingleBackupTests {

    /// Minimal stub: records add/delete calls, returns canned IDs.
    final class StubClient: BackupVaultClient, @unchecked Sendable {
        var addedNotes: [(title: String, content: String, isScraped: Bool, folderPath: String?)] = []
        var manifestFolderPaths: [String?] = []
        var updatedNotes: [(query: String, title: String?, content: String?, isScraped: Bool?, folderPath: String?)] = []
        var deletedQueries: [String] = []
        var noteContents: [String: String] = [:]
        var manifestContents: [String: String] = [:]
        var manifestNotes: [(id: UUID, title: String, folderPath: String?)] = []
        var regularNotes: [(id: UUID, title: String, folderPath: String?)] = []
        var shouldThrowOnList = false
        var shouldThrowOnManifestSave = false

        private let emptyManifestContent = """
        {"version":"1.0","lastUpdated":"2026-01-01T00:00:00Z","backups":[]}
        """

        func manifestContent(for query: String) -> String {
            if let content = manifestContents[query] {
                return content
            }
            let hashedMatches = manifestContents.keys.filter { $0.hasPrefix("\(query)__") }
            if hashedMatches.count == 1, let key = hashedMatches.first {
                return manifestContents[key] ?? emptyManifestContent
            }
            return emptyManifestContent
        }

        func addNote(title: String, content: String, isScraped: Bool, folderPath: String?) throws -> WriteResult {
            if title.hasPrefix("authsia_scrape_backups") {
                if shouldThrowOnManifestSave {
                    throw BridgeClientError.connectionFailed
                }
                manifestContents[title] = content
                manifestFolderPaths.append(folderPath)
                return WriteResult(id: title, message: "added")
            } else {
                let id = "note-\(addedNotes.count + 1)"
                addedNotes.append((title: title, content: content, isScraped: isScraped, folderPath: folderPath))
                noteContents[id] = content
                noteContents[title] = content
                return WriteResult(id: id, message: "added")
            }
        }

        func updateNote(query: String, title: String?, content: String?, isScraped: Bool?, folderPath: String?) throws -> WriteResult {
            updatedNotes.append((query: query, title: title, content: content, isScraped: isScraped, folderPath: folderPath))
            if manifestContents[query] != nil, let c = content {
                if shouldThrowOnManifestSave {
                    throw BridgeClientError.connectionFailed
                }
                manifestContents[query] = c
                manifestFolderPaths.append(folderPath)
                return WriteResult(id: query, message: "updated")
            }
            if query.hasPrefix("authsia_scrape_backups"), let c = content {
                if shouldThrowOnManifestSave {
                    throw BridgeClientError.connectionFailed
                }
                manifestContents[query] = c
                manifestFolderPaths.append(folderPath)
                return WriteResult(id: query, message: "updated")
            }
            if let c = content {
                noteContents[query] = c
            }
            return WriteResult(id: query, message: "updated")
        }

        func getNote(query: String) throws -> NoteResult {
            if let content = manifestContents[query] {
                return NoteResult(
                    id: query,
                    title: query,
                    content: content,
                    createdAt: Date(),
                    modifiedAt: Date(),
                    isFavorite: false
                )
            }
            if query.hasPrefix("authsia_scrape_backups") {
                throw BridgeClientError.bridgeError(code: "notFound", message: "not found", query: query)
            }
            if let content = noteContents[query] {
                return NoteResult(
                    id: query,
                    title: query,
                    content: content,
                    createdAt: Date(),
                    modifiedAt: Date(),
                    isFavorite: false
                )
            }
            throw BridgeClientError.bridgeError(code: "notFound", message: "not found", query: query)
        }

        func deleteNote(query: String) throws -> WriteResult {
            deletedQueries.append(query)
            noteContents.removeValue(forKey: query)
            manifestContents.removeValue(forKey: query)
            return WriteResult(id: query, message: "deleted")
        }

        func list() throws -> BridgeListPayload {
            if shouldThrowOnList {
                throw BridgeClientError.connectionFailed
            }

            return BridgeListPayload(
                accounts: [],
                passwords: [],
                certificates: [],
                notes: manifestNotes.map { note in
                    BridgeNote(
                        id: note.id,
                        title: note.title,
                        folderPath: note.folderPath,
                        isFavorite: false,
                        isCliEnabled: false,
                        isScraped: false,
                        createdAt: Date(),
                        updatedAt: Date()
                    )
                } + regularNotes.map { note in
                    BridgeNote(
                        id: note.id,
                        title: note.title,
                        folderPath: note.folderPath,
                        isFavorite: false,
                        isCliEnabled: false,
                        isScraped: false,
                        createdAt: Date(),
                        updatedAt: Date()
                    )
                },
                sshKeys: []
            )
        }
    }

    private func writeTempFile(_ content: String) throws -> String {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("backup-test-\(UUID().uuidString).env").path
        try content.write(toFile: path, atomically: true, encoding: .utf8)
        return path
    }

    private func encodeManifest(_ entries: [BackupService.BackupEntry]) throws -> String {
        let manifest = BackupService.Manifest(
            version: "1.0",
            lastUpdated: Date(timeIntervalSince1970: 1_706_000_000),
            backups: entries
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return String(data: try encoder.encode(manifest), encoding: .utf8) ?? "{}"
    }

    private func makeBackupEntry(
        id: String,
        path: String,
        folderPath: String?,
        backupNoteId: String = "legacy-note",
        description: String = "legacy backup",
        restored: Bool = false,
        slot: BackupService.BackupSlot = .latest
    ) -> BackupService.BackupEntry {
        BackupService.BackupEntry(
            id: id,
            originalPath: path,
            folderPath: folderPath,
            backupNoteId: backupNoteId,
            backupNoteName: "authsia_backup_legacy_20260101_120000",
            timestamp: Date(timeIntervalSince1970: 1_767_266_400),
            description: description,
            slot: slot,
            fileHash: "abc123",
            isRestored: restored,
            hostname: "test-mac.local",
            machineId: "MACHINE-A"
        )
    }

    @Test("scrape backups preserve original baseline and replace latest copy")
    func scrapeBackupsPreserveOriginalBaselineAndReplaceLatestCopy() async throws {
        let stub = StubClient()
        let service = BackupService(
            bridgeClient: stub,
            dateProvider: { Date() },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        let path = try writeTempFile("original content")
        defer { try? FileManager.default.removeItem(atPath: path) }

        // First backup
        _ = try await service.createBackup(of: path, originalContent: "original content", description: "first")

        let countAfterFirst = stub.addedNotes.count
        #expect(countAfterFirst == 1)
        #expect(stub.deletedQueries.isEmpty)
        #expect(stub.manifestContent(for: "authsia_scrape_backups_manifest__authsia_backups").contains(#""slot" : "baseline""#))

        // Write new content and take second backup
        _ = try await service.createBackup(of: path, originalContent: "updated content", description: "second")

        #expect(stub.addedNotes.count == 2)
        #expect(stub.deletedQueries.isEmpty)

        // Manifest should keep the original baseline plus the latest pre-change copy.
        let manifestData = Data(stub.manifestContent(for: "authsia_scrape_backups_manifest__authsia_backups").utf8)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let manifest = try decoder.decode(BackupService.Manifest.self, from: manifestData)
        let entries = manifest.backups.filter { $0.originalPath == path }
        #expect(entries.count == 2)
        #expect(entries.map(\.description).sorted() == ["first", "second"])

        // A later scrape replaces only the latest copy.
        _ = try await service.createBackup(of: path, originalContent: "third content", description: "third")

        #expect(stub.addedNotes.count == 3)
        #expect(stub.deletedQueries == ["note-2"])

        let updatedManifestData = Data(stub.manifestContent(for: "authsia_scrape_backups_manifest__authsia_backups").utf8)
        let updatedManifest = try decoder.decode(BackupService.Manifest.self, from: updatedManifestData)
        let updatedEntries = updatedManifest.backups.filter { $0.originalPath == path }
        #expect(updatedEntries.count == 2)
        #expect(updatedEntries.map(\.description).sorted() == ["first", "third"])
    }

    @Test("created backup stores a standardized absolute original path")
    func createdBackupStoresStandardizedAbsoluteOriginalPath() async throws {
        let stub = StubClient()
        let service = BackupService(
            bridgeClient: stub,
            dateProvider: { Date() },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("backup-path-\(UUID().uuidString)", isDirectory: true)
        let nested = root.appendingPathComponent("nested", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let file = root.appendingPathComponent(".env")
        try "content".write(to: file, atomically: true, encoding: .utf8)
        let unstandardizedPath = nested.appendingPathComponent("../.env").path

        let entry = try await service.createBackup(
            of: unstandardizedPath,
            originalContent: "content",
            description: "path normalization"
        )

        #expect(entry.originalPath == file.path)
    }

    @Test("restore original backup uses preserved baseline while default restore uses latest")
    func restoreOriginalBackupUsesPreservedBaselineWhileDefaultRestoreUsesLatest() async throws {
        let stub = StubClient()
        let service = BackupService(
            bridgeClient: stub,
            dateProvider: { Date() },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        let path = try writeTempFile("current")
        defer { try? FileManager.default.removeItem(atPath: path) }

        _ = try await service.createBackup(of: path, originalContent: "original content", description: "first")
        _ = try await service.createBackup(of: path, originalContent: "after first scrape", description: "second")

        let latestPreview = try await service.previewMostRecentRestore(of: path)
        #expect(latestPreview.entry.slot == .latest)
        let originalPreview = try await service.previewOriginalRestore(of: path)
        #expect(originalPreview.entry.slot == .baseline)

        _ = try await service.restoreMostRecentBackup(of: path)
        #expect(try String(contentsOfFile: path, encoding: .utf8) == "after first scrape")

        _ = try await service.restoreOriginalBackup(of: path)
        #expect(try String(contentsOfFile: path, encoding: .utf8) == "original content")
    }

    @Test("restore preview shows diff with backup note path and redacted secret values")
    func restorePreviewShowsDiffWithBackupNotePathAndRedactedSecretValues() async throws {
        let stub = StubClient()
        let service = BackupService(
            bridgeClient: stub,
            dateProvider: { Date(timeIntervalSince1970: 1_767_266_400) },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        let path = try writeTempFile("API_KEY=authsia://password/API_KEY/password\nSAFE=true\n")
        defer { try? FileManager.default.removeItem(atPath: path) }

        _ = try await service.createBackup(
            of: path,
            originalContent: "API_KEY=real-secret-value\nSAFE=true\n",
            description: "first"
        )

        let preview = try await service.previewMostRecentRestore(of: path)

        #expect(preview.diff.contains("--- current \(path)"))
        #expect(preview.diff.contains("+++ backup Authsia Backups/"))
        #expect(preview.diff.contains("-API_KEY=authsia://password/API_KEY/password"))
        #expect(preview.diff.contains("+API_KEY=<concealed by authsia>"))
        #expect(!preview.diff.contains("real-secret-value"))
        #expect(try String(contentsOfFile: path, encoding: .utf8).contains("authsia://password/API_KEY/password"))
    }

    @Test("scrape revert does not restore when preview confirmation is declined")
    func scrapeRevertDoesNotRestoreWhenPreviewConfirmationIsDeclined() async throws {
        let stub = StubClient()
        let service = BackupService(
            bridgeClient: stub,
            dateProvider: { Date(timeIntervalSince1970: 1_767_266_400) },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        let currentContent = "API_KEY=authsia://password/API_KEY/password\n"
        let path = try writeTempFile(currentContent)
        defer { try? FileManager.default.removeItem(atPath: path) }

        _ = try await service.createBackup(
            of: path,
            originalContent: "API_KEY=real-secret-value\n",
            description: "first"
        )

        let scrape = Scrape()
        try await scrape.handleRevert(
            backupService: service,
            path: path,
            machine: nil,
            confirmProceed: { false },
            confirmDeleteBackup: {
                Issue.record("Delete confirmation should not run when restore is cancelled.")
                return false
            }
        )

        #expect(try String(contentsOfFile: path, encoding: .utf8) == currentContent)
        let backups = await service.listBackups(for: path)
        #expect(backups.first?.isRestored == false)
    }

    @Test("scrape revert original can reuse a restored baseline after a later scrape")
    func scrapeRevertOriginalCanReuseRestoredBaselineAfterLaterScrape() async throws {
        let stub = StubClient()
        let service = BackupService(
            bridgeClient: stub,
            dateProvider: { Date(timeIntervalSince1970: 1_767_266_400) },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        let originalContent = "PASSWORD=original-secret\n"
        let path = try writeTempFile("PASSWORD=authsia://password/PASSWORD/password\n")
        defer { try? FileManager.default.removeItem(atPath: path) }

        _ = try await service.createBackup(of: path, originalContent: originalContent, description: "first")
        _ = try await service.createBackup(
            of: path,
            originalContent: "PASSWORD=first-migrated\n",
            description: "second"
        )

        _ = try await service.restoreOriginalBackup(of: path)
        #expect(try String(contentsOfFile: path, encoding: .utf8) == originalContent)

        try "PASSWORD=authsia://password/PASSWORD/password\n".write(toFile: path, atomically: true, encoding: .utf8)
        _ = try await service.createBackup(
            of: path,
            originalContent: "PASSWORD=second-migrated\n",
            description: "third"
        )

        let scrape = Scrape()
        try await scrape.handleRevertOriginal(
            backupService: service,
            path: path,
            machine: nil,
            confirmProceed: { true },
            confirmDeleteBackups: { false }
        )

        #expect(try String(contentsOfFile: path, encoding: .utf8) == originalContent)
    }

    @Test("cleanup after original restore deletes all scrape backups for the file")
    func cleanupAfterOriginalRestoreDeletesAllScrapeBackupsForFile() async throws {
        let stub = StubClient()
        let service = BackupService(
            bridgeClient: stub,
            dateProvider: { Date() },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        let path = try writeTempFile("current")
        let otherPath = try writeTempFile("other current")
        defer {
            try? FileManager.default.removeItem(atPath: path)
            try? FileManager.default.removeItem(atPath: otherPath)
        }

        _ = try await service.createBackup(of: path, originalContent: "original content", description: "first")
        _ = try await service.createBackup(of: path, originalContent: "after first scrape", description: "second")
        _ = try await service.createBackup(of: otherPath, originalContent: "other original", description: "other")
        _ = try await service.restoreOriginalBackup(of: path)

        let deleted = try await service.deleteScrapeBackups(for: path)

        #expect(deleted.map(\.description).sorted() == ["first", "second"])
        #expect(stub.deletedQueries.contains("note-1"))
        #expect(stub.deletedQueries.contains("note-2"))
        #expect(!stub.deletedQueries.contains("note-3"))

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let manifest = try decoder.decode(
            BackupService.Manifest.self,
            from: Data(stub.manifestContent(for: "authsia_scrape_backups_manifest__authsia_backups").utf8)
        )
        #expect(manifest.backups.map(\.originalPath) == [otherPath])
    }

    @Test("failed replacement save keeps previous backup note and manifest entry")
    func failedReplacementSaveKeepsPreviousBackupNoteAndManifestEntry() async throws {
        let stub = StubClient()
        let service = BackupService(
            bridgeClient: stub,
            dateProvider: { Date() },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        let path = try writeTempFile("original content")
        defer { try? FileManager.default.removeItem(atPath: path) }

        _ = try await service.createBackup(of: path, originalContent: "original content", description: "first")

        stub.shouldThrowOnManifestSave = true

        await #expect(throws: BridgeClientError.self) {
            _ = try await service.createBackup(of: path, originalContent: "updated content", description: "second")
        }

        #expect(!stub.deletedQueries.contains("note-1"))

        let manifestData = Data(stub.manifestContent(for: "authsia_scrape_backups_manifest__authsia_backups").utf8)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let manifest = try decoder.decode(BackupService.Manifest.self, from: manifestData)
        let entries = manifest.backups.filter { $0.originalPath == path }
        #expect(entries.map(\.description) == ["first"])
    }

    @Test("created scrape backup manifest entry records kind")
    func createdScrapeBackupManifestEntryRecordsKind() async throws {
        let stub = StubClient()
        let service = BackupService(
            bridgeClient: stub,
            dateProvider: { Date() },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        let path = try writeTempFile("content")
        defer { try? FileManager.default.removeItem(atPath: path) }

        _ = try await service.createBackup(of: path, originalContent: "content")

        let manifestContent = stub.manifestContent(for: "authsia_scrape_backups_manifest__authsia_backups")
        #expect(manifestContent.contains(#""kind" : "scrape""#))
    }

    @Test("backups for different files accumulate independently")
    func differentFilesAccumulate() async throws {
        let stub = StubClient()
        let service = BackupService(
            bridgeClient: stub,
            dateProvider: { Date() },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        let path1 = try writeTempFile("content1")
        let path2 = try writeTempFile("content2")
        defer {
            try? FileManager.default.removeItem(atPath: path1)
            try? FileManager.default.removeItem(atPath: path2)
        }

        _ = try await service.createBackup(of: path1, originalContent: "content1")
        _ = try await service.createBackup(of: path2, originalContent: "content2")

        // No deletions — different files don't replace each other
        #expect(stub.deletedQueries.isEmpty)
        #expect(stub.addedNotes.count == 2)

        let manifestData = Data(stub.manifestContent(for: "authsia_scrape_backups_manifest__authsia_backups").utf8)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let manifest = try decoder.decode(BackupService.Manifest.self, from: manifestData)
        #expect(manifest.backups.count == 2)
    }

    @Test("delete backup removes empty manifest note")
    func deleteBackupRemovesEmptyManifestNote() async throws {
        let stub = StubClient()
        let service = BackupService(
            bridgeClient: stub,
            dateProvider: { Date() },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        let path = try writeTempFile("content")
        defer { try? FileManager.default.removeItem(atPath: path) }

        _ = try await service.createBackup(of: path, originalContent: "content")
        let backup = try #require(await service.listBackups(for: path).first)
        try await service.deleteBackup(entry: backup)

        #expect(stub.deletedQueries == ["note-1", "authsia_scrape_backups_manifest__authsia_backups"])
    }

    @Test("root backups are stored under Authsia Backups folder")
    func rootBackupsUseDedicatedFolder() async throws {
        let stub = StubClient()
        let service = BackupService(
            bridgeClient: stub,
            dateProvider: { Date(timeIntervalSince1970: 1_706_000_000) },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        let path = try writeTempFile("content")
        defer { try? FileManager.default.removeItem(atPath: path) }

        _ = try await service.createBackup(of: path, originalContent: "content")

        #expect(stub.addedNotes.first?.folderPath == "Authsia Backups")
        #expect(stub.manifestFolderPaths.last == "Authsia Backups")
    }

    @Test("legacy folder manifests migrate into root Authsia Backups automatically")
    func legacyFolderManifestsMigrateIntoRootAuthsiaBackupsAutomatically() async throws {
        let stub = StubClient()
        let legacyManifestID = UUID()
        let path = try writeTempFile("current")
        defer { try? FileManager.default.removeItem(atPath: path) }

        stub.noteContents["legacy-note"] = "legacy original"
        stub.manifestNotes = [(
            id: legacyManifestID,
            title: "authsia_scrape_backups_manifest__team_api_authsia_backups",
            folderPath: "Team/API/Authsia Backups"
        )]
        stub.manifestContents[legacyManifestID.uuidString] = try encodeManifest([
            makeBackupEntry(
                id: "legacy-1",
                path: path,
                folderPath: "Team/API/Authsia Backups",
                backupNoteId: "legacy-note"
            )
        ])

        let service = BackupService(
            bridgeClient: stub,
            dateProvider: { Date(timeIntervalSince1970: 1_706_000_000) },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        let backups = await service.listBackups(for: path)

        #expect(backups.map(\.id) == ["legacy-1"])
        #expect(backups.first?.folderPath == "Authsia Backups")
        #expect(stub.updatedNotes.contains {
            $0.query == "legacy-note" &&
                $0.content == nil &&
                $0.folderPath == "Authsia Backups"
        })

        let rootManifestData = Data(
            stub.manifestContent(for: "authsia_scrape_backups_manifest__authsia_backups").utf8
        )
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let rootManifest = try decoder.decode(BackupService.Manifest.self, from: rootManifestData)
        #expect(rootManifest.backups.map(\.id) == ["legacy-1"])
        #expect(rootManifest.backups.first?.folderPath == "Authsia Backups")
    }

    @Test("legacy manifest migration does not expose fallback entries when root save fails")
    func legacyManifestMigrationDoesNotExposeFallbackEntriesWhenRootSaveFails() async throws {
        let stub = StubClient()
        let legacyManifestID = UUID()
        let path = try writeTempFile("current")
        defer { try? FileManager.default.removeItem(atPath: path) }

        stub.shouldThrowOnManifestSave = true
        stub.noteContents["legacy-note"] = "legacy original"
        stub.manifestNotes = [(
            id: legacyManifestID,
            title: "authsia_scrape_backups_manifest__team_api_authsia_backups",
            folderPath: "Team/API/Authsia Backups"
        )]
        stub.manifestContents[legacyManifestID.uuidString] = try encodeManifest([
            makeBackupEntry(
                id: "legacy-1",
                path: path,
                folderPath: "Team/API/Authsia Backups",
                backupNoteId: "legacy-note"
            )
        ])

        let service = BackupService(
            bridgeClient: stub,
            dateProvider: { Date(timeIntervalSince1970: 1_706_000_000) },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        let backups = await service.listBackups(for: path)

        #expect(backups.isEmpty)
        #expect(!stub.updatedNotes.contains {
            $0.query == "legacy-note" &&
                $0.content == nil &&
                $0.folderPath == "Authsia Backups"
        })
    }

    @Test("active modified files exclude restored-only backups")
    func activeModifiedFilesExcludeRestoredOnlyBackups() async throws {
        let stub = StubClient()
        let path = try writeTempFile("stub")
        defer { try? FileManager.default.removeItem(atPath: path) }

        stub.noteContents["restored-note"] = "original"
        stub.manifestContents["authsia_scrape_backups_manifest__authsia_backups"] = try encodeManifest([
            makeBackupEntry(
                id: "restored",
                path: path,
                folderPath: "Authsia Backups",
                backupNoteId: "restored-note",
                restored: true
            )
        ])

        let service = BackupService(
            bridgeClient: stub,
            dateProvider: { Date(timeIntervalSince1970: 1_706_000_000) },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        let visibleFiles = await service.listModifiedFiles()
        let activeFiles = await service.listModifiedFiles(activeOnly: true)

        #expect(visibleFiles == [path])
        #expect(activeFiles.isEmpty)
    }
}
