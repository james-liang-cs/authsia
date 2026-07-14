import Foundation
import CryptoKit
import AuthenticatorBridge

actor BackupService {
    
    private let baseManifestNoteName = "authsia_scrape_backups_manifest"
    private let bridgeClient: BackupVaultClient
    private let dateProvider: () -> Date
    private let backupFolderPath: String
    private var didAttemptLegacyManifestMigration = false
    private let currentMachineId: String
    private let currentHostname: String
    private static let backupFolderName = "Authsia Backups"

    enum BackupKind: String, Codable {
        case scrape
        case sshAdoption

        static func inferred(from description: String) -> BackupKind {
            description.localizedCaseInsensitiveContains("ssh adopt") ? .sshAdoption : .scrape
        }
    }

    enum BackupSlot: String, Codable {
        case baseline
        case latest
    }

    private static let timestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMdd_HHmmss"
        return formatter
    }()
    
    struct BackupEntry: Codable, Identifiable {
        let id: String
        let originalPath: String
        let folderPath: String?
        let backupNoteId: String?
        let backupNoteName: String
        let timestamp: Date
        let description: String
        let kind: BackupKind
        let slot: BackupSlot
        let fileHash: String
        var isRestored: Bool
        // nil on entries created before this feature (backward-compatible)
        let hostname: String?
        let machineId: String?
        var sourceManifestQuery: String? = nil

        enum CodingKeys: String, CodingKey {
            case id
            case originalPath
            case folderPath
            case backupNoteId
            case backupNoteName
            case timestamp
            case description
            case kind
            case slot
            case fileHash
            case isRestored
            case hostname
            case machineId
        }

        init(
            id: String,
            originalPath: String,
            folderPath: String?,
            backupNoteId: String?,
            backupNoteName: String,
            timestamp: Date,
            description: String,
            kind: BackupKind? = nil,
            slot: BackupSlot = .latest,
            fileHash: String,
            isRestored: Bool,
            hostname: String?,
            machineId: String?,
            sourceManifestQuery: String? = nil
        ) {
            self.id = id
            self.originalPath = originalPath
            self.folderPath = folderPath
            self.backupNoteId = backupNoteId
            self.backupNoteName = backupNoteName
            self.timestamp = timestamp
            self.description = description
            self.kind = kind ?? BackupKind.inferred(from: description)
            self.slot = slot
            self.fileHash = fileHash
            self.isRestored = isRestored
            self.hostname = hostname
            self.machineId = machineId
            self.sourceManifestQuery = sourceManifestQuery
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            id = try container.decode(String.self, forKey: .id)
            originalPath = try container.decode(String.self, forKey: .originalPath)
            folderPath = try container.decodeIfPresent(String.self, forKey: .folderPath)
            backupNoteId = try container.decodeIfPresent(String.self, forKey: .backupNoteId)
            backupNoteName = try container.decode(String.self, forKey: .backupNoteName)
            timestamp = try container.decode(Date.self, forKey: .timestamp)
            description = try container.decode(String.self, forKey: .description)
            kind = try container.decodeIfPresent(BackupKind.self, forKey: .kind) ??
                BackupKind.inferred(from: description)
            slot = try container.decodeIfPresent(BackupSlot.self, forKey: .slot) ??
                (kind == .scrape ? .baseline : .latest)
            fileHash = try container.decode(String.self, forKey: .fileHash)
            isRestored = try container.decode(Bool.self, forKey: .isRestored)
            hostname = try container.decodeIfPresent(String.self, forKey: .hostname)
            machineId = try container.decodeIfPresent(String.self, forKey: .machineId)
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(id, forKey: .id)
            try container.encode(originalPath, forKey: .originalPath)
            try container.encodeIfPresent(folderPath, forKey: .folderPath)
            try container.encodeIfPresent(backupNoteId, forKey: .backupNoteId)
            try container.encode(backupNoteName, forKey: .backupNoteName)
            try container.encode(timestamp, forKey: .timestamp)
            try container.encode(description, forKey: .description)
            try container.encode(kind, forKey: .kind)
            try container.encode(slot, forKey: .slot)
            try container.encode(fileHash, forKey: .fileHash)
            try container.encode(isRestored, forKey: .isRestored)
            try container.encodeIfPresent(hostname, forKey: .hostname)
            try container.encodeIfPresent(machineId, forKey: .machineId)
        }

        var formattedDate: String {
            let formatter = DateFormatter()
            formatter.dateStyle = .short
            formatter.timeStyle = .short
            return formatter.string(from: timestamp)
        }

        var backupNotePath: String {
            guard let folderPath, !folderPath.isEmpty else {
                return backupNoteName
            }
            return "\(folderPath)/\(backupNoteName)"
        }

        /// Human-readable machine label, stripping ".local" suffix.
        // NOTE: This `.local`-stripping logic mirrors MachineIdentity.displayName.
        // If the stripping rule changes in MachineIdentity, update this too.
        var displayMachine: String {
            guard let h = hostname, !h.isEmpty else {
                return machineId == nil ? "legacy backup" : "unknown machine"
            }
            return h.hasSuffix(".local") ? String(h.dropLast(".local".count)) : h
        }

        /// Returns true if this entry belongs to the given machine.
        /// Legacy entries (nil machineId) always match to preserve backward-compatibility.
        func matchesMachine(machineId: String) -> Bool {
            guard let id = self.machineId else { return true }
            return id == machineId
        }

        func withFolderPathIfMissing(_ fallback: String?) -> BackupEntry {
            guard folderPath == nil, let fallback else { return self }
            return BackupEntry(
                id: id,
                originalPath: originalPath,
                folderPath: fallback,
                backupNoteId: backupNoteId,
                backupNoteName: backupNoteName,
                timestamp: timestamp,
                description: description,
                kind: kind,
                slot: slot,
                fileHash: fileHash,
                isRestored: isRestored,
                hostname: hostname,
                machineId: machineId,
                sourceManifestQuery: sourceManifestQuery
            )
        }

        func withSourceManifestQuery(_ query: String) -> BackupEntry {
            BackupEntry(
                id: id,
                originalPath: originalPath,
                folderPath: folderPath,
                backupNoteId: backupNoteId,
                backupNoteName: backupNoteName,
                timestamp: timestamp,
                description: description,
                kind: kind,
                slot: slot,
                fileHash: fileHash,
                isRestored: isRestored,
                hostname: hostname,
                machineId: machineId,
                sourceManifestQuery: query
            )
        }

        func withBackupStorage(
            folderPath newFolderPath: String?,
            backupNoteId newBackupNoteId: String?,
            sourceManifestQuery newSourceManifestQuery: String
        ) -> BackupEntry {
            BackupEntry(
                id: id,
                originalPath: originalPath,
                folderPath: newFolderPath,
                backupNoteId: newBackupNoteId ?? backupNoteId,
                backupNoteName: backupNoteName,
                timestamp: timestamp,
                description: description,
                kind: kind,
                slot: slot,
                fileHash: fileHash,
                isRestored: isRestored,
                hostname: hostname,
                machineId: machineId,
                sourceManifestQuery: newSourceManifestQuery
            )
        }
    }
    
    struct Manifest: Codable {
        var version: String
        var lastUpdated: Date
        var backups: [BackupEntry]
        
        init(version: String = "1.0", lastUpdated: Date = Date(), backups: [BackupEntry] = []) {
            self.version = version
            self.lastUpdated = lastUpdated
            self.backups = backups
        }
    }

    struct RestorePreview {
        let entry: BackupEntry
        let diff: String
    }
    
    init(
        bridgeClient: BackupVaultClient = AuthsiaBridgeClient.shared,
        dateProvider: @escaping () -> Date = Date.init,
        machineIdentity: MachineIdentity = MachineIdentity.load()
    ) {
        self.bridgeClient = bridgeClient
        self.dateProvider = dateProvider
        // All backups consolidate into a single root "Authsia Backups" folder,
        // independent of any --folder used for the migrated secret items.
        self.backupFolderPath = Self.backupFolderName
        self.currentMachineId = machineIdentity.machineId
        self.currentHostname = machineIdentity.hostname
    }
    
    func createBackup(
        of filePath: String,
        originalContent: String,
        description: String = "",
        kind: BackupKind = .scrape
    ) async throws -> BackupEntry {
        let fileManager = FileManager.default
        let originalPath = FilePathNormalizer.absoluteStandardizedPath(filePath)

        guard fileManager.isReadableFile(atPath: originalPath) else {
            throw BackupError.fileNotReadable(originalPath)
        }

        // Scrape keeps a preserved baseline plus one replaceable latest copy.
        // Other backup kinds keep the historical one-backup-per-file behavior.
        var manifest = try await loadManifest()
        let existingBackups = try await loadBackupsForReplacement()
        let matchingBackups = existingBackups.filter {
            $0.originalPath == originalPath && $0.matchesMachine(machineId: currentMachineId)
        }
        let slot: BackupSlot
        let backupsToReplace: [BackupEntry]
        if kind == .scrape {
            let hasBaseline = matchingBackups.contains {
                $0.kind == .scrape && $0.slot == .baseline
            }
            slot = hasBaseline ? .latest : .baseline
            backupsToReplace = matchingBackups.filter {
                $0.kind == .scrape && $0.slot == .latest
            }
        } else {
            slot = .latest
            backupsToReplace = matchingBackups
        }
        let replacedBackupIDs = Set(backupsToReplace.map(\.id))
        manifest.backups.removeAll { replacedBackupIDs.contains($0.id) }

        let now = dateProvider()
        let fileName = URL(fileURLWithPath: originalPath).lastPathComponent
        let timestampLabel = Self.timestampFormatter.string(from: now)
        let backupNoteName = "authsia_backup_\(fileName)_\(timestampLabel)"
        let fileHash = sha256Hash(originalContent)

        let backupNoteId = try await storeBackupContent(backupNoteName: backupNoteName, content: originalContent)

        let entry = BackupEntry(
            id: UUID().uuidString,
            originalPath: originalPath,
            folderPath: backupFolderPath,
            backupNoteId: backupNoteId,
            backupNoteName: backupNoteName,
            timestamp: now,
            description: description,
            kind: kind,
            slot: slot,
            fileHash: fileHash,
            isRestored: false,
            hostname: currentHostname,
            machineId: currentMachineId
        )

        manifest.backups.append(entry)
        manifest.lastUpdated = Date()
        do {
            try await saveManifest(manifest)
        } catch {
            _ = try? bridgeClient.deleteNote(query: backupNoteId)
            throw error
        }

        for existing in backupsToReplace where existing.sourceManifestQuery != manifestNoteName {
            try await removeEntryFromManifest(existing)
        }
        for existing in backupsToReplace {
            _ = try? bridgeClient.deleteNote(query: backupNoteQuery(for: existing))
        }

        return entry
    }
    
    func restoreBackup(entry: BackupEntry) async throws {
        // Retrieve secure note from Authsia vault
        let content = try await retrieveBackupContent(entry: entry)
        
        let fileManager = FileManager.default
        let existingMode = (try? fileManager.attributesOfItem(atPath: entry.originalPath))?[.posixPermissions] as? Int

        try AtomicFileWriter.writeString(
            content,
            toFile: entry.originalPath,
            defaultPermissions: existingMode ?? 0o600
        )

        try await updateManifestEntry(entry, isRestored: true)
    }
    
    func restoreMostRecentBackup(of filePath: String, machineName: String? = nil) async throws -> BackupEntry {
        let entry = try await mostRecentRestoreEntry(of: filePath, machineName: machineName)
        try await restoreBackup(entry: entry)
        return entry
    }

    func restoreOriginalBackup(of filePath: String, machineName: String? = nil) async throws -> BackupEntry {
        let entry = try await originalRestoreEntry(of: filePath, machineName: machineName)
        try await restoreBackup(entry: entry)
        return entry
    }

    func previewMostRecentRestore(of filePath: String, machineName: String? = nil) async throws -> RestorePreview {
        let entry = try await mostRecentRestoreEntry(of: filePath, machineName: machineName)
        return try await restorePreview(for: entry)
    }

    func previewOriginalRestore(of filePath: String, machineName: String? = nil) async throws -> RestorePreview {
        let entry = try await originalRestoreEntry(of: filePath, machineName: machineName)
        return try await restorePreview(for: entry)
    }

    func deleteBackup(entry: BackupEntry) async throws {
        // Delete the backup content note from vault
        _ = try bridgeClient.deleteNote(query: backupNoteQuery(for: entry))

        // Remove entry from manifest, and prune the manifest note if this was
        // the last backup tracked there.
        try await removeEntryFromManifest(entry, deleteEmptyManifest: true)
    }

    func deleteScrapeBackups(for filePath: String, machineName: String? = nil) async throws -> [BackupEntry] {
        let backups = try await loadVisibleBackups()
        let machineFiltered: [BackupEntry]
        if let name = machineName {
            machineFiltered = backups.filter { $0.displayMachine.lowercased() == name.lowercased() }
        } else {
            machineFiltered = backups.filter { $0.matchesMachine(machineId: currentMachineId) }
        }

        let entries = machineFiltered
            .filter {
                $0.originalPath == filePath &&
                    $0.kind == .scrape
            }
            .sorted(by: { $0.timestamp > $1.timestamp })

        for entry in entries {
            try await deleteBackup(entry: entry)
        }

        return entries
    }
    
    func listBackups(for filePath: String? = nil, allMachines: Bool = false, machineName: String? = nil) async -> [BackupEntry] {
        do {
            let backups = try await loadVisibleBackups()
            let machineFiltered: [BackupEntry]
            if let name = machineName {
                machineFiltered = backups.filter { $0.displayMachine.lowercased() == name.lowercased() }
            } else if allMachines {
                machineFiltered = backups
            } else {
                machineFiltered = backups.filter { $0.matchesMachine(machineId: currentMachineId) }
            }

            if let path = filePath {
                return machineFiltered
                    .filter { $0.originalPath == path }
                    .sorted(by: { $0.timestamp > $1.timestamp })
            }
            return machineFiltered
                .sorted(by: { $0.timestamp > $1.timestamp })
        } catch {
            return []
        }
    }
    
    func listModifiedFiles(
        allMachines: Bool = false,
        machineName: String? = nil,
        activeOnly: Bool = false
    ) async -> [String] {
        let backups = await listBackups(allMachines: allMachines, machineName: machineName)
        let filtered = activeOnly ? backups.filter { !$0.isRestored } : backups
        return Array(Set(filtered.map { $0.originalPath })).sorted()
    }
    
    // MARK: - Private Methods
    
    private func sha256Hash(_ input: String) -> String {
        let data = Data(input.utf8)
        let hash = SHA256.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined().prefix(16).description
    }
    
    private func storeBackupContent(backupNoteName: String, content: String) async throws -> String {
        // Store as secure note in Authsia vault
        let result = try bridgeClient.addNote(
            title: backupNoteName,
            content: content,
            isScraped: false,
            folderPath: backupFolderPath
        )
        return result.id
    }
    
    private func retrieveBackupContent(entry: BackupEntry) async throws -> String {
        // Retrieve from Authsia vault
        let query = backupNoteQuery(for: entry)
        let note = try bridgeClient.getNote(query: query)
        return note.content
    }

    private func mostRecentRestoreEntry(of filePath: String, machineName: String?) async throws -> BackupEntry {
        let candidates = try await unrestoredBackups(of: filePath, machineName: machineName)
        let latestCandidates = candidates.filter { $0.slot == .latest }
        let restoreCandidates = latestCandidates.isEmpty ? candidates : latestCandidates

        guard let entry = restoreCandidates
            .sorted(by: { $0.timestamp > $1.timestamp })
            .first else {
            throw BackupError.noBackupFound(filePath)
        }

        return entry
    }

    private func originalRestoreEntry(of filePath: String, machineName: String?) async throws -> BackupEntry {
        guard let entry = try await machineFilteredBackups(machineName: machineName)
            .filter({ $0.kind == .scrape && $0.slot == .baseline })
            .filter({ $0.originalPath == filePath })
            .sorted(by: { $0.timestamp < $1.timestamp })
            .first else {
            throw BackupError.noBackupFound(filePath)
        }

        return entry
    }

    private func unrestoredBackups(of filePath: String, machineName: String?) async throws -> [BackupEntry] {
        try await machineFilteredBackups(machineName: machineName)
            .filter { $0.originalPath == filePath && !$0.isRestored }
    }

    private func machineFilteredBackups(machineName: String?) async throws -> [BackupEntry] {
        let backups = try await loadVisibleBackups()
        if let name = machineName {
            return backups.filter { $0.displayMachine.lowercased() == name.lowercased() }
        }
        return backups.filter { $0.matchesMachine(machineId: currentMachineId) }
    }

    private func restorePreview(for entry: BackupEntry) async throws -> RestorePreview {
        let backupContent = try await retrieveBackupContent(entry: entry)
        let currentContent = (try? String(contentsOfFile: entry.originalPath, encoding: .utf8)) ?? ""
        let diff = Self.redactedRestoreDiff(
            currentPath: entry.originalPath,
            backupNotePath: entry.backupNotePath,
            currentContent: currentContent,
            backupContent: backupContent
        )
        return RestorePreview(entry: entry, diff: diff)
    }

    private static func redactedRestoreDiff(
        currentPath: String,
        backupNotePath: String,
        currentContent: String,
        backupContent: String
    ) -> String {
        let operations = diffOperations(from: lines(in: currentContent), to: lines(in: backupContent))
        var output = [
            "--- current \(currentPath)",
            "+++ backup \(backupNotePath)",
            "@@ restore preview (secret values redacted) @@",
        ]
        var changedLineCount = 0

        for operation in operations {
            switch operation {
            case .unchanged:
                continue
            case .removed(let line):
                output.append("-\(redactedDiffLine(line))")
                changedLineCount += 1
            case .added(let line):
                output.append("+\(redactedDiffLine(line))")
                changedLineCount += 1
            }
        }

        if changedLineCount == 0 {
            output.append("No changes between current file and backup.")
        }

        return output.joined(separator: "\n")
    }

    private enum DiffOperation {
        case unchanged(String)
        case removed(String)
        case added(String)
    }

    private static func lines(in content: String) -> [String] {
        var lines = content.components(separatedBy: .newlines)
        if lines.last == "" {
            lines.removeLast()
        }
        return lines
    }

    private static func diffOperations(from oldLines: [String], to newLines: [String]) -> [DiffOperation] {
        var lengths = Array(
            repeating: Array(repeating: 0, count: newLines.count + 1),
            count: oldLines.count + 1
        )

        if !oldLines.isEmpty && !newLines.isEmpty {
            for oldIndex in stride(from: oldLines.count - 1, through: 0, by: -1) {
                for newIndex in stride(from: newLines.count - 1, through: 0, by: -1) {
                    if oldLines[oldIndex] == newLines[newIndex] {
                        lengths[oldIndex][newIndex] = lengths[oldIndex + 1][newIndex + 1] + 1
                    } else {
                        lengths[oldIndex][newIndex] = max(
                            lengths[oldIndex + 1][newIndex],
                            lengths[oldIndex][newIndex + 1]
                        )
                    }
                }
            }
        }

        var operations: [DiffOperation] = []
        var oldIndex = 0
        var newIndex = 0

        while oldIndex < oldLines.count && newIndex < newLines.count {
            if oldLines[oldIndex] == newLines[newIndex] {
                operations.append(.unchanged(oldLines[oldIndex]))
                oldIndex += 1
                newIndex += 1
            } else if lengths[oldIndex + 1][newIndex] >= lengths[oldIndex][newIndex + 1] {
                operations.append(.removed(oldLines[oldIndex]))
                oldIndex += 1
            } else {
                operations.append(.added(newLines[newIndex]))
                newIndex += 1
            }
        }

        while oldIndex < oldLines.count {
            operations.append(.removed(oldLines[oldIndex]))
            oldIndex += 1
        }

        while newIndex < newLines.count {
            operations.append(.added(newLines[newIndex]))
            newIndex += 1
        }

        return operations
    }

    private static func redactedDiffLine(_ line: String) -> String {
        guard let equalsIndex = line.firstIndex(of: "=") else {
            if line.contains("authsia://") {
                return line
            }
            return redactedIfLikelySecretBlockLine(line)
        }

        let assignmentPrefix = line[..<equalsIndex].trimmingCharacters(in: .whitespaces)
        guard isShellAssignmentPrefix(assignmentPrefix) else {
            if line.contains("authsia://") {
                return line
            }
            return redactedIfLikelySecretBlockLine(line)
        }

        let valueStart = line.index(after: equalsIndex)
        if isAuthsiaReferenceValue(String(line[valueStart...])) {
            return line
        }
        return "\(line[..<valueStart])\(OutputMasker.placeholder)"
    }

    private static func isAuthsiaReferenceValue(_ value: String) -> Bool {
        var trimmed = value.trimmingCharacters(in: .whitespaces)
        if trimmed.count >= 2,
           let first = trimmed.first,
           let last = trimmed.last,
           (first == "\"" && last == "\"") || (first == "'" && last == "'") {
            trimmed = String(trimmed.dropFirst().dropLast())
        }
        return trimmed.hasPrefix("authsia://") && !trimmed.unicodeScalars.contains {
            CharacterSet.whitespacesAndNewlines.contains($0)
        }
    }

    private static func redactedIfLikelySecretBlockLine(_ line: String) -> String {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return line }
        if trimmed.contains("PRIVATE KEY") || trimmed.hasPrefix("-----BEGIN ") || trimmed.hasPrefix("-----END ") {
            return OutputMasker.placeholder
        }
        if trimmed.count >= 40 && trimmed.range(of: #"^[A-Za-z0-9+/=_-]+$"#, options: .regularExpression) != nil {
            return OutputMasker.placeholder
        }
        return line
    }

    private static func isShellAssignmentPrefix(_ prefix: String) -> Bool {
        let name: String
        if prefix.hasPrefix("export ") {
            name = prefix.dropFirst("export ".count).trimmingCharacters(in: .whitespaces)
        } else {
            name = prefix
        }

        guard let first = name.unicodeScalars.first else { return false }
        let validFirst = CharacterSet.letters.contains(first) || first == "_"
        guard validFirst else { return false }

        return name.unicodeScalars.allSatisfy { scalar in
            CharacterSet.alphanumerics.contains(scalar) || scalar == "_"
        }
    }

    private func loadVisibleBackups() async throws -> [BackupEntry] {
        deduplicateBackups(try await loadManifest().backups)
    }

    private func loadBackupsForReplacement() async throws -> [BackupEntry] {
        deduplicateBackups(try await loadManifest().backups)
    }

    private func loadManifestIfExists(query: String, defaultEntryFolderPath: String?) async throws -> Manifest? {
        do {
            let note = try bridgeClient.getNote(query: query)
            return try decodeManifest(note.content, defaultEntryFolderPath: defaultEntryFolderPath, sourceQuery: query)
        } catch {
            if let bridgeError = error as? BridgeClientError,
               case .bridgeError(let code, _, _) = bridgeError,
               code == "notFound" {
                return nil
            }
            throw error
        }
    }

    private func deduplicateBackups(_ backups: [BackupEntry]) -> [BackupEntry] {
        var uniqueByID: [String: BackupEntry] = [:]
        uniqueByID.reserveCapacity(backups.count)
        for entry in backups {
            uniqueByID[entry.id] = entry
        }
        return Array(uniqueByID.values)
    }

    private func backupNoteQuery(for entry: BackupEntry) -> String {
        if let backupNoteId = entry.backupNoteId {
            return backupNoteId
        }

        guard let resolvedID = resolveLegacyBackupNoteID(for: entry) else {
            return entry.backupNoteName
        }
        return resolvedID
    }

    private func resolveLegacyBackupNoteID(for entry: BackupEntry) -> String? {
        let notes: [BridgeNote]
        do {
            notes = try bridgeClient.list().notes.filter { $0.title == entry.backupNoteName }
        } catch {
            return nil
        }

        let targetFolderPath = Self.normalizeFolderPath(entry.folderPath)
        if let exactFolderMatch = notes.first(where: {
            Self.normalizeFolderPath($0.folderPath) == targetFolderPath
        }) {
            return exactFolderMatch.id.uuidString
        }

        guard notes.count == 1 else {
            return nil
        }
        return notes[0].id.uuidString
    }
    
    private func loadManifest() async throws -> Manifest {
        var manifest = try await loadCurrentManifest()
        guard !didAttemptLegacyManifestMigration else {
            return manifest
        }
        didAttemptLegacyManifestMigration = true
        manifest = try await migrateLegacyManifestsIfNeeded(into: manifest)
        return manifest
    }

    private func loadCurrentManifest() async throws -> Manifest {
        let noteName = manifestNoteName
        do {
            let note = try bridgeClient.getNote(query: noteName)
            return try decodeManifest(note.content, defaultEntryFolderPath: backupFolderPath, sourceQuery: noteName)
        } catch {
            if let bridgeError = error as? BridgeClientError,
               case .bridgeError(let code, _, _) = bridgeError,
               code == "notFound" {
                if let manifest = try await loadManifestByExactNoteTitle(noteName) {
                    return manifest
                }
                return Manifest()
            }
            throw error
        }
    }

    private func migrateLegacyManifestsIfNeeded(into currentManifest: Manifest) async throws -> Manifest {
        let notes: [BridgeNote]
        do {
            notes = try bridgeClient.list().notes
        } catch {
            return currentManifest
        }

        let legacyManifestNotes = notes.filter { isBackupManifestNote($0) && !isCurrentManifestNote($0) }
        guard !legacyManifestNotes.isEmpty else {
            return currentManifest
        }

        var manifest = currentManifest
        var seenEntryIDs = Set(manifest.backups.map(\.id))
        var notesToMove: Set<String> = []
        var didMigrate = false

        for manifestNote in legacyManifestNotes {
            guard let legacyManifest = try await loadManifestIfExists(
                query: manifestNote.id.uuidString,
                defaultEntryFolderPath: manifestNote.folderPath
            ) else {
                continue
            }

            for entry in legacyManifest.backups where seenEntryIDs.insert(entry.id).inserted {
                let backupNoteID = entry.backupNoteId ?? resolveLegacyBackupNoteID(for: entry)
                if let backupNoteID {
                    notesToMove.insert(backupNoteID)
                }

                manifest.backups.append(
                    entry.withBackupStorage(
                        folderPath: backupNoteID == nil ? entry.folderPath : backupFolderPath,
                        backupNoteId: backupNoteID,
                        sourceManifestQuery: manifestNoteName
                    )
                )
                didMigrate = true
            }
        }

        guard didMigrate else {
            return currentManifest
        }

        manifest.lastUpdated = Date()
        do {
            try await saveManifest(manifest)
        } catch {
            return currentManifest
        }

        for noteID in notesToMove {
            _ = try? bridgeClient.updateNote(
                query: noteID,
                title: nil,
                content: nil,
                isScraped: nil,
                folderPath: backupFolderPath
            )
        }
        return manifest
    }

    private func isBackupManifestNote(_ note: BridgeNote) -> Bool {
        note.title == baseManifestNoteName || note.title.hasPrefix("\(baseManifestNoteName)__")
    }

    private func isCurrentManifestNote(_ note: BridgeNote) -> Bool {
        note.title == manifestNoteName &&
            Self.normalizeFolderPath(note.folderPath) == Self.normalizeFolderPath(backupFolderPath)
    }

    private func loadManifestByExactNoteTitle(_ title: String) async throws -> Manifest? {
        let notes: [BridgeNote]
        do {
            notes = try bridgeClient.list().notes
        } catch {
            return nil
        }

        let targetFolderPath = Self.normalizeFolderPath(backupFolderPath)
        let matches = notes.filter {
            $0.title == title && Self.normalizeFolderPath($0.folderPath) == targetFolderPath
        }
        guard matches.count == 1, let match = matches.first else {
            return nil
        }

        let note = try bridgeClient.getNote(query: match.id.uuidString)
        return try decodeManifest(note.content, defaultEntryFolderPath: backupFolderPath, sourceQuery: match.id.uuidString)
    }

    private func decodeManifest(_ content: String, defaultEntryFolderPath: String?, sourceQuery: String) throws -> Manifest {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        var manifest = try decoder.decode(Manifest.self, from: Data(content.utf8))
        let normalizedDefaultFolderPath = Self.normalizeFolderPath(defaultEntryFolderPath)
        manifest.backups = manifest.backups.map {
            $0.withFolderPathIfMissing(normalizedDefaultFolderPath).withSourceManifestQuery(sourceQuery)
        }
        return manifest
    }
    
    private func saveManifest(_ manifest: Manifest) async throws {
        let noteName = manifestNoteName
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let manifestData = try encoder.encode(manifest)
        let manifestContent = String(data: manifestData, encoding: .utf8) ?? "{}"

        // Try to update existing manifest, or create new one
        do {
            _ = try bridgeClient.updateNote(
                query: noteName,
                title: nil,
                content: manifestContent,
                isScraped: nil,
                folderPath: backupFolderPath
            )
        } catch {
            // If manifest doesn't exist, create it
            if let bridgeError = error as? BridgeClientError,
               case .bridgeError(let code, _, _) = bridgeError,
               code == "notFound" {
                _ = try bridgeClient.addNote(
                    title: noteName,
                    content: manifestContent,
                    isScraped: false,
                    folderPath: backupFolderPath
                )
            } else {
                throw error
            }
        }
    }
    
    private func addEntryToManifest(_ entry: BackupEntry) async throws {
        var manifest = try await loadManifest()
        manifest.backups.append(entry)
        manifest.lastUpdated = Date()
        try await saveManifest(manifest)
    }
    
    private func updateManifestEntry(_ entry: BackupEntry, isRestored: Bool) async throws {
        if let sourceManifestQuery = entry.sourceManifestQuery {
            var manifest = try await loadManifestIfExists(
                query: sourceManifestQuery,
                defaultEntryFolderPath: entry.folderPath
            ) ?? Manifest()
            if let index = manifest.backups.firstIndex(where: { $0.id == entry.id }) {
                var updatedEntry = entry
                updatedEntry.isRestored = isRestored
                manifest.backups[index] = updatedEntry
                manifest.lastUpdated = Date()
                try await updateExistingManifest(manifest, query: sourceManifestQuery)
            }
            return
        }

        var manifest = try await loadManifest()
        if let index = manifest.backups.firstIndex(where: { $0.id == entry.id }) {
            var updatedEntry = entry
            updatedEntry.isRestored = isRestored
            manifest.backups[index] = updatedEntry
            manifest.lastUpdated = Date()
            try await saveManifest(manifest)
        }
    }
    
    private func removeEntryFromManifest(_ entry: BackupEntry, deleteEmptyManifest: Bool = false) async throws {
        if let sourceManifestQuery = entry.sourceManifestQuery {
            var manifest = try await loadManifestIfExists(
                query: sourceManifestQuery,
                defaultEntryFolderPath: entry.folderPath
            ) ?? Manifest()
            manifest.backups.removeAll { $0.id == entry.id }
            manifest.lastUpdated = Date()
            if deleteEmptyManifest && manifest.backups.isEmpty {
                _ = try bridgeClient.deleteNote(query: sourceManifestQuery)
            } else {
                try await updateExistingManifest(manifest, query: sourceManifestQuery)
            }
            return
        }

        var manifest = try await loadManifest()
        manifest.backups.removeAll { $0.id == entry.id }
        manifest.lastUpdated = Date()
        if deleteEmptyManifest && manifest.backups.isEmpty {
            _ = try bridgeClient.deleteNote(query: manifestNoteName)
        } else {
            try await saveManifest(manifest)
        }
    }

    private func updateExistingManifest(_ manifest: Manifest, query: String) async throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let manifestData = try encoder.encode(manifest)
        let manifestContent = String(data: manifestData, encoding: .utf8) ?? "{}"
        _ = try bridgeClient.updateNote(
            query: query,
            title: nil,
            content: manifestContent,
            isScraped: nil,
            folderPath: nil
        )
    }

    private var manifestNoteName: String {
        "\(baseManifestNoteName)__\(Self.slugifyFolderPath(Self.backupFolderName))"
    }

    private static func normalizeFolderPath(_ folderPath: String?) -> String? {
        guard let folderPath else { return nil }
        let segments = folderPath
            .split(separator: "/")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard !segments.isEmpty else { return nil }
        return segments.joined(separator: "/")
    }

    private static func slugifyFolderPath(_ folderPath: String) -> String {
        let allowed = CharacterSet.alphanumerics
        let mapped = folderPath.unicodeScalars.map { scalar -> Character in
            allowed.contains(scalar) ? Character(scalar) : "_"
        }
        let collapsed = String(mapped).replacingOccurrences(of: "_+", with: "_", options: .regularExpression)
        let trimmed = collapsed.trimmingCharacters(in: CharacterSet(charactersIn: "_")).lowercased()
        return trimmed.isEmpty ? "folder" : trimmed
    }

    enum BackupError: LocalizedError {
        case fileNotReadable(String)
        case backupNotFound(String)
        case noBackupFound(String)
        case vaultError(String)
        
        var errorDescription: String? {
            switch self {
            case .fileNotReadable(let path):
                return "Cannot read file for backup: \(path). Check file permissions and retry."
            case .backupNotFound(let path):
                return "Backup file not found: \(path). Run the matching list command to see available backups."
            case .noBackupFound(let path):
                return "No backup found for: \(path). Run the matching list command to see available backups."
            case .vaultError(let message):
                return "Vault error: \(message). Run `authsia unlock` and retry."
            }
        }
    }
}

protocol BackupVaultClient: Sendable {
    func addNote(title: String, content: String, isScraped: Bool, folderPath: String?) throws -> WriteResult
    func updateNote(query: String, title: String?, content: String?, isScraped: Bool?, folderPath: String?) throws -> WriteResult
    func getNote(query: String) throws -> NoteResult
    func deleteNote(query: String) throws -> WriteResult
    func list() throws -> BridgeListPayload
}

extension AuthsiaBridgeClient: BackupVaultClient {}
