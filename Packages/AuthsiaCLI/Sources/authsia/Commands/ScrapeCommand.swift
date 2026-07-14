import ArgumentParser
import Foundation
import AuthenticatorBridge

struct Scrape: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "scrape",
        abstract: "Scan for and migrate hardcoded secrets to Authsia",
        discussion: """
            Scans configuration files for potential secrets and allows interactive migration.
            
            Supports:
            - .env files: Auto-rewrite with authsia:// references
            - Shell configs (.zshrc, .bashrc, etc.): Auto-replace with confirmation
            - Directory paths: Shallow by default; use --recursive to scan subdirectories
            - SSH private keys: Skipped with guidance to use authsia ssh adopt
            
            Examples:
              authsia scrape                          # Scan current directory
              authsia scrape --path ~/.zshrc          # Scan specific file
              authsia scrape --type api-key --path .env   # API keys and tokens only
              authsia scrape --path ./certs           # Scan direct files in a directory
              authsia scrape --path ./certs --recursive  # Include subdirectories
              authsia scrape --path .env --folder Team/API
              authsia scrape --dry-run                # Preview changes only
              authsia scrape --replace-all            # Non-interactive replace-all migration
              authsia scrape --revert ~/.zshrc        # Revert from current machine's backup
              authsia scrape --revert-original ~/.zshrc  # Revert to the first pre-Authsia backup
              authsia scrape --revert ~/.zshrc --machine james-macbook  # Revert from a specific machine
              authsia scrape --list-modified          # Table of backups (current machine)
              authsia scrape --list-modified --all-machines  # Table of backups from all machines
            """
    )
    
    enum ConfidenceLevel: String, ExpressibleByArgument, CaseIterable {
        case high, medium, low
        static var allValueStrings: [String] { allCases.map(\.rawValue) }
    }

    enum CredentialType: Hashable, ExpressibleByArgument, CaseIterable {
        case apiKey
        case password
        case json
        case cert

        init?(argument: String) {
            switch argument.lowercased() {
            case "api-key", "api-keys", "apikey", "api", "token", "tokens":
                self = .apiKey
            case "password", "passwords":
                self = .password
            case "json", "json-credential", "json-credentials", "jsoncredential":
                self = .json
            case "cert", "certs", "certificate", "certificates":
                self = .cert
            default:
                return nil
            }
        }

        init?(secret: DetectedSecret) {
            switch secret.type {
            case .apiKey, .token, .secret, .accessKey:
                self = .apiKey
            case .password, .unknown:
                self = .password
            case .jsonCredential:
                self = .json
            case .certificate:
                self = .cert
            case .sshKey:
                return nil
            }
        }

        static var allValueStrings: [String] {
            ["api-key", "password", "json", "cert"]
        }
    }

    enum ShellConfigMigrationResult: Equatable {
        case applied([DetectedSecret])
        case noChanges
        case cancelled
        case dryRun
    }

    static func confirmApplyChangesPrompt() -> Bool {
        FileHandle.standardOutput.write(Data("Apply these changes? [y/N]: ".utf8))

        guard let input = readLine()?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() else {
            return false
        }
        guard !input.isEmpty else {
            return false
        }

        return input == "y" || input == "yes"
    }
    
    @Option(name: .shortAndLong, parsing: .upToNextOption,
            help: "Paths to scan (files or directories; directories are shallow unless --recursive is set)")
    var path: [String] = []

    @Flag(name: .long,
          help: "Recursively scan subdirectories for directory paths")
    var recursive = false

    @Option(
        name: .shortAndLong,
        help: "Folder path to assign migrated items; backups are stored under root Authsia Backups",
        completion: .custom(ShellCompletionMetadata.completeFolders)
    )
    var folder: String?
    
    @Option(name: .long,
            help: "Minimum confidence level: high, medium, low (default: low)")
    var confidence: ConfidenceLevel = .low

    @Option(name: .shortAndLong, parsing: .upToNextOption,
            help: "Credential types to include. Allowed credential types: api-key, password, json, cert")
    var type: [CredentialType] = []
    
    @Flag(name: .long,
          help: "Preview changes without modifying files")
    var dryRun = false
    
    @Flag(name: .shortAndLong,
          help: "Skip interactive selection, auto-select all")
    var yes = false

    @Flag(name: .long,
          help: "Non-interactive mode: select all secrets, overwrite existing values, and apply --folder to existing Authsia references")
    var replaceAll = false
    
    @Option(name: .long,
            help: "Revert a previously modified file to its backup")
    var revert: String?

    @Option(name: .long,
            help: "Revert a previously modified file to its original pre-Authsia scrape backup")
    var revertOriginal: String?
    
    @Flag(name: .long,
            help: "List modified backup entries as a table")
    var listModified = false
    
    @Flag(name: .long,
          help: "Revert all modified files to their last backup")
    var revertAll = false
    
    @Flag(name: .shortAndLong,
          help: "Suppress non-essential output")
    var quiet = false

    @Flag(name: .long,
          help: "Include backups from all machines (applies to --list-modified only)")
    var allMachines = false

    @Option(name: .long,
            help: "Revert from a specific machine's backup (use --list-modified --all-machines to see machine names)")
    var machine: String?

    func run() async throws {
        try await AuthsiaBridgeClient.shared.withRequestedCommand("scrape", includeAutomationCredential: false) {
            let backupService = BackupService()

            if allMachines && (revert != nil || revertOriginal != nil || revertAll) {
                throw ValidationError(
                    "--all-machines is not valid with --revert, --revert-original, or --revert-all. " +
                    "Use --machine <name> to revert from a specific machine's backup. " +
                    "Run 'authsia scrape --list-modified --all-machines' to see available machine names."
                )
            }

            if revert != nil && revertOriginal != nil {
                throw ValidationError("Use only one of --revert or --revert-original.")
            }

            if let revertPath = revert {
                try await handleRevert(backupService: backupService, path: revertPath, machine: machine)
                return
            }

            if let revertPath = revertOriginal {
                try await handleRevertOriginal(backupService: backupService, path: revertPath, machine: machine)
                return
            }

            if revertAll {
                try await handleRevertAll(backupService: backupService, machine: machine)
                return
            }

            if listModified {
                try await handleListModified(backupService: backupService, allMachines: allMachines)
                return
            }

            try await scanAndMigrate(backupService: backupService)
        }
    }

    func handleRevert(
        backupService: BackupService,
        path: String,
        machine: String?,
        confirmProceed: () -> Bool = { CLIPrompt.confirm("Proceed with revert?", defaultValue: false) },
        confirmDeleteBackup: () -> Bool = {
            CLIPrompt.confirm("Delete the backup from Authsia vault?", defaultValue: false)
        }
    ) async throws {
        let expandedPath = FilePathNormalizer.absoluteStandardizedPath(path)

        let candidates = await backupService.listBackups(for: expandedPath, machineName: machine)
        if !candidates.isEmpty && !candidates.contains(where: { !$0.isRestored }) {
            // All backups for this path are already marked restored
            print("⚠️  All backups for \(expandedPath) have already been restored.")
            if machine == nil {
                print("Tip: run 'authsia scrape --list-modified --all-machines' to see backups from other machines,")
                print("     then use --machine <name> to revert from a specific machine.")
            }
            return
        }

        do {
            let preview = try await backupService.previewMostRecentRestore(of: expandedPath, machineName: machine)
            let entry = preview.entry
            print("Reverting: \(expandedPath)")
            print("  Backup from:  \(entry.displayMachine)")
            print("  Created:      \(entry.formattedDate)")
            print("  Hash:         \(entry.fileHash)")
            print("")
            print(preview.diff)
            print("")

            guard confirmProceed() else {
                print("Cancelled.")
                return
            }

            try await backupService.restoreBackup(entry: entry)
            print("✅ Successfully reverted \(expandedPath)")

            if confirmDeleteBackup() {
                do {
                    try await backupService.deleteBackup(entry: entry)
                    print("🗑️  Backup deleted from vault.")
                } catch {
                    print("⚠️  Failed to delete backup: \(error.localizedDescription)")
                }
            } else {
                print("📦 Backup retained in vault for future use.")
            }
        } catch {
            print("❌ Failed to revert: \(error.localizedDescription)")
            if machine == nil {
                print("Tip: run 'authsia scrape --list-modified --all-machines' to see backups from other machines,")
                print("     then use --machine <name> to revert from a specific machine.")
            }
            throw error
        }
    }

    func handleRevertOriginal(
        backupService: BackupService,
        path: String,
        machine: String?,
        confirmProceed: () -> Bool = { CLIPrompt.confirm("Proceed with revert?", defaultValue: false) },
        confirmDeleteBackups: () -> Bool = {
            CLIPrompt.confirm("Delete all scrape backups for this file from Authsia vault?", defaultValue: false)
        }
    ) async throws {
        let expandedPath = FilePathNormalizer.absoluteStandardizedPath(path)

        let candidates = await backupService.listBackups(for: expandedPath, machineName: machine)
        if !candidates.isEmpty && !candidates.contains(where: { $0.kind == .scrape && $0.slot == .baseline }) {
            print("⚠️  Original backup for \(expandedPath) is unavailable.")
            if machine == nil {
                print("Tip: run 'authsia scrape --list-modified --all-machines' to see backups from other machines,")
                print("     then use --machine <name> to revert from a specific machine.")
            }
            return
        }

        do {
            let preview = try await backupService.previewOriginalRestore(of: expandedPath, machineName: machine)
            let entry = preview.entry
            print("Reverting original: \(expandedPath)")
            print("  Backup from:  \(entry.displayMachine)")
            print("  Created:      \(entry.formattedDate)")
            print("  Hash:         \(entry.fileHash)")
            print("")
            print(preview.diff)
            print("")

            guard confirmProceed() else {
                print("Cancelled.")
                return
            }

            try await backupService.restoreBackup(entry: entry)
            print("✅ Successfully reverted \(expandedPath) to original backup")

            if confirmDeleteBackups() {
                do {
                    let deleted = try await backupService.deleteScrapeBackups(for: expandedPath, machineName: machine)
                    print("🗑️  Deleted \(deleted.count) scrape backup(s) from vault.")
                } catch {
                    print("⚠️  Failed to delete backup: \(error.localizedDescription)")
                }
            } else {
                print("📦 Scrape backups retained in vault for future use.")
            }
        } catch {
            print("❌ Failed to revert original: \(error.localizedDescription)")
            if machine == nil {
                print("Tip: run 'authsia scrape --list-modified --all-machines' to see backups from other machines,")
                print("     then use --machine <name> to revert from a specific machine.")
            }
            throw error
        }
    }

    private func handleRevertAll(backupService: BackupService, machine: String?) async throws {
        let modifiedFiles = await backupService.listModifiedFiles(machineName: machine, activeOnly: true)

        guard !modifiedFiles.isEmpty else {
            print("No modified files found.")
            return
        }

        var previews: [BackupService.RestorePreview] = []
        print("🔄 Reverting all modified files:")
        for file in modifiedFiles {
            do {
                let preview = try await backupService.previewMostRecentRestore(of: file, machineName: machine)
                previews.append(preview)
                print("  - \(file)")
            } catch {
                print("  - \(file) (preview failed: \(error.localizedDescription))")
            }
        }

        guard !previews.isEmpty else {
            print("No restorable backups found.")
            return
        }

        print("")
        for preview in previews {
            print(preview.diff)
            print("")
        }

        guard CLIPrompt.confirm("Proceed with revert?", defaultValue: false) else {
            print("Cancelled.")
            return
        }

        let deleteBackups = CLIPrompt.confirm("Also delete backups from Authsia vault after reverting?", defaultValue: false)

        for preview in previews {
            let file = preview.entry.originalPath
            do {
                try await backupService.restoreBackup(entry: preview.entry)
                print("✅ Reverted: \(file)")

                if deleteBackups {
                    do {
                        try await backupService.deleteBackup(entry: preview.entry)
                        print("   🗑️  Backup deleted.")
                    } catch {
                        print("   ⚠️  Failed to delete backup: \(error.localizedDescription)")
                    }
                }
            } catch {
                print("❌ Failed to revert \(file): \(error.localizedDescription)")
            }
        }
    }

    private func handleListModified(backupService: BackupService, allMachines: Bool) async throws {
        let modifiedFiles = await backupService.listModifiedFiles(allMachines: allMachines)

        guard !modifiedFiles.isEmpty else {
            print("No modified files found.")
            if !allMachines {
                print("Tip: use --all-machines to see backups from other machines.")
            }
            return
        }

        var backups: [BackupService.BackupEntry] = []
        for file in modifiedFiles {
            backups.append(contentsOf: await backupService.listBackups(for: file, allMachines: allMachines))
        }
        print(TableFormatter.formatBackups(backups))
    }
    
    private func scanAndMigrate(backupService: BackupService) async throws {
        let detectionService = SecretDetectionService()
        let scannerService = FileScannerService()
        let shellConfigService = ShellConfigService()
        
        let pathsToScan: [String]
        if path.isEmpty {
            pathsToScan = resolveDefaultPaths()
        } else {
            pathsToScan = path.map { FilePathNormalizer.absoluteStandardizedPath($0) }
        }
        
        if pathsToScan.isEmpty && !quiet {
            print("No configuration files found to scan.")
            return
        }
        
        if !quiet {
            print("🔍 Scanning for secrets in \(pathsToScan.count) location(s)...")
        }
        
        let scanProgress: FileScannerService.ScanProgressHandler?
        if quiet {
            scanProgress = nil
        } else {
            scanProgress = { progress in
                print("🔎 \(progress.displayMessage)")
            }
        }
        var secrets = await scannerService.scanPaths(
            pathsToScan,
            detectionService: detectionService,
            recursive: recursive,
            progress: scanProgress
        )
        
        let minimumConfidence: SecretConfidence
        switch confidence {
        case .high: minimumConfidence = .high
        case .medium: minimumConfidence = .medium
        case .low: minimumConfidence = .low
        }
        
        secrets = secrets.filter { $0.confidence >= minimumConfidence }
        secrets = filterSecretsByCredentialType(secrets)

        let sshSecrets = secrets.filter { $0.type == .sshKey }
        if !sshSecrets.isEmpty {
            secrets.removeAll { $0.type == .sshKey }
            if !quiet {
                print(Self.sshAdoptionGuidance(for: sshSecrets))
            }
        }
        
        guard !secrets.isEmpty else {
            let references = await scannerService.findAuthsiaReferences(in: pathsToScan, recursive: recursive)
            if !references.isEmpty {
                if !quiet {
                    print("✅ No new raw secrets found.")
                    print("ℹ️ \(references.count) item(s) are already using Authsia references.")
                }

                if replaceAll, !dryRun, let folderPath = normalizeFolderPath(folder) {
                    let shellReferences = await scannerService.findShellAuthsiaReferences(
                        in: pathsToScan,
                        recursive: recursive
                    )
                    guard shellReferences.isEmpty else {
                        if !quiet {
                            print(
                                "⚠️  Skipped folder update for existing shell-substitution references. " +
                                "Only authsia:// references can be rewritten safely."
                            )
                        }
                        return
                    }
                    let filesToRewrite = try AuthsiaReferenceRewriteService.filesNeedingFolderRewrite(
                        in: pathsToScan,
                        folderPath: folderPath,
                        recursive: recursive
                    )
                    let createdBackups = try await createBackups(
                        for: filesToRewrite,
                        backupService: backupService,
                        description: "Before authsia scrape reference folder update"
                    )
                    let updatedCount = await applyFolderToReferencedItems(references, folderPath: folderPath)
                    if updatedCount == references.count {
                        do {
                            _ = try AuthsiaReferenceRewriteService.applyFolder(to: filesToRewrite, folderPath: folderPath)
                        } catch {
                            await deleteBackups(createdBackups, backupService: backupService)
                            throw error
                        }
                    } else if !quiet, !filesToRewrite.isEmpty {
                        await deleteBackups(createdBackups, backupService: backupService)
                        print("⚠️  Skipped source URI folder rewrite because not all referenced items were updated.")
                    }
                    if !quiet {
                        print("📁 Updated folder to '\(folderPath)' for \(updatedCount)/\(references.count) referenced item(s).")
                    }
                } else if replaceAll, dryRun, folder != nil, !quiet {
                    print("🔍 DRY RUN: Would update folder for referenced vault items.")
                } else if folder != nil, !quiet {
                    print("ℹ️ Use --replace-all to also apply --folder to already referenced vault items.")
                }
            } else if !quiet, sshSecrets.isEmpty {
                print("✅ No secrets found in scanned files.")
            }
            return
        }
        
        if !quiet {
            print("Found \(secrets.count) potential secret(s)")
        }
        
        let selectedSecrets = try selectedSecretsForMigration(from: secrets)
        
        guard !selectedSecrets.isEmpty else {
            print("No secrets selected. Exiting.")
            return
        }
        
        if !quiet {
            print("📋 Selected \(selectedSecrets.count) secret(s) for migration")
        }
        
        let fileReplacementSecrets = fileReplacementSecrets(from: selectedSecrets)
        let nonFileReplacementSecrets = nonFileReplacementSecretsForStorage(from: selectedSecrets)

        let shellConfigSecrets = fileReplacementSecrets.filter { $0.isShellConfig }
        let envFileSecrets = fileReplacementSecrets.filter { $0.isEnvFile }
        var didApplyChanges = false
        var didDryRun = false

        if !shellConfigSecrets.isEmpty {
            let shellConfigResult = try await handleShellConfigMigration(
                secrets: shellConfigSecrets,
                shellConfigService: shellConfigService,
                backupService: backupService
            )
            if case .cancelled = shellConfigResult {
                return
            }
            if case .applied = shellConfigResult {
                didApplyChanges = true
            }
            if case .dryRun = shellConfigResult {
                didDryRun = true
            }
        }

        if !envFileSecrets.isEmpty {
            let envResult = try await handleEnvFileMigration(
                secrets: envFileSecrets,
                backupService: backupService
            )
            if case .cancelled = envResult {
                return
            }
            // Show app-code migration guidance after auto-rewrite
            if case .applied(let appliedSecrets) = envResult, !quiet {
                CodeExamples.showMigrationExamples(for: appliedSecrets, folderPath: normalizeFolderPath(folder))
            }
            if case .applied = envResult {
                didApplyChanges = true
            }
            if case .dryRun = envResult {
                didDryRun = true
            }
        }

        if !nonFileReplacementSecrets.isEmpty {
            let summary = try await addSecretsToAuthsia(nonFileReplacementSecrets)
            if summary.results.contains(where: {
                $0.outcome == .added || $0.outcome == .updated || $0.outcome == .reused
            }) {
                didApplyChanges = true
            }
        }
        
        print("")
        print(Self.migrationCompletionMessage(didApplyChanges: didApplyChanges, didDryRun: didDryRun))
    }

    static func migrationCompletionMessage(didApplyChanges: Bool, didDryRun: Bool) -> String {
        if didApplyChanges {
            return "✅ Migration complete!"
        }
        if didDryRun {
            return "🔍 Dry run complete. No changes made."
        }
        return "No changes applied."
    }

    func selectedSecretsForMigration(
        from secrets: [DetectedSecret],
        isInteractiveSession: Bool = TerminalContext.isInteractiveSession,
        selector: ([DetectedSecret]) -> [DetectedSecret] = CheckboxTUI.selectSecrets
    ) throws -> [DetectedSecret] {
        if yes || replaceAll {
            return secrets
        }

        guard isInteractiveSession else {
            throw ValidationError(
                "Interactive secret selection requires a TTY. Re-run with --yes or --replace-all."
            )
        }

        return selector(secrets)
    }

    func filterSecretsByCredentialType(_ secrets: [DetectedSecret]) -> [DetectedSecret] {
        guard !type.isEmpty else { return secrets }
        let allowedTypes = Set(type)
        return secrets.filter { secret in
            guard let credentialType = CredentialType(secret: secret) else {
                return false
            }
            return allowedTypes.contains(credentialType)
        }
    }
    
    func handleShellConfigMigration(
        secrets: [DetectedSecret],
        shellConfigService: ShellConfigService,
        backupService: BackupService,
        confirmApplyChanges: () -> Bool = Self.confirmApplyChangesPrompt,
        storeSecrets: (([DetectedSecret]) async throws -> ScrapeMigrationSummary)? = nil
    ) async throws -> ShellConfigMigrationResult {
        let targetFolderPath = normalizeFolderPath(folder)
        let diffs = await shellConfigService.generateDiff(for: secrets, folderPath: targetFolderPath)
        
        if dryRun {
            await shellConfigService.displayDiff(diffs)
            print("")
            print("🔍 DRY RUN: No changes made.")
            return .dryRun
        }
        
        await shellConfigService.displayDiff(diffs)
        print("")
        
        if !replaceAll {
            guard confirmApplyChanges() else {
                print("Cancelled. No changes made.")
                return .cancelled
            }
        } else if !quiet {
            print("Applying changes (--replace-all).")
        }

        let summary = try await (storeSecrets ?? addSecretsToAuthsia)(secrets)
        let storedSecrets = rewriteableSecrets(from: summary, selectedSecrets: secrets)
        guard !storedSecrets.isEmpty else {
            if !quiet {
                print("")
                print("No file changes applied because no selected secrets were stored in Authsia.")
            }
            return .noChanges
        }
        if storedSecrets.count < secrets.count, !quiet {
            print("")
            print(
                "⚠️  Applying file changes for \(storedSecrets.count)/\(secrets.count) stored secret(s). " +
                "Skipped secrets remain unchanged."
            )
        }

        let uniqueFiles = Array(Set(storedSecrets.map { $0.filePath })).sorted()
        let createdBackups = try await createBackups(
            for: uniqueFiles,
            backupService: backupService,
            description: "Before authsia scrape migration"
        )

        do {
            let modifiedFiles = try await shellConfigService.applyChanges(storedSecrets, folderPath: targetFolderPath)
            print("")
            print("✅ Modified files:")
            for file in modifiedFiles {
                print("  - \(file)")
            }
        } catch {
            await deleteBackups(createdBackups, backupService: backupService)
            print("❌ Failed to apply changes: \(error.localizedDescription)")
            throw error
        }
        
        return .applied(storedSecrets)
    }

    func handleEnvFileMigration(
        secrets: [DetectedSecret],
        backupService: BackupService,
        confirmApplyChanges: () -> Bool = Self.confirmApplyChangesPrompt,
        storeSecrets: (([DetectedSecret]) async throws -> ScrapeMigrationSummary)? = nil
    ) async throws -> ShellConfigMigrationResult {
        let targetFolderPath = normalizeFolderPath(folder)
        let diffs = EnvFileRewriteService.generateDiff(for: secrets, folderPath: targetFolderPath)

        if dryRun {
            EnvFileRewriteService.displayDiff(diffs)
            print("")
            print("🔍 DRY RUN: No changes made to .env files.")
            return .dryRun
        }

        EnvFileRewriteService.displayDiff(diffs)
        print("")

        if !replaceAll {
            guard confirmApplyChanges() else {
                print("Cancelled. No changes made.")
                return .cancelled
            }
        } else if !quiet {
            print("Applying .env changes (--replace-all).")
        }

        // Store the secret values before rewriting files so references never point at missing vault items.
        let summary = try await (storeSecrets ?? addSecretsToAuthsia)(secrets)
        let storedSecrets = rewriteableSecrets(from: summary, selectedSecrets: secrets)
        guard !storedSecrets.isEmpty else {
            if !quiet {
                print("")
                print("No file changes applied because no selected secrets were stored in Authsia.")
            }
            return .noChanges
        }
        if storedSecrets.count < secrets.count, !quiet {
            print("")
            print(
                "⚠️  Applying file changes for \(storedSecrets.count)/\(secrets.count) stored secret(s). " +
                "Skipped secrets remain unchanged."
            )
        }

        // Back up each affected file immediately before modifying it.
        let uniqueFiles = Array(Set(storedSecrets.map(\.filePath))).sorted()
        let createdBackups = try await createBackups(
            for: uniqueFiles,
            backupService: backupService,
            description: "Before authsia scrape .env migration"
        )

        // Patch the files
        do {
            try EnvFileRewriteService.rewrite(
                secrets: storedSecrets,
                folderPath: targetFolderPath,
                referenceBySecretID: summary.referenceBySecretID
            )
        } catch {
            await deleteBackups(createdBackups, backupService: backupService)
            throw error
        }

        if !quiet {
            print("")
            print("✅ Updated \(uniqueFiles.count) .env file(s). Secrets replaced with authsia:// references.")
            print("   Use `authsia exec -- <cmd>` from that folder to run with secrets resolved.")
        }
        return .applied(storedSecrets)
    }

    func rewriteableSecrets(
        from summary: ScrapeMigrationSummary,
        selectedSecrets: [DetectedSecret]
    ) -> [DetectedSecret] {
        let storedResults = summary.results.filter { result in
            switch result.outcome {
            case .added, .updated, .reused:
                return true
            case .skipped:
                return false
            }
        }

        let storedIDs = Set(storedResults.map(\.secret.id))
        let storedCoverageKeys = Set(storedResults.map(\.secret.storageCoverageKey))
        var output = selectedSecrets.filter {
            storedIDs.contains($0.id) || storedCoverageKeys.contains($0.storageCoverageKey)
        }

        // Certificate migration can coalesce cert and key lines into one vault write.
        // Map that stored result back onto the original source lines for the rewrite.
        for result in storedResults where !selectedSecrets.contains(result.secret) {
            let relatedSecrets = selectedSecrets.filter {
                $0.filePath == result.secret.filePath &&
                $0.authsiaKey == result.secret.authsiaKey
            }
            for secret in relatedSecrets where !output.contains(secret) {
                output.append(secret)
            }
        }

        return output
    }

    private func createBackups(
        for filePaths: [String],
        backupService: BackupService,
        description: String
    ) async throws -> [BackupService.BackupEntry] {
        var backups: [BackupService.BackupEntry] = []
        do {
            for filePath in filePaths {
                let normalizedPath = FilePathNormalizer.absoluteStandardizedPath(filePath)
                let originalContent = try String(contentsOfFile: normalizedPath, encoding: .utf8)
                let backup = try await backupService.createBackup(
                    of: normalizedPath,
                    originalContent: originalContent,
                    description: description
                )
                backups.append(backup)
            }
        } catch {
            await deleteBackups(backups, backupService: backupService)
            throw error
        }
        return backups
    }

    private func deleteBackups(_ backups: [BackupService.BackupEntry], backupService: BackupService) async {
        for backup in backups {
            try? await backupService.deleteBackup(entry: backup)
        }
    }

    private func addSecretsToAuthsia(_ secrets: [DetectedSecret]) async throws -> ScrapeMigrationSummary {
        print("")
        print("📝 Adding secrets to Authsia...")

        let bridgeClient = AuthsiaBridgeClient.shared
        let conflictMode: ScrapeMigrator.ConflictMode
        if replaceAll {
            conflictMode = .overwrite
        } else if yes {
            conflictMode = .skip
        } else {
            conflictMode = .prompt { secret in
                if !quiet {
                    print("  ⚠️  '\(secret.authsiaKey)' already exists in Authsia.")
                }
                return CLIPrompt.confirm("     Overwrite existing value?", defaultValue: false)
            }
        }

        let migrator = ScrapeMigrator(
            client: bridgeClient,
            conflictMode: conflictMode,
            folderPath: normalizeFolderPath(folder)
        )
        let summary = try migrator.migrate(secrets)

        if !quiet {
            for result in summary.results {
                switch result.outcome {
                case .added:
                    print("  ✅ \(result.secret.authsiaKey)")
                case .updated:
                    print("  ✅ \(result.secret.authsiaKey) (updated)")
                case .reused:
                    print("  ✅ \(result.secret.authsiaKey) (reused existing item)")
                case .skipped:
                    if yes {
                        print("  ⚠️  '\(result.secret.authsiaKey)' already exists in Authsia.")
                        print("     Skipped (use interactive mode to overwrite).")
                    } else {
                        print("     Skipped.")
                    }
                }
            }
        }

        if !quiet {
            print("")
            var summaryLine = "Added \(summary.addedCount)/\(secrets.count) secrets to Authsia."
            let reusedCount = summary.results.filter { $0.outcome == .reused }.count
            if reusedCount > 0 {
                summaryLine += " (\(reusedCount) reused)"
            }
            if summary.skippedCount > 0 {
                summaryLine += " (\(summary.skippedCount) skipped)"
            }
            print(summaryLine)
            if !summary.failed.isEmpty {
                print("⚠️  \(summary.failed.count) secret(s) failed to add. You can add them manually:")
                for (secret, _) in summary.failed {
                    switch secret.type {
                    case .jsonCredential, .sshKey:
                        print("  - \(secret.authsiaKey) (\(secret.type.description))")
                    default:
                        print("  $ \(secret.addToAuthsiaCommand)")
                    }
                }
            }
        }
        return summary
    }

    private func applyFolderToReferencedItems(_ references: [AuthsiaReference], folderPath: String) async -> Int {
        let bridgeClient = AuthsiaBridgeClient.shared
        let payload: BridgeListPayload
        do {
            payload = try bridgeClient.list()
        } catch {
            if !quiet {
                print("  ⚠️  Failed to load referenced vault items.")
            }
            return 0
        }
        var updatedCount = 0

        for reference in references {
            guard let itemID = referencedItemID(for: reference, in: payload) else {
                if !quiet {
                    print("  ⚠️  Failed to find a unique \(reference.itemType.rawValue) '\(reference.query)'.")
                }
                continue
            }

            do {
                switch reference.itemType {
                case .password:
                    _ = try bridgeClient.updatePassword(
                        query: itemID,
                        name: nil,
                        username: nil,
                        password: nil,
                        website: nil,
                        notes: nil,
                        isScraped: nil,
                        folderPath: folderPath
                    )
                case .apiKey:
                    _ = try bridgeClient.updateAPIKey(
                        query: itemID,
                        name: nil,
                        key: nil,
                        website: nil,
                        notes: nil,
                        isScraped: nil,
                        folderPath: folderPath
                    )
                case .certificate:
                    _ = try bridgeClient.updateCertificate(
                        query: itemID,
                        name: nil,
                        certificate: nil,
                        privateKey: nil,
                        notes: nil,
                        folderPath: folderPath
                    )
                case .note:
                    _ = try bridgeClient.updateNote(
                        query: itemID,
                        title: nil,
                        content: nil,
                        isScraped: nil,
                        folderPath: folderPath
                    )
                case .ssh:
                    _ = try bridgeClient.updateSSH(
                        query: itemID,
                        name: nil,
                        publicKey: nil,
                        privateKey: nil,
                        comment: nil,
                        fingerprint: nil,
                        isScraped: nil,
                        folderPath: folderPath
                    )
                }
                updatedCount += 1
            } catch {
                if !quiet {
                    print("  ⚠️  Failed to update folder for \(reference.itemType.rawValue) '\(reference.query)'.")
                }
            }
        }

        return updatedCount
    }

    private func referencedItemID(for reference: AuthsiaReference, in payload: BridgeListPayload) -> String? {
        switch reference.itemType {
        case .password:
            return uniqueReferencedItemID(
                query: reference.query,
                folderPath: reference.folderPath,
                items: payload.passwords,
                id: { $0.id.uuidString },
                name: { $0.name },
                folder: { $0.folderPath }
            )
        case .apiKey:
            return uniqueReferencedItemID(
                query: reference.query,
                folderPath: reference.folderPath,
                items: payload.apiKeys,
                id: { $0.id.uuidString },
                name: { $0.name },
                folder: { $0.folderPath }
            )
        case .certificate:
            return uniqueReferencedItemID(
                query: reference.query,
                folderPath: reference.folderPath,
                items: payload.certificates,
                id: { $0.id.uuidString },
                name: { $0.name },
                folder: { $0.folderPath }
            )
        case .note:
            return uniqueReferencedItemID(
                query: reference.query,
                folderPath: reference.folderPath,
                items: payload.notes,
                id: { $0.id.uuidString },
                name: { $0.title },
                folder: { $0.folderPath }
            )
        case .ssh:
            return uniqueReferencedItemID(
                query: reference.query,
                folderPath: reference.folderPath,
                items: payload.sshKeys,
                id: { $0.id.uuidString },
                name: { $0.name },
                folder: { $0.folderPath }
            )
        }
    }

    private func uniqueReferencedItemID<T>(
        query: String,
        folderPath: String?,
        items: [T],
        id: (T) -> String,
        name: (T) -> String,
        folder: (T) -> String?
    ) -> String? {
        let trimmedQuery = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedQuery.isEmpty else { return nil }

        let sourceFolder = normalizeFolderPath(folderPath)
        if let exactID = items.first(where: { id($0).caseInsensitiveCompare(trimmedQuery) == .orderedSame }) {
            guard sourceFolder == nil || normalizeFolderPath(folder(exactID)) == sourceFolder else {
                return nil
            }
            return id(exactID)
        }

        var matches = items.filter {
            name($0).trimmingCharacters(in: .whitespacesAndNewlines)
                .caseInsensitiveCompare(trimmedQuery) == .orderedSame
        }
        if let sourceFolder {
            matches = matches.filter { normalizeFolderPath(folder($0)) == sourceFolder }
        }
        guard matches.count == 1, let match = matches.first else { return nil }
        return id(match)
    }

    func fileReplacementSecrets(from secrets: [DetectedSecret]) -> [DetectedSecret] {
        return secrets.filter { secret in
            if secret.isEnvFile { return true }
            if secret.isShellConfig { return true }
            return false
        }
    }

    func nonFileReplacementSecretsForStorage(from secrets: [DetectedSecret]) -> [DetectedSecret] {
        guard !dryRun else {
            return []
        }
        let fileReplacementSecrets = fileReplacementSecrets(from: secrets)
        return secrets.filter { !fileReplacementSecrets.contains($0) }
    }
    
    private func resolveDefaultPaths() -> [String] {
        Self.resolveDefaultPaths(
            fileManager: .default,
            homeDirectory: FileManager.default.homeDirectoryForCurrentUser,
            currentDirectory: FileManager.default.currentDirectoryPath
        )
    }

    static func sshAdoptionGuidance(for secrets: [DetectedSecret]) -> String {
        let count = secrets.count
        let directories = Set(secrets.map {
            ($0.filePath as NSString).deletingLastPathComponent
        })
        let pathSuggestion = directories.count == 1 ? (directories.first ?? "~/.ssh") : "<path>"
        return """
        ℹ️ Skipped \(count) SSH private key\(count == 1 ? "" : "s").
        SSH private keys are handled by `authsia ssh adopt` so Authsia can preserve public-key metadata, approval policy, and host bindings.
        Run: authsia ssh adopt --path \(pathSuggestion) --dry-run
        """
    }

    static func resolveDefaultPaths(
        fileManager: FileManager,
        homeDirectory: URL,
        currentDirectory: String
    ) -> [String] {
        var paths: [String] = []
        for pattern in [".env", ".env.local", ".env.development", ".env.production"] {
            let fullPath = (currentDirectory as NSString).appendingPathComponent(pattern)
            if fileManager.fileExists(atPath: fullPath) {
                paths.append(fullPath)
            }
        }
        
        let home = homeDirectory.path
        for config in [".zshrc", ".bashrc", ".bash_profile", ".zprofile"] {
            let fullPath = (home as NSString).appendingPathComponent(config)
            if fileManager.fileExists(atPath: fullPath) {
                paths.append(fullPath)
            }
        }

        let kubeConfig = (home as NSString).appendingPathComponent(".kube/config")
        if fileManager.fileExists(atPath: kubeConfig) {
            paths.append(kubeConfig)
        }
        
        return paths
    }
}
