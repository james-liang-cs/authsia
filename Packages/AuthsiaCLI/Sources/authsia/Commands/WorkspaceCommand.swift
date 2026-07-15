import ArgumentParser
import Darwin
import Foundation
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData

protocol WorkspaceSetupVaultClient: ScrapeVaultClient {
    @discardableResult
    func ensureVaultFolder(path: String) throws -> WriteResult
}

struct Workspace: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "workspace",
        abstract: "Initialize and run repo-local Authsia workspaces",
        discussion: """
            Examples:
              authsia workspace init --env-file .env --agent codex
              authsia workspace update --recursive-env --dry-run
              authsia workspace run -- npm test
              authsia workspace sync --dry-run
              authsia workspace env add API_KEY authsia://api-key/API_KEY/key
            """,
        subcommands: [
            Init.self,
            Update.self,
            Reset.self,
            Run.self,
            Status.self,
            Sync.self,
            Guard.self,
            Agent.self,
            Env.self,
            Forget.self,
        ]
    )

    struct Init: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "init",
            abstract: "Set up this repo for Authsia-safe terminal and agent workflows",
            discussion: """
                Examples:
                  authsia workspace init --dry-run --recursive-env
                  authsia workspace init --yes --env-file .env --folder Workspaces/api
                  authsia workspace init --env-file .env --agent codex --agent cursor
                  authsia workspace init --plan-json
                  authsia workspace init --plan-json --local-preview
                  authsia workspace init --apply-json workspace-plan.json
                """
        )

        @Flag(name: .long, help: "Preview workspace setup without writing files")
        var dryRun = false

        @Flag(name: .long, help: "Emit a sanitized JSON setup plan for app integrations")
        var planJson = false

        @Flag(name: .long, help: "Build preview from local workspace files only; skips live vault conflict checks")
        var localPreview = false

        @Option(name: .long, help: "Apply a sanitized workspace setup selection JSON file")
        var applyJson: String?

        @Flag(name: .long, help: "Apply without prompts; requires at least one --env-file")
        var yes = false

        @Option(name: .long, help: "Authsia folder to use for migrated workspace secrets")
        var folder: String?

        @Option(name: .long, parsing: .upToNextOption, help: "Env file to review/manage")
        var envFile: [String] = []

        @Flag(
            name: .long,
            help: "Merge auto-discovered env files up to 3 directories deep with explicit --env-file paths"
        )
        var recursiveEnv = false

        @Option(
            name: .long,
            help: "Agent rules to install; normal init defaults to claude-code: claude-code, cursor, codex, windsurf, copilot"
        )
        var agent: [AgentTool] = []

        @Flag(name: .long, help: "Install rules for all supported agents")
        var allAgents = false

        static let secretReviewInstructions = "Enter=confirm detected secrets, row numbers=toggle, a=select all, c=clear all"
        static let yesRequiresEnvFileMessage = "--yes requires at least one explicit --env-file. " +
            "Use --dry-run to preview discovered env files. Then re-run with --yes --env-file .env."
        private static let noEnvSecretGuidanceLines = [
            "To add secrets later:",
            "- Clipboard path: copy a secret, open Authsia from the menu bar, and save with " +
                "Save to workspace on to bind it during save.",
            "- CLI path: bind an existing CLI-enabled item with authsia workspace env add <NAME> <authsia://...>",
            "- Then workspace run and agent commands can receive <NAME> as an env var.",
        ]

        func run() async throws {
            if planJson && dryRun {
                throw ValidationError("Use either --plan-json or --dry-run, not both.")
            }
            if applyJson != nil && (dryRun || planJson || yes || localPreview) {
                throw ValidationError("Use --apply-json by itself; preview first with --plan-json.")
            }
            if localPreview && !(planJson || dryRun) {
                throw ValidationError("Use --local-preview with --plan-json or --dry-run.")
            }
            if yes && envFile.isEmpty {
                throw ValidationError(Self.yesRequiresEnvFileMessage)
            }
            if yes && recursiveEnv {
                throw ValidationError("--yes does not support --recursive-env. Review recursively with --dry-run or interactive mode.")
            }
            if allAgents && !agent.isEmpty {
                throw ValidationError("Use either --agent or --all-agents, not both.")
            }

            let workingDirectory = URL(
                fileURLWithPath: FileManager.default.currentDirectoryPath,
                isDirectory: true
            )
            let root = WorkspaceRootResolver.resolveInitRoot(startingAt: workingDirectory)

            if let conflictRoot = WorkspaceRootResolver.conflictingExistingWorkspaceRoot(
                startingAt: workingDirectory,
                initRoot: root
            ) {
                Self.warnExistingWorkspaceConflict(existingRoot: conflictRoot, initRoot: root)
                if applyJson == nil, !planJson, !dryRun, !yes {
                    guard TerminalContext.isInteractiveSession else {
                        throw ValidationError(
                            Self.existingWorkspaceConflictMessage(existingRoot: conflictRoot, initRoot: root)
                        )
                    }
                    guard CLIPrompt.confirm(
                        "Create a separate workspace at \(root.path) anyway?",
                        defaultValue: false
                    ) else {
                        print("Cancelled. No changes made.")
                        return
                    }
                }
            }

            if let applyJson {
                let selection = try WorkspaceSetupExchange.readSelection(from: applyJson)
                let selectedAgents = try WorkspaceSetupExchange.selectedAgents(from: selection)
                let selectedEnvFiles = selection.envFiles.map(\.relativePath)
                let plan = try await WorkspaceInitPlanner.plan(
                    workspaceRoot: root,
                    explicitEnvFiles: selectedEnvFiles.isEmpty ? envFile : selectedEnvFiles,
                    folderOverride: selection.authsiaFolder ?? folder,
                    agents: selectedAgents,
                    discoverNestedEnvFiles: recursiveEnv,
                    vaultIndex: nil
                )
                let resolved = try WorkspaceSetupExchange.resolve(selection, against: plan)
                try await Self.apply(
                    plan: plan,
                    selectedEnvFiles: resolved.envFiles,
                    selectedSecrets: resolved.secrets
                )
                return
            }

            let agents = Self.selectedAgents(
                allAgents: allAgents,
                explicitAgents: agent,
                defaultToClaudeCode: !planJson
            )
            let plan = try await WorkspaceInitPlanner.plan(
                workspaceRoot: root,
                explicitEnvFiles: envFile,
                folderOverride: folder,
                agents: agents,
                discoverNestedEnvFiles: recursiveEnv,
                vaultIndex: localPreview ? nil : try Workspace.loadVaultIndex(failOnApprovalDenial: planJson)
            )
            if planJson {
                try WorkspaceSetupExchange.printPlanJSON(plan, mode: .initWorkspace)
                return
            }
            print(Self.renderPlan(plan))

            if dryRun {
                return
            }

            let selectedEnvPlans: [WorkspaceEnvFilePlan]
            let selectedSecrets: [WorkspaceSecretSelection]
            if yes {
                selectedEnvPlans = plan.envFiles
                selectedSecrets = try WorkspaceUpdatePlanner.defaultSecretSelectionsForExplicitEnvFiles(
                    plan: plan,
                    explicitEnvFiles: envFile
                )
            } else {
                guard TerminalContext.isInteractiveSession else {
                    throw ValidationError(
                        "Interactive workspace init requires a TTY. Re-run with --dry-run or --yes --env-file <path>."
                    )
                }
                let fileIndexByPath = Dictionary(
                    uniqueKeysWithValues: plan.envFiles.enumerated().map { index, envFile in
                        (envFile.absolutePath, index + 1)
                    }
                )
                selectedEnvPlans = Self.promptForEnvFiles(plan.envFiles)
                selectedSecrets = selectedEnvPlans.flatMap { envFile in
                    Self.promptForSecrets(
                        envFile,
                        fileIndex: fileIndexByPath[envFile.absolutePath] ?? 1
                    )
                }
                guard Self.confirmApply(
                    plan: plan,
                    selectedSecrets: selectedSecrets,
                    selectedEnvFiles: selectedEnvPlans
                ) else {
                    print("Cancelled. No changes made.")
                    return
                }
            }

            try await Self.apply(plan: plan, selectedEnvFiles: selectedEnvPlans, selectedSecrets: selectedSecrets)
        }

        static func selectedAgents(
            allAgents: Bool,
            explicitAgents: [AgentTool],
            defaultToClaudeCode: Bool = true
        ) -> [AgentTool] {
            if allAgents {
                return AgentTool.allCases
            }
            return explicitAgents.isEmpty && defaultToClaudeCode ? [.claudeCode] : explicitAgents
        }

        static func existingWorkspaceConflictMessage(existingRoot: URL, initRoot: URL) -> String {
            "An Authsia workspace already exists at \(existingRoot.path). " +
                "init would create a separate workspace at \(initRoot.path). " +
                "Re-run from \(existingRoot.path) to update it. To intentionally create a separate workspace, " +
                "preview with `authsia workspace init --dry-run`, then re-run with " +
                "`authsia workspace init --yes --env-file <path>`."
        }

        static func renderPlan(_ plan: WorkspaceInitPlan) -> String {
            var lines: [String] = [
                "Authsia workspace: \(plan.config.workspace.name)",
                "Folder: \(plan.config.workspace.authsiaFolder)",
                "",
                "Env files:",
            ]
            if plan.envFiles.isEmpty {
                lines.append("- none found")
                lines.append("")
                lines.append(contentsOf: noEnvSecretGuidanceLines)
            } else {
                for (index, envFile) in plan.envFiles.enumerated() {
                    let selected = envFile.secrets.filter(\.selectedByDefault).count
                    let ignored = max(0, envFile.secrets.count - selected)
                    lines.append(
                        "- [\(index + 1)] \(envFile.relativePath): " +
                        "\(selected) selected secret(s), \(ignored) review item(s)"
                    )
                    let review = renderSecretReview(
                        envFile,
                        fileIndex: index + 1,
                        folderPath: plan.config.workspace.authsiaFolder
                    )
                    if !review.isEmpty {
                        lines.append(contentsOf: review.components(separatedBy: "\n"))
                    }
                }
            }
            if !plan.agents.isEmpty {
                lines.append("")
                lines.append("Agent rules:")
                for agent in plan.agents {
                    lines.append("- \(agent.title)")
                }
            }
            if !plan.removedEnvFiles.isEmpty {
                lines.append("")
                lines.append("Removed managed env files:")
                lines.append(contentsOf: plan.removedEnvFiles.map { "- \($0)" })
            }
            WorkspaceStatusReporter.appendMissingReferenceGuidance(plan.missingReferences, to: &lines)
            WorkspaceStatusReporter.appendUnverifiedReferenceGuidance(plan.unverifiedReferences, to: &lines)
            return lines.joined(separator: "\n")
        }

        static func renderSecretReview(
            _ envFile: WorkspaceEnvFilePlan,
            fileIndex: Int,
            selectedIDs: Set<UUID>? = nil,
            folderPath: String? = nil
        ) -> String {
            var lines: [String] = []
            for (index, secret) in envFile.secrets.enumerated() {
                let selected = selectedIDs?.contains(secret.secret.id) ?? secret.selectedByDefault
                let marker = secret.conflict == nil ? (selected ? "[x]" : "[ ]") : "[!]"
                let type = secret.secret.type.rawValue.lowercased()
                let storeTarget = folderPath.map { "\($0)/\(secret.secret.authsiaKey)" } ?? secret.secret.authsiaKey
                lines.append(
                    "  [\(fileIndex).\(index + 1)] \(marker) \(secret.secret.key)  " +
                    "type=\(type)  confidence=\(secret.secret.confidence.rawValue)"
                )
                if let conflict = secret.conflict {
                    lines.append("      existing: \(conflict.displayLine)")
                }
                lines.append("      store: \(storeTarget)")
                lines.append("      reference: \(secret.replacementLine)")
            }
            return lines.joined(separator: "\n")
        }

        fileprivate static func promptForEnvFiles(_ envFiles: [WorkspaceEnvFilePlan]) -> [WorkspaceEnvFilePlan] {
            guard !envFiles.isEmpty else { return [] }
            print("")
            print("Select env files to manage (comma-separated, Enter for all): ", terminator: "")
            let answer = readLine()?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !answer.isEmpty else { return envFiles }
            let indexes = Set(answer.split(separator: ",").compactMap { Int($0.trimmingCharacters(in: .whitespaces)) })
            return envFiles.enumerated().compactMap { index, envFile in
                indexes.contains(index + 1) ? envFile : nil
            }
        }

        fileprivate static func promptForSecrets(
            _ envFile: WorkspaceEnvFilePlan,
            fileIndex: Int
        ) -> [WorkspaceSecretSelection] {
            guard !envFile.secrets.isEmpty else { return [] }
            let selected = defaultInteractiveSecretIDs(envFile)
            print("")
            print(envFile.relativePath)
            print(renderSecretReview(envFile, fileIndex: fileIndex, selectedIDs: selected))
            print("\(secretReviewInstructions): ", terminator: "")
            let answer = readLine()?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            var output = resolveSecretSelections(envFile, answer: answer, fileIndex: fileIndex)
            for secret in envFile.secrets where secret.conflict != nil {
                if let action = promptForConflictAction(secret) {
                    output.append(WorkspaceSecretSelection(secret: secret.secret, action: action))
                }
            }
            if let suggestion = WorkspaceEnvironmentSuggestion.from(path: envFile.relativePath),
               !output.isEmpty,
               CLIPrompt.confirm("Tag selected items as \(suggestion)?", defaultValue: false) {
                output = output.map {
                    WorkspaceSecretSelection(
                        secret: $0.secret,
                        action: $0.action,
                        environments: [suggestion]
                    )
                }
            }
            return output
        }

        static func resolveSecretSelections(
            _ envFile: WorkspaceEnvFilePlan,
            answer: String,
            fileIndex: Int = 1
        ) -> [WorkspaceSecretSelection] {
            let normalizedAnswer = answer.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if ["c", "clear", "clear all", "q"].contains(normalizedAnswer) {
                return []
            }

            let conflictIDs = Set(envFile.secrets.compactMap { $0.conflict == nil ? nil : $0.secret.id })
            var selected = defaultInteractiveSecretIDs(envFile)
            if ["a", "all"].contains(normalizedAnswer) {
                selected = defaultInteractiveSecretIDs(envFile)
            } else if ["h", "high", "high-confidence"].contains(normalizedAnswer) {
                selected = highConfidenceSecretIDs(envFile)
            } else {
                for raw in normalizedAnswer.split(separator: ",") {
                    guard let number = secretNumber(from: raw, fileIndex: fileIndex),
                          envFile.secrets.indices.contains(number - 1) else {
                        continue
                    }
                    let id = envFile.secrets[number - 1].secret.id
                    guard !conflictIDs.contains(id) else { continue }
                    if selected.contains(id) {
                        selected.remove(id)
                    } else {
                        selected.insert(id)
                    }
                }
            }

            return envFile.secrets
                .filter { selected.contains($0.secret.id) }
                .map { WorkspaceSecretSelection(secret: $0.secret, action: .create) }
        }

        private static func defaultInteractiveSecretIDs(_ envFile: WorkspaceEnvFilePlan) -> Set<UUID> {
            Set(envFile.secrets
                .filter { $0.conflict == nil }
                .map(\.secret.id))
        }

        private static func highConfidenceSecretIDs(_ envFile: WorkspaceEnvFilePlan) -> Set<UUID> {
            Set(envFile.secrets
                .filter { $0.conflict == nil && $0.secret.confidence == .high }
                .map(\.secret.id))
        }

        private static func secretNumber(from raw: Substring, fileIndex: Int) -> Int? {
            let token = raw.trimmingCharacters(in: .whitespaces)
            if let number = Int(token) {
                return number
            }

            let parts = token.split(separator: ".", maxSplits: 1)
            guard parts.count == 2,
                  Int(parts[0]) == fileIndex,
                  let number = Int(parts[1]) else {
                return nil
            }
            return number
        }

        private static func promptForConflictAction(_ secret: WorkspaceEnvSecretPlan) -> WorkspaceSecretAction? {
            guard let conflict = secret.conflict else { return nil }
            print("")
            print("Existing Authsia item for \(secret.secret.key): \(conflict.displayLine)")
            print("Choose action: [s]kip, [u]pdate existing item, [r]euse existing item: ", terminator: "")
            let answer = readLine()?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
            switch answer {
            case "u", "update":
                return .update
            case "r", "reuse":
                return .reuse
            default:
                return nil
            }
        }

        fileprivate static func warnExistingWorkspaceConflict(existingRoot: URL, initRoot: URL) {
            let message = "warning: an Authsia workspace already exists at \(existingRoot.path); " +
                "init will create a separate workspace at \(initRoot.path)\n"
            FileHandle.standardError.write(Data(message.utf8))
        }

        fileprivate static func confirmApply(
            plan: WorkspaceInitPlan,
            selectedSecrets: [WorkspaceSecretSelection],
            selectedEnvFiles: [WorkspaceEnvFilePlan]
        ) -> Bool {
            print("")
            print("Apply workspace setup?")
            print("- Create/update \(WorkspaceConfigStore.relativeConfigPath)")
            print("- Target Authsia folder \(plan.config.workspace.authsiaFolder)")
            let writeCount = selectedSecrets.filter { $0.action == .create || $0.action == .update }.count
            let reuseCount = selectedSecrets.filter { $0.action == .reuse }.count
            print("- Store/update \(writeCount) Authsia item(s)")
            if reuseCount > 0 {
                print("- Reuse \(reuseCount) existing Authsia item(s)")
            }
            print("- Rewrite \(selectedEnvFiles.count) env file(s)")
            if !plan.agents.isEmpty {
                print("- Install \(plan.agents.count) agent rule set(s)")
            }
            return CLIPrompt.confirm("Apply?", defaultValue: true)
        }

        static func apply(
            plan: WorkspaceInitPlan,
            selectedEnvFiles: [WorkspaceEnvFilePlan],
            selectedSecrets: [WorkspaceSecretSelection],
            removedAgents: [AgentTool] = [],
            backupService: BackupService = BackupService(),
            vaultClient: WorkspaceSetupVaultClient = AuthsiaBridgeClient.shared
        ) async throws {
            try validateNoMissingReferences(plan: plan, selectedEnvFiles: selectedEnvFiles)
            let vaultSecretSelections = selectedSecrets.filter { isWorkspaceMigratableSecret($0.secret) }
            let secretsToRewrite = vaultSecretSelections.map(\.secret)
            if !vaultSecretSelections.isEmpty {
                let scrape = configuredScrapeForEnvMigration(folder: plan.config.workspace.authsiaFolder)
                let actionBySecretID = Dictionary(
                    uniqueKeysWithValues: vaultSecretSelections.map { ($0.secret.id, $0.action) }
                )
                _ = try await scrape.handleEnvFileMigration(
                    secrets: secretsToRewrite,
                    backupService: backupService,
                    confirmApplyChanges: { true },
                    storeSecrets: { secrets in
                        let migrator = ScrapeMigrator(
                            client: vaultClient,
                            conflictMode: .choose { secret in
                                switch actionBySecretID[secret.id] ?? .create {
                                case .create:
                                    return .skip
                                case .update:
                                    return .overwrite
                                case .reuse:
                                    return .reuse
                                }
                            },
                            folderPath: plan.config.workspace.authsiaFolder,
                            environmentTagsBySecretID: Dictionary(
                                uniqueKeysWithValues: vaultSecretSelections.compactMap { selection in
                                    selection.environments.map { (selection.secret.id, $0) }
                                }
                            )
                        )
                        let summary = try migrator.migrate(secrets)
                        try validateSelectedSecretsStored(summary, selectedSecrets: secrets)
                        try validateSelectedVaultSecretsVisible(
                            summary,
                            selectedSecrets: secrets,
                            vaultClient: vaultClient,
                            folderPath: plan.config.workspace.authsiaFolder
                        )
                        return summary
                    }
                )
            }

            let config = WorkspaceConfig(
                schemaVersion: 2,
                workspace: plan.config.workspace,
                managedEnvFiles: selectedEnvFiles.map(\.relativePath),
                agents: plan.config.agents,
                guardSettings: plan.config.guardSettings,
                envBindings: plan.config.envBindings
            )
            try WorkspaceConfigStore.write(config, toWorkspaceRoot: plan.workspaceRoot)
            Workspace.recordKnownWorkspaceRoot(plan.workspaceRoot)
            if !removedAgents.isEmpty {
                let result = try AgentRuleInstaller.uninstall(projectRoot: plan.workspaceRoot, agents: removedAgents)
                print(AgentRuleInstaller.renderRemovalResult(result))
            }
            if !plan.agents.isEmpty {
                let result = try AgentRuleInstaller.install(projectRoot: plan.workspaceRoot, agents: plan.agents)
                print(AgentRuleInstaller.renderResult(result))
            }
            print("Authsia workspace is ready.")
            print("Run securely with: authsia workspace run -- <command>")
            if plan.envFiles.isEmpty {
                print("")
                print(Self.noEnvSecretGuidanceLines.joined(separator: "\n"))
            }
        }

        static func configuredScrapeForEnvMigration(folder: String) -> Scrape {
            var scrape = Scrape()
            scrape.path = []
            scrape.recursive = false
            scrape.folder = folder
            scrape.confidence = .low
            scrape.type = []
            scrape.dryRun = false
            scrape.yes = true
            scrape.replaceAll = false
            scrape.revert = nil
            scrape.revertOriginal = nil
            scrape.listModified = false
            scrape.revertAll = false
            scrape.quiet = false
            scrape.allMachines = false
            scrape.machine = nil
            return scrape
        }

        static func validateNoMissingReferences(
            plan: WorkspaceInitPlan,
            selectedEnvFiles: [WorkspaceEnvFilePlan]
        ) throws {
            let selectedPaths = Set(selectedEnvFiles.map(\.relativePath))
            let blocking = plan.missingReferences.filter { selectedPaths.contains($0.relativePath) }
            guard !blocking.isEmpty else { return }
            var lines = [
                "Workspace setup found \(blocking.count) Authsia reference(s) that do not exist in the vault. " +
                    "No workspace files were written.",
            ]
            WorkspaceStatusReporter.appendMissingReferenceGuidance(blocking, to: &lines)
            throw ValidationError(lines.joined(separator: "\n"))
        }

        static func validateSelectedSecretsStored(
            _ summary: ScrapeMigrationSummary,
            selectedSecrets: [DetectedSecret]
        ) throws {
            let storedIDs = Set(summary.results.compactMap { result -> UUID? in
                switch result.outcome {
                case .added, .updated, .reused:
                    return result.secret.id
                case .skipped:
                    return nil
                }
            })
            let storedCoverageKeys = Set(summary.results.compactMap { result -> DetectedSecret.StorageCoverageKey? in
                switch result.outcome {
                case .added, .updated, .reused:
                    return result.secret.storageCoverageKey
                case .skipped:
                    return nil
                }
            })
            let failedIDs = Set(summary.failed.map(\.0.id))
            let missingSecrets = selectedSecrets.filter {
                failedIDs.contains($0.id) ||
                    (!storedIDs.contains($0.id) && !storedCoverageKeys.contains($0.storageCoverageKey))
            }

            guard missingSecrets.isEmpty else {
                var message = "Workspace setup could not store \(missingSecrets.count) selected secret(s) in Authsia. " +
                    "No workspace files were rewritten."
                let details = missingSecrets.map { secret in
                    "- \(secret.key): \(storageFailureReason(for: secret, failed: summary.failed))"
                }
                if !details.isEmpty {
                    message += "\nFailed item(s):\n" + details.joined(separator: "\n")
                }
                message += "\nResolve the skipped or failed item(s), then rerun workspace init or update."
                throw ValidationError(message)
            }
        }

        static func validateSelectedVaultSecretsVisible(
            _ summary: ScrapeMigrationSummary,
            selectedSecrets: [DetectedSecret],
            vaultClient: WorkspaceSetupVaultClient,
            folderPath: String
        ) throws {
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
            var checkedKeys = Set<String>()
            var missing: [String] = []

            for secret in selectedSecrets where isWorkspaceMigratableSecret(secret) {
                guard storedIDs.contains(secret.id) || storedCoverageKeys.contains(secret.storageCoverageKey) else {
                    continue
                }
                let itemType = secret.type.storesAsAPIKey ? "api-key" : "password"
                let checkKey = "\(itemType)|\(secret.authsiaKey.lowercased())|\(normalizedFolderPath(folderPath) ?? "")"
                guard checkedKeys.insert(checkKey).inserted else { continue }
                let visibleID: String?
                if secret.type.storesAsAPIKey {
                    visibleID = try vaultClient.existingAPIKeyID(named: secret.authsiaKey, folderPath: folderPath)
                } else {
                    visibleID = try vaultClient.existingPasswordID(named: secret.authsiaKey, folderPath: folderPath)
                }
                if visibleID == nil {
                    missing.append(secret.authsiaKey)
                }
            }

            guard missing.isEmpty else {
                let details = missing.sorted().map {
                    "- \($0): not visible in folder \(folderPath)"
                }
                throw ValidationError(
                    "Workspace setup could not verify \(missing.count) selected vault item(s) in Authsia. " +
                        "No workspace files were rewritten.\nFailed item(s):\n" +
                        details.joined(separator: "\n") +
                        "\nResolve the missing item(s), then rerun workspace init or update."
                )
            }
        }

        private static func storageFailureReason(
            for secret: DetectedSecret,
            failed: [(DetectedSecret, Error)]
        ) -> String {
            guard let failure = failed.first(where: { $0.0.id == secret.id }) else {
                return "not stored"
            }
            return redactedStorageFailure(failure.1.localizedDescription, for: secret)
        }

        private static func redactedStorageFailure(_ message: String, for secret: DetectedSecret) -> String {
            let marker = "<concealed by authsia>"
            var redacted = message
            let sensitiveValues = [secret.value, secret.rawContent].compactMap { $0 }.filter { !$0.isEmpty }
            for value in sensitiveValues {
                redacted = redacted.replacingOccurrences(of: value, with: marker)
            }
            return redacted
        }

        private static func normalizedFolderPath(_ folderPath: String?) -> String? {
            guard let folderPath else { return nil }
            let segments = folderPath
                .split(separator: "/")
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            return segments.isEmpty ? nil : segments.joined(separator: "/")
        }
    }

    struct Update: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "update",
            abstract: "Refresh this repo's Authsia workspace",
            discussion: """
                Examples:
                  authsia workspace update --dry-run --recursive-env
                  authsia workspace update --yes --env-file .env.local
                  authsia workspace update --agent claude-code --agent codex
                  authsia workspace update --plan-json
                  authsia workspace update --plan-json --local-preview
                  authsia workspace update --apply-json workspace-update.json
                """
        )

        @Flag(name: .long, help: "Preview workspace update without writing files")
        var dryRun = false

        @Flag(name: .long, help: "Emit a sanitized JSON update plan for app integrations")
        var planJson = false

        @Flag(name: .long, help: "Build preview from local workspace files only; skips live vault conflict checks")
        var localPreview = false

        @Option(name: .long, help: "Apply a sanitized workspace update selection JSON file")
        var applyJson: String?

        @Flag(name: .long, help: "Apply without prompts; requires at least one --env-file")
        var yes = false

        @Option(name: .long, parsing: .upToNextOption, help: "Additional env file to review/manage")
        var envFile: [String] = []

        @Flag(
            name: .long,
            help: "Merge auto-discovered env files up to 3 directories deep with explicit --env-file paths"
        )
        var recursiveEnv = false

        @Option(name: .long, help: "Agent rules to add: claude-code, cursor, codex, windsurf, copilot")
        var agent: [AgentTool] = []

        @Flag(name: .long, help: "Install rules for all supported agents")
        var allAgents = false

        func run() async throws {
            if planJson && dryRun {
                throw ValidationError("Use either --plan-json or --dry-run, not both.")
            }
            if applyJson != nil && (dryRun || planJson || yes || localPreview) {
                throw ValidationError("Use --apply-json by itself; preview first with --plan-json.")
            }
            if localPreview && !(planJson || dryRun) {
                throw ValidationError("Use --local-preview with --plan-json or --dry-run.")
            }
            if yes && envFile.isEmpty {
                throw ValidationError(Init.yesRequiresEnvFileMessage)
            }
            if yes && recursiveEnv {
                throw ValidationError("--yes does not support --recursive-env. Review recursively with --dry-run or interactive mode.")
            }
            if allAgents && !agent.isEmpty {
                throw ValidationError("Use either --agent or --all-agents, not both.")
            }

            guard let root = WorkspaceRootResolver.findWorkspaceRoot(
                startingAt: URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
            ) else {
                throw WorkspaceConfigError.missingConfig
            }
            if let applyJson {
                let selection = try WorkspaceSetupExchange.readSelection(from: applyJson)
                let selectedAgents = try WorkspaceSetupExchange.selectedAgents(from: selection)
                let selectedEnvFiles = selection.envFiles.map(\.relativePath)
                let existingConfig = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
                let existingAgents = (existingConfig.agents?.rules ?? []).compactMap(AgentTool.init(argument:))
                let selectedAgentSet = Set(selectedAgents)
                let removedAgents = existingAgents.filter { !selectedAgentSet.contains($0) }
                let plan = try await WorkspaceUpdatePlanner.plan(
                    workspaceRoot: root,
                    explicitEnvFiles: selectedEnvFiles.isEmpty ? envFile : selectedEnvFiles,
                    agents: selectedAgents,
                    discoverNestedEnvFiles: recursiveEnv,
                    mergeExistingAgents: false,
                    vaultIndex: nil
                )
                let resolved = try WorkspaceSetupExchange.resolve(selection, against: plan)
                try await Init.apply(
                    plan: plan,
                    selectedEnvFiles: resolved.envFiles,
                    selectedSecrets: resolved.secrets,
                    removedAgents: removedAgents
                )
                return
            }

            let agents = allAgents ? AgentTool.allCases : agent
            let plan = try await WorkspaceUpdatePlanner.plan(
                workspaceRoot: root,
                explicitEnvFiles: envFile,
                agents: agents,
                discoverNestedEnvFiles: recursiveEnv,
                vaultIndex: localPreview ? nil : try Workspace.loadVaultIndex(failOnApprovalDenial: planJson)
            )
            if planJson {
                try WorkspaceSetupExchange.printPlanJSON(plan, mode: .update)
                return
            }
            print(Init.renderPlan(plan))

            if dryRun {
                return
            }

            let selectedEnvPlans: [WorkspaceEnvFilePlan]
            let selectedSecrets: [WorkspaceSecretSelection]
            if yes {
                selectedEnvPlans = plan.envFiles
                selectedSecrets = try WorkspaceUpdatePlanner.defaultSecretSelectionsForExplicitEnvFiles(
                    plan: plan,
                    explicitEnvFiles: envFile
                )
            } else {
                guard TerminalContext.isInteractiveSession else {
                    throw ValidationError(
                        "Interactive workspace update requires a TTY. Re-run with --dry-run or --yes --env-file <path>."
                    )
                }
                let fileIndexByPath = Dictionary(
                    uniqueKeysWithValues: plan.envFiles.enumerated().map { index, envFile in
                        (envFile.absolutePath, index + 1)
                    }
                )
                selectedEnvPlans = Init.promptForEnvFiles(plan.envFiles)
                selectedSecrets = selectedEnvPlans.flatMap { envFile in
                    Init.promptForSecrets(
                        envFile,
                        fileIndex: fileIndexByPath[envFile.absolutePath] ?? 1
                    )
                }
                guard Init.confirmApply(
                    plan: plan,
                    selectedSecrets: selectedSecrets,
                    selectedEnvFiles: selectedEnvPlans
                ) else {
                    print("Cancelled. No changes made.")
                    return
                }
            }

            try await Init.apply(plan: plan, selectedEnvFiles: selectedEnvPlans, selectedSecrets: selectedSecrets)
        }
    }

    struct Reset: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "reset",
            abstract: "Remove repo-local Authsia workspace metadata",
            discussion: """
                Examples:
                  authsia workspace reset --dry-run
                  authsia workspace reset --yes
                """
        )

        @Flag(name: .long, help: "Preview workspace reset without writing files")
        var dryRun = false

        @Flag(name: .long, help: "Reset without prompting after confirmation has already happened")
        var yes = false

        func run() async throws {
            guard let root = WorkspaceRootResolver.findWorkspaceRoot(
                startingAt: URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
            ) else {
                throw WorkspaceConfigError.missingConfig
            }
            _ = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
            let backupService = BackupService()
            let plan = try await WorkspaceResetPlanner.plan(workspaceRoot: root, backupService: backupService)
            print(WorkspaceResetPlanner.renderDryRun(plan))

            if dryRun {
                return
            }

            if !yes {
                guard TerminalContext.isInteractiveSession else {
                    throw ValidationError(
                        "Interactive workspace reset requires a TTY. Re-run with --dry-run to preview before resetting."
                    )
                }
                guard CLIPrompt.confirm("Reset workspace metadata?", defaultValue: false) else {
                    print("Cancelled. No changes made.")
                    return
                }
            }

            let result = try await WorkspaceResetPlanner.apply(plan, backupService: backupService)
            Workspace.recordKnownWorkspaceRoot(root)
            print(WorkspaceResetPlanner.renderApplyResult(result))
            print("Authsia workspace reset complete.")
        }
    }

    struct Forget: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "forget",
            abstract: "Forget recorded workspace roots",
            shouldDisplay: false
        )

        @Option(name: .long, help: .hidden) var root: String?
        @Option(name: .long, help: .hidden) var under: [String] = []
        @Option(name: .long, help: .hidden) var missingUnder: [String] = []

        func run() throws {
            let roots = try Self.forget(
                root: root,
                under: under,
                missingUnder: missingUnder,
                store: .shared,
                appDefaults: UserDefaults(suiteName: Self.appDefaultsSuiteName),
                fileManager: .default
            )
            if roots.isEmpty {
                print("No matching workspace roots were recorded.")
                return
            }
            print("Forgot workspace root(s):")
            for root in roots {
                print("- \(root)")
            }
        }

        static func forget(
            root: String?,
            under prefixes: [String] = [],
            missingUnder missingPrefixes: [String],
            store: WorkspaceKnownRootsStore,
            appDefaults: UserDefaults? = nil,
            fileManager: FileManager
        ) throws -> [String] {
            let normalizedRoot = root.map(normalizedPath)
            let normalizedPrefixes = prefixes.map(normalizedPrefix).filter { !$0.isEmpty }
            let normalizedMissingPrefixes = missingPrefixes.map(normalizedPrefix).filter { !$0.isEmpty }
            guard normalizedRoot != nil || !normalizedPrefixes.isEmpty || !normalizedMissingPrefixes.isEmpty else {
                throw ValidationError("Provide --root PATH, --under PREFIX, or --missing-under PREFIX.")
            }

            let currentRoots = uniqueNormalized(try store.load() + appRoots(from: appDefaults))
            let staleRoots = currentRoots.filter { currentRoot in
                guard normalizedRoot == nil || currentRoot != normalizedRoot else {
                    return true
                }
                if normalizedPrefixes.contains(where: { currentRoot.hasPrefix($0) }) {
                    return true
                }
                return normalizedMissingPrefixes.contains(where: { currentRoot.hasPrefix($0) }) &&
                    !fileManager.fileExists(atPath: currentRoot)
            }

            for staleRoot in staleRoots {
                try store.forget(staleRoot)
            }
            forgetAppRoots(staleRoots, defaults: appDefaults)
            return staleRoots
        }

        private static let appDefaultsSuiteName = "app.authsia"
        private static let appKnownRootsKey = "workspaceKnownRoots"
        private static let appPinnedRootsKey = "workspacePinnedRoots"
        private static let emptyEncodedRoots = "[]"

        private static func normalizedPath(_ path: String) -> String {
            URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL.path
        }

        private static func normalizedPrefix(_ prefix: String) -> String {
            let trimmed = prefix.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return "" }
            return URL(fileURLWithPath: trimmed, isDirectory: true).standardizedFileURL.path
        }

        private static func appRoots(from defaults: UserDefaults?) -> [String] {
            guard let defaults else { return [] }
            return uniqueNormalized(
                decodedRoots(defaults.string(forKey: appKnownRootsKey) ?? emptyEncodedRoots) +
                    decodedRoots(defaults.string(forKey: appPinnedRootsKey) ?? emptyEncodedRoots)
            )
        }

        private static func forgetAppRoots(_ roots: [String], defaults: UserDefaults?) {
            guard let defaults else { return }
            let rootSet = Set(uniqueNormalized(roots))
            guard !rootSet.isEmpty else { return }
            removeAppRoots(rootSet, key: appKnownRootsKey, defaults: defaults)
            removeAppRoots(rootSet, key: appPinnedRootsKey, defaults: defaults)
            defaults.synchronize()
        }

        private static func removeAppRoots(_ roots: Set<String>, key: String, defaults: UserDefaults) {
            let current = defaults.string(forKey: key) ?? emptyEncodedRoots
            let remaining = decodedRoots(current).filter { !roots.contains($0) }
            let updated = encodedRoots(remaining)
            guard updated != current else { return }
            defaults.set(updated, forKey: key)
        }

        private static func decodedRoots(_ encoded: String) -> [String] {
            guard let data = encoded.data(using: .utf8),
                  let decoded = try? JSONDecoder().decode([String].self, from: data) else {
                return []
            }
            return uniqueNormalized(decoded)
        }

        private static func encodedRoots(_ roots: [String]) -> String {
            let normalizedRoots = uniqueNormalized(roots)
            guard let data = try? JSONEncoder().encode(normalizedRoots),
                  let encoded = String(data: data, encoding: .utf8) else {
                return emptyEncodedRoots
            }
            return encoded
        }

        private static func uniqueNormalized(_ roots: [String]) -> [String] {
            var seen = Set<String>()
            return roots.compactMap { root in
                let normalized = normalizedPath(root)
                guard !normalized.isEmpty, seen.insert(normalized).inserted else { return nil }
                return normalized
            }
        }
    }

    struct Run: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "run",
            abstract: "Run any command through this workspace's Authsia env files",
            discussion: """
                Examples:
                  authsia workspace run -- npm test
                  authsia workspace run --env-file .env.local -- python scripts/deploy.py
                  authsia workspace run --shell "npm run build && npm test"
                  authsia workspace run --dry-run -- npm start
                """
        )

        @Flag(name: .long, help: "Show env files and command without running")
        var dryRun = false

        @Option(name: .long, parsing: .upToNextOption, help: "Additional env file for this run")
        var envFile: [String] = []

        @Option(name: .long, help: "Use this environment for one run without changing the saved selection")
        var environment: String?

        @Flag(name: .customLong("default-only"), help: "Use only untagged default-environment items for one run")
        var defaultOnly = false

        @Option(
            name: .customLong("shell"),
            parsing: .remaining,
            help: "Run a quoted child command string through /bin/sh -c"
        )
        var shellCommandParts: [String] = []

        @Argument(parsing: .postTerminator)
        var commandArgs: [String] = []

        func run() throws {
            if environment != nil && defaultOnly {
                throw ValidationError("Use either --environment or --default-only, not both.")
            }
            let builtPlan = try WorkspaceRunPlan.build(
                startingAt: URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true),
                extraEnvFiles: envFile,
                commandArgs: commandArgs,
                shellCommandParts: shellCommandParts
            )
            let plan: WorkspaceRunPlan
            if builtPlan.config.schemaVersion >= 2 {
                let selection = try Self.environmentSelection(
                    environment: environment,
                    defaultOnly: defaultOnly,
                    workspaceRoot: builtPlan.workspaceRoot
                )
                guard let payload = Workspace.loadWorkspaceMetadataPayload(
                    try Self.validationMetadataRequest(for: builtPlan),
                    requestedCommand: BridgeContext.workspaceRunRequestedCommand
                ) else {
                    throw ValidationError(
                        "Workspace environment validation is unavailable. Run `authsia workspace env validate`."
                    )
                }
                plan = try Self.applyingEnvironment(
                    to: builtPlan,
                    selection: selection,
                    payload: payload
                )
            } else {
                if environment != nil || defaultOnly {
                    throw ValidationError("Workspace environment selection requires schema v2. Run `authsia workspace update` first.")
                }
                plan = builtPlan
            }
            if dryRun {
                print(Self.renderDryRun(plan, parentEnvironment: ProcessInfo.processInfo.environment))
                return
            }

            try Exec.validateCommand(plan.commandArgs)
            let parentEnvironment = ProcessInfo.processInfo.environment
            let bindingNames = try Self.workspaceBindingNames(
                plan: plan,
                parentEnvironment: parentEnvironment
            )
            if Self.isSecretFreeProbe(plan: plan) ||
                Self.isBindingFreeInvocation(plan: plan, bindingNames: bindingNames) ||
                Self.isAgentShimInvocation(parentEnvironment: parentEnvironment) ||
                !Self.shouldDelegateToExec(plan: plan, parentEnvironment: parentEnvironment) {
                let exitCode = Exec.runChildProcess(
                    command: Exec.childCommandArguments(command: plan.commandArgs, shell: plan.usesShell),
                    environment: try Self.directPassthroughEnvironment(
                        parentEnvironment: parentEnvironment,
                        plan: plan
                    ),
                    masker: OutputMasker(secrets: [])
                )
                Darwin.exit(exitCode)
            }

            let exec = Self.configuredExec(for: plan)
            try exec.run()
        }

        static func validationMetadataRequest(
            for plan: WorkspaceRunPlan
        ) throws -> WorkspaceMetadataRequestPayload {
            let envFileReferences = try plan.envFiles.flatMap { path in
                try EnvFileParser.parse(contentsOf: path).map(\.value)
            }
            return Workspace.Env.validationMetadataRequest(
                plan.config,
                additionalReferences: envFileReferences
            )
        }

        static func environmentSelection(
            environment: String?,
            defaultOnly: Bool,
            workspaceRoot: URL,
            store: WorkspaceEnvironmentSelectionStore = WorkspaceEnvironmentSelectionStore()
        ) throws -> WorkspaceEnvironmentSelection {
            if defaultOnly {
                return .defaultOnly
            }
            if let environment {
                return .named(environment)
            }
            if let stored = try store.activeEnvironment(for: workspaceRoot) {
                return .named(stored)
            }
            return .defaultOnly
        }

        static func applyingEnvironment(
            to plan: WorkspaceRunPlan,
            selection: WorkspaceEnvironmentSelection,
            payload: BridgeListPayload
        ) throws -> WorkspaceRunPlan {
            let managedCount = plan.managedEnvFileCount
            let evaluation = try WorkspaceEnvironmentEvaluation.evaluate(
                config: plan.config,
                envFiles: Array(plan.envFiles.prefix(managedCount)),
                explicitEnvFiles: Array(plan.envFiles.dropFirst(managedCount)),
                payload: payload,
                selection: selection
            )
            let blockingIssues = evaluation.resolution.issues
            guard blockingIssues.isEmpty else {
                let kinds = blockingIssues.map(\.kind.rawValue).sorted().joined(separator: ", ")
                throw ValidationError("Workspace environment validation failed: \(kinds). Run `authsia workspace env validate`.")
            }
            let activeName: String?
            switch evaluation.resolution.selection {
            case .defaultOnly: activeName = nil
            case .named(let name): activeName = name
            }
            return WorkspaceRunPlan(
                workspaceRoot: plan.workspaceRoot,
                config: plan.config,
                envFiles: [],
                managedEnvFileCount: 0,
                envBindings: evaluation.environmentOverrides,
                activeEnvironment: activeName,
                defaultOnly: activeName == nil,
                commandArgs: plan.commandArgs,
                usesShell: plan.usesShell
            )
        }

        static func shouldDelegateToExec(plan: WorkspaceRunPlan, parentEnvironment: [String: String]) -> Bool {
            !plan.envFiles.isEmpty ||
                !plan.envBindings.isEmpty ||
                parentEnvironment.values.contains(where: SecretReference.isSecretReference) ||
                parentEnvironment[AutomationAccessResolver.environmentKey] != nil ||
                parentEnvironment[AutomationAccessResolver.sshEnvironmentKey] != nil
        }

        /// Read-only infrastructure probes that agent/IDE harnesses spawn constantly
        /// (the VS Code Docker extension polling `docker context ls`, Claude Code's
        /// `npm view …@latest version` update check, etc.). These never read the
        /// injected environment, yet routing them through `authsia exec` resolves every
        /// managed secret and fires an agent JIT preflight before the command runs —
        /// surfacing as an approval the moment an agent tool launches. When the wrapped
        /// command is a known probe we run it inside the workspace boundary WITHOUT
        /// injecting secrets, so no resolve and no JIT happen. A misclassification only
        /// means a command that did want a secret runs without it and fails loudly; it
        /// never leaks a secret or grants access.
        ///
        /// Only an explicit `--` command vector is classifiable. A `--shell` string is
        /// opaque (it can chain commands or expand variables) and always delegates.
        private static let versionOrHelpFlags: Set<String> = [
            "--version", "-v", "-V", "--help", "-h",
        ]

        static func directPassthroughEnvironment(parentEnvironment: [String: String]) -> [String: String] {
            var environment = parentEnvironment
            Exec.removeAutomationCredentials(from: &environment)
            environment.removeValue(forKey: WorkspaceGuardedTerminal.shimInvocationEnvironmentName)
            return environment
        }

        static func directPassthroughEnvironment(
            parentEnvironment: [String: String],
            plan: WorkspaceRunPlan
        ) throws -> [String: String] {
            var environment = parentEnvironment
            for (key, value) in try literalEnvFileValues(from: plan.envFiles) {
                environment[key] = value
            }
            for key in try authsiaReferencedEnvNames(from: plan.envFiles) {
                environment.removeValue(forKey: key)
            }
            for key in plan.envBindings.keys {
                environment.removeValue(forKey: key)
            }
            return directPassthroughEnvironment(parentEnvironment: environment)
        }

        private static func literalEnvFileValues(from paths: [String]) throws -> [String: String] {
            try Exec.mergeEnvFiles(paths).filter { !SecretReference.isSecretReference($0.value) }
        }

        private static func authsiaReferencedEnvNames(from paths: [String]) throws -> Set<String> {
            var names = Set<String>()
            for path in paths {
                for entry in try EnvFileParser.parse(contentsOf: path) where SecretReference.isSecretReference(entry.value) {
                    names.insert(entry.key)
                }
            }
            return names
        }

        /// Guarded-terminal shims wrap every configured tool, so an agent harness
        /// spawning `python3`/`npm` for scratch work would otherwise resolve every
        /// workspace secret and fire a JIT approval even though the command never
        /// reads the injected env. When the invocation came from a shim AND the
        /// caller chain is agentic, keep only literal workspace env values and skip
        /// Authsia reference resolution — agents that need secrets must ask explicitly
        /// via `authsia exec` or `authsia workspace run`.
        static func isAgentShimInvocation(
            parentEnvironment: [String: String],
            processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry(),
            stdinIsTTY: Bool = TerminalContext.stdinIsTTY
        ) -> Bool {
            guard parentEnvironment[WorkspaceGuardedTerminal.shimInvocationEnvironmentName] == "1",
                  parentEnvironment[AutomationAccessResolver.environmentKey] == nil,
                  parentEnvironment[AutomationAccessResolver.sshEnvironmentKey] == nil else {
                return false
            }
            // A confirmed agent marker always suppresses secret resolution for shim scratch work.
            if AgentRuntimeContextResolver.hasExplicitAgentInvocationMarker(environment: parentEnvironment) {
                return true
            }
            // Otherwise only suppress when the ancestry is agentic AND stdin is not a TTY.
            // Redirecting stdout must not make a human guarded-terminal command agentic.
            return AgenticProcessDetector.containsAgenticProcess(processAncestry) && !stdinIsTTY
        }

        static func isSecretFreeProbe(plan: WorkspaceRunPlan) -> Bool {
            guard !plan.usesShell, let rawProgram = plan.commandArgs.first else { return false }
            let program = (rawProgram as NSString).lastPathComponent
            let rest = Array(plan.commandArgs.dropFirst())

            // A bare version/help query (e.g. `node --version`) never consumes secrets,
            // regardless of program.
            if !rest.isEmpty,
               rest.allSatisfy({ $0.hasPrefix("-") }),
               rest.contains(where: versionOrHelpFlags.contains) {
                return true
            }

            let tokens = rest.filter { !$0.hasPrefix("-") }.map { $0.lowercased() }
            guard let subcommand = tokens.first else { return false }

            switch program {
            case "docker":
                if ["version", "info", "ps", "images"].contains(subcommand) {
                    return true
                }
                let contextCommand = tokens.dropFirst().first
                return subcommand == "context" && (contextCommand == "ls" || contextCommand == "inspect")
            case "npm":
                if ["view", "info", "ls", "list", "outdated", "ping"].contains(subcommand) {
                    return true
                }
                let configCommand = tokens.dropFirst().first
                return subcommand == "config" && (configCommand == "get" || configCommand == "list")
            case "pnpm":
                if ["view", "info", "ls", "list", "outdated"].contains(subcommand) {
                    return true
                }
                let configCommand = tokens.dropFirst().first
                return subcommand == "config" && (configCommand == "get" || configCommand == "list")
            case "yarn":
                if ["info", "list", "outdated"].contains(subcommand) {
                    return true
                }
                let configCommand = tokens.dropFirst().first
                return subcommand == "config" && (configCommand == "get" || configCommand == "list")
            case "pip", "pip3":
                return ["list", "show"].contains(subcommand)
            case "kubectl", "terraform", "tofu", "go":
                return subcommand == "version"
            case "cargo":
                return ["metadata", "tree"].contains(subcommand)
            case "gcloud":
                if subcommand == "version" {
                    return true
                }
                let configCommand = tokens.dropFirst().first
                return subcommand == "config" && (configCommand == "list" || configCommand == "get-value")
            default:
                return false
            }
        }

        /// Workspace-managed env names a delegated run would resolve: configured
        /// env bindings, Authsia references in managed env files, and parent-env
        /// entries whose value is an Authsia reference (guarded terminals keep those).
        static func workspaceBindingNames(
            plan: WorkspaceRunPlan,
            parentEnvironment: [String: String]
        ) throws -> Set<String> {
            var names = Set(plan.envBindings.keys)
            names.formUnion(try authsiaReferencedEnvNames(from: plan.envFiles))
            for (key, value) in parentEnvironment where SecretReference.isSecretReference(value) {
                names.insert(key)
            }
            return names
        }

        /// Command shapes whose workspace-env consumption is fully visible in argv:
        /// inline interpreter code (`python3 -c`) and docker's explicit env
        /// forwarding (`-e`/`--env`/`--build-arg`). When no configured binding name
        /// appears in argv, run inside the workspace boundary WITHOUT resolving
        /// secrets, so no approval fires. Like the probe check above, this is not a
        /// security boundary: the guarded parent env holds no secret values, so a
        /// misclassification only means a command that did want a secret runs
        /// without it and fails loudly; it never leaks a secret or grants access.
        static func isBindingFreeInvocation(plan: WorkspaceRunPlan, bindingNames: Set<String>) -> Bool {
            guard !plan.usesShell, let rawProgram = plan.commandArgs.first else { return false }
            let program = (rawProgram as NSString).lastPathComponent
            let arguments = Array(plan.commandArgs.dropFirst())
            switch program {
            case "python", "python3":
                // Only a leading `-c` is classifiable: the inline string is the whole
                // top-level program. Scripts, modules, and REPLs run code outside argv.
                guard arguments.first == "-c" else { return false }
                return referencesNoBinding(
                    arguments: arguments,
                    bindingNames: bindingNames,
                    implicitEnvPrefix: "PYTHON"
                )
            case "docker":
                // Containers only see explicitly forwarded env. Compose interpolates
                // opaque files and --env-file contents are not in argv, so both delegate.
                let subcommand = arguments.first { !$0.hasPrefix("-") }?.lowercased()
                guard subcommand != nil, subcommand != "compose" else { return false }
                guard !arguments.contains(where: { $0 == "--env-file" || $0.hasPrefix("--env-file=") }) else {
                    return false
                }
                return referencesNoBinding(
                    arguments: arguments,
                    bindingNames: bindingNames,
                    implicitEnvPrefix: "DOCKER_"
                )
            default:
                return false
            }
        }

        /// A binding inside the tool's own env namespace (PYTHONSTARTUP, DOCKER_HOST)
        /// changes tool behavior without ever appearing in argv, so it always delegates.
        private static func referencesNoBinding(
            arguments: [String],
            bindingNames: Set<String>,
            implicitEnvPrefix: String
        ) -> Bool {
            !bindingNames.contains { name in
                name.hasPrefix(implicitEnvPrefix) ||
                    arguments.contains { containsIdentifier(name, in: $0) }
            }
        }

        private static func containsIdentifier(_ name: String, in text: String) -> Bool {
            guard !name.isEmpty else { return false }
            var searchRange = text.startIndex..<text.endIndex
            while let range = text.range(of: name, range: searchRange) {
                let boundedBefore = range.lowerBound == text.startIndex ||
                    !isIdentifierCharacter(text[text.index(before: range.lowerBound)])
                let boundedAfter = range.upperBound == text.endIndex ||
                    !isIdentifierCharacter(text[range.upperBound])
                if boundedBefore && boundedAfter { return true }
                searchRange = text.index(after: range.lowerBound)..<text.endIndex
            }
            return false
        }

        private static func isIdentifierCharacter(_ character: Character) -> Bool {
            character == "_" || character.isLetter || character.isNumber
        }

        static func configuredExec(for plan: WorkspaceRunPlan) -> Exec {
            var exec = Exec()
            exec.type = nil
            exec.query = nil
            exec.typeOption = nil
            exec.queryOption = nil
            exec.folder = nil
            exec.env = nil
            exec.all = false
            exec.allMachines = false
            exec.field = nil
            exec.envFile = plan.envFiles
            exec.environmentOverrides = plan.envBindings
            exec.environmentScope = plan.activeEnvironment.map(EnvironmentAccessScope.named)
                ?? (plan.config.schemaVersion >= 2 ? .defaultOnly : nil)
            exec.shellCommandParts = plan.usesShell ? plan.commandArgs : []
            exec.commandArgs = plan.usesShell ? [] : plan.commandArgs
            return exec
        }

        static func renderDryRun(
            _ plan: WorkspaceRunPlan,
            parentEnvironment: [String: String],
            processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry()
        ) -> String {
            let description = executionDescription(
                plan: plan,
                parentEnvironment: parentEnvironment,
                processAncestry: processAncestry
            )
            return [
                WorkspaceRunPlan.renderDryRun(plan),
                "Execution: \(description)",
            ].joined(separator: "\n")
        }

        private static func executionDescription(
            plan: WorkspaceRunPlan,
            parentEnvironment: [String: String],
            processAncestry: [AgenticProcessReference]
        ) -> String {
            if isSecretFreeProbe(plan: plan) {
                return "direct passthrough (read-only probe; workspace secrets not injected)"
            }
            if let bindingNames = try? workspaceBindingNames(plan: plan, parentEnvironment: parentEnvironment),
               isBindingFreeInvocation(plan: plan, bindingNames: bindingNames) {
                return "direct passthrough (command references no workspace binding; secrets not injected)"
            }
            if isAgentShimInvocation(parentEnvironment: parentEnvironment, processAncestry: processAncestry) {
                return "direct passthrough (guarded shim under agent; literal env kept, Authsia refs not resolved)"
            }
            guard shouldDelegateToExec(plan: plan, parentEnvironment: parentEnvironment) else {
                return "direct passthrough (no workspace secrets detected)"
            }
            if hasAuthsiaReferences(plan: plan, parentEnvironment: parentEnvironment) {
                return "authsia exec (Authsia references require approval/JIT unless already authorized)"
            }
            if !plan.envFiles.isEmpty {
                return "authsia exec (workspace env files active; no Authsia references detected)"
            }
            return "authsia exec (workspace boundary active; no Authsia references detected)"
        }

        private static func hasAuthsiaReferences(
            plan: WorkspaceRunPlan,
            parentEnvironment: [String: String]
        ) -> Bool {
            if plan.envBindings.values.contains(where: SecretReference.isSecretReference) {
                return true
            }
            if parentEnvironment.values.contains(where: SecretReference.isSecretReference) {
                return true
            }
            guard let envFileValues = try? Exec.mergeEnvFiles(plan.envFiles).values else {
                return false
            }
            return envFileValues.contains(where: SecretReference.isSecretReference)
        }
    }

    struct Env: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "env",
            abstract: "Manage workspace env bindings",
            discussion: """
                Examples:
                  authsia workspace env list
                  authsia workspace env add API_KEY authsia://api-key/API_KEY/key
                  authsia workspace env remove API_KEY
                  authsia workspace env validate
                """,
            subcommands: [List.self, Add.self, Remove.self, Validate.self]
        )

        struct EnvBindingStatus: Equatable {
            let name: String
            let displayLine: String
        }

        struct ValidationResult: Equatable {
            let valid: [EnvBindingStatus]
            let missing: [EnvBindingStatus]
            let unverified: [EnvBindingStatus]
        }

        struct List: ParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "list",
                abstract: "List workspace env bindings",
                discussion: """
                    Examples:
                      authsia workspace env list
                    """
            )

            func run() throws {
                let root = try Env.workspaceRoot()
                let config = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
                let payload = try AuthsiaBridgeClient.shared.list()
                let active = try WorkspaceEnvironmentSelectionStore().activeEnvironment(for: root)
                let evaluation = WorkspaceEnvironmentEvaluation.evaluate(
                    config: config,
                    payload: payload,
                    selection: active.map(WorkspaceEnvironmentSelection.named) ?? .defaultOnly
                )
                print(Env.renderList(config, evaluation: evaluation))
            }
        }

        struct Add: ParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "add",
                abstract: "Add or update a workspace env binding",
                discussion: """
                    Examples:
                      authsia workspace env add API_KEY authsia://api-key/API_KEY/key
                      authsia workspace env add DB_PASSWORD authsia://password/DB_PASSWORD/password?folder=Workspaces%2Fapi
                    """
            )

            @Argument(help: "Environment variable name")
            var name: String

            @Argument(help: "Authsia reference URI")
            var reference: String

            func run() throws {
                let binding = try Env.addBinding(name: name, reference: reference, workspaceRoot: Env.workspaceRoot())
                print("Added workspace env binding \(binding.name).")
            }
        }

        struct Remove: ParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "remove",
                abstract: "Remove a workspace env binding",
                discussion: """
                    Examples:
                      authsia workspace env remove API_KEY
                      authsia workspace env remove API_KEY authsia://api-key/API_KEY/key
                    """
            )

            @Argument(help: "Environment variable name")
            var name: String

            @Argument(help: "Exact Authsia reference when the variable has multiple bindings")
            var reference: String?

            func run() throws {
                print(try Env.removeBinding(name: name, reference: reference, workspaceRoot: Env.workspaceRoot()))
            }
        }

        struct Validate: ParsableCommand {
            static let configuration = CommandConfiguration(
                commandName: "validate",
                abstract: "Validate workspace env bindings against Authsia",
                discussion: """
                    Examples:
                      authsia workspace env validate
                    """
            )

            func run() throws {
                let config = try WorkspaceConfigStore.read(fromWorkspaceRoot: Env.workspaceRoot())
                let request = Env.validationMetadataRequest(config)
                let payload = Workspace.loadWorkspaceMetadataPayload(
                    request,
                    requestedCommand: BridgeContext.workspaceEnvValidateRequestedCommand
                )
                print(Env.renderValidation(Env.validateBindings(
                    config,
                    vaultIndex: payload.map(WorkspaceVaultIndex.init(payload:))
                )))
            }
        }

        static func addBinding(
            name: String,
            reference: String,
            workspaceRoot: URL,
            fileManager: FileManager = .default,
            knownRootsStore: WorkspaceKnownRootsStore = .shared
        ) throws -> WorkspaceConfig.EnvBinding {
            let binding = WorkspaceConfig.EnvBinding(name: name, reference: reference)
            var config = try WorkspaceConfigStore.read(fromWorkspaceRoot: workspaceRoot, fileManager: fileManager)
            let bindings: [WorkspaceConfig.EnvBinding]
            if config.schemaVersion >= 2 {
                bindings = config.envBindings.filter {
                    !($0.name == binding.name && $0.reference == binding.reference)
                } + [binding]
            } else {
                bindings = config.envBindings.filter { $0.name != binding.name } + [binding]
            }
            config = WorkspaceConfig(
                schemaVersion: config.schemaVersion,
                workspace: config.workspace,
                managedEnvFiles: config.managedEnvFiles,
                agents: config.agents,
                guardSettings: config.guardSettings,
                envBindings: bindings
            )
            try WorkspaceConfigStore.write(config, toWorkspaceRoot: workspaceRoot, fileManager: fileManager)
            Workspace.recordKnownWorkspaceRoot(workspaceRoot, store: knownRootsStore)
            return binding
        }

        static func removeBinding(
            name: String,
            reference: String? = nil,
            workspaceRoot: URL,
            fileManager: FileManager = .default,
            knownRootsStore: WorkspaceKnownRootsStore = .shared
        ) throws -> String {
            let normalizedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
            var config = try WorkspaceConfigStore.read(fromWorkspaceRoot: workspaceRoot, fileManager: fileManager)
            let matchingBindings = config.envBindings.filter { $0.name == normalizedName }
            guard !matchingBindings.isEmpty else {
                return "No workspace env binding \(normalizedName). Run `authsia workspace env list` to see " +
                    "configured bindings, or bind one with authsia workspace env add <NAME> <authsia://...>."
            }
            let normalizedReference = reference?.trimmingCharacters(in: .whitespacesAndNewlines)
            if config.schemaVersion >= 2, matchingBindings.count > 1, normalizedReference == nil {
                throw ValidationError(
                    "Workspace env variable \(normalizedName) has multiple bindings. Re-run with its exact " +
                    "Authsia reference from `authsia workspace env list`."
                )
            }
            let bindings: [WorkspaceConfig.EnvBinding]
            if let normalizedReference {
                bindings = config.envBindings.filter {
                    !($0.name == normalizedName && $0.reference == normalizedReference)
                }
                guard bindings.count != config.envBindings.count else {
                    return "No workspace env binding \(normalizedName) matches that reference. Run " +
                        "`authsia workspace env list` to see configured bindings."
                }
            } else {
                bindings = config.envBindings.filter { $0.name != normalizedName }
            }
            config = WorkspaceConfig(
                schemaVersion: config.schemaVersion,
                workspace: config.workspace,
                managedEnvFiles: config.managedEnvFiles,
                agents: config.agents,
                guardSettings: config.guardSettings,
                envBindings: bindings
            )
            try WorkspaceConfigStore.write(config, toWorkspaceRoot: workspaceRoot, fileManager: fileManager)
            Workspace.recordKnownWorkspaceRoot(workspaceRoot, store: knownRootsStore)
            return "Removed workspace env binding \(normalizedName)."
        }

        static func renderList(_ config: WorkspaceConfig) -> String {
            var lines = ["Workspace env bindings:"]
            if config.envBindings.isEmpty {
                lines.append("No workspace env bindings configured.")
                lines.append("Bind one with authsia workspace env add <NAME> <authsia://...>.")
            } else {
                lines.append(contentsOf: config.envBindings.map { "\($0.name)=\($0.reference)" })
            }
            return lines.joined(separator: "\n")
        }

        static func renderList(
            _ config: WorkspaceConfig,
            evaluation: WorkspaceEnvironmentEvaluation
        ) -> String {
            let activeEnvironment: String
            switch evaluation.resolution.selection {
            case .defaultOnly: activeEnvironment = "Default environment"
            case .named(let name): activeEnvironment = name
            }
            var lines = [
                "Workspace env bindings:",
                "Active environment: \(activeEnvironment)",
            ]
            guard !config.envBindings.isEmpty else {
                lines.append("No workspace env bindings configured.")
                lines.append("Bind one with authsia workspace env add <NAME> <authsia://...>.")
                return lines.joined(separator: "\n")
            }
            for (index, binding) in config.envBindings.enumerated() {
                let id = "binding-\(index)"
                let matchesBinding: (WorkspaceEnvironmentCandidate) -> Bool = {
                    $0.id == id || $0.id.hasPrefix(id + "#")
                }
                let candidate = evaluation.resolution.effective.first(where: matchesBinding) ??
                    evaluation.resolution.inactive.first(where: matchesBinding) ??
                    evaluation.resolution.overridden.first(where: matchesBinding)
                let environments = candidate.map {
                    $0.environments.isEmpty ? "Default environment" : $0.environments.joined(separator: ", ")
                } ?? "Unresolved"
                let state = evaluation.resolution.effective.contains(where: matchesBinding) ? "effective" : "inactive"
                lines.append("\(binding.name): \(environments) · \(state) · \(binding.reference)")
            }
            return lines.joined(separator: "\n")
        }

        static func validateBindings(_ config: WorkspaceConfig, vaultIndex: WorkspaceVaultIndex?) -> ValidationResult {
            var valid: [EnvBindingStatus] = []
            var missing: [EnvBindingStatus] = []
            var unverified: [EnvBindingStatus] = []
            for binding in config.envBindings {
                let status = bindingStatus(binding)
                guard let vaultIndex else {
                    unverified.append(status)
                    continue
                }
                if let reference = authsiaReference(from: binding), vaultIndex.contains(reference) {
                    valid.append(status)
                } else {
                    missing.append(status)
                }
            }
            return ValidationResult(valid: valid, missing: missing, unverified: unverified)
        }

        static func validationMetadataRequest(
            _ config: WorkspaceConfig,
            additionalReferences: [String] = []
        ) -> WorkspaceMetadataRequestPayload {
            let configuredReferences = config.envBindings.map(\.reference) + additionalReferences
            let references = Set(configuredReferences.compactMap { value -> WorkspaceMetadataReference? in
                guard let reference = try? SecretReference.parse(value) else { return nil }
                let itemType: WorkspaceMetadataItemType
                switch reference.type {
                case .password:
                    itemType = .password
                case .apiKey:
                    itemType = .apiKey
                case .cert:
                    itemType = .certificate
                case .note:
                    itemType = .note
                case .ssh:
                    itemType = .ssh
                case .otp:
                    return nil
                }
                return WorkspaceMetadataReference(
                    itemType: itemType,
                    itemName: reference.item,
                    folderPath: reference.folder
                )
            }).sorted {
                ($0.itemType.rawValue, $0.itemName, $0.folderPath ?? "") <
                    ($1.itemType.rawValue, $1.itemName, $1.folderPath ?? "")
            }
            return WorkspaceMetadataRequestPayload(
                workspaceFolder: config.workspace.authsiaFolder,
                mode: .validate,
                references: references
            )
        }

        static func renderValidation(_ result: ValidationResult) -> String {
            var lines: [String] = []
            appendValidationSection("Valid workspace env bindings:", result.valid, to: &lines)
            appendValidationSection("Missing Authsia references:", result.missing, to: &lines)
            appendValidationSection("Unverified Authsia references:", result.unverified, to: &lines)
            if lines.isEmpty {
                lines.append("No workspace env bindings configured.")
                lines.append("Bind one with authsia workspace env add <NAME> <authsia://...>.")
            }
            return lines.joined(separator: "\n")
        }

        private static func workspaceRoot() throws -> URL {
            guard let root = WorkspaceRootResolver.findWorkspaceRoot(
                startingAt: URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
            ) else {
                throw WorkspaceConfigError.missingConfig
            }
            return root
        }

        private static func bindingStatus(_ binding: WorkspaceConfig.EnvBinding) -> EnvBindingStatus {
            EnvBindingStatus(name: binding.name, displayLine: displayLine(for: binding))
        }

        private static func displayLine(for binding: WorkspaceConfig.EnvBinding) -> String {
            guard let reference = try? SecretReference.parse(binding.reference) else {
                return "invalid reference"
            }
            let folder = reference.folder.map { " in folder \($0)" } ?? ""
            return "\(reference.displayName) \(reference.item)\(folder)"
        }

        private static func authsiaReference(from binding: WorkspaceConfig.EnvBinding) -> AuthsiaReference? {
            guard let reference = try? SecretReference.parse(binding.reference) else { return nil }
            let itemType: AuthsiaReference.ItemType
            switch reference.type {
            case .password:
                itemType = .password
            case .apiKey:
                itemType = .apiKey
            case .cert:
                itemType = .certificate
            case .note:
                itemType = .note
            case .ssh:
                itemType = .ssh
            case .otp:
                return nil
            }
            return AuthsiaReference(itemType: itemType, query: reference.item, folderPath: reference.folder)
        }

        private static func appendValidationSection(
            _ title: String,
            _ values: [EnvBindingStatus],
            to lines: inout [String]
        ) {
            guard !values.isEmpty else { return }
            if !lines.isEmpty { lines.append("") }
            lines.append(title)
            lines.append(contentsOf: values.map { "- \($0.name): \($0.displayLine)" })
        }
    }

    struct Status: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "status",
            abstract: "Show repo-local Authsia workspace status",
            discussion: """
                Examples:
                  authsia workspace status
                  authsia workspace status --format json
                """
        )

        enum OutputFormat: String, ExpressibleByArgument {
            case table
            case json
        }

        @Option(name: .long, help: "Output format: table or json")
        var format: OutputFormat = .table

        func run() async throws {
            guard let root = WorkspaceRootResolver.findWorkspaceRoot(
                startingAt: URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
            ) else {
                throw WorkspaceConfigError.missingConfig
            }
            let initialContext = try await Self.initialStatusContext(workspaceRoot: root)
            let metadataRequest = Workspace.workspaceStatusMetadataRequest(initialContext.status)
            let vaultPayload = Workspace.loadWorkspaceMetadataPayload(
                metadataRequest,
                requestedCommand: BridgeContext.workspaceStatusRequestedCommand
            )
            let status: WorkspaceStatus
            if let vaultPayload {
                status = try await WorkspaceStatusReporter.build(
                    workspaceRoot: root,
                    vaultIndex: WorkspaceVaultIndex(payload: vaultPayload),
                    activeEnvironment: initialContext.activeEnvironment
                )
            } else {
                status = initialContext.status
            }
            Workspace.recordKnownWorkspaceRoot(root)
            switch format {
            case .table:
                print(WorkspaceStatusReporter.renderTable(status))
            case .json:
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
                let data = try encoder.encode(status)
                print(String(decoding: data, as: UTF8.self))
            }
        }

        static func initialStatusContext(
            workspaceRoot root: URL,
            selectionStore: WorkspaceEnvironmentSelectionStore = WorkspaceEnvironmentSelectionStore()
        ) async throws -> (status: WorkspaceStatus, activeEnvironment: String?) {
            let activeEnvironment = try selectionStore.activeEnvironment(for: root)
            let status = try await WorkspaceStatusReporter.build(
                workspaceRoot: root,
                activeEnvironment: activeEnvironment
            )
            return (status, activeEnvironment)
        }
    }

    struct Sync: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "sync",
            abstract: "Reconcile workspace vault folder and env bindings",
            discussion: """
                Compares the local Vault Workspaces/<folder> items with .authsia/workspace.json.
                Importer UIs can select all missing rows and apply one action to selected rows:
                create, import encrypted bundle, copy, move, or skip.

                Examples:
                  authsia workspace sync --dry-run
                  authsia workspace sync --plan-json
                  authsia workspace sync --folder Workspaces/api --plan-json
                  authsia workspace sync --apply-json workspace-sync-selection.json
                """
        )

        @Flag(name: .long, help: "Preview workspace sync without writing files")
        var dryRun = false

        @Flag(name: .long, help: "Emit a sanitized JSON sync plan for app integrations")
        var planJson = false

        @Option(name: .long, help: "Apply a sanitized workspace sync selection JSON file")
        var applyJson: String?

        @Option(name: .long, help: "Authsia workspace folder to sync before local config exists")
        var folder: String?

        func run() throws {
            let selectedModes = [dryRun, planJson, applyJson != nil].filter { $0 }.count
            guard selectedModes <= 1 else {
                throw ValidationError("Use only one of --dry-run, --plan-json, or --apply-json.")
            }
            let workingDirectory = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
            let root = try Self.syncRoot(startingAt: workingDirectory, folderOverride: folder)
            let config = try Self.syncConfig(workspaceRoot: root, folderOverride: folder)

            let vaultPayload: BridgeListPayload?
            if Self.requiresProtectedVaultList(applyJson: applyJson) {
                vaultPayload = try Workspace.loadVaultPayload()
            } else {
                vaultPayload = Workspace.loadWorkspaceMetadataPayload(
                    Self.workspaceMetadataRequest(config: config),
                    requestedCommand: BridgeContext.workspaceSyncPreviewRequestedCommand
                )
            }
            let plan = Self.plan(workspaceRoot: root, config: config, vaultPayload: vaultPayload)
            if let applyJson {
                let selection = try WorkspaceSetupExchange.readSyncSelection(from: applyJson)
                print(try Self.apply(selection, toWorkspaceRoot: root, currentPlan: plan))
                Workspace.recordKnownWorkspaceRoot(root)
                return
            }
            if planJson {
                try WorkspaceSetupExchange.printSyncPlanJSON(plan, workspace: config.workspace)
            } else {
                print(Self.renderDryRun(plan))
            }
            Workspace.recordKnownWorkspaceRoot(root)
        }

        static func plan(workspaceRoot: URL, vaultPayload: BridgeListPayload?) throws -> WorkspaceSyncPlan {
            let config = try WorkspaceConfigStore.read(fromWorkspaceRoot: workspaceRoot)
            return plan(workspaceRoot: workspaceRoot, config: config, vaultPayload: vaultPayload)
        }

        static func workspaceMetadataRequest(config: WorkspaceConfig) -> WorkspaceMetadataRequestPayload {
            WorkspaceMetadataRequestPayload(
                workspaceFolder: config.workspace.authsiaFolder,
                mode: .syncPreview,
                references: []
            )
        }

        static func requiresProtectedVaultList(applyJson _: String?) -> Bool {
            false
        }

        static func plan(
            workspaceRoot: URL,
            config: WorkspaceConfig,
            vaultPayload: BridgeListPayload?
        ) -> WorkspaceSyncPlan {
            return WorkspaceSyncPlanner.plan(
                workspaceRoot: workspaceRoot,
                config: config,
                vaultPayload: vaultPayload
            )
        }

        static func syncRoot(startingAt workingDirectory: URL, folderOverride: String?) throws -> URL {
            if folderOverride != nil {
                return WorkspaceRootResolver.findWorkspaceRoot(startingAt: workingDirectory) ??
                    WorkspaceRootResolver.resolveInitRoot(startingAt: workingDirectory)
            }
            guard let root = WorkspaceRootResolver.findWorkspaceRoot(startingAt: workingDirectory) else {
                throw WorkspaceConfigError.missingConfig
            }
            return root
        }

        static func syncConfig(workspaceRoot root: URL, folderOverride: String?) throws -> WorkspaceConfig {
            do {
                let config = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
                guard let folderOverride else { return config }
                if normalizedWorkspaceFolder(config.workspace.authsiaFolder) == normalizedWorkspaceFolder(folderOverride) {
                    return config
                }
                throw ValidationError(
                    "Selected folder is already linked to \(config.workspace.authsiaFolder), not \(folderOverride)."
                )
            } catch WorkspaceConfigError.missingConfig {
                guard let folderOverride else { throw WorkspaceConfigError.missingConfig }
                return WorkspaceConfig(
                    workspace: WorkspaceConfig.Workspace(
                        name: workspaceName(root: root, folder: folderOverride),
                        authsiaFolder: folderOverride
                    ),
                    managedEnvFiles: [],
                    agents: nil
                )
            }
        }

        static func apply(
            _ selection: WorkspaceSetupExchange.SyncSelectionPayload,
            toWorkspaceRoot root: URL,
            currentPlan plan: WorkspaceSyncPlan,
            fileManager: FileManager = .default
        ) throws -> String {
            let rowsByID = Dictionary(uniqueKeysWithValues: plan.rows.map { ($0.id, $0) })
            var config = try syncConfigForApply(workspaceRoot: root, plan: plan, fileManager: fileManager)
            var bindings = config.envBindings
            var updatedNames: [String] = []

            for selectedRow in selection.rows {
                guard let row = rowsByID[selectedRow.id] else {
                    throw ValidationError(Self.staleSelectionMessage)
                }

                switch selectedRow.action {
                case .none, .skip:
                    continue
                case .repairConfig:
                    guard let reference = row.localReference else {
                        throw ValidationError(Self.missingLocalReferenceMessage(envName: row.envName))
                    }
                    let binding = WorkspaceConfig.EnvBinding(name: row.envName, reference: reference)
                    if config.schemaVersion >= 2 {
                        guard let expectedReference = row.expectedReference else {
                            throw ValidationError(Self.staleSelectionMessage)
                        }
                        bindings.removeAll {
                            $0.name == binding.name && $0.reference == expectedReference
                        }
                        bindings.removeAll { $0.name == binding.name && $0.reference == binding.reference }
                    } else {
                        bindings.removeAll { $0.name == binding.name }
                    }
                    bindings.append(binding)
                    updatedNames.append(binding.name)
                case .addToConfig:
                    guard let reference = row.localReference else {
                        throw ValidationError(Self.missingLocalReferenceMessage(envName: row.envName))
                    }
                    let binding = WorkspaceConfig.EnvBinding(name: row.envName, reference: reference)
                    if config.schemaVersion >= 2 {
                        bindings.removeAll { $0.name == binding.name && $0.reference == binding.reference }
                    } else {
                        bindings.removeAll { $0.name == binding.name }
                    }
                    bindings.append(binding)
                    updatedNames.append(binding.name)
                case .create, .importEncrypted, .copyExisting, .moveExisting:
                    throw ValidationError(Self.appMediatedActionMessage(action: selectedRow.action))
                }
            }

            guard !updatedNames.isEmpty else {
                return "No workspace sync changes applied. Refresh preview with `authsia workspace sync --plan-json`, " +
                    "select at least one non-skip row, then re-run `authsia workspace sync --apply-json <file>`."
            }

            config = WorkspaceConfig(
                schemaVersion: config.schemaVersion,
                workspace: config.workspace,
                managedEnvFiles: config.managedEnvFiles,
                agents: config.agents,
                guardSettings: config.guardSettings,
                envBindings: bindings
            )
            try WorkspaceConfigStore.write(config, toWorkspaceRoot: root, fileManager: fileManager)
            return "Updated workspace env bindings: \(updatedNames.joined(separator: ", "))"
        }

        private static func syncConfigForApply(
            workspaceRoot root: URL,
            plan: WorkspaceSyncPlan,
            fileManager: FileManager
        ) throws -> WorkspaceConfig {
            do {
                return try WorkspaceConfigStore.read(fromWorkspaceRoot: root, fileManager: fileManager)
            } catch WorkspaceConfigError.missingConfig {
                return WorkspaceConfig(
                    workspace: WorkspaceConfig.Workspace(
                        name: workspaceName(root: root, folder: plan.authsiaFolder),
                        authsiaFolder: plan.authsiaFolder
                    ),
                    managedEnvFiles: [],
                    agents: nil
                )
            }
        }

        private static func workspaceName(root: URL, folder: String) -> String {
            normalizedWorkspaceFolder(folder)
                .split(separator: "/")
                .last
                .map(String.init) ?? root.lastPathComponent
        }

        private static func normalizedWorkspaceFolder(_ folder: String) -> String {
            folder
                .split(separator: "/")
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
                .joined(separator: "/")
        }

        static let staleSelectionMessage = "The workspace sync preview is stale. Refresh with " +
            "`authsia workspace sync --plan-json`, select rows from the new preview, then re-run " +
            "`authsia workspace sync --apply-json <file>`. Open Authsia > Workspace > Sync to refresh " +
            "and apply from the app."

        static func missingLocalReferenceMessage(envName: String) -> String {
            "Workspace sync row \(envName) has no local Authsia reference to apply. Refresh with " +
                "`authsia workspace sync --plan-json` and choose a row that has a Vault reference. Open " +
                "Authsia > Workspace > Sync to resolve it interactively."
        }

        static func appMediatedActionMessage(action: WorkspaceSyncAction) -> String {
            "Workspace sync action \(action.rawValue) requires the Authsia app because it needs secret values " +
                "or source item selection. Open Authsia > Workspace > Sync for create/import/copy/move actions, " +
                "or use --apply-json only for repairConfig/addToConfig rows."
        }

        static func renderDryRun(_ plan: WorkspaceSyncPlan) -> String {
            var lines = [
                "Workspace sync: \(plan.authsiaFolder)",
                "Satisfied: \(plan.satisfied.count)",
                "Missing locally: \(plan.missing.count)",
                "Local extras: \(plan.extras.count)",
                "Config mismatches: \(plan.mismatches.count)",
            ]
            appendRows("Missing locally", plan.missing, to: &lines)
            appendRows("Local extras", plan.extras, to: &lines)
            appendRows("Config mismatches", plan.mismatches, to: &lines)
            return lines.joined(separator: "\n")
        }

        private static func appendRows(_ title: String, _ rows: [WorkspaceSyncRow], to lines: inout [String]) {
            guard !rows.isEmpty else { return }
            lines.append("")
            lines.append("\(title):")
            lines.append(contentsOf: rows.map { "- \($0.envName): \($0.itemType) \($0.itemName)" })
        }
    }

    fileprivate static func recordKnownWorkspaceRoot(
        _ root: URL,
        store: WorkspaceKnownRootsStore = .shared
    ) {
        try? store.record(root.standardizedFileURL.path)
    }

    struct Guard: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "guard",
            abstract: "Prepare an agent-safe guarded terminal",
            discussion: """
                \(WorkspaceGuardedTerminal.shellExpansionWarning)

                Examples:
                  authsia workspace guard --dry-run
                  eval "$(authsia workspace guard --print-env)"
                  authsia workspace guard --print-env --auto
                  authsia workspace guard --tool claude --tool codex
                """
        )

        @Flag(name: .long, help: "Preview guarded terminal setup without writing shims")
        var dryRun = false

        @Flag(name: .long, help: "Print shell exports for the guarded terminal")
        var printEnv = false

        @Flag(name: .long, help: "For shell startup hooks, print exports only when workspace auto-guard is enabled")
        var auto = false

        @Option(name: .long, parsing: .upToNextOption, help: "Additional tool to shim")
        var tool: [String] = []

        @Option(name: .long, help: "Authsia executable path for generated shims")
        var authsiaPath: String?

        func run() throws {
            let environment = ProcessInfo.processInfo.environment
            guard !auto || printEnv else {
                throw ValidationError(Self.autoRequiresPrintEnvMessage)
            }
            guard let root = Self.workspaceRootForGuard(
                auto: auto,
                startingAt: URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true),
                environment: environment
            ) else {
                if auto { return }
                throw WorkspaceConfigError.missingConfig
            }
            let config = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
            if auto, !Self.shouldPrintAutoEnv(config: config, environment: environment) {
                return
            }
            let effectiveConfig = Self.configPersistingRequestedTools(config, requestedTools: tool)
            if !dryRun, effectiveConfig != config {
                try WorkspaceConfigStore.write(effectiveConfig, toWorkspaceRoot: root)
            }
            let plan = try WorkspaceGuardedTerminal.plan(
                workspaceRoot: root,
                tools: Self.toolsForGuard(config: effectiveConfig, requestedTools: []),
                aliasTools: effectiveConfig.guardSettings.tools,
                unsetEnvironmentNames: Self.environmentNamesToUnset(config: effectiveConfig, workspaceRoot: root)
            )
            // Warn on stderr (never stdout — `--print-env` output is eval'd) when an
            // explicit `--tool` request names a blocked tool that won't be shimmed.
            let blockedRequests = WorkspaceGuardedTerminal.blockedTools(in: tool)
            if !blockedRequests.isEmpty {
                StandardError.writeLine(
                    "Not shimming blocked tools: \(blockedRequests.joined(separator: ", ")). " +
                        "These can expose secrets outside Authsia's masking boundary; " +
                        "use `authsia workspace run -- <tool>` instead."
                )
            }
            if dryRun {
                print(Self.renderDryRun(plan))
                print(WorkspaceGuardedTerminal.shellExpansionWarning)
                return
            }

            let authsiaExecutablePath = authsiaPath ?? CommandLine.arguments.first ?? "authsia"
            let result = try WorkspaceGuardedTerminal.install(
                plan,
                authsiaExecutablePath: authsiaExecutablePath
            )
            // Best-effort prune of stale shim dirs from dead shells. Each guarded shell
            // mints a new dir and nothing tears it down, so they accumulate in the temp
            // dir until a reboot. Skip the one we just installed; leave recent dirs that
            // likely back other live shells.
            WorkspaceGuardedTerminal.cleanupStaleShimDirectories(
                in: plan.shimDirectory.deletingLastPathComponent(),
                keeping: plan.shimDirectory
            )
            if printEnv {
                let activeEnvironment = try WorkspaceEnvironmentSelectionStore().activeEnvironment(for: root)
                print(Self.renderShellExports(
                    plan,
                    authsiaExecutablePath: authsiaExecutablePath,
                    activeEnvironment: activeEnvironment
                ))
            } else {
                print(Self.renderInstallResult(result))
                print(WorkspaceGuardedTerminal.shellExpansionWarning)
            }
        }

        static let autoRequiresPrintEnvMessage = "--auto is only valid with --print-env. " +
            "Use `authsia workspace guard --print-env --auto` from a shell startup hook, " +
            "or remove --auto for manual guarded terminal setup."

        static func workspaceRootForGuard(
            auto: Bool,
            startingAt: URL,
            environment: [String: String],
            fileManager: FileManager = .default
        ) -> URL? {
            if let root = WorkspaceRootResolver.findWorkspaceRoot(startingAt: startingAt) {
                return root
            }
            guard auto,
                  environment["AUTHSIA_WORKSPACE_GUARD"] == "1",
                  let rootPath = environment["AUTHSIA_WORKSPACE_ROOT"],
                  !rootPath.isEmpty else {
                return nil
            }
            let root = URL(fileURLWithPath: rootPath, isDirectory: true).standardizedFileURL
            let configURL = root.appendingPathComponent(WorkspaceConfigStore.relativeConfigPath)
            guard fileManager.fileExists(atPath: configURL.path) else { return nil }
            return root
        }

        static func renderDryRun(_ plan: WorkspaceGuardedTerminalPlan) -> String {
            [
                "Guarded terminal: \(plan.workspaceRoot.lastPathComponent)",
                "Shim directory: \(plan.shimDirectory.path)",
                "Tools: \(plan.tools.joined(separator: ", "))",
                "Parent shell receives no plaintext secrets.",
            ].joined(separator: "\n")
        }

        static func renderInstallResult(_ result: WorkspaceGuardedTerminalInstallResult) -> String {
            [
                "Guarded terminal shims ready.",
                "Shim directory: \(result.shimDirectory.path)",
                "Installed: \(result.installedTools.isEmpty ? "none" : result.installedTools.joined(separator: ", "))",
                "Skipped: \(result.skippedTools.isEmpty ? "none" : result.skippedTools.joined(separator: ", "))",
            ].joined(separator: "\n")
        }

        static func renderShellExports(
            _ plan: WorkspaceGuardedTerminalPlan,
            authsiaExecutablePath: String = "authsia",
            activeEnvironment: String? = nil
        ) -> String {
            var lines = [
                "if [ -z \"${AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH+x}\" ]; then",
                "    export AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH=\"$PATH\"",
                "fi",
                "export PATH=\(WorkspaceGuardedTerminal.shellQuoted(plan.shimDirectory.path)):$PATH",
                "export AUTHSIA_WORKSPACE_GUARD=1",
                "export AUTHSIA_WORKSPACE_GUARD_SHIM_DIR=\(WorkspaceGuardedTerminal.shellQuoted(plan.shimDirectory.path))",
                "export AUTHSIA_WORKSPACE_ROOT=\(WorkspaceGuardedTerminal.shellQuoted(plan.workspaceRoot.path))",
            ]
            let unsetExports = WorkspaceGuardedTerminal.unsetEnvironmentExports(plan.unsetEnvironmentNames)
            if !unsetExports.isEmpty {
                lines.append(unsetExports)
            }
            lines.append(contentsOf: [
                WorkspaceGuardedTerminal.shellWrapperExports(
                    authsiaExecutablePath: authsiaExecutablePath,
                    aliasTools: plan.aliasTools
                ),
                "printf '%s\\n' \(WorkspaceGuardedTerminal.shellQuoted(guardedBanner(activeEnvironment: activeEnvironment))) >&2",
            ])
            return lines.joined(separator: "\n")
        }

        static func shouldPrintAutoEnv(config: WorkspaceConfig, environment: [String: String]) -> Bool {
            config.guardSettings.autoTabs && !isAlreadyGuarded(environment: environment)
        }

        private static func isAlreadyGuarded(environment: [String: String]) -> Bool {
            guard environment["AUTHSIA_WORKSPACE_GUARD"] == "1" else { return false }
            let pathEntries = (environment["PATH"] ?? "").split(separator: ":")
            return pathEntries.contains { $0.contains("authsia-guard-") }
        }

        private static func guardedBanner(activeEnvironment: String?) -> String {
            let banner = "Authsia guarded terminal active. " +
                "Workspace-managed parent env names cleared; supported tools route through workspace run."
            guard let activeEnvironment = activeEnvironment?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !activeEnvironment.isEmpty else {
                return banner
            }
            return banner + " Effective environment: \(activeEnvironment). " +
                "Default environment items remain available."
        }

        static func toolsForGuard(config: WorkspaceConfig, requestedTools: [String]) -> [String] {
            WorkspaceGuardedTerminal.defaultTools +
                config.guardSettings.tools +
                customTools(from: requestedTools)
        }

        static func configPersistingRequestedTools(
            _ config: WorkspaceConfig,
            requestedTools: [String]
        ) -> WorkspaceConfig {
            let requested = customTools(from: requestedTools)
            guard !requested.isEmpty else { return config }
            let tools = WorkspaceConfig.GuardSettings(
                autoTabs: config.guardSettings.autoTabs,
                tools: config.guardSettings.tools + requested
            ).tools
            guard tools != config.guardSettings.tools else { return config }
            return WorkspaceConfig(
                schemaVersion: config.schemaVersion,
                workspace: config.workspace,
                managedEnvFiles: config.managedEnvFiles,
                agents: config.agents,
                guardSettings: WorkspaceConfig.GuardSettings(
                    autoTabs: config.guardSettings.autoTabs,
                    tools: tools
                ),
                envBindings: config.envBindings
            )
        }

        private static func customTools(from tools: [String]) -> [String] {
            let defaults = Set(WorkspaceGuardedTerminal.defaultTools)
            return WorkspaceGuardedTerminal.shimmableTools(from: tools)
                .filter { !defaults.contains($0) }
        }

        static func environmentNamesToUnset(
            config: WorkspaceConfig,
            workspaceRoot: URL,
            fileManager: FileManager = .default
        ) -> [String] {
            var names = config.envBindings.map(\.name)
            for relativePath in config.managedEnvFiles where WorkspaceConfigStore.isCommitSafeRelativePath(relativePath) {
                let path = workspaceRoot.appendingPathComponent(relativePath).path
                guard fileManager.fileExists(atPath: path) else { continue }
                guard let entries = try? EnvFileParser.parse(contentsOf: path) else { continue }
                names.append(contentsOf: entries.compactMap { entry in
                    SecretReference.isSecretReference(entry.value) ? entry.key : nil
                })
            }
            return WorkspaceGuardedTerminal.environmentNamesToUnset(from: names)
        }
    }

    struct Agent: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "agent",
            abstract: "Open or print a secret-free AI tool launch",
            discussion: """
                Examples:
                  authsia workspace agent --tool codex --print
                  authsia workspace agent --tool cursor --dry-run
                  authsia workspace agent --tool claude-code --goal-file task.txt
                  authsia workspace agent --tool vscode --goal "Review this workspace without raw secrets"
                """
        )

        @Option(name: .long, help: "Agent tool; default claude-code: claude-code, codex, vscode, cursor, windsurf")
        var tool: WorkspaceAgentTool = .claudeCode

        @Flag(name: .long, help: "Preview the launch without opening an app")
        var dryRun = false

        @Flag(name: .customLong("print"), help: "Print the launch command instead of opening an app")
        var printLaunchCommand = false

        @Option(name: .long, help: "Agent goal to include in the printed handoff")
        var goal: String?

        @Option(name: .long, help: "Read the agent goal from a UTF-8 text file")
        var goalFile: String?

        func run() throws {
            let plan = try WorkspaceAgentLaunchPlan.build(
                startingAt: URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true),
                tool: tool
            )
            let resolvedGoal = try Self.resolvedGoal(goal: goal, goalFile: goalFile)
            if let trimmedGoal = resolvedGoal {
                print(WorkspaceAgentLaunchPlan.renderHandoff(plan, goal: trimmedGoal))
            } else {
                print(WorkspaceAgentLaunchPlan.render(plan))
            }

            guard Self.shouldOpenTool(
                dryRun: dryRun,
                printLaunchCommand: printLaunchCommand,
                hasGoalHandoff: resolvedGoal != nil
            ) else {
                return
            }

            if let openArguments = plan.openArguments {
                try WorkspaceAgentLauncher.open(arguments: openArguments)
                print("Opened \(tool.title).")
            } else {
                // Terminal tools (codex, claude-code) have no GUI app to open; run them
                // in the current terminal, inheriting this shell's TTY and environment.
                print("Launching \(tool.title) in this terminal…")
                try WorkspaceAgentLauncher.runInCurrentTerminal(
                    tool: tool,
                    workingDirectory: plan.workspaceRoot
                )
            }
        }

        static func shouldOpenTool(
            dryRun: Bool,
            printLaunchCommand: Bool,
            hasGoalHandoff: Bool
        ) -> Bool {
            !dryRun && !printLaunchCommand && !hasGoalHandoff
        }

        static func resolvedGoal(
            goal: String?,
            goalFile: String?,
            standardInput: () throws -> String = {
                String(data: FileHandle.standardInput.readDataToEndOfFile(), encoding: .utf8) ?? ""
            }
        ) throws -> String? {
            if goal != nil && goalFile != nil {
                throw ValidationError("Use either --goal or --goal-file, not both.")
            }
            if let goal {
                return try validatedGoal(goal)
            }
            guard let goalFile else { return nil }
            if goalFile == "-" {
                return try validatedGoal(standardInput())
            }
            let fileURL: URL
            if goalFile.hasPrefix("/") {
                fileURL = URL(fileURLWithPath: goalFile)
            } else {
                fileURL = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
                    .appendingPathComponent(goalFile)
            }
            do {
                return try validatedGoal(String(contentsOf: fileURL, encoding: .utf8))
            } catch let error as ValidationError {
                throw error
            } catch {
                throw ValidationError("Could not read --goal-file \(goalFile): \(error.localizedDescription)")
            }
        }

        static func validatedGoal(_ goal: String) throws -> String {
            switch AgentWorkspaceGoalHandoff.validationFailure(for: goal) {
            case .empty:
                throw ValidationError("--goal cannot be empty.")
            case .likelySecret:
                throw ValidationError("--goal appears to contain a secret. Replace raw values with Authsia refs or placeholders.")
            case nil:
                return goal.trimmingCharacters(in: .whitespacesAndNewlines)
            }
        }
    }

    static func workspaceStatusMetadataRequest(_ status: WorkspaceStatus) -> WorkspaceMetadataRequestPayload {
        let references = Set(status.unverifiedReferences.compactMap { reference -> WorkspaceMetadataReference? in
            let itemType: WorkspaceMetadataItemType
            switch reference.itemType {
            case "password":
                itemType = .password
            case "api-key":
                itemType = .apiKey
            case "certificate":
                itemType = .certificate
            case "note":
                itemType = .note
            case "ssh":
                itemType = .ssh
            default:
                return nil
            }
            return WorkspaceMetadataReference(
                itemType: itemType,
                itemName: reference.item,
                folderPath: reference.folderPath
            )
        }).sorted {
            ($0.itemType.rawValue, $0.itemName, $0.folderPath ?? "") <
                ($1.itemType.rawValue, $1.itemName, $1.folderPath ?? "")
        }
        return WorkspaceMetadataRequestPayload(
            workspaceFolder: status.config.workspace.authsiaFolder,
            mode: .status,
            references: references
        )
    }

    /// Loads the vault index for live previews. Listing requires bridge approval, so
    /// `--local-preview` callers pass a nil vault index instead. When a live JSON preview
    /// chooses to load it, an explicit denial rethrows to fail the preview; a locked or
    /// unreachable bridge still returns nil so the preview degrades gracefully.
    private static func loadVaultPayload(failOnApprovalDenial: Bool = false) throws -> BridgeListPayload? {
        do {
            return try AuthsiaBridgeClient.shared.list()
        } catch {
            if failOnApprovalDenial, BridgeClientError.isApprovalDenied(error) {
                throw error
            }
            return nil
        }
    }

    private static func loadVaultIndex(failOnApprovalDenial: Bool = false) throws -> WorkspaceVaultIndex? {
        guard let payload = try loadVaultPayload(failOnApprovalDenial: failOnApprovalDenial) else {
            return nil
        }
        return WorkspaceVaultIndex(payload: payload)
    }

    private static func loadWorkspaceMetadataPayload(
        _ payload: WorkspaceMetadataRequestPayload,
        requestedCommand: String
    ) -> BridgeListPayload? {
        try? AuthsiaBridgeClient.shared.workspaceMetadata(payload, requestedCommand: requestedCommand)
    }
}

enum WorkspaceAgentTool: String, CaseIterable, ExpressibleByArgument {
    case codex
    case claudeCode
    case vsCode
    case cursor
    case windsurf

    init?(argument: String) {
        switch argument.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "codex":
            self = .codex
        case "claude", "claude-code", "claudecode":
            self = .claudeCode
        case "vscode", "vs-code", "visual-studio-code", "code":
            self = .vsCode
        case "cursor":
            self = .cursor
        case "windsurf":
            self = .windsurf
        default:
            return nil
        }
    }

    static var allValueStrings: [String] {
        ["codex", "claude-code", "vscode", "cursor", "windsurf"]
    }

    var title: String {
        switch self {
        case .codex:
            return "Codex"
        case .claudeCode:
            return "Claude Code"
        case .vsCode:
            return "VS Code"
        case .cursor:
            return "Cursor"
        case .windsurf:
            return "Windsurf"
        }
    }

    var applicationName: String? {
        switch self {
        case .codex, .claudeCode:
            return nil
        case .vsCode:
            return "Visual Studio Code"
        case .cursor:
            return "Cursor"
        case .windsurf:
            return "Windsurf"
        }
    }

    var shellCommand: String {
        switch self {
        case .codex:
            return "codex"
        case .claudeCode:
            return "claude"
        case .vsCode:
            return "code ."
        case .cursor:
            return "cursor ."
        case .windsurf:
            return "windsurf ."
        }
    }

    var agentPlatform: String {
        switch self {
        case .codex:
            return "codex"
        case .claudeCode:
            return "claude-code"
        case .vsCode:
            return "copilot"
        case .cursor:
            return "cursor"
        case .windsurf:
            return "windsurf"
        }
    }

    var markedShellCommand: String {
        "env AUTHSIA_AGENT_PLATFORM=\(agentPlatform) AUTHSIA_AGENT_INVOKES_AUTHSIA=1 \(shellCommand)"
    }
}

struct WorkspaceAgentLaunchPlan: Equatable {
    let workspaceRoot: URL
    let tool: WorkspaceAgentTool

    var launchCommand: String {
        guardedLaunchPrefix + " && \(tool.markedShellCommand)"
    }

    var openArguments: [String]? {
        guard let applicationName = tool.applicationName else { return nil }
        return [
            "-n",
            "--env", "AUTHSIA_AGENT_PLATFORM=\(tool.agentPlatform)",
            "--env", "AUTHSIA_AGENT_INVOKES_AUTHSIA=1",
            "-a", applicationName,
            "--args",
            workspaceRoot.path,
        ]
    }

    static func build(startingAt: URL, tool: WorkspaceAgentTool) throws -> WorkspaceAgentLaunchPlan {
        guard let root = WorkspaceRootResolver.findWorkspaceRoot(startingAt: startingAt) else {
            throw WorkspaceConfigError.missingConfig
        }
        _ = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        return WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: tool)
    }

    static func render(_ plan: WorkspaceAgentLaunchPlan) -> String {
        var lines = [
            "Agentic workspace launch: \(plan.tool.title)",
            "Command: \(plan.launchCommand)",
        ]
        if let appName = plan.tool.applicationName {
            lines.append("App: \(appName)")
        }
        lines.append(
            "Secret handling: Authsia injects no managed secrets. Launch from a guarded terminal " +
            "(authsia workspace guard) so ambient shell secrets are not inherited; use " +
            "authsia workspace run -- <command> or authsia exec for JIT/automation-controlled secret access."
        )
        return lines.joined(separator: "\n")
    }

    static func renderHandoff(_ plan: WorkspaceAgentLaunchPlan, goal: String) -> String {
        AgentWorkspaceGoalHandoff.make(
            workspaceName: plan.workspaceRoot.lastPathComponent,
            toolName: plan.tool.title,
            launchCommand: plan.launchCommand,
            goal: goal
        )?.clipboardText ?? ""
    }

    private var guardedLaunchPrefix: String {
        let root = Self.shellQuoted(workspaceRoot.path)
        return "cd \(root) && __authsia_guard_env=\"$(authsia workspace guard --print-env)\" && " +
            "eval \"$__authsia_guard_env\" && unset __authsia_guard_env"
    }

    private static func shellQuoted(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }
}

struct WorkspaceAgentTerminalLaunchRequest: Equatable {
    let executable: String
    let arguments: [String]
    let workingDirectory: URL
    let environmentOverrides: [String: String]
}

enum WorkspaceAgentLauncher {
    static func open(arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        process.arguments = arguments
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw ValidationError(openFailureMessage())
        }
    }

    static func openFailureMessage() -> String {
        "Failed to open agent tool. Make sure the app is installed and can be opened by macOS, " +
            "or run `authsia workspace agent --print` to copy the launch command and paste it into a guarded terminal."
    }

    /// Run a terminal agent in the current terminal. Inherits stdio so the tool gets
    /// this shell's TTY (interactive), and inherits the environment so a guarded shell's
    /// PATH/shims still apply. Replacing this process gives the interactive tool direct
    /// ownership of the terminal instead of nesting under `authsia`.
    static func runInCurrentTerminal(tool: WorkspaceAgentTool, workingDirectory: URL) throws {
        let program = tool.shellCommand
        let request = currentTerminalLaunchRequest(tool: tool, workingDirectory: workingDirectory)
        guard FileManager.default.changeCurrentDirectoryPath(request.workingDirectory.path) else {
            throw ValidationError(enterDirectoryFailureMessage(path: request.workingDirectory.path))
        }
        for (key, value) in request.environmentOverrides {
            setenv(key, value, 1)
        }

        fflush(stdout)
        fflush(stderr)

        var argv = request.arguments.map { strdup($0) }
        argv.append(nil)
        defer {
            for argument in argv where argument != nil {
                free(argument)
            }
        }

        execvp(request.executable, &argv)
        let launchErrno = errno
        if launchErrno == ENOENT {
            throw ValidationError(missingProgramMessage(program: program))
        }
        throw ValidationError(launchFailureMessage(program: program, detail: String(cString: strerror(launchErrno))))
    }

    static func missingProgramMessage(program: String) -> String {
        "Could not find \(program) on PATH. Install \(program), open a guarded terminal that has it on PATH, " +
            "or run `authsia workspace agent --print` with the same --tool to copy the launch command."
    }

    static func enterDirectoryFailureMessage(path: String) -> String {
        "Could not enter workspace folder \(path). Make sure the folder still exists, run " +
            "`authsia workspace status` from the workspace root, or run `authsia workspace agent --print` " +
            "to copy the launch command."
    }

    static func launchFailureMessage(program: String, detail: String) -> String {
        "Failed to launch \(program): \(detail). Fix the terminal/PATH issue, or run " +
            "`authsia workspace agent --print` with the same --tool to copy the command for a guarded terminal."
    }

    static func currentTerminalLaunchRequest(
        tool: WorkspaceAgentTool,
        workingDirectory: URL,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> WorkspaceAgentTerminalLaunchRequest {
        let program = tool.shellCommand
        var environmentOverrides = [
            "AUTHSIA_AGENT_PLATFORM": tool.agentPlatform,
            "AUTHSIA_AGENT_INVOKES_AUTHSIA": "1",
        ]
        let term = environment["TERM"]?.trimmingCharacters(in: .whitespacesAndNewlines)
        if term == nil || term == "" || term == "dumb" {
            environmentOverrides["TERM"] = "xterm-256color"
        }
        return WorkspaceAgentTerminalLaunchRequest(
            executable: program,
            arguments: [program],
            workingDirectory: workingDirectory,
            environmentOverrides: environmentOverrides
        )
    }
}
