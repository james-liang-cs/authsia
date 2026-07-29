import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
@testable import authsia

@Suite("Workspace init planner")
struct WorkspaceInitPlannerTests {
    @Test("yes mode without env file guides preview and explicit env file retry")
    func yesModeWithoutEnvFileGuidesPreviewAndExplicitEnvFileRetry() async throws {
        let initCommand = try Workspace.Init.parse(["--yes"])
        do {
            try await initCommand.run()
            Issue.record("Expected workspace init --yes without --env-file to fail")
        } catch let error as ValidationError {
            let message = String(describing: error)
            #expect(message.contains("--yes requires at least one explicit --env-file."))
            #expect(message.contains("Use --dry-run to preview discovered env files."))
            #expect(message.contains("Then re-run with --yes --env-file .env"))
        }

        let updateCommand = try Workspace.Update.parse(["--yes"])
        do {
            try await updateCommand.run()
            Issue.record("Expected workspace update --yes without --env-file to fail")
        } catch let error as ValidationError {
            let message = String(describing: error)
            #expect(message.contains("--yes requires at least one explicit --env-file."))
            #expect(message.contains("Use --dry-run to preview discovered env files."))
            #expect(message.contains("Then re-run with --yes --env-file .env"))
        }
    }

    @Test("discovers env files and preselects detected non-conflicting secrets")
    func discoversEnvFilesAndPreselectsDetectedNonConflictingSecrets() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try "DB_PASSWORD=plain_password_abcdefghijklmnopqrstuvwxyz123456\nPORT=3000\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        try "LOCAL_PASSWORD=local_password_abcdefghijklmnopqrstuvwxyz123456\n".write(
            to: root.appendingPathComponent(".env.local"),
            atomically: true,
            encoding: .utf8
        )

        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            folderOverride: nil,
            agents: [.codex]
        )

        #expect(plan.config.workspace.name == root.lastPathComponent)
        #expect(plan.config.workspace.authsiaFolder == "Workspaces/\(root.lastPathComponent)")
        #expect(plan.config.guardSettings.responseMode == .confirm)
        #expect(plan.envFiles.map(\.relativePath) == [".env", ".env.local"])
        let password = try #require(plan.envFiles.first?.secrets.first { $0.secret.key == "DB_PASSWORD" })
        #expect(password.selectedByDefault)
        #expect(plan.envFiles.flatMap(\.secrets).map(\.secret.key) == ["DB_PASSWORD", "LOCAL_PASSWORD"])
        #expect(plan.envFiles.flatMap(\.secrets).allSatisfy { !$0.replacementLine.contains("plain_password") })
    }

    @Test("workspace setup plans password and API key detections")
    func workspaceSetupPlansPasswordAndAPIKeyDetections() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try """
        DB_PASSWORD=plain_password_abcdefghijklmnopqrstuvwxyz123456
        API_KEY=AUTHSIA_FIXTURE_SECRET_abcdefghijklmnopqrstuvwxyz123456
        SERVICE_TOKEN=tok_live_abcdefghijklmnopqrstuvwxyz123456
        CLIENT_SECRET=secret_live_abcdefghijklmnopqrstuvwxyz123456
        """.write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )

        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            folderOverride: nil,
            agents: []
        )
        let payload = WorkspaceSetupExchange.payload(for: plan, mode: .initWorkspace)

        #expect(plan.envFiles.flatMap(\.secrets).map(\.secret.key) == [
            "DB_PASSWORD",
            "API_KEY",
            "SERVICE_TOKEN",
            "CLIENT_SECRET",
        ])
        #expect(payload.envFiles.flatMap(\.reviewItems).map(\.key) == [
            "DB_PASSWORD",
            "API_KEY",
            "SERVICE_TOKEN",
            "CLIENT_SECRET",
        ])
        #expect(plan.envFiles.flatMap(\.secrets).map(\.replacementLine).contains {
            $0.contains("API_KEY=authsia://api-key/API_KEY/key?folder=")
        })
    }

    @Test("workspace setup plan json is sanitized and includes agent rules")
    func workspaceSetupPlanJSONIsSanitizedAndIncludesAgentRules() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try "APP_PASSWORD=abcd1234_password\nHF_TOKEN=qwerasdv\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )

        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            folderOverride: nil,
            agents: [.codex]
        )
        let payload = WorkspaceSetupExchange.payload(for: plan, mode: .initWorkspace)
        let data = try JSONEncoder().encode(payload)
        let json = try #require(String(data: data, encoding: .utf8))
        let envFile = try #require(payload.envFiles.first)

        #expect(payload.schemaVersion == 1)
        #expect(payload.agentRules.first { $0.id == "codex" }?.selected == true)
        #expect(envFile.reviewItems.map(\.key) == ["APP_PASSWORD", "HF_TOKEN"])
        #expect(envFile.reviewItems.allSatisfy { $0.selectedByDefault })
        #expect(!json.contains("abcd1234"))
        #expect(!json.contains("qwerasdv"))
    }

    @Test("workspace setup preview marks live vault conflicts as action choices")
    func workspaceSetupPreviewMarksLiveVaultConflictsAsActionChoices() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try "DB_PASSWORD=plain_password_abcdefghijklmnopqrstuvwxyz123456\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let vaultPayload = BridgeListPayload(
            accounts: [],
            passwords: [
                BridgePassword(
                    id: UUID(),
                    name: "DB_PASSWORD",
                    username: "",
                    website: nil,
                    folderPath: "Workspaces/\(root.lastPathComponent)",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: true,
                    createdAt: Date(),
                    updatedAt: Date()
                ),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            folderOverride: nil,
            agents: [],
            vaultIndex: WorkspaceVaultIndex(payload: vaultPayload)
        )
        let payload = WorkspaceSetupExchange.payload(for: plan, mode: .update)
        let item = try #require(payload.envFiles.first?.reviewItems.first)

        #expect(item.key == "DB_PASSWORD")
        #expect(item.hasConflict)
        #expect(item.selected == false)
        #expect(item.selectedByDefault == false)
        #expect(item.action == .skip)
        #expect(item.conflict?.contains("password DB_PASSWORD") == true)
    }

    @Test("workspace setup preview marks existing API key conflicts as action choices")
    func workspaceSetupPreviewMarksExistingAPIKeyConflictsAsActionChoices() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try "API_KEY=AUTHSIA_FIXTURE_SECRET_abcdefghijklmnopqrstuvwxyz1234567890\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let vaultPayload = BridgeListPayload(
            accounts: [],
            passwords: [],
            apiKeys: [
                apiKey(id: "00000000-0000-0000-0000-000000000001", name: "API_KEY", folderPath: "Workspaces/\(root.lastPathComponent)"),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            folderOverride: nil,
            agents: [],
            vaultIndex: WorkspaceVaultIndex(payload: vaultPayload)
        )
        let item = try #require(WorkspaceSetupExchange.payload(for: plan, mode: .update).envFiles.first?.reviewItems.first)

        #expect(item.key == "API_KEY")
        #expect(item.hasConflict)
        #expect(item.selectedByDefault == false)
        #expect(item.action == .skip)
        #expect(item.conflict?.contains("api-key API_KEY") == true)
    }

    @Test("workspace setup apply honors reviewed conflict action without live vault index")
    func workspaceSetupApplyHonorsReviewedConflictActionWithoutLiveVaultIndex() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try "DB_PASSWORD=plain_password_abcdefghijklmnopqrstuvwxyz123456\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                BridgePassword(
                    id: UUID(),
                    name: "DB_PASSWORD",
                    username: "",
                    website: nil,
                    folderPath: "Workspaces/\(root.lastPathComponent)",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: true,
                    createdAt: Date(),
                    updatedAt: Date()
                ),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )
        let previewPlan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            folderOverride: nil,
            agents: [],
            vaultIndex: WorkspaceVaultIndex(payload: payload)
        )
        let envFile = try #require(WorkspaceSetupExchange.payload(for: previewPlan, mode: .update).envFiles.first)
        let item = try #require(envFile.reviewItems.first)
        let selection = WorkspaceSetupExchange.SelectionPayload(
            schemaVersion: 1,
            mode: .update,
            authsiaFolder: previewPlan.config.workspace.authsiaFolder,
            envFiles: [
                WorkspaceSetupExchange.EnvFileSelection(
                    relativePath: envFile.relativePath,
                    selected: true,
                    secrets: [
                        WorkspaceSetupExchange.SecretSelection(id: item.id, action: .update),
                    ]
                ),
            ],
            agentRules: []
        )
        let applyPlan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            folderOverride: nil,
            agents: [],
            vaultIndex: nil
        )

        let resolved = try WorkspaceSetupExchange.resolve(selection, against: applyPlan)

        #expect(resolved.secrets.map(\.secret.key) == ["DB_PASSWORD"])
        #expect(resolved.secrets.map(\.action) == [.update])
    }

    @Test("workspace setup selection resolves selected rows without raw values")
    func workspaceSetupSelectionResolvesSelectedRowsWithoutRawValues() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try "APP_PASSWORD=abcd1234_password\nLOCAL_PASSWORD=qwerasdv_password\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )

        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            folderOverride: nil,
            agents: [.codex]
        )
        let payload = WorkspaceSetupExchange.payload(for: plan, mode: .initWorkspace)
        let envFile = try #require(payload.envFiles.first)
        let selection = WorkspaceSetupExchange.SelectionPayload(
            schemaVersion: 1,
            mode: .initWorkspace,
            authsiaFolder: payload.workspace.authsiaFolder,
            envFiles: [
                WorkspaceSetupExchange.EnvFileSelection(
                    relativePath: envFile.relativePath,
                    selected: true,
                    secrets: envFile.reviewItems.map {
                        WorkspaceSetupExchange.SecretSelection(id: $0.id, action: $0.action)
                    }
                ),
            ],
            agentRules: [
                WorkspaceSetupExchange.AgentRuleSelection(id: "codex", selected: true),
            ]
        )

        let resolved = try WorkspaceSetupExchange.resolve(selection, against: plan)

        #expect(resolved.envFiles.map(\.relativePath) == [".env"])
        #expect(resolved.secrets.map(\.secret.key) == ["APP_PASSWORD", "LOCAL_PASSWORD"])
        #expect(resolved.secrets.allSatisfy { $0.action == .create })
    }

    @Test("workspace setup selection excludes a deselected agent rule")
    func workspaceSetupSelectionExcludesDeselectedAgentRule() throws {
        let selection = WorkspaceSetupExchange.SelectionPayload(
            schemaVersion: 1,
            mode: .update,
            authsiaFolder: "Workspaces/api",
            envFiles: [],
            agentRules: [
                WorkspaceSetupExchange.AgentRuleSelection(id: "codex", selected: false),
                WorkspaceSetupExchange.AgentRuleSelection(id: "claude-code", selected: true),
            ]
        )

        let selected = try WorkspaceSetupExchange.selectedAgents(from: selection)

        #expect(!selected.contains(.codex))
        #expect(selected.contains(.claudeCode))
    }

    @Test("workspace setup apply does not materialize a vault folder without selected secrets")
    func workspaceSetupApplyDoesNotCreateVaultFolderWithoutSelectedSecrets() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let envDirectory = root.appendingPathComponent("web", isDirectory: true)
        try FileManager.default.createDirectory(at: envDirectory, withIntermediateDirectories: true)
        try "NEXT_PUBLIC_SITE=docflow\n".write(
            to: envDirectory.appendingPathComponent(".env.local"),
            atomically: true,
            encoding: .utf8
        )
        let vaultClient = RecordingWorkspaceSetupVaultClient()

        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: ["web/.env.local"],
            folderOverride: nil,
            agents: []
        )
        try await Workspace.Init.apply(
            plan: plan,
            selectedEnvFiles: plan.envFiles,
            selectedSecrets: [],
            vaultClient: vaultClient
        )

        #expect(vaultClient.ensuredFolders.isEmpty)
        let config = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        #expect(config.workspace.authsiaFolder == plan.config.workspace.authsiaFolder)
    }

    @Test("workspace setup apply ignores stale non-migratable selections")
    func workspaceSetupApplyIgnoresStaleNonMigratableSelections() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try "DB_PASSWORD=plain_password_abcdefghijklmnopqrstuvwxyz123456\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let vaultClient = RecordingWorkspaceSetupVaultClient()
        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [".env"],
            folderOverride: nil,
            agents: []
        )
        let certificate = workspaceDetectedSecret(
            key: "TLS_CERT",
            type: .certificate,
            value: "-----BEGIN CERTIFICATE-----\nMIIDtest\n-----END CERTIFICATE-----",
            filePath: root.appendingPathComponent(".env").path
        )

        try await Workspace.Init.apply(
            plan: plan,
            selectedEnvFiles: [],
            selectedSecrets: [
                WorkspaceSecretSelection(secret: certificate, action: .create),
            ],
            vaultClient: vaultClient
        )

        #expect(vaultClient.addedPasswords.isEmpty)
        #expect(vaultClient.addedAPIKeys.isEmpty)
        #expect(vaultClient.addedCertificates.isEmpty)
        #expect(vaultClient.addedNotes.isEmpty)
        #expect(vaultClient.ensuredFolders.isEmpty)
    }

    @Test("workspace setup apply stores selected passwords in the workspace folder before rewriting env files")
    func workspaceSetupApplyStoresSelectedPasswordsInWorkspaceFolder() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try "DB_PASSWORD=plain_password_abcdefghijklmnopqrstuvwxyz123456\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let vaultClient = RecordingWorkspaceSetupVaultClient()
        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [".env"],
            folderOverride: nil,
            agents: []
        )
        let secret = try #require(plan.envFiles.first?.secrets.first)

        try await Workspace.Init.apply(
            plan: plan,
            selectedEnvFiles: plan.envFiles,
            selectedSecrets: [WorkspaceSecretSelection(secret: secret.secret, action: .create)],
            backupService: BackupService(bridgeClient: WorkspaceResetBackupVaultClient()),
            vaultClient: vaultClient
        )

        #expect(vaultClient.ensuredFolders.isEmpty)
        #expect(vaultClient.addedPasswords == ["DB_PASSWORD"])
        #expect(vaultClient.addedPasswordFolders == [plan.config.workspace.authsiaFolder])
        #expect(try read(".env", in: root).contains("DB_PASSWORD=authsia://password/DB_PASSWORD/password?folder="))
    }

    @Test("workspace setup stores selected api keys in the API Keys category before rewriting env files")
    func workspaceSetupStoresSelectedAPIKeysInWorkspaceFolder() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try "API_KEY=AUTHSIA_FIXTURE_SECRET_abcdefghijklmnopqrstuvwxyz1234567890\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let vaultClient = RecordingWorkspaceSetupVaultClient()
        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [".env"],
            folderOverride: nil,
            agents: []
        )
        let secret = try #require(plan.envFiles.first?.secrets.first)

        try await Workspace.Init.apply(
            plan: plan,
            selectedEnvFiles: plan.envFiles,
            selectedSecrets: [WorkspaceSecretSelection(secret: secret.secret, action: .create)],
            backupService: BackupService(bridgeClient: WorkspaceResetBackupVaultClient()),
            vaultClient: vaultClient
        )

        #expect(secret.secret.type == .apiKey)
        #expect(secret.replacementLine.contains("API_KEY=authsia://api-key/API_KEY/key?folder="))
        #expect(vaultClient.addedAPIKeys == ["API_KEY"])
        #expect(vaultClient.addedAPIKeyFolders == [plan.config.workspace.authsiaFolder])
        #expect(vaultClient.addedPasswords.isEmpty)
        #expect(try read(".env", in: root).contains("API_KEY=authsia://api-key/API_KEY/key?folder="))
    }

    @Test("workspace setup refuses to rewrite env files when stored passwords are not visible in the vault")
    func workspaceSetupRefusesToRewriteWhenStoredPasswordsAreNotVisible() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let originalEnv = "DB_PASSWORD=plain_password_abcdefghijklmnopqrstuvwxyz123456\n"
        try originalEnv.write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let vaultClient = RecordingWorkspaceSetupVaultClient(exposeAddedPasswords: false)
        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [".env"],
            folderOverride: nil,
            agents: []
        )
        let secret = try #require(plan.envFiles.first?.secrets.first)

        do {
            try await Workspace.Init.apply(
                plan: plan,
                selectedEnvFiles: plan.envFiles,
                selectedSecrets: [WorkspaceSecretSelection(secret: secret.secret, action: .create)],
                backupService: BackupService(bridgeClient: WorkspaceResetBackupVaultClient()),
                vaultClient: vaultClient
            )
            Issue.record("Expected workspace setup to fail when the stored password is not visible in the vault")
        } catch {
            let message = (error as? ValidationError)?.message ?? String(describing: error)
            #expect(message.contains("DB_PASSWORD"))
            #expect(message.contains("No workspace files were rewritten"))
        }

        #expect(vaultClient.addedPasswords == ["DB_PASSWORD"])
        #expect(try read(".env", in: root) == originalEnv)
        #expect(!FileManager.default.fileExists(
            atPath: root.appendingPathComponent(WorkspaceConfigStore.relativeConfigPath).path
        ))
    }

    @Test("workspace setup does not depend on legacy vault folder precreation")
    func workspaceSetupDoesNotDependOnLegacyVaultFolderPrecreation() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let originalEnv = "DB_PASSWORD=plain_password_abcdefghijklmnopqrstuvwxyz123456\n"
        try originalEnv.write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let vaultClient = RecordingWorkspaceSetupVaultClient(
            ensureError: BridgeClientError.bridgeError(code: "accessDenied", message: "denied", query: nil)
        )

        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [".env"],
            folderOverride: nil,
            agents: []
        )
        let secret = try #require(plan.envFiles.first?.secrets.first)

        try await Workspace.Init.apply(
            plan: plan,
            selectedEnvFiles: plan.envFiles,
            selectedSecrets: [WorkspaceSecretSelection(secret: secret.secret, action: .create)],
            backupService: BackupService(bridgeClient: WorkspaceResetBackupVaultClient()),
            vaultClient: vaultClient
        )

        #expect(vaultClient.ensuredFolders.isEmpty)
        #expect(vaultClient.addedPasswords == ["DB_PASSWORD"])
        #expect(try read(".env", in: root) != originalEnv)
        #expect(FileManager.default.fileExists(
            atPath: root.appendingPathComponent(WorkspaceConfigStore.relativeConfigPath).path
        ))
    }

    @Test("workspace setup fails when a selected env file references a missing Authsia item")
    func workspaceSetupFailsWhenSelectedEnvFileReferencesMissingAuthsiaItem() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let encodedFolder = "Workspaces%2F\(root.lastPathComponent)"
        try "DB_PASSWORD=authsia://password/DB_PASSWORD/password?folder=\(encodedFolder)\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let emptyPayload = BridgeListPayload(
            accounts: [],
            passwords: [],
            certificates: [],
            notes: [],
            sshKeys: []
        )
        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [".env"],
            folderOverride: nil,
            agents: [],
            vaultIndex: WorkspaceVaultIndex(payload: emptyPayload)
        )
        #expect(plan.missingReferences.map(\.item) == ["DB_PASSWORD"])
        let vaultClient = RecordingWorkspaceSetupVaultClient()

        do {
            try await Workspace.Init.apply(
                plan: plan,
                selectedEnvFiles: plan.envFiles,
                selectedSecrets: [],
                vaultClient: vaultClient
            )
            Issue.record("Expected workspace setup to fail for missing Authsia references")
        } catch {
            #expect(String(describing: error).contains("DB_PASSWORD"))
        }

        #expect(vaultClient.ensuredFolders.isEmpty)
        #expect(!FileManager.default.fileExists(
            atPath: root.appendingPathComponent(WorkspaceConfigStore.relativeConfigPath).path
        ))
    }

    @Test("workspace setup ignores missing references in unselected env files")
    func workspaceSetupIgnoresMissingReferencesInUnselectedEnvFiles() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try "DB_PASSWORD=plain_password_abcdefghijklmnopqrstuvwxyz123456\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        try "OTHER_PASSWORD=authsia://password/OTHER_PASSWORD/password\n".write(
            to: root.appendingPathComponent(".env.other"),
            atomically: true,
            encoding: .utf8
        )
        let emptyPayload = BridgeListPayload(
            accounts: [],
            passwords: [],
            certificates: [],
            notes: [],
            sshKeys: []
        )
        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [".env", ".env.other"],
            folderOverride: nil,
            agents: [],
            vaultIndex: WorkspaceVaultIndex(payload: emptyPayload)
        )
        #expect(plan.missingReferences.map(\.item) == ["OTHER_PASSWORD"])
        let selectedEnvFiles = plan.envFiles.filter { $0.relativePath == ".env" }
        let secret = try #require(selectedEnvFiles.first?.secrets.first)
        let vaultClient = RecordingWorkspaceSetupVaultClient()

        try await Workspace.Init.apply(
            plan: plan,
            selectedEnvFiles: selectedEnvFiles,
            selectedSecrets: [WorkspaceSecretSelection(secret: secret.secret, action: .create)],
            backupService: BackupService(bridgeClient: WorkspaceResetBackupVaultClient()),
            vaultClient: vaultClient
        )

        #expect(vaultClient.addedPasswords == ["DB_PASSWORD"])
        #expect(try read(".env", in: root).contains("DB_PASSWORD=authsia://password/DB_PASSWORD/password?folder="))
    }

    @Test("applying an update with a deselected agent rule removes that rule's files")
    func updateApplyRemovesDeselectedAgentRule() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: WorkspaceConfig.Agents(rules: ["codex", "claude-code"])
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex, .claudeCode])
        // Codex rules live in AGENTS.md, Claude Code rules in CLAUDE.md.
        let codexRule = root.appendingPathComponent("AGENTS.md")
        let claudeRule = root.appendingPathComponent("CLAUDE.md")
        #expect(FileManager.default.fileExists(atPath: codexRule.path))
        #expect(FileManager.default.fileExists(atPath: claudeRule.path))

        // Reproduce the app's `workspace update --apply-json` glue: keep claude-code,
        // deselect codex.
        let selection = WorkspaceSetupExchange.SelectionPayload(
            schemaVersion: 1,
            mode: .update,
            authsiaFolder: config.workspace.authsiaFolder,
            envFiles: [],
            agentRules: [
                WorkspaceSetupExchange.AgentRuleSelection(id: "codex", selected: false),
                WorkspaceSetupExchange.AgentRuleSelection(id: "claude-code", selected: true),
            ]
        )
        let selectedAgents = try WorkspaceSetupExchange.selectedAgents(from: selection)
        let existingAgents = (config.agents?.rules ?? []).compactMap(AgentTool.init(argument:))
        let selectedAgentSet = Set(selectedAgents)
        let removedAgents = existingAgents.filter { !selectedAgentSet.contains($0) }
        #expect(removedAgents == [.codex])

        let plan = try await WorkspaceUpdatePlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            agents: selectedAgents,
            mergeExistingAgents: false,
            vaultIndex: nil
        )
        try await Workspace.Init.apply(
            plan: plan,
            selectedEnvFiles: [],
            selectedSecrets: [],
            removedAgents: removedAgents,
            vaultClient: RecordingWorkspaceSetupVaultClient()
        )

        // The deselected rule's file is gone; the kept rule's file remains.
        #expect(!FileManager.default.fileExists(atPath: codexRule.path))
        #expect(FileManager.default.fileExists(atPath: claudeRule.path))
        let updatedConfig = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        #expect(updatedConfig.agents?.rules == ["claude-code"])
    }

    @Test("applying an update with all agent rules deselected removes all managed rule files")
    func updateApplyRemovesAllDeselectedAgentRules() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: WorkspaceConfig.Agents(rules: ["codex", "claude-code"])
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex, .claudeCode])

        let selection = WorkspaceSetupExchange.SelectionPayload(
            schemaVersion: 1,
            mode: .update,
            authsiaFolder: config.workspace.authsiaFolder,
            envFiles: [],
            agentRules: [
                WorkspaceSetupExchange.AgentRuleSelection(id: "codex", selected: false),
                WorkspaceSetupExchange.AgentRuleSelection(id: "claude-code", selected: false),
            ]
        )
        let selectedAgents = try WorkspaceSetupExchange.selectedAgents(from: selection)
        let existingAgents = (config.agents?.rules ?? []).compactMap(AgentTool.init(argument:))
        let selectedAgentSet = Set(selectedAgents)
        let removedAgents = existingAgents.filter { !selectedAgentSet.contains($0) }
        let plan = try await WorkspaceUpdatePlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            agents: selectedAgents,
            mergeExistingAgents: false,
            vaultIndex: nil
        )

        try await Workspace.Init.apply(
            plan: plan,
            selectedEnvFiles: [],
            selectedSecrets: [],
            removedAgents: removedAgents,
            vaultClient: RecordingWorkspaceSetupVaultClient()
        )

        #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent("AGENTS.md").path))
        #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent("CLAUDE.md").path))
        #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent(".authsia/agent-rules.md").path))
        let updatedConfig = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        #expect(updatedConfig.agents == nil)
    }

    @Test("applying an update refreshes a selected stale agent rule")
    func updateApplyRefreshesSelectedStaleAgentRule() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: WorkspaceConfig.Agents(rules: ["codex"])
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])
        let currentRules = try read("AGENTS.md", in: root)
        let staleRules = currentRules.replacingOccurrences(
            of: AgentRuleInstaller.managedStartMarker,
            with: "\(AgentRuleInstaller.managedStartMarker)\nOutdated Authsia rule content."
        )
        #expect(staleRules != currentRules)
        try staleRules.write(
            to: root.appendingPathComponent("AGENTS.md"),
            atomically: true,
            encoding: .utf8
        )

        let plan = try await WorkspaceUpdatePlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            agents: [.codex],
            mergeExistingAgents: false,
            vaultIndex: nil
        )
        try await Workspace.Init.apply(
            plan: plan,
            selectedEnvFiles: [],
            selectedSecrets: [],
            vaultClient: RecordingWorkspaceSetupVaultClient()
        )

        #expect(try read("AGENTS.md", in: root) == currentRules)
    }

    @Test("workspace setup selection rejects create action for existing Authsia items")
    func workspaceSetupSelectionRejectsCreateActionForExistingAuthsiaItems() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try "DB_PASSWORD=plain_password_abcdefghijklmnopqrstuvwxyz123456\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                BridgePassword(
                    id: UUID(),
                    name: "DB_PASSWORD",
                    username: "",
                    website: nil,
                    folderPath: "Workspaces/\(root.lastPathComponent)",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: true,
                    createdAt: Date(),
                    updatedAt: Date()
                ),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )
        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            folderOverride: nil,
            agents: [],
            vaultIndex: WorkspaceVaultIndex(payload: payload)
        )
        let envFile = try #require(WorkspaceSetupExchange.payload(for: plan, mode: .update).envFiles.first)
        let item = try #require(envFile.reviewItems.first)
        let selection = WorkspaceSetupExchange.SelectionPayload(
            schemaVersion: 1,
            mode: .update,
            authsiaFolder: plan.config.workspace.authsiaFolder,
            envFiles: [
                WorkspaceSetupExchange.EnvFileSelection(
                    relativePath: envFile.relativePath,
                    selected: true,
                    secrets: [
                        WorkspaceSetupExchange.SecretSelection(id: item.id, action: .create),
                    ]
                ),
            ],
            agentRules: []
        )

        do {
            _ = try WorkspaceSetupExchange.resolve(selection, against: plan)
            Issue.record("Expected stale create selection to be rejected.")
        } catch {
            let message = (error as? ValidationError)?.message ?? String(describing: error)
            #expect(message.contains("DB_PASSWORD"))
            #expect(message.contains("choose Update or Reuse"))
        }
    }

    @Test("workspace init configures scrape defaults before env migration")
    func workspaceInitConfiguresScrapeDefaultsBeforeEnvMigration() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let envURL = root.appendingPathComponent(".env")
        let originalLine = "STRIPE_SECRET_KEY=AUTHSIA_FIXTURE_SECRET_abcdefghijklmnopqrstuvwxyz123456"
        try "\(originalLine)\n".write(to: envURL, atomically: true, encoding: .utf8)
        let secret = DetectedSecret(
            filePath: envURL.path,
            lineNumber: 1,
            originalLine: originalLine,
            key: "STRIPE_SECRET_KEY",
            value: "AUTHSIA_FIXTURE_SECRET_abcdefghijklmnopqrstuvwxyz123456",
            rawContent: nil,
            confidence: .high,
            type: .secret,
            entropy: 4.8,
            description: "test secret",
            sshMetadata: nil
        )
        let scrape = Workspace.Init.configuredScrapeForEnvMigration(folder: "Workspaces/api")

        let result = try await scrape.handleEnvFileMigration(
            secrets: [secret],
            backupService: BackupService(),
            confirmApplyChanges: { true },
            storeSecrets: { secrets in
                ScrapeMigrationSummary(
                    addedCount: 0,
                    skippedCount: secrets.count,
                    failed: [],
                    results: secrets.map {
                        ScrapeMigrationResult(secret: $0, outcome: .skipped)
                    }
                )
            }
        )

        #expect(result == .noChanges)
        let rewritten = try String(contentsOf: envURL, encoding: .utf8)
        #expect(rewritten.contains(originalLine))
    }

    @Test("workspace env migration keeps duplicate rows rewriteable after one stored item")
    func workspaceEnvMigrationKeepsDuplicateRowsRewriteableAfterOneStoredItem() {
        let value = "AUTHSIA_FIXTURE_SECRET_flask_secret_keyabcdefghijklmnopqrstuvwxyz123456"
        let secret = workspaceDetectedSecret(
            key: "FLASK_SECRET_KEY",
            value: value,
            filePath: "/tmp/project/.env",
            lineNumber: 1
        )
        let duplicate = workspaceDetectedSecret(
            key: "FLASK_SECRET_KEY",
            value: value,
            filePath: "/tmp/project/.env.workshop",
            lineNumber: 1
        )
        let scrape = Workspace.Init.configuredScrapeForEnvMigration(folder: "Workspaces/api")
        let summary = ScrapeMigrationSummary(
            addedCount: 1,
            skippedCount: 1,
            failed: [],
            results: [
                ScrapeMigrationResult(secret: secret, outcome: .added),
                ScrapeMigrationResult(secret: duplicate, outcome: .skipped),
            ]
        )

        let rewriteable = scrape.rewriteableSecrets(from: summary, selectedSecrets: [secret, duplicate])

        #expect(rewriteable.map(\.filePath) == [secret.filePath, duplicate.filePath])
    }

    @Test("workspace init rejects selected secrets that were not stored")
    func workspaceInitRejectsSelectedSecretsThatWereNotStored() throws {
        let secret = DetectedSecret(
            filePath: "/tmp/workspace/.env",
            lineNumber: 1,
            originalLine: "STRIPE_SECRET_KEY=AUTHSIA_FIXTURE_SECRET_abcdefghijklmnopqrstuvwxyz123456",
            key: "STRIPE_SECRET_KEY",
            value: "AUTHSIA_FIXTURE_SECRET_abcdefghijklmnopqrstuvwxyz123456",
            rawContent: nil,
            confidence: .high,
            type: .secret,
            entropy: 4.8,
            description: "test secret",
            sshMetadata: nil
        )
        let summary = ScrapeMigrationSummary(
            addedCount: 0,
            skippedCount: 1,
            failed: [],
            results: [
                ScrapeMigrationResult(secret: secret, outcome: .skipped),
            ]
        )

        #expect(throws: ValidationError.self) {
            try Workspace.Init.validateSelectedSecretsStored(summary, selectedSecrets: [secret])
        }
    }

    @Test("workspace init accepts duplicate selected rows covered by one stored item")
    func workspaceInitAcceptsDuplicateSelectedRowsCoveredByOneStoredItem() throws {
        let secret = workspaceDetectedSecret(key: "FLASK_SECRET_KEY")
        let duplicate = workspaceDetectedSecret(
            key: "FLASK_SECRET_KEY",
            value: secret.value,
            filePath: "/tmp/project/.env.workshop",
            lineNumber: 26
        )
        let summary = ScrapeMigrationSummary(
            addedCount: 1,
            skippedCount: 1,
            failed: [],
            results: [
                ScrapeMigrationResult(secret: secret, outcome: .added),
                ScrapeMigrationResult(secret: duplicate, outcome: .skipped),
            ]
        )

        try Workspace.Init.validateSelectedSecretsStored(summary, selectedSecrets: [secret, duplicate])
    }

    @Test("workspace init rejects duplicate selected rows with different values")
    func workspaceInitRejectsDuplicateSelectedRowsWithDifferentValues() throws {
        let secret = workspaceDetectedSecret(key: "FLASK_SECRET_KEY")
        let duplicate = workspaceDetectedSecret(
            key: "FLASK_SECRET_KEY",
            value: "different_secret_value_abcdefghijklmnopqrstuvwxyz123456",
            filePath: "/tmp/project/.env.workshop",
            lineNumber: 26
        )
        let summary = ScrapeMigrationSummary(
            addedCount: 1,
            skippedCount: 1,
            failed: [],
            results: [
                ScrapeMigrationResult(secret: secret, outcome: .added),
                ScrapeMigrationResult(secret: duplicate, outcome: .skipped),
            ]
        )

        #expect(throws: ValidationError.self) {
            try Workspace.Init.validateSelectedSecretsStored(summary, selectedSecrets: [secret, duplicate])
        }
    }

    @Test("workspace init reports failed selected keys without leaking values")
    func workspaceInitReportsFailedSelectedKeysWithoutLeakingValues() throws {
        let secretValue = "AUTHSIA_FIXTURE_SECRET_abcdefghijklmnopqrstuvwxyz123456"
        let secret = DetectedSecret(
            filePath: "/tmp/workspace/.env",
            lineNumber: 1,
            originalLine: "STRIPE_SECRET_KEY=\(secretValue)",
            key: "STRIPE_SECRET_KEY",
            value: secretValue,
            rawContent: nil,
            confidence: .high,
            type: .secret,
            entropy: 4.8,
            description: "test secret",
            sshMetadata: nil
        )
        let storageError = NSError(
            domain: "AuthsiaWorkspaceStorage",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "bridge denied storage for \(secretValue)"]
        )
        let summary = ScrapeMigrationSummary(
            addedCount: 0,
            skippedCount: 0,
            failed: [(secret, storageError)],
            results: []
        )

        do {
            try Workspace.Init.validateSelectedSecretsStored(summary, selectedSecrets: [secret])
            Issue.record("Expected selected secret storage failure to throw.")
        } catch {
            let message = (error as? ValidationError)?.message ?? String(describing: error)
            #expect(message.contains("STRIPE_SECRET_KEY"))
            #expect(message.contains("bridge denied storage"))
            #expect(!message.contains(secretValue))
            #expect(message.contains("<concealed by authsia>"))
            #expect(message.contains("No workspace files were rewritten"))
        }
    }

    @Test("default env discovery includes env files up to three nested directories")
    func defaultEnvDiscoveryIncludesEnvFilesUpToThreeNestedDirectories() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try "API_KEY=AUTHSIA_FIXTURE_SECRET_rootabcdefghijklmnopqrstuvwxyz123456\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        try "DELPHI_TOKEN=tok_live_delphiabcdefghijklmnopqrstuvwxyz123456\n".write(
            to: root.appendingPathComponent(".delphi.env.local"),
            atomically: true,
            encoding: .utf8
        )
        try "DELPHI_PUBLIC_TOKEN=tok_live_publicdelphiabcdefghijklmnopqrstuvwxyz123456\n".write(
            to: root.appendingPathComponent("delphi.env.local"),
            atomically: true,
            encoding: .utf8
        )
        try writeNestedFile(
            "APP_TOKEN=tok_live_appabcdefghijklmnopqrstuvwxyz123456\n",
            relativePath: "apps/api/.env",
            in: root
        )
        try writeNestedFile(
            "WORKER_TOKEN=tok_live_workerabcdefghijklmnopqrstuvwxyz123456\n",
            relativePath: "services/worker/config/.env.local",
            in: root
        )
        try writeNestedFile(
            "IGNORED_TOKEN=tok_live_deepabcdefghijklmnopqrstuvwxyz123456\n",
            relativePath: "services/worker/config/deep/.env",
            in: root
        )

        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            folderOverride: nil,
            agents: []
        )

        #expect(plan.envFiles.map(\.relativePath) == [
            ".env",
            ".delphi.env.local",
            "apps/api/.env",
            "delphi.env.local",
            "services/worker/config/.env.local",
        ])
    }

    @Test("recursive env discovery finds package env files and prunes generated folders")
    func recursiveEnvDiscoveryFindsPackageEnvFilesAndPrunesGeneratedFolders() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try "API_KEY=AUTHSIA_FIXTURE_SECRET_rootabcdefghijklmnopqrstuvwxyz123456\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        try writeNestedFile(
            "APP_TOKEN=tok_live_appabcdefghijklmnopqrstuvwxyz123456\n",
            relativePath: "apps/api/.env",
            in: root
        )
        try writeNestedFile(
            "WEB_TOKEN=tok_live_webabcdefghijklmnopqrstuvwxyz123456\n",
            relativePath: "packages/web/.env.local",
            in: root
        )
        try writeNestedFile(
            "IGNORED_TOKEN=tok_live_deepabcdefghijklmnopqrstuvwxyz123456\n",
            relativePath: "services/worker/config/deep/.env",
            in: root
        )
        try writeNestedFile(
            "IGNORED_TOKEN=tok_live_nodeabcdefghijklmnopqrstuvwxyz123456\n",
            relativePath: "node_modules/demo/.env",
            in: root
        )
        try writeNestedFile(
            "IGNORED_TOKEN=tok_live_buildabcdefghijklmnopqrstuvwxyz123456\n",
            relativePath: "build/.env",
            in: root
        )

        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            folderOverride: nil,
            agents: [],
            discoverNestedEnvFiles: true
        )
        let rendered = Workspace.Init.renderPlan(plan)

        #expect(plan.envFiles.map(\.relativePath) == [".env", "apps/api/.env", "packages/web/.env.local"])
        #expect(plan.config.managedEnvFiles == [".env", "apps/api/.env", "packages/web/.env.local"])
        #expect(rendered.contains("- [2] apps/api/.env:"))
        #expect(rendered.contains("- [3] packages/web/.env.local:"))
        #expect(!rendered.contains("node_modules"))
        #expect(!rendered.contains("services/worker/config/deep"))
        #expect(!rendered.contains("tok_live"))
    }

    @Test("explicit env files limit planning")
    func explicitEnvFilesLimitPlanning() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try "API_KEY=AUTHSIA_FIXTURE_SECRET_abcdefghijklmnopqrstuvwxyz123456\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        try "PROD_TOKEN=prod_live_abcdefghijklmnopqrstuvwxyz123456\n".write(
            to: root.appendingPathComponent(".env.production"),
            atomically: true,
            encoding: .utf8
        )

        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [".env.production"],
            folderOverride: "Team/API",
            agents: []
        )

        #expect(plan.config.workspace.authsiaFolder == "Workspaces/Team/API")
        #expect(plan.envFiles.map(\.relativePath) == [".env.production"])
    }

    @Test("explicit env files must exist")
    func explicitEnvFilesMustExist() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        await #expect(throws: WorkspacePlannerError.self) {
            try await WorkspaceInitPlanner.plan(
                workspaceRoot: root,
                explicitEnvFiles: [".env.missing"],
                folderOverride: nil,
                agents: []
            )
        }
    }

    @Test("explicit env file errors explain how to choose a workspace path")
    func explicitEnvFileErrorsExplainHowToChooseWorkspacePath() async throws {
        let root = try makeWorkspaceRoot()
        let outside = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-outside-env-\(UUID().uuidString)")
        defer {
            try? FileManager.default.removeItem(at: root)
            try? FileManager.default.removeItem(at: outside)
        }
        try "API_KEY=AUTHSIA_FIXTURE_SECRET_abcdefghijklmnopqrstuvwxyz123456\n".write(
            to: outside,
            atomically: true,
            encoding: .utf8
        )

        do {
            _ = try await WorkspaceInitPlanner.plan(
                workspaceRoot: root,
                explicitEnvFiles: [outside.path],
                folderOverride: nil,
                agents: []
            )
            Issue.record("Expected outside env file to fail")
        } catch let error as WorkspacePlannerError {
            #expect(error.errorDescription?.contains("Env file must be inside the workspace") == true)
            #expect(error.errorDescription?.contains("Move the file into the workspace") == true)
            #expect(error.errorDescription?.contains("pass a relative path such as --env-file .env") == true)
        }

        do {
            _ = try await WorkspaceInitPlanner.plan(
                workspaceRoot: root,
                explicitEnvFiles: [".env.missing"],
                folderOverride: nil,
                agents: []
            )
            Issue.record("Expected missing env file to fail")
        } catch let error as WorkspacePlannerError {
            #expect(error.errorDescription?.contains("Env file does not exist: .env.missing") == true)
            #expect(error.errorDescription?.contains("Create it first") == true)
            #expect(error.errorDescription?.contains("pass the correct relative path") == true)
            #expect(error.errorDescription?.contains("authsia workspace init --dry-run") == true)
            #expect(error.errorDescription?.contains("authsia workspace update --dry-run") == true)
            #expect(error.errorDescription?.contains("Authsia > Workspace") == true)
        }
    }

    @Test("agent rules are deduplicated before config write")
    func agentRulesAreDeduplicatedBeforeConfigWrite() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let plan = try await WorkspaceInitPlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            folderOverride: nil,
            agents: [.codex, .codex, .claudeCode]
        )

        #expect(plan.agents == [.codex, .claudeCode])
        #expect(plan.config.agents?.rules == ["codex", "claude-code"])
    }

    @Test("workspace init defaults to Claude Code agent rules like app setup")
    func workspaceInitDefaultsToClaudeCodeAgentRulesLikeAppSetup() {
        #expect(Workspace.Init.selectedAgents(allAgents: false, explicitAgents: []) == [.claudeCode])
        #expect(Workspace.Init.selectedAgents(
            allAgents: false,
            explicitAgents: [],
            defaultToClaudeCode: false
        ).isEmpty)
        #expect(Workspace.Init.selectedAgents(allAgents: false, explicitAgents: [.cursor]) == [.cursor])
        #expect(Workspace.Init.selectedAgents(allAgents: true, explicitAgents: []) == AgentTool.allCases)
    }

    @Test("init preview numbers env files and redacts secret values")
    func initPreviewNumbersEnvFilesAndRedactsSecretValues() {
        let secret = DetectedSecret(
            filePath: "/tmp/project/.env",
            lineNumber: 1,
            originalLine: "API_KEY=AUTHSIA_FIXTURE_SECRET_abcdefghijklmnopqrstuvwxyz123456",
            key: "API_KEY",
            value: "AUTHSIA_FIXTURE_SECRET_abcdefghijklmnopqrstuvwxyz123456",
            rawContent: nil,
            confidence: .high,
            type: .password,
            entropy: 5.0,
            description: "API key",
            sshMetadata: nil
        )
        let plan = WorkspaceInitPlan(
            workspaceRoot: URL(fileURLWithPath: "/tmp/project", isDirectory: true),
            config: WorkspaceConfig(
                workspace: WorkspaceConfig.Workspace(name: "project", authsiaFolder: "Workspaces/project"),
                managedEnvFiles: [".env", ".env.local"],
                agents: nil
            ),
            envFiles: [
                WorkspaceEnvFilePlan(
                    relativePath: ".env",
                    absolutePath: "/tmp/project/.env",
                    secrets: [
                        WorkspaceEnvSecretPlan(
                            secret: secret,
                            selectedByDefault: true,
                            replacementLine: "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fproject",
                            conflict: nil
                        ),
                    ],
                    authsiaReferenceCount: 0
                ),
                WorkspaceEnvFilePlan(
                    relativePath: ".env.local",
                    absolutePath: "/tmp/project/.env.local",
                    secrets: [],
                    authsiaReferenceCount: 0
                ),
            ],
            removedEnvFiles: [],
            agents: [],
            missingReferences: [],
            unverifiedReferences: []
        )

        let rendered = Workspace.Init.renderPlan(plan)

        #expect(rendered.contains("- [1] .env: 1 selected secret(s), 0 review item(s)"))
        #expect(rendered.contains("- [2] .env.local: 0 selected secret(s), 0 review item(s)"))
        #expect(rendered.contains("[1.1] [x] API_KEY  type=password  confidence=high"))
        #expect(rendered.contains("store: Workspaces/project/API_KEY"))
        #expect(rendered.contains("reference: API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fproject"))
        #expect(!rendered.contains("sk_live"))
    }

    @Test("init preview guides no-env workspaces to import and bind secrets")
    func initPreviewGuidesNoEnvWorkspacesToImportAndBindSecrets() {
        let plan = WorkspaceInitPlan(
            workspaceRoot: URL(fileURLWithPath: "/tmp/project", isDirectory: true),
            config: WorkspaceConfig(
                workspace: WorkspaceConfig.Workspace(name: "project", authsiaFolder: "Workspaces/project"),
                managedEnvFiles: [],
                agents: nil
            ),
            envFiles: [],
            removedEnvFiles: [],
            agents: [],
            missingReferences: [],
            unverifiedReferences: []
        )

        let rendered = Workspace.Init.renderPlan(plan)

        #expect(rendered.contains("- none found"))
        #expect(rendered.contains("To add secrets later:"))
        #expect(rendered.contains("Clipboard path: copy a secret"))
        #expect(rendered.contains("Save to workspace on to bind it during save"))
        #expect(rendered.contains("CLI path: bind an existing CLI-enabled item"))
        #expect(rendered.contains("authsia workspace env add <NAME> <authsia://...>"))
        #expect(!rendered.contains("Authsia's menu bar clipboard import"))
        #expect(rendered.contains("workspace run and agent commands can receive <NAME> as an env var"))
    }

    @Test("interactive review copy explains clear all select all and confirm")
    func interactiveReviewCopyExplainsClearAllSelectAllAndConfirm() {
        let secret = DetectedSecret(
            filePath: "/tmp/project/.env",
            lineNumber: 1,
            originalLine: "API_KEY=AUTHSIA_FIXTURE_SECRET_abcdefghijklmnopqrstuvwxyz123456",
            key: "API_KEY",
            value: "AUTHSIA_FIXTURE_SECRET_abcdefghijklmnopqrstuvwxyz123456",
            rawContent: nil,
            confidence: .high,
            type: .password,
            entropy: 5.0,
            description: "API key",
            sshMetadata: nil
        )
        let envFile = WorkspaceEnvFilePlan(
            relativePath: ".env",
            absolutePath: "/tmp/project/.env",
            secrets: [
                WorkspaceEnvSecretPlan(
                    secret: secret,
                    selectedByDefault: true,
                    replacementLine: "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fproject",
                    conflict: WorkspaceSecretConflict(
                        itemType: "password",
                        item: "API_KEY",
                        folderPath: "Workspaces/project"
                    )
                ),
            ],
            authsiaReferenceCount: 0
        )

        let rendered = Workspace.Init.renderSecretReview(envFile, fileIndex: 1)
        let instructions = Workspace.Init.secretReviewInstructions

        #expect(rendered.contains("[1.1] [!] API_KEY  type=password  confidence=high"))
        #expect(rendered.contains("existing: password API_KEY in folder Workspaces/project"))
        #expect(rendered.contains("reference: API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fproject"))
        #expect(instructions.contains("Enter=confirm detected secrets"))
        #expect(instructions.contains("a=select all"))
        #expect(instructions.contains("c=clear all"))
        #expect(!rendered.contains("sk_live"))
    }

    @Test("secret review does not auto-create existing item conflicts")
    func secretReviewDoesNotAutoCreateExistingItemConflicts() {
        let secret = workspaceDetectedSecret(key: "API_KEY")
        let envFile = WorkspaceEnvFilePlan(
            relativePath: ".env",
            absolutePath: "/tmp/project/.env",
            secrets: [
                WorkspaceEnvSecretPlan(
                    secret: secret,
                    selectedByDefault: true,
                    replacementLine: "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fproject",
                    conflict: WorkspaceSecretConflict(
                        itemType: "password",
                        item: "API_KEY",
                        folderPath: "Workspaces/project"
                    )
                ),
            ],
            authsiaReferenceCount: 0
        )

        #expect(Workspace.Init.resolveSecretSelections(envFile, answer: "").isEmpty)
        #expect(Workspace.Init.resolveSecretSelections(envFile, answer: "1").isEmpty)
        #expect(Workspace.Init.resolveSecretSelections(envFile, answer: "a").isEmpty)
    }

    @Test("secret review commands clear all and select all detected secrets by default")
    func secretReviewCommandsClearAllAndSelectAllDetectedSecretsByDefault() {
        let high = workspaceDetectedSecret(key: "API_KEY", confidence: .high)
        let medium = workspaceDetectedSecret(key: "MAYBE_TOKEN", confidence: .medium)
        let envFile = WorkspaceEnvFilePlan(
            relativePath: ".env",
            absolutePath: "/tmp/project/.env",
            secrets: [
                WorkspaceEnvSecretPlan(
                    secret: high,
                    selectedByDefault: true,
                    replacementLine: "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fproject",
                    conflict: nil
                ),
                WorkspaceEnvSecretPlan(
                    secret: medium,
                    selectedByDefault: false,
                    replacementLine: "MAYBE_TOKEN=authsia://password/MAYBE_TOKEN/password?folder=Workspaces%2Fproject",
                    conflict: nil
                ),
            ],
            authsiaReferenceCount: 0
        )

        #expect(Workspace.Init.resolveSecretSelections(envFile, answer: "c").isEmpty)
        #expect(Workspace.Init.resolveSecretSelections(envFile, answer: "").map(\.secret.key) == [
            "API_KEY",
            "MAYBE_TOKEN",
        ])
        #expect(Workspace.Init.resolveSecretSelections(envFile, answer: "a").map(\.secret.key) == [
            "API_KEY",
            "MAYBE_TOKEN",
        ])
        #expect(Workspace.Init.resolveSecretSelections(envFile, answer: "h").map(\.secret.key) == ["API_KEY"])
        #expect(Workspace.Init.resolveSecretSelections(envFile, answer: "2").map(\.secret.key) == ["API_KEY"])
        #expect(Workspace.Init.resolveSecretSelections(envFile, answer: "1.2", fileIndex: 1).map(\.secret.key) == [
            "API_KEY",
        ])
    }

    @Test("interactive env file selection confirms all detected review secrets by default")
    func interactiveEnvFileSelectionConfirmsAllDetectedReviewSecretsByDefault() {
        let key = workspaceDetectedSecret(key: "HF_KEY", confidence: .medium, type: .apiKey)
        let token = workspaceDetectedSecret(key: "HF_TOKEN", confidence: .medium, type: .token)
        let envFile = WorkspaceEnvFilePlan(
            relativePath: ".env",
            absolutePath: "/tmp/HumanFirst/.env",
            secrets: [
                WorkspaceEnvSecretPlan(
                    secret: key,
                    selectedByDefault: false,
                    replacementLine: "HF_KEY=authsia://password/HF_KEY/password?folder=Workspaces%2FHumanFirst",
                    conflict: nil
                ),
                WorkspaceEnvSecretPlan(
                    secret: token,
                    selectedByDefault: false,
                    replacementLine: "HF_TOKEN=authsia://password/HF_TOKEN/password?folder=Workspaces%2FHumanFirst",
                    conflict: nil
                ),
            ],
            authsiaReferenceCount: 0
        )

        let selected = Workspace.Init.resolveSecretSelections(envFile, answer: "")

        #expect(selected.map(\.secret.key) == ["HF_KEY", "HF_TOKEN"])
    }
}
