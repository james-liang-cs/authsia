import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
@testable import authsia

@Suite("Workspace config")
struct WorkspaceConfigTests {
    @Test("workspace help exposes update reset guard and agent commands")
    func workspaceHelpExposesUpdateResetGuardAndAgentCommands() {
        let help = Workspace.helpMessage(columns: 160)
        let initHelp = Workspace.Init.helpMessage(columns: 160)
        let updateHelp = Workspace.Update.helpMessage(columns: 160)
        let runHelp = Workspace.Run.helpMessage(columns: 160)
        let syncHelp = Workspace.Sync.helpMessage(columns: 160)
        let guardHelp = Workspace.Guard.helpMessage(columns: 160)
        let agentHelp = Workspace.Agent.helpMessage(columns: 160)
        let resetHelp = Workspace.Reset.helpMessage(columns: 160)

        #expect(help.contains("update"))
        #expect(help.contains("Refresh this repo's Authsia workspace"))
        #expect(help.contains("reset"))
        #expect(help.contains("Remove repo-local Authsia workspace metadata"))
        #expect(help.contains("guard"))
        #expect(help.contains("Prepare an agent-safe guarded terminal"))
        #expect(!help.contains("sessions"))
        #expect(!help.contains("Show safe multi-session workspace commands"))
        #expect(help.contains("agent"))
        #expect(help.contains("Open or print a secret-free AI tool launch"))
        #expect(help.contains("env"))
        #expect(help.contains("Manage workspace env bindings"))
        #expect(help.contains("sync"))
        #expect(help.contains("Reconcile workspace vault folder and env bindings"))
        #expect(!help.contains("forget"))
        #expect(initHelp.contains("--recursive-env"))
        #expect(initHelp.contains("--plan-json"))
        #expect(initHelp.contains("--local-preview"))
        #expect(initHelp.contains("--apply-json"))
        #expect(updateHelp.contains("--recursive-env"))
        #expect(updateHelp.contains("--plan-json"))
        #expect(updateHelp.contains("--local-preview"))
        #expect(updateHelp.contains("--apply-json"))
        #expect(agentHelp.contains("--tool"))
        #expect(agentHelp.contains("--dry-run"))
        #expect(agentHelp.contains("--print"))
        #expect(runHelp.contains("--shell"))
        #expect(syncHelp.contains("--plan-json"))
        #expect(syncHelp.contains("--apply-json"))
        #expect(guardHelp.contains("--dry-run"))
        #expect(guardHelp.contains("--print-env"))
        #expect(guardHelp.contains("--auto"))
        #expect(guardHelp.contains("--tool"))
        #expect(guardHelp.contains("curl $API_KEY"))
        #expect(resetHelp.contains("--yes"))
    }

    @Test("workspace help includes examples for every workspace subcommand")
    func workspaceHelpIncludesExamplesForEveryWorkspaceSubcommand() {
        let helpMessages: [(String, String, [String])] = [
            (
                "workspace",
                Workspace.helpMessage(columns: 160),
                [
                    "authsia workspace init --env-file .env --agent codex",
                    "authsia workspace run -- npm test",
                    "authsia workspace env add API_KEY authsia://api-key/API_KEY/key",
                ]
            ),
            (
                "workspace init",
                Workspace.Init.helpMessage(columns: 160),
                [
                    "authsia workspace init --dry-run --recursive-env",
                    "authsia workspace init --yes --env-file .env --folder Workspaces/api",
                    "authsia workspace init --plan-json",
                ]
            ),
            (
                "workspace update",
                Workspace.Update.helpMessage(columns: 160),
                [
                    "authsia workspace update --dry-run --recursive-env",
                    "authsia workspace update --yes --env-file .env.local",
                    "authsia workspace update --plan-json",
                ]
            ),
            (
                "workspace reset",
                Workspace.Reset.helpMessage(columns: 160),
                [
                    "authsia workspace reset --dry-run",
                    "authsia workspace reset --yes",
                ]
            ),
            (
                "workspace run",
                Workspace.Run.helpMessage(columns: 160),
                [
                    "authsia workspace run -- npm test",
                    "authsia workspace run --env-file .env.local -- python scripts/deploy.py",
                    "authsia workspace run --shell \"npm run build && npm test\"",
                ]
            ),
            (
                "workspace status",
                Workspace.Status.helpMessage(columns: 160),
                [
                    "authsia workspace status",
                    "authsia workspace status --format json",
                ]
            ),
            (
                "workspace sync",
                Workspace.Sync.helpMessage(columns: 160),
                [
                    "authsia workspace sync --dry-run",
                    "authsia workspace sync --plan-json",
                    "authsia workspace sync --apply-json workspace-sync-selection.json",
                ]
            ),
            (
                "workspace guard",
                Workspace.Guard.helpMessage(columns: 160),
                [
                    "authsia workspace guard --dry-run",
                    "eval \"$(authsia workspace guard --print-env)\"",
                    "authsia workspace guard --print-env --auto",
                ]
            ),
            (
                "workspace agent",
                Workspace.Agent.helpMessage(columns: 160),
                [
                    "authsia workspace agent --tool codex --print",
                    "authsia workspace agent --tool cursor --dry-run",
                    "authsia workspace agent --tool claude-code --goal-file task.txt",
                ]
            ),
            (
                "workspace env",
                Workspace.Env.helpMessage(columns: 160),
                [
                    "authsia workspace env list",
                    "authsia workspace env add API_KEY authsia://api-key/API_KEY/key",
                    "authsia workspace env validate",
                ]
            ),
        ]

        for (command, help, examples) in helpMessages {
            #expect(help.contains("Examples:"), "\(command) help should include an Examples section")
            for example in examples {
                #expect(help.contains(example), "\(command) help should include example: \(example)")
            }
        }
    }

    @Test("workspace local preview flag parses for setup and update")
    func workspaceLocalPreviewFlagParsesForSetupAndUpdate() throws {
        let initCommand = try Workspace.Init.parse(["--plan-json", "--local-preview"])
        let updateCommand = try Workspace.Update.parse(["--plan-json", "--local-preview"])

        #expect(initCommand.planJson)
        #expect(initCommand.localPreview)
        #expect(updateCommand.planJson)
        #expect(updateCommand.localPreview)
    }

    @Test("workspace env subcommand help includes concrete examples")
    func workspaceEnvSubcommandHelpIncludesConcreteExamples() {
        let helpMessages: [(String, String, [String])] = [
            (
                "workspace env list",
                Workspace.Env.List.helpMessage(columns: 160),
                ["authsia workspace env list"]
            ),
            (
                "workspace env add",
                Workspace.Env.Add.helpMessage(columns: 160),
                [
                    "authsia workspace env add API_KEY authsia://api-key/API_KEY/key",
                    "authsia workspace env add DB_PASSWORD authsia://password/DB_PASSWORD/password?folder=Workspaces%2Fapi",
                ]
            ),
            (
                "workspace env remove",
                Workspace.Env.Remove.helpMessage(columns: 160),
                ["authsia workspace env remove API_KEY"]
            ),
            (
                "workspace env validate",
                Workspace.Env.Validate.helpMessage(columns: 160),
                ["authsia workspace env validate"]
            ),
        ]

        for (command, help, examples) in helpMessages {
            #expect(help.contains("Examples:"), "\(command) help should include an Examples section")
            for example in examples {
                #expect(help.contains(example), "\(command) help should include example: \(example)")
            }
        }
        #expect(
            Workspace.Env.Validate.helpMessage(columns: 160)
                .contains("Validate the active workspace environment against Authsia")
        )
    }

    @Test("store writes commit-safe relative config")
    func storeWritesCommitSafeRelativeConfig() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env", ".env.local"],
            agents: WorkspaceConfig.Agents(rules: ["codex", "claude-code"])
        )

        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let raw = try read(".authsia/workspace.json", in: root)
        #expect(raw.contains("\"schemaVersion\" : 1"))
        #expect(raw.contains("\"authsiaFolder\" : \"Workspaces/api\""))
        #expect(!raw.contains(root.path))
        let loaded = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        #expect(loaded == config)
    }

    @Test("store normalizes workspace folder under Workspaces")
    func storeNormalizesWorkspaceFolderUnderWorkspaces() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Team/API"),
            managedEnvFiles: [],
            agents: nil
        )

        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let raw = try read(".authsia/workspace.json", in: root)
        let loaded = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        #expect(raw.contains("\"authsiaFolder\" : \"Workspaces/Team/API\""))
        #expect(loaded.workspace.authsiaFolder == "Workspaces/Team/API")
    }

    @Test("store exposes schema v2 while preserving v1 until explicit migration")
    func storePreservesV1UntilExplicitMigration() throws {
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: WorkspaceConfig.Agents(rules: ["codex"])
        )

        let preserved = try WorkspaceConfigStore.migrateToCurrentSchema(config)
        let migrated = WorkspaceConfigStore.migratedToV2(config)

        #expect(WorkspaceConfigStore.currentSchemaVersion == 2)
        #expect(preserved == config)
        #expect(migrated.schemaVersion == WorkspaceConfigStore.currentSchemaVersion)
    }

    @Test("schema v2 accepts duplicate binding names while schema v1 rejects them")
    func schemaV2AcceptsDuplicateBindingNames() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let bindings = [
            WorkspaceConfig.EnvBinding(name: "DATABASE_URL", reference: "authsia://api-key/one/key"),
            WorkspaceConfig.EnvBinding(name: "DATABASE_URL", reference: "authsia://api-key/two/key"),
        ]
        let workspace = WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api")

        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.write(
                WorkspaceConfig(schemaVersion: 1, workspace: workspace, managedEnvFiles: [], agents: nil, envBindings: bindings),
                toWorkspaceRoot: root
            )
        }
        try WorkspaceConfigStore.write(
            WorkspaceConfig(schemaVersion: 2, workspace: workspace, managedEnvFiles: [], agents: nil, envBindings: bindings),
            toWorkspaceRoot: root
        )
        let loaded = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        #expect(loaded.schemaVersion == 2)
        #expect(loaded.envBindings.count == 2)
    }

    @Test("store writes commit-safe workspace env bindings")
    func storeWritesCommitSafeWorkspaceEnvBindings() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(
                    name: "HF_TOKEN",
                    reference: "authsia://password/HF_TOKEN/password?folder=Workspaces%2Fapi"
                ),
            ]
        )

        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let raw = try read(".authsia/workspace.json", in: root)
        #expect(raw.contains("\"envBindings\""))
        #expect(!raw.contains("<concealed by authsia>"))
        let loaded = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        #expect(loaded.envBindings == config.envBindings)
    }

    @Test("store decodes legacy workspace config without env bindings")
    func storeDecodesLegacyWorkspaceConfigWithoutEnvBindings() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        try Data(
            """
            {
              "schemaVersion": 1,
              "workspace": {
                "name": "api",
                "authsiaFolder": "Workspaces/api"
              },
              "managedEnvFiles": [],
              "agents": null
            }
            """.utf8
        ).write(to: root.appendingPathComponent(".authsia/workspace.json"), options: .atomic)

        let config = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)

        #expect(config.envBindings.isEmpty)
        #expect(config.guardSettings.autoTabs)
        #expect(config.guardSettings.responseMode == .observe)
    }

    @Test("store writes guarded terminal auto tab setting")
    func storeWritesGuardedTerminalAutoTabSetting() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            guardSettings: WorkspaceConfig.GuardSettings(autoTabs: false)
        )

        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let raw = try read(".authsia/workspace.json", in: root)
        #expect(raw.contains("\"guard\""))
        #expect(raw.contains("\"autoTabs\" : false"))
        let loaded = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        #expect(!loaded.guardSettings.autoTabs)
    }

    @Test("store rejects invalid workspace env bindings")
    func storeRejectsInvalidWorkspaceEnvBindings() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let invalidName = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(name: "BAD-NAME", reference: "authsia://password/API/password"),
            ]
        )
        let invalidReference = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(name: "API_KEY", reference: "plain-value"),
            ]
        )

        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.write(invalidName, toWorkspaceRoot: root)
        }
        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.write(invalidReference, toWorkspaceRoot: root)
        }
    }

    @Test("store rejects unsupported schema with recovery guidance")
    func storeRejectsUnsupportedSchemaWithRecoveryGuidance() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        try """
        {
          "schemaVersion": 3,
          "workspace": {
            "name": "api",
            "authsiaFolder": "Workspaces/api"
          },
          "managedEnvFiles": [".env"],
          "agents": {
            "rules": ["codex"]
          }
        }
        """.write(
            to: root.appendingPathComponent(".authsia/workspace.json"),
            atomically: true,
            encoding: .utf8
        )

        do {
            _ = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
            Issue.record("Expected unsupported schema error")
        } catch let error as WorkspaceConfigError {
            #expect(error == .unsupportedSchema(3))
            #expect(error.errorDescription?.contains("supports schema version 2") == true)
            #expect(error.errorDescription?.contains("Update Authsia") == true)
            #expect(error.errorDescription?.contains("authsia workspace update") == true)
        }
    }

    @Test("store rejects invalid workspace config with recovery guidance")
    func storeRejectsInvalidWorkspaceConfigWithRecoveryGuidance() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        try "{ not json".write(
            to: root.appendingPathComponent(".authsia/workspace.json"),
            atomically: true,
            encoding: .utf8
        )

        do {
            _ = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
            Issue.record("Expected invalid workspace config error")
        } catch let error as WorkspaceConfigError {
            #expect(error == .invalidConfigFile)
            #expect(error.errorDescription?.contains(".authsia/workspace.json") == true)
            #expect(error.errorDescription?.contains("Fix the JSON") == true)
            #expect(error.errorDescription?.contains("restore it from version control") == true)
            #expect(error.errorDescription?.contains("remove it and run `authsia workspace init`") == true)
        }
    }

    @Test("store rejects invalid workspace fields with recovery guidance")
    func storeRejectsInvalidWorkspaceFieldsWithRecoveryGuidance() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        try """
        {
          "schemaVersion": 1,
          "workspace": {
            "name": "",
            "authsiaFolder": "Workspaces/api"
          },
          "managedEnvFiles": [".env"],
          "agents": null
        }
        """.write(
            to: root.appendingPathComponent(".authsia/workspace.json"),
            atomically: true,
            encoding: .utf8
        )

        do {
            _ = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
            Issue.record("Expected invalid workspace field error")
        } catch let error as WorkspaceConfigError {
            #expect(error == .emptyWorkspaceName)
            #expect(error.errorDescription?.contains("Workspace name cannot be empty.") == true)
            #expect(error.errorDescription?.contains("Fix .authsia/workspace.json") == true)
            #expect(error.errorDescription?.contains("restore it from version control") == true)
            #expect(error.errorDescription?.contains("remove it and run `authsia workspace init`") == true)
        }
    }

    @Test("missing workspace config guidance names folder setup and app setup")
    func missingWorkspaceConfigGuidanceNamesFolderSetupAndAppSetup() {
        let message = WorkspaceConfigError.missingConfig.errorDescription ?? ""

        #expect(message.contains("this folder or its parents"))
        #expect(message.contains("authsia workspace init"))
        #expect(message.contains("project root"))
        #expect(message.contains("Authsia > Workspace"))
        #expect(message.contains(".authsia/workspace.json"))
        #expect(!message.contains("Run: authsia workspace init"))
    }

    @Test("store rejects absolute managed env files")
    func storeRejectsAbsoluteManagedEnvFiles() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [root.appendingPathComponent(".env").path],
            agents: nil
        )

        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        }
    }
}

@Suite("Workspace root resolver")
struct WorkspaceRootResolverTests {
    @Test("finds workspace config in ancestor")
    func findsWorkspaceConfigInAncestor() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        try "{}".write(
            to: root.appendingPathComponent(".authsia/workspace.json"),
            atomically: true,
            encoding: .utf8
        )
        let nested = root.appendingPathComponent("Sources/App", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)

        let resolved = WorkspaceRootResolver.findWorkspaceRoot(startingAt: nested)

        #expect(resolved == root)
    }

    @Test("init root falls back to git root")
    func initRootFallsBackToGitRoot() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".git"),
            withIntermediateDirectories: true
        )
        let nested = root.appendingPathComponent("Sources/App", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)

        let resolved = WorkspaceRootResolver.resolveInitRoot(startingAt: nested)

        #expect(resolved == root)
    }

    @Test("flags existing nested workspace when init targets a different root")
    func flagsExistingNestedWorkspaceWhenInitTargetsDifferentRoot() throws {
        let gitRoot = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: gitRoot) }
        let nested = gitRoot.appendingPathComponent("packages/api", isDirectory: true)
        try FileManager.default.createDirectory(
            at: nested.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        try "{}".write(
            to: nested.appendingPathComponent(".authsia/workspace.json"),
            atomically: true,
            encoding: .utf8
        )

        let conflict = WorkspaceRootResolver.conflictingExistingWorkspaceRoot(
            startingAt: nested,
            initRoot: gitRoot
        )

        #expect(conflict?.standardizedFileURL == nested.standardizedFileURL)
    }

    @Test("existing workspace conflict guidance names dry run and explicit env file yes retry")
    func existingWorkspaceConflictGuidanceNamesDryRunAndExplicitEnvFileYesRetry() {
        let existingRoot = URL(fileURLWithPath: "/tmp/app/packages/api", isDirectory: true)
        let initRoot = URL(fileURLWithPath: "/tmp/app", isDirectory: true)

        let message = Workspace.Init.existingWorkspaceConflictMessage(
            existingRoot: existingRoot,
            initRoot: initRoot
        )

        #expect(message.contains("An Authsia workspace already exists at /tmp/app/packages/api"))
        #expect(message.contains("Re-run from /tmp/app/packages/api to update it"))
        #expect(message.contains("authsia workspace init --dry-run"))
        #expect(message.contains("authsia workspace init --yes --env-file <path>"))
        #expect(!message.contains("pass --yes to create a separate workspace"))
    }

    @Test("no conflict when existing workspace is at the init root")
    func noConflictWhenExistingWorkspaceIsAtInitRoot() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        try "{}".write(
            to: root.appendingPathComponent(".authsia/workspace.json"),
            atomically: true,
            encoding: .utf8
        )

        let conflict = WorkspaceRootResolver.conflictingExistingWorkspaceRoot(
            startingAt: root,
            initRoot: root
        )

        #expect(conflict == nil)
    }

    @Test("no conflict when no existing workspace is present")
    func noConflictWhenNoExistingWorkspaceIsPresent() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let nested = root.appendingPathComponent("Sources/App", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)

        let conflict = WorkspaceRootResolver.conflictingExistingWorkspaceRoot(
            startingAt: nested,
            initRoot: root
        )

        #expect(conflict == nil)
    }
}

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

@Suite("Workspace update planner")
struct WorkspaceUpdatePlannerTests {
    @Test("update scopes unscoped named bindings to the workspace folder")
    func updateScopesUnscopedNamedBindingsToWorkspaceFolder() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let uuidReference = "authsia://password/00000000-0000-0000-0000-000000000001/password"
        let externalReference = "authsia://password/Shared/password?folder=Shared"
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                .init(name: "API_KEY", reference: "authsia://api-key/API_KEY/key"),
                .init(name: "SHARED_PASSWORD", reference: externalReference),
                .init(name: "UUID_PASSWORD", reference: uuidReference),
            ]
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let plan = try await WorkspaceUpdatePlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            agents: []
        )

        #expect(plan.config.envBindings.map(\.reference) == [
            "authsia://api-key/API_KEY/key?folder=Workspaces%2Fapi",
            externalReference,
            uuidReference,
        ])
    }

    @Test("update reuses config and merges explicit env files")
    func updateReusesConfigAndMergesExplicitEnvFiles() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: WorkspaceConfig.Agents(rules: ["codex"])
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        try "NEW_PASSWORD=plain_password_abcdefghijklmnopqrstuvwxyz123456\n".write(
            to: root.appendingPathComponent(".env.local"),
            atomically: true,
            encoding: .utf8
        )

        let plan = try await WorkspaceUpdatePlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [".env.local"],
            agents: [.codex, .claudeCode]
        )

        #expect(plan.config.workspace == config.workspace)
        #expect(plan.config.managedEnvFiles == [".env", ".env.local"])
        #expect(plan.config.agents?.rules == ["codex", "claude-code"])
        #expect(plan.envFiles.map(\.relativePath) == [".env", ".env.local"])
        #expect(plan.envFiles.first?.authsiaReferenceCount == 1)
        let password = try #require(plan.envFiles.last?.secrets.first { $0.secret.key == "NEW_PASSWORD" })
        #expect(password.selectedByDefault)
    }

    @Test("update removes missing managed env files from config preview")
    func updateRemovesMissingManagedEnvFilesFromConfigPreview() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env", ".env.local"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "PORT=3000\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )

        let plan = try await WorkspaceUpdatePlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            agents: []
        )
        let rendered = Workspace.Init.renderPlan(plan)

        #expect(plan.config.managedEnvFiles == [".env"])
        #expect(plan.envFiles.map(\.relativePath) == [".env"])
        #expect(plan.removedEnvFiles == [".env.local"])
        #expect(rendered.contains("Removed managed env files:"))
        #expect(rendered.contains("- .env.local"))
    }

    @Test("native update can replace existing agent rules with exact selection")
    func nativeUpdateCanReplaceExistingAgentRulesWithExactSelection() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: WorkspaceConfig.Agents(rules: ["codex", "claude-code"])
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let plan = try await WorkspaceUpdatePlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            agents: [.codex],
            mergeExistingAgents: false
        )

        #expect(plan.config.agents?.rules == ["codex"])
        #expect(plan.agents == [.codex])
    }

    @Test("update previews existing item conflicts and keeps yes conservative")
    func updatePreviewsExistingItemConflictsAndKeepsYesConservative() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "DB_PASSWORD=plain_password_conflictabcdefghijklmnopqrstuvwxyz123456\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                password(id: "00000000-0000-0000-0000-000000000001", name: "DB_PASSWORD", folderPath: "Workspaces/api"),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let plan = try await WorkspaceUpdatePlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [".env"],
            agents: [],
            vaultIndex: WorkspaceVaultIndex(payload: payload)
        )
        let secretPlan = try #require(plan.envFiles.first?.secrets.first)
        let selectedSecrets = try WorkspaceUpdatePlanner.defaultSelectedSecretsForExplicitEnvFiles(
            plan: plan,
            explicitEnvFiles: [".env"]
        )
        let rendered = Workspace.Init.renderPlan(plan)

        #expect(secretPlan.conflict?.item == "DB_PASSWORD")
        #expect(secretPlan.selectedByDefault == false)
        #expect(selectedSecrets.isEmpty)
        #expect(rendered.contains("existing: password DB_PASSWORD in folder Workspaces/api"))
        #expect(!rendered.contains("plain_password_conflict"))
    }

    @Test("non-interactive update selects secrets only from explicit env files")
    func nonInteractiveUpdateSelectsSecretsOnlyFromExplicitEnvFiles() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "EXISTING_PASSWORD=plain_password_existingabcdefghijklmnopqrstuvwxyz123456\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        try "NEW_PASSWORD=plain_password_newabcdefghijklmnopqrstuvwxyz123456\n".write(
            to: root.appendingPathComponent(".env.local"),
            atomically: true,
            encoding: .utf8
        )

        let plan = try await WorkspaceUpdatePlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [".env.local"],
            agents: []
        )
        let selectedSecrets = try WorkspaceUpdatePlanner.defaultSelectedSecretsForExplicitEnvFiles(
            plan: plan,
            explicitEnvFiles: [".env.local"]
        )

        #expect(plan.config.managedEnvFiles == [".env", ".env.local"])
        #expect(selectedSecrets.map(\.key) == ["NEW_PASSWORD"])
    }

    @Test("default update merges discovered package env files up to three nested directories")
    func defaultUpdateMergesDiscoveredPackageEnvFilesUpToThreeNestedDirectories() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        try writeNestedFile(
            "APP_PASSWORD=plain_password_appabcdefghijklmnopqrstuvwxyz123456\n",
            relativePath: "apps/api/.env",
            in: root
        )
        try writeNestedFile(
            "WORKER_PASSWORD=plain_password_workerabcdefghijklmnopqrstuvwxyz123456\n",
            relativePath: "services/worker/config/.env.local",
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

        let plan = try await WorkspaceUpdatePlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            agents: []
        )

        #expect(plan.config.managedEnvFiles == [
            ".env",
            "apps/api/.env",
            "services/worker/config/.env.local",
        ])
        #expect(plan.envFiles.map(\.relativePath).contains("apps/api/.env"))
        #expect(plan.envFiles.map(\.relativePath).contains("services/worker/config/.env.local"))
        #expect(!plan.envFiles.map(\.relativePath).contains("services/worker/config/deep/.env"))
        let nestedSecret = try #require(plan.envFiles.first { $0.relativePath == "apps/api/.env" }?.secrets.first {
            $0.secret.key == "APP_PASSWORD"
        })
        let workerSecret = try #require(
            plan.envFiles.first { $0.relativePath == "services/worker/config/.env.local" }?.secrets.first {
                $0.secret.key == "WORKER_PASSWORD"
            }
        )
        #expect(nestedSecret.selectedByDefault)
        #expect(workerSecret.selectedByDefault)
    }

    @Test("update preview warns when authsia refs cannot be validated against the vault")
    func updatePreviewWarnsWhenVaultReferencesCannotBeValidated() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try """
        API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi
        """.write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )

        let plan = try await WorkspaceUpdatePlanner.plan(
            workspaceRoot: root,
            explicitEnvFiles: [],
            agents: [],
            vaultIndex: nil
        )
        let rendered = Workspace.Init.renderPlan(plan)

        #expect(plan.unverifiedReferences.map(\.item) == ["API_KEY"])
        #expect(rendered.contains("Unverified Authsia references:"))
        #expect(rendered.contains("password API_KEY in folder Workspaces/api"))
        #expect(rendered.contains("Open Authsia or run `authsia list passwords`, then rerun this command"))
        #expect(rendered.contains("If Authsia reports it cannot read the Keychain, open Authsia once"))
        #expect(rendered.contains("If an item is missing, restore the raw value"))
        #expect(!rendered.contains("Missing Authsia references:"))
    }
}

@Suite("Agent rule installer")
struct AgentRuleInstallerTests {
    @Test("agent rules describe only selected agent platforms")
    func agentRulesDescribeOnlySelectedAgentPlatforms() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])

        let agentsRules = try read("AGENTS.md", in: root)
        let sharedRules = try read(".authsia/agent-rules.md", in: root)
        for rules in [agentsRules, sharedRules] {
            #expect(rules.contains("AUTHSIA_AGENT_PLATFORM=codex"))
            #expect(rules.contains(
                "Before running an Authsia command, use the full command's `-h` help " +
                    "to confirm its arguments and options."
            ))
            #expect(!rules.contains("AUTHSIA_AGENT_PLATFORM=<claude-code|codex|cursor|windsurf|copilot>"))
            #expect(!rules.contains("AUTHSIA_AGENT_PLATFORM=claude-code"))
            #expect(!rules.contains("AUTHSIA_AGENT_PLATFORM=cursor"))
            #expect(!rules.contains("AUTHSIA_AGENT_PLATFORM=windsurf"))
            #expect(!rules.contains("AUTHSIA_AGENT_PLATFORM=copilot"))
            #expect(!rules.contains("Every GitHub Copilot Authsia terminal command"))
        }
    }
}

@Suite("Workspace reset planner")
struct WorkspaceResetPlannerTests {
    @Test("reset dry-run previews config env files and rule artifacts")
    func resetDryRunPreviewsConfigEnvFilesAndRuleArtifacts() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env", ".env.local"],
            agents: WorkspaceConfig.Agents(rules: ["codex"])
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])

        let plan = try await WorkspaceResetPlanner.plan(workspaceRoot: root)
        let rendered = WorkspaceResetPlanner.renderDryRun(plan)

        #expect(rendered.contains("Remove workspace config: .authsia/workspace.json"))
        #expect(rendered.contains("- .env: keep file, 1 authsia refs"))
        #expect(rendered.contains("- .env.local: missing"))
        #expect(rendered.contains("Agent rule artifacts:"))
        #expect(rendered.contains(".authsia/agent-rules.md"))
        #expect(rendered.contains("AGENTS.md"))
        #expect(rendered.contains("Env file restore:"))
        #expect(rendered.contains("- .env: restore from Authsia scrape backup"))
        #expect(!rendered.contains("Env file rollback is not automatic"))
        #expect(!rendered.contains("authsia scrape --revert .env"))
    }

    @Test("reset apply removes config and managed agent artifacts")
    func resetApplyRemovesConfigAndManagedAgentArtifacts() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: WorkspaceConfig.Agents(rules: ["codex"])
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "PORT=3000\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])

        let plan = try await WorkspaceResetPlanner.plan(workspaceRoot: root)
        let result = try await WorkspaceResetPlanner.apply(plan)

        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        }
        #expect(FileManager.default.fileExists(atPath: root.appendingPathComponent(".env").path))
        #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent(".authsia/agent-rules.md").path))
        #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent("AGENTS.md").path))
        #expect(result.removed.contains(".authsia/workspace.json"))
    }

    @Test("reset removes merged Claude settings while preserving custom values")
    func resetApplyStructurallyRemovesMergedClaudeSettings() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: WorkspaceConfig.Agents(rules: ["claude-code"])
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "PORT=3000\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        try writeNestedFile("""
        {
          "customTopLevel": "preserve",
          "hooks": {
            "PreToolUse": [
              {
                "matcher": "Bash",
                "hooks": [
                  {
                    "type": "command",
                    "command": "echo custom"
                  }
                ]
              }
            ]
          },
          "sandbox": {
            "network": {
              "allowMachLookup": [
                "Custom.Service"
              ],
              "allowUnixSockets": [
                "~/custom.sock"
              ]
            }
          }
        }
        """, relativePath: ".claude/settings.local.json", in: root)
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])

        let plan = try await WorkspaceResetPlanner.plan(workspaceRoot: root)
        #expect(plan.agentRemoval.updated.contains(".claude/settings.local.json"))
        #expect(plan.agentRemoval.manualSteps.isEmpty)
        let result = try await WorkspaceResetPlanner.apply(plan)

        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        }
        #expect(FileManager.default.fileExists(atPath: root.appendingPathComponent(".env").path))
        let settingsURL = root.appendingPathComponent(".claude/settings.local.json")
        #expect(FileManager.default.fileExists(atPath: settingsURL.path))
        let settings = try String(contentsOf: settingsURL, encoding: .utf8)
        let settingsObject = try #require(
            JSONSerialization.jsonObject(with: Data(settings.utf8)) as? [String: Any]
        )
        #expect(settingsObject["customTopLevel"] as? String == "preserve")
        let hooks = try #require(settingsObject["hooks"] as? [String: Any])
        let preToolUse = try #require(hooks["PreToolUse"] as? [[String: Any]])
        let bash = try #require(preToolUse.first { $0["matcher"] as? String == "Bash" })
        #expect((bash["hooks"] as? [[String: Any]])?.contains {
            $0["command"] as? String == "echo custom"
        } == true)
        let sandbox = try #require(settingsObject["sandbox"] as? [String: Any])
        let network = try #require(sandbox["network"] as? [String: Any])
        #expect((network["allowMachLookup"] as? [String]) == ["Custom.Service"])
        #expect((network["allowUnixSockets"] as? [String]) == ["~/custom.sock"])
        #expect(!settings.contains("authsia agent record-command --platform claude-code --source hook"))
        #expect(!settings.contains("Authsia.Bridge"))
        #expect(!settings.contains("Authsia.SSHAgent"))
        #expect(!settings.contains("~/.authsia/agent.sock"))
        #expect(result.updated.contains(".claude/settings.local.json"))
        #expect(result.manualSteps.isEmpty)
        #expect(result.removed.contains(".authsia/workspace.json"))
    }

    @Test("reset removes generated Claude settings after repeated install")
    func resetRemovesGeneratedClaudeSettingsAfterRepeatedInstall() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: WorkspaceConfig.Agents(rules: ["claude-code"])
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])

        let plan = try await WorkspaceResetPlanner.plan(workspaceRoot: root)
        #expect(plan.agentRemoval.removed.contains(".claude/settings.local.json"))
        let result = try await WorkspaceResetPlanner.apply(plan)

        #expect(!FileManager.default.fileExists(
            atPath: root.appendingPathComponent(".claude/settings.local.json").path
        ))
        #expect(result.removed.contains(".claude/settings.local.json"))
        #expect(!result.updated.contains(".claude/settings.local.json"))
        #expect(result.manualSteps.isEmpty)
    }

    @Test("reset apply restores managed env files from scrape backups before removing workspace metadata")
    func resetApplyRestoresManagedEnvFilesFromScrapeBackups() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        let envFile = root.appendingPathComponent(".env")
        let originalContent = "API_KEY=real-secret-value\n"
        try originalContent.write(to: envFile, atomically: true, encoding: .utf8)
        let vaultClient = WorkspaceResetBackupVaultClient()
        let backupService = BackupService(
            bridgeClient: vaultClient,
            dateProvider: { Date(timeIntervalSince1970: 1_767_266_400) },
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )
        _ = try await backupService.createBackup(
            of: envFile.path,
            originalContent: originalContent,
            description: "workspace setup"
        )
        try "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi\n".write(
            to: envFile,
            atomically: true,
            encoding: .utf8
        )

        let plan = try await WorkspaceResetPlanner.plan(workspaceRoot: root)
        let result = try await WorkspaceResetPlanner.apply(plan, backupService: backupService)

        #expect(try String(contentsOf: envFile, encoding: .utf8) == originalContent)
        #expect(result.restoredEnvFiles.contains(".env"))
        #expect(result.removed.contains(".authsia/workspace.json"))
        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        }
    }

    @Test("reset apply warns but continues when an env backup is missing")
    func resetApplyWarnsButContinuesWhenEnvBackupIsMissing() async throws {
        let root = try makeResetRootWithManagedEnvFile()
        defer { try? FileManager.default.removeItem(at: root) }
        let envFile = root.appendingPathComponent(".env")
        let authsiaReferenceContent = try String(contentsOf: envFile, encoding: .utf8)
        let backupService = BackupService(
            bridgeClient: WorkspaceResetBackupVaultClient(),
            machineIdentity: MachineIdentity(machineId: "MACHINE-A", hostname: "test-mac.local")
        )

        let plan = try await WorkspaceResetPlanner.plan(workspaceRoot: root, backupService: backupService)
        let result = try await WorkspaceResetPlanner.apply(plan, backupService: backupService)
        let rendered = WorkspaceResetPlanner.renderApplyResult(result)

        #expect(try String(contentsOf: envFile, encoding: .utf8) == authsiaReferenceContent)
        #expect(result.restoredEnvFiles.isEmpty)
        #expect(result.warnings.contains {
            $0.contains(".env") && $0.contains("No backup found")
        })
        #expect(result.removed.contains(".authsia/workspace.json"))
        #expect(rendered.contains("Warnings:"))
        #expect(rendered.contains(".env"))
        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        }
    }

    @Test("reset planner requires existing config")
    func resetPlannerRequiresExistingConfig() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        await #expect(throws: WorkspaceConfigError.self) {
            try await WorkspaceResetPlanner.plan(workspaceRoot: root)
        }
    }

    @Test("reset preview rethrows when the vault approval is denied")
    func resetPreviewRethrowsOnApprovalDenial() async throws {
        let root = try makeResetRootWithManagedEnvFile()
        defer { try? FileManager.default.removeItem(at: root) }
        let backupService = BackupService(
            bridgeClient: WorkspaceResetDenyingVaultClient(
                error: BridgeClientError.bridgeError(code: "notAuthorized", message: "Access denied", query: nil)
            )
        )

        await #expect(throws: BridgeClientError.self) {
            try await WorkspaceResetPlanner.plan(workspaceRoot: root, backupService: backupService)
        }
    }

    @Test("reset preview captures restore error when the vault is unavailable")
    func resetPreviewCapturesRestoreErrorWhenUnavailable() async throws {
        let root = try makeResetRootWithManagedEnvFile()
        defer { try? FileManager.default.removeItem(at: root) }
        let backupService = BackupService(
            bridgeClient: WorkspaceResetDenyingVaultClient(
                error: BridgeClientError.bridgeError(code: "appUnavailable", message: "locked", query: nil)
            )
        )

        let plan = try await WorkspaceResetPlanner.plan(workspaceRoot: root, backupService: backupService)
        let envFile = try #require(plan.envFiles.first { $0.relativePath == ".env" })
        #expect(envFile.restoreError != nil)
    }

    @Test("orphaned env files list files with refs that cannot be restored")
    func orphanedEnvFilesListUnrestorableFiles() async throws {
        let root = try makeResetRootWithManagedEnvFile()
        defer { try? FileManager.default.removeItem(at: root) }
        let backupService = BackupService(
            bridgeClient: WorkspaceResetDenyingVaultClient(
                error: BridgeClientError.bridgeError(code: "appUnavailable", message: "locked", query: nil)
            )
        )

        let plan = try await WorkspaceResetPlanner.plan(workspaceRoot: root, backupService: backupService)

        #expect(plan.orphanedEnvFiles.map(\.relativePath) == [".env"])
    }

    @Test("dry run warns loudly when reset would orphan env files")
    func dryRunWarnsWhenResetWouldOrphanEnvFiles() async throws {
        let root = try makeResetRootWithManagedEnvFile()
        defer { try? FileManager.default.removeItem(at: root) }
        let backupService = BackupService(
            bridgeClient: WorkspaceResetDenyingVaultClient(
                error: BridgeClientError.bridgeError(code: "appUnavailable", message: "locked", query: nil)
            )
        )

        let plan = try await WorkspaceResetPlanner.plan(workspaceRoot: root, backupService: backupService)
        let rendered = WorkspaceResetPlanner.renderDryRun(plan)

        #expect(rendered.contains("WARNING"))
        #expect(rendered.contains("unusable authsia:// references"))
        #expect(rendered.contains(".env"))
    }
}

private func makeResetRootWithManagedEnvFile() throws -> URL {
    let root = try makeWorkspaceRoot()
    let config = WorkspaceConfig(
        workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
        managedEnvFiles: [".env"],
        agents: nil
    )
    try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
    try "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi\n".write(
        to: root.appendingPathComponent(".env"),
        atomically: true,
        encoding: .utf8
    )
    return root
}

@Suite("Workspace run planner")
struct WorkspaceRunPlannerTests {
    static let humanShimAncestry: [AgenticProcessReference] = [
        AgenticProcessReference(processName: "python3", bundleIdentifier: nil),
        AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
        AgenticProcessReference(processName: "codex", bundleIdentifier: nil),
    ]

    @Test("guarded shim passes through outside any Authsia workspace")
    func guardedShimPassesThroughOutsideWorkspace() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-outside-workspace-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        var environment = ProcessInfo.processInfo.environment
        environment[WorkspaceGuardedTerminal.shimInvocationEnvironmentName] = "1"
        environment["AUTHSIA_WORKSPACE_GUARD"] = "1"
        environment["AUTHSIA_WORKSPACE_ROOT"] = directory.appendingPathComponent("guard-origin").path
        environment["AUTHSIA_FIXTURE_REF"] = "authsia://password/Fixture/password"

        let result = try runBuiltAuthsia(
            arguments: [
                "workspace", "run", "--", "/usr/bin/python3", "-c",
                #"import os; assert "AUTHSIA_FIXTURE_REF" not in os.environ; print("YAML OK")"#,
            ],
            currentDirectory: directory,
            environment: environment
        )

        #expect(result.status == 0)
        #expect(result.stdout == "YAML OK\n")
        #expect(!result.stderr.contains("No Authsia workspace"))
    }

    @Test("explicit workspace run remains fail closed outside a workspace")
    func explicitWorkspaceRunOutsideWorkspaceStillFails() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-explicit-outside-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        var environment = ProcessInfo.processInfo.environment
        environment.removeValue(forKey: WorkspaceGuardedTerminal.shimInvocationEnvironmentName)
        environment.removeValue(forKey: "AUTHSIA_WORKSPACE_GUARD")
        environment.removeValue(forKey: "AUTHSIA_WORKSPACE_ROOT")

        let result = try runBuiltAuthsia(
            arguments: ["workspace", "run", "--", "/usr/bin/python3", "--version"],
            currentDirectory: directory,
            environment: environment
        )

        #expect(result.status != 0)
        #expect(result.stderr.contains("No Authsia workspace"))
    }

    private func runBuiltAuthsia(
        arguments: [String],
        currentDirectory: URL,
        environment: [String: String]
    ) throws -> (status: Int32, stdout: String, stderr: String) {
        var packageRoot = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 {
            packageRoot.deleteLastPathComponent()
        }
        let process = Process()
        process.executableURL = packageRoot.appendingPathComponent(".build/debug/authsia")
        process.arguments = arguments
        process.currentDirectoryURL = currentDirectory
        process.environment = environment
        let output = Pipe()
        let error = Pipe()
        process.standardOutput = output
        process.standardError = error

        try process.run()
        process.waitUntilExit()

        return (
            process.terminationStatus,
            String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "",
            String(data: error.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        )
    }

    @Test("managed env files become absolute exec env files")
    func managedEnvFilesBecomeAbsoluteExecEnvFiles() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env", ".env.local"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "".write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)
        try "".write(to: root.appendingPathComponent(".env.local"), atomically: true, encoding: .utf8)

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [".env.production"],
            commandArgs: ["npm", "dev"]
        )

        #expect(plan.envFiles == [
            root.appendingPathComponent(".env").path,
            root.appendingPathComponent(".env.local").path,
            ".env.production",
        ])
        #expect(plan.commandArgs == ["npm", "dev"])
        #expect(!plan.usesShell)
    }

    @Test("workspace run requests exact metadata for active secret references")
    func workspaceRunRequestsExactMetadataForActiveSecretReferences() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let managedEnvFile = root.appendingPathComponent(".env")
        let explicitEnvFile = root.appendingPathComponent(".env.override")
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(
                    name: "API_KEY",
                    reference: "authsia://api-key/API_KEY/key?folder=Workspaces%2Fapi"
                ),
            ]
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "DB_PASSWORD=authsia://password/DB_PASSWORD/password?folder=Workspaces%2Fapi\n".write(
            to: managedEnvFile,
            atomically: true,
            encoding: .utf8
        )
        try "RUNBOOK=authsia://note/Runbook/content?folder=Workspaces%2Fapi\nLITERAL=value\n".write(
            to: explicitEnvFile,
            atomically: true,
            encoding: .utf8
        )
        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [explicitEnvFile.path],
            commandArgs: ["/usr/bin/true"]
        )

        #expect(try Workspace.Run.requiresValidationMetadata(for: plan))
        let request = try Workspace.Run.validationMetadataRequest(for: plan)

        #expect(request.workspaceFolder == "Workspaces/api")
        #expect(request.mode == .validate)
        #expect(Set(request.references) == Set([
            WorkspaceMetadataReference(
                itemType: .apiKey,
                itemName: "API_KEY",
                folderPath: "Workspaces/api"
            ),
            WorkspaceMetadataReference(
                itemType: .password,
                itemName: "DB_PASSWORD",
                folderPath: "Workspaces/api"
            ),
            WorkspaceMetadataReference(
                itemType: .note,
                itemName: "Runbook",
                folderPath: "Workspaces/api"
            ),
        ]))
    }

    @Test("workspace run skips metadata when every configured value is literal")
    func workspaceRunSkipsMetadataWhenEveryConfiguredValueIsLiteral() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let nested = root.appendingPathComponent("services/payments", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        let explicitEnvFile = root.appendingPathComponent(".env.override")
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env", "services/payments/.env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "ROOT_MODE=local\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        try "PAYMENTS_MODE=sandbox\n".write(
            to: nested.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        try "LOG_LEVEL=debug\n".write(
            to: explicitEnvFile,
            atomically: true,
            encoding: .utf8
        )
        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [explicitEnvFile.path],
            commandArgs: ["/usr/bin/true"]
        )

        #expect(try !Workspace.Run.requiresValidationMetadata(for: plan))
    }

    @Test("workspace run requests environment metadata from sibling managed scopes")
    func workspaceRunRequestsEnvironmentMetadataFromSiblingManagedScopes() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let nested = root.appendingPathComponent("services/payments", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env", "services/payments/.env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "ROOT_KEY=authsia://api-key/ROOT_KEY/key?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        try "PAYMENTS_KEY=authsia://api-key/PAYMENTS_KEY/key?folder=Workspaces%2Fapi%2Fservices\n".write(
            to: nested.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["/usr/bin/true"]
        )

        let request = try Workspace.Run.validationMetadataRequest(for: plan)

        #expect(Set(request.references) == Set([
            WorkspaceMetadataReference(
                itemType: .apiKey,
                itemName: "ROOT_KEY",
                folderPath: "Workspaces/api"
            ),
            WorkspaceMetadataReference(
                itemType: .apiKey,
                itemName: "PAYMENTS_KEY",
                folderPath: "Workspaces/api/services"
            ),
        ]))
    }

    @Test("managed env files follow the command directory scope")
    func managedEnvFilesFollowCommandDirectoryScope() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let nested = root.appendingPathComponent("services/payments", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: ["services/payments/.env", ".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "".write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)
        try "".write(to: nested.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        let rootPlan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["npm", "test"]
        )
        let nestedPlan = try WorkspaceRunPlan.build(
            startingAt: nested,
            extraEnvFiles: [],
            commandArgs: ["npm", "test"]
        )

        #expect(rootPlan.envFiles == [root.appendingPathComponent(".env").path])
        #expect(rootPlan.managedEnvFileCount == 1)
        #expect(nestedPlan.envFiles == [
            root.appendingPathComponent(".env").path,
            nested.appendingPathComponent(".env").path,
        ])
        #expect(nestedPlan.managedEnvFileCount == 2)
    }

    @Test("missing managed env file guidance explains restore or update")
    func missingManagedEnvFileGuidanceExplainsRestoreOrUpdate() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env.missing"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        do {
            _ = try WorkspaceRunPlan.build(
                startingAt: root,
                extraEnvFiles: [],
                commandArgs: ["npm", "dev"]
            )
            Issue.record("Expected missing managed env file to fail")
        } catch {
            let message = String(describing: error)
            #expect(message.contains("Managed env file \".env.missing\" is missing."))
            #expect(message.contains("Restore the file if it should still be managed."))
            #expect(message.contains("Run `authsia workspace update` to remove stale managed env files."))
        }
    }

    @Test("env binding duplicated by managed env file explains how to resolve")
    func envBindingDuplicatedByManagedEnvFileExplainsResolution() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(
                    name: "API_KEY",
                    reference: "authsia://password/API_KEY/password?folder=Workspaces%2Fapi"
                ),
            ]
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "API_KEY=authsia://password/Other/password?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )

        do {
            _ = try WorkspaceRunPlan.build(
                startingAt: root,
                extraEnvFiles: [],
                commandArgs: ["npm", "dev"]
            )
            Issue.record("Expected duplicated env binding to fail")
        } catch {
            let message = String(describing: error)
            #expect(message.contains("Workspace env binding \"API_KEY\" is also defined in managed env file \".env\"."))
            #expect(message.contains("Remove API_KEY from .env"))
            #expect(message.contains("authsia workspace env remove API_KEY"))
        }
    }

    @Test("shell command keeps managed env files and uses Exec shell mode")
    func shellCommandKeepsManagedEnvFilesAndUsesExecShellMode() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "".write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: [],
            shellCommandParts: ["--", "curl", "\"$API_KEY\""]
        )

        #expect(plan.envFiles == [root.appendingPathComponent(".env").path])
        #expect(plan.commandArgs == ["curl", "\"$API_KEY\""])
        #expect(plan.usesShell)
        #expect(Exec.childCommandArguments(command: plan.commandArgs, shell: plan.usesShell) == [
            "/bin/sh",
            "-c",
            "curl \"$API_KEY\"",
        ])
    }

    @Test("plain workspace commands without secret inputs bypass exec")
    func plainWorkspaceCommandsWithoutSecretInputsBypassExec() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["printf", "ok"]
        )

        #expect(!Workspace.Run.shouldDelegateToExec(plan: plan, parentEnvironment: ["PATH": "/usr/bin"]))
    }

    @Test("workspace commands with secret inputs still delegate to exec")
    func workspaceCommandsWithSecretInputsStillDelegateToExec() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "".write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["printf", "ok"]
        )

        #expect(Workspace.Run.shouldDelegateToExec(plan: plan, parentEnvironment: ["PATH": "/usr/bin"]))

        let noEnvRoot = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: noEnvRoot) }
        let noEnvConfig = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "worker", authsiaFolder: "Workspaces/worker"),
            managedEnvFiles: [],
            agents: nil
        )
        try WorkspaceConfigStore.write(noEnvConfig, toWorkspaceRoot: noEnvRoot)
        let noEnvPlan = try WorkspaceRunPlan.build(
            startingAt: noEnvRoot,
            extraEnvFiles: [],
            commandArgs: ["printf", "ok"],
            shellCommandParts: []
        )
        let parentEnvironment = [
            "PATH": "/usr/bin",
            "API_KEY": "authsia://password/API_KEY/password?folder=Workspaces%2Fapi",
        ]

        #expect(Workspace.Run.shouldDelegateToExec(plan: noEnvPlan, parentEnvironment: parentEnvironment))
    }

    @Test("workspace env bindings delegate to exec without managed env files")
    func workspaceEnvBindingsDelegateToExecWithoutManagedEnvFiles() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let binding = WorkspaceConfig.EnvBinding(
            name: "HF_TOKEN",
            reference: "authsia://password/HF_TOKEN/password?folder=Workspaces%2Fapi"
        )
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [binding]
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["node", "-e", "console.log(process.env.HF_TOKEN)"]
        )
        let exec = Workspace.Run.configuredExec(for: plan)

        #expect(plan.envFiles.isEmpty)
        #expect(plan.envBindings == ["HF_TOKEN": binding.reference])
        #expect(Workspace.Run.shouldDelegateToExec(plan: plan, parentEnvironment: ["PATH": "/usr/bin"]))
        #expect(exec.environmentOverrides == ["HF_TOKEN": binding.reference])
    }

    @Test("workspace run dry-run names direct or mediated execution path")
    func workspaceRunDryRunNamesDirectOrMediatedExecutionPath() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let directPlan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["printf", "ok"]
        )
        let directOutput = Workspace.Run.renderDryRun(
            directPlan,
            parentEnvironment: ["PATH": "/usr/bin"]
        )

        #expect(directOutput.contains("Execution: direct passthrough (no workspace secrets detected)"))

        try "PLAIN=value\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let plainEnvConfig = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(plainEnvConfig, toWorkspaceRoot: root)
        let plainEnvPlan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["npm", "test"]
        )
        let plainEnvOutput = Workspace.Run.renderDryRun(
            plainEnvPlan,
            parentEnvironment: ["PATH": "/usr/bin"]
        )

        #expect(plainEnvOutput.contains(
            "Execution: authsia exec (workspace env files active; no Authsia references detected)"
        ))

        try "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let mediatedPlan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["npm", "test"]
        )
        let mediatedOutput = Workspace.Run.renderDryRun(
            mediatedPlan,
            parentEnvironment: ["PATH": "/usr/bin"]
        )

        #expect(mediatedOutput.contains(
            "Execution: authsia exec (Authsia references require approval/JIT unless already authorized)"
        ))
    }

    @Test("workspace run dry-run shows env binding names without resolved values")
    func workspaceRunDryRunShowsEnvBindingNamesWithoutResolvedValues() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(
                    name: "HF_TOKEN",
                    reference: "authsia://password/HF_TOKEN/password?folder=Workspaces%2Fapi"
                ),
            ]
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["node"]
        )
        let output = Workspace.Run.renderDryRun(plan, parentEnvironment: ["PATH": "/usr/bin"])

        #expect(output.contains("Env bindings:"))
        #expect(output.contains("- HF_TOKEN"))
        #expect(!output.contains("authsia://password/HF_TOKEN"))
        #expect(output.contains(
            "Execution: authsia exec (Authsia references require approval/JIT unless already authorized)"
        ))
    }

    @Test("workspace run configures exec defaults for delegated runs")
    func workspaceRunConfiguresExecDefaultsForDelegatedRuns() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "".write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        let shellPlan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: [],
            shellCommandParts: ["--", "printf", "ok"]
        )
        let shellExec = Workspace.Run.configuredExec(for: shellPlan)

        #expect(shellExec.resolvedType == nil)
        #expect(shellExec.resolvedQuery == nil)
        #expect(shellExec.folder == nil)
        #expect(shellExec.env == nil)
        #expect(!shellExec.all)
        #expect(!shellExec.allMachines)
        #expect(shellExec.field == nil)
        #expect(shellExec.envFile == [root.appendingPathComponent(".env").path])
        #expect(shellExec.environmentOverrides.isEmpty)
        #expect(shellExec.shellCommand == "printf ok")
        #expect(shellExec.resolvedCommandArgs == ["printf ok"])

        let directPlan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["printf", "ok"]
        )
        let directExec = Workspace.Run.configuredExec(for: directPlan)

        #expect(directExec.shellCommand == nil)
        #expect(directExec.resolvedCommandArgs == ["printf", "ok"])
    }

    @Test("read-only infra probes bypass exec even with managed secrets")
    func readOnlyInfraProbesBypassExecEvenWithManagedSecrets() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )

        let probes: [[String]] = [
            ["/usr/local/bin/docker", "context", "ls", "--format", "{{json .}}"],
            ["/usr/local/bin/docker", "context", "inspect", "default"],
            ["docker", "version"],
            ["docker", "info"],
            ["/usr/local/bin/npm", "view", "@anthropic-ai/claude-code@latest", "version", "--prefer-online"],
            ["npm", "config", "get", "registry"],
            ["pnpm", "outdated"],
            ["pip", "list"],
            ["pip3", "show", "requests"],
            ["kubectl", "version", "--client"],
            ["kubectl", "version"],
            ["terraform", "version"],
            ["tofu", "version"],
            ["go", "version"],
            ["cargo", "metadata", "--no-deps"],
            ["cargo", "tree"],
            ["gcloud", "version"],
            ["gcloud", "config", "list"],
            ["gcloud", "config", "get-value", "project"],
        ]
        for argv in probes {
            let plan = try WorkspaceRunPlan.build(startingAt: root, extraEnvFiles: [], commandArgs: argv)
            #expect(Workspace.Run.isSecretFreeProbe(plan: plan), "expected probe: \(argv.joined(separator: " "))")
            // A managed .env makes shouldDelegateToExec true; the probe check overrides it.
            #expect(Workspace.Run.shouldDelegateToExec(plan: plan, parentEnvironment: ["PATH": "/usr/bin"]))
        }
    }

    @Test("secret-consuming commands are not treated as probes")
    func secretConsumingCommandsAreNotTreatedAsProbes() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "".write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        let nonProbes: [[String]] = [
            ["/usr/local/bin/docker", "compose", "up"],
            ["docker", "context", "create", "staging"],
            ["docker", "context", "rm", "staging"],
            ["docker", "context", "use", "staging"],
            ["docker", "run", "--rm", "alpine", "env"],
            ["npm", "config", "delete", "registry"],
            ["npm", "config", "edit"],
            ["npm", "config", "set", "registry", "https://registry.npmjs.org/"],
            ["npm", "test"],
            ["npm", "run", "serve"],
            ["pnpm", "config", "set", "store-dir", ".pnpm-store"],
            ["yarn", "config", "set", "npmRegistryServer", "https://registry.yarnpkg.com"],
            ["node", "scripts/deploy.js"],
            ["python3", "app.py"],
            ["printf", "ok"],
            ["pip", "install", "requests"],
            ["pip3", "download", "requests"],
            ["kubectl", "apply", "-f", "deploy.yaml"],
            ["terraform", "apply"],
            ["tofu", "plan"],
            ["go", "run", "main.go"],
            ["cargo", "run"],
            ["gcloud", "config", "set", "project", "demo"],
            ["gcloud", "auth", "login"],
        ]
        for argv in nonProbes {
            let plan = try WorkspaceRunPlan.build(startingAt: root, extraEnvFiles: [], commandArgs: argv)
            #expect(!Workspace.Run.isSecretFreeProbe(plan: plan), "unexpected probe: \(argv.joined(separator: " "))")
        }
    }

    @Test("shell commands are never classified as probes")
    func shellCommandsAreNeverClassifiedAsProbes() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "".write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        // A read-only probe expressed as an opaque shell string is not classifiable
        // (it can chain or expand), so it must still delegate.
        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: [],
            shellCommandParts: ["--", "docker", "context", "ls"]
        )
        #expect(plan.usesShell)
        #expect(!Workspace.Run.isSecretFreeProbe(plan: plan))
    }

    private func makeBindingWorkspaceRoot(
        bindingNames: [String] = ["DATABASE_URL"]
    ) throws -> URL {
        let root = try makeWorkspaceRoot()
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: bindingNames.map {
                WorkspaceConfig.EnvBinding(
                    name: $0,
                    reference: "authsia://password/\($0)/password?folder=Workspaces%2Fapi"
                )
            }
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        return root
    }

    @Test("inline python that references no workspace binding passes through")
    func inlinePythonWithoutBindingReferencePassesThrough() throws {
        let root = try makeBindingWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let bindingFree: [[String]] = [
            ["python3", "-c", "print(\"ok\")"],
            ["python3", "-c", "import os; print(os.environ[\"DEMO_MASK\"])"],
            ["/usr/bin/python3", "-c", "import json; print(json.dumps({}))"],
            ["python", "-c", "print(1)"],
            // Identifier boundaries: neither DATABASE_URL_V2 nor XDATABASE_URL is the binding.
            ["python3", "-c", "import os; os.environ[\"DATABASE_URL_V2\"]"],
            ["python3", "-c", "x = \"XDATABASE_URL\""],
        ]
        for argv in bindingFree {
            let plan = try WorkspaceRunPlan.build(startingAt: root, extraEnvFiles: [], commandArgs: argv)
            let names = try Workspace.Run.workspaceBindingNames(
                plan: plan,
                parentEnvironment: ["PATH": "/usr/bin"]
            )
            #expect(names == ["DATABASE_URL"])
            #expect(
                Workspace.Run.isBindingFreeInvocation(plan: plan, bindingNames: names),
                "expected passthrough: \(argv.joined(separator: " "))"
            )
            // Bindings make shouldDelegateToExec true; the binding-free check overrides it.
            #expect(Workspace.Run.shouldDelegateToExec(plan: plan, parentEnvironment: ["PATH": "/usr/bin"]))
        }
    }

    @Test("inline python referencing a workspace binding delegates to exec")
    func inlinePythonReferencingBindingDelegates() throws {
        let root = try makeBindingWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let referencing: [[String]] = [
            ["python3", "-c", "import os; connect(os.environ[\"DATABASE_URL\"])"],
            ["python3", "-c", "print(\"DATABASE_URL\")"],
            ["python3", "-c", "import os", "DATABASE_URL"],
        ]
        for argv in referencing {
            let plan = try WorkspaceRunPlan.build(startingAt: root, extraEnvFiles: [], commandArgs: argv)
            let names = try Workspace.Run.workspaceBindingNames(
                plan: plan,
                parentEnvironment: ["PATH": "/usr/bin"]
            )
            #expect(
                !Workspace.Run.isBindingFreeInvocation(plan: plan, bindingNames: names),
                "expected delegate: \(argv.joined(separator: " "))"
            )
        }
    }

    @Test("ambiguous python invocations keep delegating")
    func ambiguousPythonInvocationsKeepDelegating() throws {
        let root = try makeBindingWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        // Code outside argv may read any env name, so only a leading `-c` is classifiable.
        let ambiguous: [[String]] = [
            ["python3", "app.py"],
            ["python3", "-m", "http.server"],
            ["python3"],
            ["python3", "-i", "-c", "print(1)"],
            ["python3", "-B", "-c", "print(1)"],
        ]
        for argv in ambiguous {
            let plan = try WorkspaceRunPlan.build(startingAt: root, extraEnvFiles: [], commandArgs: argv)
            let names = try Workspace.Run.workspaceBindingNames(
                plan: plan,
                parentEnvironment: ["PATH": "/usr/bin"]
            )
            #expect(
                !Workspace.Run.isBindingFreeInvocation(plan: plan, bindingNames: names),
                "expected delegate: \(argv.joined(separator: " "))"
            )
        }
    }

    @Test("python delegates when a binding lives in python's implicit env namespace")
    func pythonDelegatesForImplicitEnvNamespaceBindings() throws {
        let root = try makeBindingWorkspaceRoot(bindingNames: ["PYTHONSTARTUP"])
        defer { try? FileManager.default.removeItem(at: root) }

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["python3", "-c", "print(1)"]
        )
        let names = try Workspace.Run.workspaceBindingNames(
            plan: plan,
            parentEnvironment: ["PATH": "/usr/bin"]
        )
        #expect(!Workspace.Run.isBindingFreeInvocation(plan: plan, bindingNames: names))
    }

    @Test("docker invocations without explicit env forwarding pass through")
    func dockerInvocationsWithoutEnvForwardingPassThrough() throws {
        let root = try makeBindingWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        // Containers only receive env that is explicitly forwarded, so a run
        // without -e/--env/--env-file cannot consume workspace bindings.
        let bindingFree: [[String]] = [
            ["docker", "run", "--rm", "alpine", "env"],
            ["docker", "ps"],
            ["docker", "build", "-t", "img", "."],
        ]
        for argv in bindingFree {
            let plan = try WorkspaceRunPlan.build(startingAt: root, extraEnvFiles: [], commandArgs: argv)
            let names = try Workspace.Run.workspaceBindingNames(
                plan: plan,
                parentEnvironment: ["PATH": "/usr/bin"]
            )
            #expect(
                Workspace.Run.isBindingFreeInvocation(plan: plan, bindingNames: names),
                "expected passthrough: \(argv.joined(separator: " "))"
            )
        }
    }

    @Test("docker env forwarding, env files, and compose delegate to exec")
    func dockerEnvForwardingEnvFilesAndComposeDelegate() throws {
        let root = try makeBindingWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let delegating: [[String]] = [
            ["docker", "run", "-e", "DATABASE_URL", "alpine"],
            ["docker", "run", "--env", "DATABASE_URL=x", "alpine"],
            ["docker", "build", "--build-arg", "DATABASE_URL", "."],
            ["docker", "run", "--env-file", ".env", "alpine"],
            ["docker", "run", "--env-file=.env", "alpine"],
            ["docker", "compose", "up"],
        ]
        for argv in delegating {
            let plan = try WorkspaceRunPlan.build(startingAt: root, extraEnvFiles: [], commandArgs: argv)
            let names = try Workspace.Run.workspaceBindingNames(
                plan: plan,
                parentEnvironment: ["PATH": "/usr/bin"]
            )
            #expect(
                !Workspace.Run.isBindingFreeInvocation(plan: plan, bindingNames: names),
                "expected delegate: \(argv.joined(separator: " "))"
            )
        }
    }

    @Test("docker delegates when a binding lives in docker's implicit env namespace")
    func dockerDelegatesForImplicitEnvNamespaceBindings() throws {
        let root = try makeBindingWorkspaceRoot(bindingNames: ["DOCKER_HOST"])
        defer { try? FileManager.default.removeItem(at: root) }

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["docker", "ps"]
        )
        let names = try Workspace.Run.workspaceBindingNames(
            plan: plan,
            parentEnvironment: ["PATH": "/usr/bin"]
        )
        #expect(!Workspace.Run.isBindingFreeInvocation(plan: plan, bindingNames: names))
    }

    @Test("shell commands are never binding-free invocations")
    func shellCommandsAreNeverBindingFreeInvocations() throws {
        let root = try makeBindingWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: [],
            shellCommandParts: ["--", "python3", "-c", "print(1)"]
        )
        #expect(plan.usesShell)
        let names = try Workspace.Run.workspaceBindingNames(
            plan: plan,
            parentEnvironment: ["PATH": "/usr/bin"]
        )
        #expect(!Workspace.Run.isBindingFreeInvocation(plan: plan, bindingNames: names))
    }

    @Test("binding names include parent environment authsia references")
    func bindingNamesIncludeParentEnvironmentAuthsiaReferences() throws {
        let root = try makeBindingWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["python3", "-c", "import os; os.environ[\"API_KEY\"]"]
        )
        let names = try Workspace.Run.workspaceBindingNames(
            plan: plan,
            parentEnvironment: [
                "PATH": "/usr/bin",
                "API_KEY": "authsia://password/API_KEY/password?folder=Workspaces%2Fapi",
            ]
        )
        #expect(names == ["DATABASE_URL", "API_KEY"])
        #expect(!Workspace.Run.isBindingFreeInvocation(plan: plan, bindingNames: names))
    }

    @Test("managed env file authsia references count as bindings, not just workspace env bind entries")
    func managedEnvFileAuthsiaReferencesCountAsBindings() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try """
        PLAIN=value
        API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi
        """.write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        let unreferencing = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["python3", "-c", "print(\"ok\")"]
        )
        let unreferencingNames = try Workspace.Run.workspaceBindingNames(
            plan: unreferencing,
            parentEnvironment: ["PATH": "/usr/bin"]
        )
        #expect(unreferencingNames == ["API_KEY"])
        #expect(Workspace.Run.isBindingFreeInvocation(plan: unreferencing, bindingNames: unreferencingNames))

        let referencing = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["python3", "-c", "import os; connect(os.environ[\"API_KEY\"])"]
        )
        let referencingNames = try Workspace.Run.workspaceBindingNames(
            plan: referencing,
            parentEnvironment: ["PATH": "/usr/bin"]
        )
        #expect(!Workspace.Run.isBindingFreeInvocation(plan: referencing, bindingNames: referencingNames))
    }

    @Test("workspace run dry-run names binding-free passthrough")
    func workspaceRunDryRunNamesBindingFreePassthrough() throws {
        let root = try makeBindingWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["python3", "-c", "print(\"ok\")"]
        )
        let output = Workspace.Run.renderDryRun(
            plan,
            parentEnvironment: ["PATH": "/usr/bin"],
            processAncestry: Self.humanShimAncestry
        )
        #expect(output.contains(
            "Execution: direct passthrough (command references no workspace binding; secrets not injected)"
        ))
    }

    @Test("direct passthrough scrubs automation credentials")
    func directPassthroughScrubsAutomationCredentials() {
        let environment = Workspace.Run.directPassthroughEnvironment(parentEnvironment: [
            AutomationAccessResolver.environmentKey: "11111111-1111-1111-1111-111111111111",
            AutomationAccessResolver.sshEnvironmentKey: "22222222-2222-2222-2222-222222222222",
            "PATH": "/usr/bin",
        ])

        #expect(environment[AutomationAccessResolver.environmentKey] == nil)
        #expect(environment[AutomationAccessResolver.sshEnvironmentKey] == nil)
        #expect(environment["PATH"] == "/usr/bin")
    }

    @Test("shim script marks guarded shim invocation")
    func shimScriptMarksGuardedShimInvocation() {
        let script = WorkspaceGuardedTerminal.shimScript(
            authsiaExecutablePath: "/usr/local/bin/authsia",
            toolPath: "/opt/homebrew/bin/npm"
        )

        #expect(script.contains("export AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION=1"))
    }

    @Test("shell wrapper functions mark guarded shim invocation")
    func shellWrapperFunctionsMarkGuardedShimInvocation() {
        let exports = WorkspaceGuardedTerminal.shellWrapperExports(authsiaExecutablePath: "authsia")

        #expect(exports.contains(
            "AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION=1 command 'authsia' workspace run --"
        ))
    }

    @Test("agent shim invocations bypass secret injection")
    func agentShimInvocationsBypassSecretInjection() {
        let agentAncestry = [
            AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
            AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
            AgenticProcessReference(processName: "claude", bundleIdentifier: nil),
        ]
        let terminalAncestry = [
            AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
            AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
            AgenticProcessReference(processName: "Terminal", bundleIdentifier: "com.apple.Terminal"),
        ]
        let ideTerminalAncestry = [
            AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
            AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
            AgenticProcessReference(processName: "visual-studio-code", bundleIdentifier: nil),
        ]
        let marked = [
            "PATH": "/usr/bin",
            "AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION": "1",
        ]

        #expect(Workspace.Run.isAgentShimInvocation(
            parentEnvironment: marked,
            processAncestry: agentAncestry,
            stdinIsTTY: false
        ))
        #expect(!Workspace.Run.isAgentShimInvocation(
            parentEnvironment: ["PATH": "/usr/bin"],
            processAncestry: agentAncestry,
            stdinIsTTY: false
        ))
        #expect(!Workspace.Run.isAgentShimInvocation(
            parentEnvironment: marked,
            processAncestry: terminalAncestry,
            stdinIsTTY: false
        ))
        #expect(!Workspace.Run.isAgentShimInvocation(
            parentEnvironment: marked,
            processAncestry: ideTerminalAncestry,
            stdinIsTTY: false
        ))

        var automationEnvironment = marked
        automationEnvironment[AutomationAccessResolver.environmentKey] = "11111111-1111-1111-1111-111111111111"
        #expect(!Workspace.Run.isAgentShimInvocation(
            parentEnvironment: automationEnvironment,
            processAncestry: agentAncestry,
            stdinIsTTY: false
        ))
    }

    @Test("guarded shim under codex keeps human env resolution when stdin is a TTY")
    func guardedShimUnderCodexKeepsHumanEnvWhenStdinIsTTY() {
        let env = [WorkspaceGuardedTerminal.shimInvocationEnvironmentName: "1"]
        // stdin remains a TTY even if stdout is redirected: NOT an agent shim invocation.
        #expect(!Workspace.Run.isAgentShimInvocation(
            parentEnvironment: env,
            processAncestry: Self.humanShimAncestry,
            stdinIsTTY: true
        ))
        // Agent-spawned shim child without a stdin TTY: IS an agent shim invocation.
        #expect(Workspace.Run.isAgentShimInvocation(
            parentEnvironment: env,
            processAncestry: Self.humanShimAncestry,
            stdinIsTTY: false
        ))
        // Explicit agent marker forces agent treatment even with a stdin TTY.
        #expect(Workspace.Run.isAgentShimInvocation(
            parentEnvironment: env.merging([
                AgentRuntimeContextResolver.environmentPlatformKey: "codex",
                AgentRuntimeContextResolver.environmentInvokesAuthsiaKey: "1",
            ]) { _, new in new },
            processAncestry: Self.humanShimAncestry,
            stdinIsTTY: true
        ))
    }

    @Test("child environments drop the shim invocation marker")
    func childEnvironmentsDropShimInvocationMarker() {
        let passthrough = Workspace.Run.directPassthroughEnvironment(parentEnvironment: [
            "AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION": "1",
            "PATH": "/usr/bin",
        ])
        #expect(passthrough["AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION"] == nil)

        var execChild = [
            "AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION": "1",
            "PATH": "/usr/bin",
        ]
        Exec.removeGuardedTerminalShim(from: &execChild)
        #expect(execChild["AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION"] == nil)
    }

    @Test("agent shim passthrough keeps literal workspace env values")
    func agentShimPassthroughKeepsLiteralWorkspaceEnvValues() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try """
        PLAIN=value
        API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi
        """.write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["python3", "script.py"]
        )
        let passthrough = try Workspace.Run.directPassthroughEnvironment(parentEnvironment: [
            AutomationAccessResolver.environmentKey: "11111111-1111-1111-1111-111111111111",
            "AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION": "1",
            "PATH": "/usr/bin",
        ], plan: plan)

        #expect(passthrough["PLAIN"] == "value")
        #expect(passthrough["API_KEY"] == nil)
        #expect(passthrough[AutomationAccessResolver.environmentKey] == nil)
        #expect(passthrough["AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION"] == nil)
    }

    @Test("agent shim passthrough drops managed secret names")
    func agentShimPassthroughDropsManagedSecretNames() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(
                    name: "HF_TOKEN",
                    reference: "authsia://password/HF_TOKEN/password?folder=Workspaces%2Fapi"
                ),
            ]
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try """
        API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi
        PLAIN=value
        """.write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["python3", "script.py"]
        )
        let passthrough = try Workspace.Run.directPassthroughEnvironment(parentEnvironment: [
            "AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION": "1",
            "API_KEY": "ambient-api-key",
            "HF_TOKEN": "ambient-token",
            "PATH": "/usr/bin",
        ], plan: plan)

        #expect(passthrough["PLAIN"] == "value")
        #expect(passthrough["API_KEY"] == nil)
        #expect(passthrough["HF_TOKEN"] == nil)
        #expect(passthrough["PATH"] == "/usr/bin")
    }

    @Test("workspace run dry-run names agent shim passthrough")
    func workspaceRunDryRunNamesAgentShimPassthrough() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["python3", "script.py"]
        )
        let output = Workspace.Run.renderDryRun(
            plan,
            parentEnvironment: [
                "PATH": "/usr/bin",
                "AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION": "1",
            ],
            processAncestry: [
                AgenticProcessReference(processName: "claude", bundleIdentifier: nil),
            ]
        )

        #expect(output.contains(
            "Execution: direct passthrough (guarded shim under agent; literal env kept, Authsia refs not resolved)"
        ))
    }

    @Test("workspace run dry-run names read-only probe passthrough")
    func workspaceRunDryRunNamesReadOnlyProbePassthrough() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["docker", "context", "ls"]
        )
        let output = Workspace.Run.renderDryRun(plan, parentEnvironment: ["PATH": "/usr/bin"])

        #expect(output.contains(
            "Execution: direct passthrough (read-only probe; workspace secrets not injected)"
        ))
    }
}

@Suite("Workspace env bindings")
struct WorkspaceEnvBindingTests {
    @Test("env add scopes unscoped names while preserving explicit folders and UUIDs")
    func envAddCanonicalizesOnlyUnscopedNamedReferences() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let knownRootsDirectory = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: knownRootsDirectory) }
        let knownRootsStore = WorkspaceKnownRootsStore(applicationSupportDirectory: knownRootsDirectory)
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        let externalReference = "authsia://password/Shared/password?folder=Shared"
        let uuidReference = "authsia://password/00000000-0000-0000-0000-000000000001/password"

        let scoped = try Workspace.Env.addBinding(
            name: "API_KEY",
            reference: "authsia://api-key/API_KEY/key",
            workspaceRoot: root,
            knownRootsStore: knownRootsStore
        )
        let external = try Workspace.Env.addBinding(
            name: "SHARED_PASSWORD",
            reference: externalReference,
            workspaceRoot: root,
            knownRootsStore: knownRootsStore
        )
        let uuid = try Workspace.Env.addBinding(
            name: "UUID_PASSWORD",
            reference: uuidReference,
            workspaceRoot: root,
            knownRootsStore: knownRootsStore
        )

        #expect(scoped.reference == "authsia://api-key/API_KEY/key?folder=Workspaces%2Fapi")
        #expect(external.reference == externalReference)
        #expect(uuid.reference == uuidReference)
        #expect(try WorkspaceConfigStore.read(fromWorkspaceRoot: root).envBindings.map(\.reference) == [
            "authsia://api-key/API_KEY/key?folder=Workspaces%2Fapi",
            externalReference,
            uuidReference,
        ])
    }

    @Test("env add list and remove update workspace config")
    func envAddListAndRemoveUpdateWorkspaceConfig() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let knownRootsDirectory = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: knownRootsDirectory) }
        let knownRootsStore = WorkspaceKnownRootsStore(applicationSupportDirectory: knownRootsDirectory)
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let added = try Workspace.Env.addBinding(
            name: "  HF_TOKEN  ",
            reference: "authsia://password/HF_TOKEN/password?folder=Workspaces%2Fapi",
            workspaceRoot: root,
            knownRootsStore: knownRootsStore
        )
        let listed = Workspace.Env.renderList(try WorkspaceConfigStore.read(fromWorkspaceRoot: root))
        let removed = try Workspace.Env.removeBinding(
            name: "HF_TOKEN",
            workspaceRoot: root,
            knownRootsStore: knownRootsStore
        )

        #expect(added.name == "HF_TOKEN")
        #expect(listed.contains("Workspace env bindings:"))
        #expect(listed.contains("HF_TOKEN=authsia://password/HF_TOKEN/password?folder=Workspaces%2Fapi"))
        #expect(removed == "Removed workspace env binding HF_TOKEN.")
        #expect(try WorkspaceConfigStore.read(fromWorkspaceRoot: root).envBindings.isEmpty)
        #expect(try knownRootsStore.load() == [root.standardizedFileURL.path])
    }

    @Test("schema v2 env add preserves same-name bindings for different environment items")
    func schemaV2EnvAddPreservesSameNameBindings() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let knownRootsDirectory = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: knownRootsDirectory) }
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        _ = try Workspace.Env.addBinding(
            name: "API_KEY",
            reference: "authsia://password/prod-id/password",
            workspaceRoot: root,
            knownRootsStore: WorkspaceKnownRootsStore(applicationSupportDirectory: knownRootsDirectory)
        )
        _ = try Workspace.Env.addBinding(
            name: "API_KEY",
            reference: "authsia://password/staging-id/password",
            workspaceRoot: root,
            knownRootsStore: WorkspaceKnownRootsStore(applicationSupportDirectory: knownRootsDirectory)
        )

        let bindings = try WorkspaceConfigStore.read(fromWorkspaceRoot: root).envBindings
        #expect(bindings.map(\.name) == ["API_KEY", "API_KEY"])
        #expect(bindings.map(\.reference) == [
            "authsia://password/prod-id/password?folder=Workspaces%2Fapi",
            "authsia://password/staging-id/password?folder=Workspaces%2Fapi",
        ])
    }

    @Test("schema v2 env remove requires a reference for same-name bindings")
    func schemaV2EnvRemovePreservesOtherEnvironmentBindings() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let development = "authsia://password/development-id/password"
        let production = "authsia://password/production-id/password"
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                .init(name: "API_KEY", reference: development),
                .init(name: "API_KEY", reference: production),
            ]
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        #expect(throws: ValidationError.self) {
            try Workspace.Env.removeBinding(name: "API_KEY", workspaceRoot: root)
        }
        let removed = try Workspace.Env.removeBinding(
            name: "API_KEY",
            reference: development,
            workspaceRoot: root
        )

        #expect(removed == "Removed workspace env binding API_KEY.")
        #expect(try WorkspaceConfigStore.read(fromWorkspaceRoot: root).envBindings == [
            .init(name: "API_KEY", reference: production),
        ])
    }

    @Test("workspace forget removes exact and validation roots")
    func workspaceForgetRemovesExactAndValidationRoots() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let knownRootsDirectory = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: knownRootsDirectory) }
        let knownRootsStore = WorkspaceKnownRootsStore(applicationSupportDirectory: knownRootsDirectory)
        let staleContainer = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-cli-validate.\(UUID().uuidString)", isDirectory: true)
        let staleRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent(staleContainer.lastPathComponent, isDirectory: true)
            .appendingPathComponent("workspace", isDirectory: true)
        let unrelatedRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("unrelated-workspace", isDirectory: true)
        let defaultsOnlyRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-cli-validate.\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("workspace", isDirectory: true)
        let defaultsSuiteName = "authsia-cli-tests-\(UUID().uuidString)"
        let appDefaults = try #require(UserDefaults(suiteName: defaultsSuiteName))
        defer { appDefaults.removePersistentDomain(forName: defaultsSuiteName) }
        try FileManager.default.createDirectory(at: staleRoot, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: staleContainer) }

        try knownRootsStore.record([root.path, staleRoot.path, unrelatedRoot.path])
        appDefaults.set(
            "[\"\(defaultsOnlyRoot.standardizedFileURL.path)\"]",
            forKey: "workspaceKnownRoots"
        )
        appDefaults.set(
            "[\"\(root.standardizedFileURL.path)\"]",
            forKey: "workspacePinnedRoots"
        )

        let forgottenExact = try Workspace.Forget.forget(
            root: root.path,
            under: [],
            missingUnder: [],
            store: knownRootsStore,
            appDefaults: appDefaults,
            fileManager: .default
        )
        let forgottenStale = try Workspace.Forget.forget(
            root: nil,
            under: [FileManager.default.temporaryDirectory.appendingPathComponent("authsia-cli-validate.").path],
            missingUnder: [],
            store: knownRootsStore,
            appDefaults: appDefaults,
            fileManager: .default
        )

        #expect(forgottenExact == [root.standardizedFileURL.path])
        #expect(forgottenStale == [staleRoot.standardizedFileURL.path, defaultsOnlyRoot.standardizedFileURL.path])
        #expect(try knownRootsStore.load() == [unrelatedRoot.standardizedFileURL.path])
        #expect(appDefaults.string(forKey: "workspaceKnownRoots") == "[]")
        #expect(appDefaults.string(forKey: "workspacePinnedRoots") == "[]")
    }

    @Test("empty env list validate and remove guide binding next step")
    func emptyEnvListValidateAndRemoveGuideBindingNextStep() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let listed = Workspace.Env.renderList(config)
        let validated = Workspace.Env.renderValidation(
            Workspace.Env.validateBindings(config, vaultIndex: nil)
        )
        let removed = try Workspace.Env.removeBinding(
            name: "API_KEY",
            workspaceRoot: root
        )

        #expect(listed.contains("No workspace env bindings configured."))
        #expect(validated.contains("No workspace env bindings configured."))
        #expect(removed.contains("No workspace env binding API_KEY."))
        #expect(listed.contains("authsia workspace env add <NAME> <authsia://...>"))
        #expect(validated.contains("authsia workspace env add <NAME> <authsia://...>"))
        #expect(removed.contains("Run `authsia workspace env list` to see configured bindings"))
        #expect(removed.contains("authsia workspace env add <NAME> <authsia://...>"))
    }

    @Test("env validate reports valid missing and unverified bindings")
    func envValidateReportsValidMissingAndUnverifiedBindings() throws {
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(
                    name: "API_KEY",
                    reference: "authsia://password/API_KEY/password?folder=Workspaces%2Fapi"
                ),
                WorkspaceConfig.EnvBinding(
                    name: "RUNBOOK",
                    reference: "authsia://note/Runbook/content?folder=Workspaces%2Fapi"
                ),
            ]
        )
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                password(id: "00000000-0000-0000-0000-000000000001", name: "API_KEY", folderPath: "Workspaces/api"),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let validated = Workspace.Env.validateBindings(
            config,
            vaultIndex: WorkspaceVaultIndex(payload: payload)
        )
        let unverified = Workspace.Env.validateBindings(config, vaultIndex: nil)
        let rendered = Workspace.Env.renderValidation(validated)

        #expect(validated.valid.map(\.name) == ["API_KEY"])
        #expect(validated.missing.map(\.name) == ["RUNBOOK"])
        #expect(unverified.unverified.map(\.name) == ["API_KEY", "RUNBOOK"])
        #expect(rendered.contains("Valid workspace env bindings:"))
        #expect(rendered.contains("- API_KEY"))
        #expect(rendered.contains("Missing Authsia references:"))
        #expect(rendered.contains("- RUNBOOK: note Runbook in folder Workspaces/api"))
    }

    @Test("env validate requests only exact configured workspace references")
    func envValidateRequestsOnlyExactConfiguredWorkspaceReferences() throws {
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(
                    name: "API_KEY",
                    reference: "authsia://api-key/API_KEY/key?folder=Workspaces%2Fapi"
                ),
                WorkspaceConfig.EnvBinding(
                    name: "RUNBOOK",
                    reference: "authsia://note/Runbook/content?folder=Workspaces%2Fapi"
                ),
            ]
        )

        let request = Workspace.Env.validationMetadataRequest(config)

        #expect(request == WorkspaceMetadataRequestPayload(
            workspaceFolder: "Workspaces/api",
            mode: .validate,
            references: [
                WorkspaceMetadataReference(
                    itemType: .apiKey,
                    itemName: "API_KEY",
                    folderPath: "Workspaces/api"
                ),
                WorkspaceMetadataReference(
                    itemType: .note,
                    itemName: "Runbook",
                    folderPath: "Workspaces/api"
                ),
            ]
        ))
    }

    @Test("workspace env list uses exact scoped metadata")
    func workspaceEnvListUsesExactScopedMetadata() throws {
        let sourceURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources/authsia/Commands/WorkspaceCommand.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        let envStart = try #require(source.range(of: "struct Env: ParsableCommand"))
        let start = try #require(source.range(
            of: "struct List: ParsableCommand",
            range: envStart.lowerBound..<source.endIndex
        ))
        let end = try #require(source.range(
            of: "struct Add: ParsableCommand",
            range: start.upperBound..<source.endIndex
        ))
        let implementation = source[start.lowerBound..<end.lowerBound]

        #expect(implementation.contains("AuthsiaBridgeClient.shared.workspaceMetadata("))
        #expect(implementation.contains("BridgeContext.workspaceEnvBindingsListRequestedCommand"))
        #expect(!implementation.contains("AuthsiaBridgeClient.shared.list()"))
    }

    @Test("workspace env validate evaluates the stored environment with run references")
    func workspaceEnvValidateEvaluatesStoredEnvironmentWithRunReferences() throws {
        let sourceURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources/authsia/Commands/WorkspaceCommand.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)
        let start = try #require(source.range(of: "struct Validate: AsyncParsableCommand"))
        let end = try #require(source.range(
            of: "static func addBinding",
            range: start.upperBound..<source.endIndex
        ))
        let implementation = source[start.lowerBound..<end.lowerBound]

        #expect(implementation.contains("Workspace.Run.validationMetadataRequest(for: plan)"))
        #expect(implementation.contains("WorkspaceEnvironmentSelectionStore().activeEnvironment"))
        #expect(implementation.contains("WorkspaceStatusReporter.build("))
        #expect(implementation.contains("Env.validationFailures(status)"))
        #expect(implementation.contains("throw ValidationError"))
    }

    @Test("workspace env validation treats every unresolved state as blocking")
    func workspaceEnvValidationTreatsEveryUnresolvedStateAsBlocking() {
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: .init(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil
        )
        let missing = WorkspaceMissingReference(
            relativePath: ".env",
            itemType: "password",
            item: "DB_PASSWORD",
            folderPath: "Workspaces/api"
        )
        var status = WorkspaceStatus(
            config: config,
            envFiles: [],
            envBindings: [],
            agentRules: [],
            missingReferences: [missing],
            unverifiedReferences: [missing]
        )
        status.environmentIssueCount = 2

        #expect(Workspace.Env.validationFailures(status) == [
            "1 missing reference(s)",
            "1 unverified reference(s)",
            "2 environment resolution issue(s)",
        ])
    }
}

@Suite("Workspace sync planner")
struct WorkspaceSyncPlannerTests {
    @Test("sync reports missing rows when importer has no workspace folder")
    func syncReportsMissingRowsWhenImporterHasNoWorkspaceFolder() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = workspaceSyncConfig(bindings: [
            WorkspaceConfig.EnvBinding(
                name: "API_KEY",
                reference: "authsia://password/API_KEY/password?folder=Workspaces%2Fapi"
            ),
            WorkspaceConfig.EnvBinding(
                name: "DB_PASSWORD",
                reference: "authsia://password/DB_PASSWORD/password?folder=Workspaces%2Fapi"
            ),
        ])

        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(passwords: [])
        )

        #expect(plan.authsiaFolder == "Workspaces/api")
        #expect(plan.satisfied.isEmpty)
        #expect(plan.missing.map(\.envName) == ["API_KEY", "DB_PASSWORD"])
        #expect(plan.missing.allSatisfy { $0.action == .skip })
        #expect(plan.missing.allSatisfy { $0.selected })
    }

    @Test("sync reports satisfied and missing rows for partial vault folder")
    func syncReportsSatisfiedAndMissingRowsForPartialVaultFolder() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = workspaceSyncConfig(bindings: [
            WorkspaceConfig.EnvBinding(
                name: "API_KEY",
                reference: "authsia://password/API_KEY/password?folder=Workspaces%2Fapi"
            ),
            WorkspaceConfig.EnvBinding(
                name: "DB_PASSWORD",
                reference: "authsia://password/DB_PASSWORD/password?folder=Workspaces%2Fapi"
            ),
        ])

        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(passwords: [
                password(id: "00000000-0000-0000-0000-000000000001", name: "API_KEY", folderPath: "Workspaces/api"),
            ])
        )

        #expect(plan.satisfied.map(\.envName) == ["API_KEY"])
        #expect(plan.satisfied.first?.action == WorkspaceSyncAction.none)
        #expect(plan.missing.map(\.envName) == ["DB_PASSWORD"])
    }

    @Test("sync reports local extras when vault folder has unbound items")
    func syncReportsLocalExtrasWhenVaultFolderHasUnboundItems() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = workspaceSyncConfig(bindings: [
            WorkspaceConfig.EnvBinding(
                name: "API_KEY",
                reference: "authsia://password/API_KEY/password?folder=Workspaces%2Fapi"
            ),
        ])

        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(passwords: [
                password(id: "00000000-0000-0000-0000-000000000001", name: "API_KEY", folderPath: "Workspaces/api"),
                password(id: "00000000-0000-0000-0000-000000000002", name: "EXTRA_TOKEN", folderPath: "Workspaces/api"),
                password(id: "00000000-0000-0000-0000-000000000003", name: "OTHER_TOKEN", folderPath: "Personal"),
            ])
        )

        #expect(plan.extras.map(\.envName) == ["EXTRA_TOKEN"])
        #expect(plan.extras.first?.action == .addToConfig)
        #expect(plan.extras.first?.selected == true)
    }

    @Test("sync reports API key extras with api-key references")
    func syncReportsAPIKeyExtrasWithAPIKeyReferences() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = workspaceSyncConfig(bindings: [])

        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(
                passwords: [],
                apiKeys: [
                    apiKey(id: "00000000-0000-0000-0000-000000000001", name: "STRIPE_KEY", folderPath: "Workspaces/api"),
                ]
            )
        )

        #expect(plan.extras.map(\.envName) == ["STRIPE_KEY"])
        #expect(plan.extras.first?.itemType == "api-key")
        #expect(plan.extras.first?.localReference == "authsia://api-key/STRIPE_KEY/key?folder=Workspaces%2Fapi")
    }

    @Test("sync includes descendant folders and excludes sibling folders")
    func syncIncludesDescendantFoldersOnly() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = workspaceSyncConfig(bindings: [
            WorkspaceConfig.EnvBinding(
                name: "NESTED_PASSWORD",
                reference: "authsia://password/NESTED_PASSWORD/password?folder=Workspaces%2Fapi%2Fservices"
            ),
        ])

        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(passwords: [
                password(
                    id: "00000000-0000-0000-0000-000000000001",
                    name: "NESTED_PASSWORD",
                    folderPath: "Workspaces/api/services"
                ),
                password(
                    id: "00000000-0000-0000-0000-000000000002",
                    name: "NESTED_EXTRA",
                    folderPath: "Workspaces/api/services"
                ),
                password(
                    id: "00000000-0000-0000-0000-000000000003",
                    name: "SIBLING_EXTRA",
                    folderPath: "Workspaces/api-old"
                ),
            ])
        )

        #expect(plan.satisfied.map(\.envName) == ["NESTED_PASSWORD"])
        #expect(plan.satisfied.first?.folderPath == "Workspaces/api/services")
        #expect(plan.extras.map(\.envName) == ["NESTED_EXTRA"])
        #expect(plan.extras.first?.folderPath == "Workspaces/api/services")
    }

    @Test("sync preserves explicit external and unscoped UUID references")
    func syncPreservesExternalReferences() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = workspaceSyncConfig(bindings: [
            WorkspaceConfig.EnvBinding(
                name: "SHARED_PASSWORD",
                reference: "authsia://password/SHARED_PASSWORD/password?folder=Shared"
            ),
            WorkspaceConfig.EnvBinding(
                name: "UUID_PASSWORD",
                reference: "authsia://password/00000000-0000-0000-0000-000000000001/password"
            ),
        ])

        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(passwords: [
                password(
                    id: "00000000-0000-0000-0000-000000000002",
                    name: "SHARED_PASSWORD",
                    folderPath: "Workspaces/api"
                ),
            ])
        )
        let externalRows = plan.rows.filter { $0.status == .external }

        #expect(externalRows.map(\.envName) == ["SHARED_PASSWORD", "UUID_PASSWORD"])
        #expect(externalRows.allSatisfy { !$0.selected && $0.action == .none })
        #expect(plan.missing.isEmpty)
        #expect(plan.mismatches.isEmpty)
    }

    @Test("sync treats managed env file references as tracked")
    func syncTreatsManagedEnvFileReferencesAsTracked() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try """
        STRIPE_KEY=authsia://api-key/STRIPE_KEY/key?folder=Workspaces%2Fapi
        """.write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil,
            envBindings: []
        )

        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(
                passwords: [],
                apiKeys: [
                    apiKey(
                        id: "00000000-0000-0000-0000-000000000001",
                        name: "STRIPE_KEY",
                        folderPath: "Workspaces/api"
                    ),
                ]
            )
        )

        #expect(plan.satisfied.map(\.envName) == ["STRIPE_KEY"])
        #expect(plan.extras.isEmpty)
    }

    @Test("sync reports config mismatch when a workspace-local reference name differs")
    func syncReportsConfigMismatchWhenWorkspaceLocalReferenceNameDiffers() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = workspaceSyncConfig(bindings: [
            WorkspaceConfig.EnvBinding(
                name: "API_KEY",
                reference: "authsia://password/OLD_API_KEY/password?folder=Workspaces%2Fapi"
            ),
        ])

        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(passwords: [
                password(id: "00000000-0000-0000-0000-000000000001", name: "API_KEY", folderPath: "Workspaces/api"),
            ])
        )

        #expect(plan.mismatches.map(\.envName) == ["API_KEY"])
        #expect(plan.mismatches.first?.expectedReference == "authsia://password/OLD_API_KEY/password?folder=Workspaces%2Fapi")
        #expect(plan.mismatches.first?.localReference == "authsia://password/API_KEY/password?folder=Workspaces%2Fapi")
        #expect(plan.mismatches.first?.action == .repairConfig)
    }

    @Test("sync bulk selection applies action to selected missing rows only")
    func syncBulkSelectionAppliesActionToSelectedMissingRowsOnly() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = workspaceSyncConfig(bindings: [
            WorkspaceConfig.EnvBinding(
                name: "API_KEY",
                reference: "authsia://password/API_KEY/password?folder=Workspaces%2Fapi"
            ),
            WorkspaceConfig.EnvBinding(
                name: "DB_PASSWORD",
                reference: "authsia://password/DB_PASSWORD/password?folder=Workspaces%2Fapi"
            ),
        ])
        var plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(passwords: [])
        )
        plan.rows[1].selected = false

        let updated = WorkspaceSyncPlanner.applying(.create, toSelectedRowsIn: plan)

        #expect(updated.rows[0].action == .create)
        #expect(updated.rows[1].action == .skip)
    }
}

@Suite("Workspace sync command")
struct WorkspaceSyncCommandTests {
    @Test("workspace sync preview and apply request scoped metadata without references")
    func workspaceSyncPreviewAndApplyRequestScopedMetadata() {
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil
        )

        let request = Workspace.Sync.workspaceMetadataRequest(config: config)

        #expect(request.workspaceFolder == "Workspaces/api")
        #expect(request.mode == .syncPreview)
        #expect(request.references.isEmpty)
        #expect(!Workspace.Sync.requiresProtectedVaultList(applyJson: nil))
        #expect(!Workspace.Sync.requiresProtectedVaultList(applyJson: "selection.json"))
    }

    @Test("workspace sync plan JSON reports missing partial and extra rows")
    func workspaceSyncPlanJsonReportsMissingPartialAndExtraRows() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = workspaceSyncConfig(bindings: [
            WorkspaceConfig.EnvBinding(
                name: "API_KEY",
                reference: "authsia://password/API_KEY/password?folder=Workspaces%2Fapi"
            ),
            WorkspaceConfig.EnvBinding(
                name: "DB_PASSWORD",
                reference: "authsia://password/DB_PASSWORD/password?folder=Workspaces%2Fapi"
            ),
        ])
        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(passwords: [
                password(id: "00000000-0000-0000-0000-000000000001", name: "API_KEY", folderPath: "Workspaces/api"),
                password(id: "00000000-0000-0000-0000-000000000002", name: "EXTRA_TOKEN", folderPath: "Workspaces/api"),
            ])
        )

        let payload = WorkspaceSetupExchange.syncPayload(for: plan, workspace: config.workspace)
        let encoded = String(decoding: try WorkspaceSetupExchange.encodedSyncPayload(payload), as: UTF8.self)

        #expect(payload.rows.map(\.status).contains(.satisfied))
        #expect(payload.rows.map(\.status).contains(.missingLocally))
        #expect(payload.rows.map(\.status).contains(.localExtra))
        #expect(encoded.contains("\"envName\" : \"DB_PASSWORD\""))
        #expect(encoded.contains("\"action\" : \"addToConfig\""))
        #expect(!encoded.contains("secret-value"))
    }

    @Test("workspace sync apply JSON repairs config bindings without secret values")
    func workspaceSyncApplyJsonRepairsConfigBindingsWithoutSecretValues() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = workspaceSyncConfig(bindings: [
            WorkspaceConfig.EnvBinding(
                name: "API_KEY",
                reference: "authsia://password/OLD_API_KEY/password?folder=Workspaces%2Fapi"
            ),
        ])
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(passwords: [
                password(id: "00000000-0000-0000-0000-000000000001", name: "API_KEY", folderPath: "Workspaces/api"),
                password(id: "00000000-0000-0000-0000-000000000002", name: "EXTRA_TOKEN", folderPath: "Workspaces/api"),
            ])
        )
        let selection = WorkspaceSetupExchange.SyncSelectionPayload(
            schemaVersion: WorkspaceSetupExchange.schemaVersion,
            rows: plan.rows.map {
                WorkspaceSetupExchange.SyncRowSelection(id: $0.id, action: $0.action)
            }
        )

        let result = try Workspace.Sync.apply(selection, toWorkspaceRoot: root, currentPlan: plan)
        let updated = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        let raw = try read(".authsia/workspace.json", in: root)

        #expect(result.contains("Updated workspace env bindings: API_KEY, EXTRA_TOKEN"))
        #expect(updated.envBindings.map(\.name) == ["API_KEY", "EXTRA_TOKEN"])
        #expect(updated.envBindings[0].reference == "authsia://password/API_KEY/password?folder=Workspaces%2Fapi")
        #expect(updated.envBindings[1].reference == "authsia://password/EXTRA_TOKEN/password?folder=Workspaces%2Fapi")
        #expect(!raw.contains("secret-value"))
    }

    @Test("schema v2 sync repair replaces the exact mismatched binding")
    func schemaV2SyncRepairReplacesExactMismatchedBinding() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let oldReference = "authsia://password/OLD_API_KEY/password?folder=Workspaces%2Fapi"
        let newReference = "authsia://password/API_KEY/password?folder=Workspaces%2Fapi"
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: .init(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [.init(name: "API_KEY", reference: oldReference)]
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(passwords: [
                password(id: "00000000-0000-0000-0000-000000000001", name: "API_KEY", folderPath: "Workspaces/api"),
            ])
        )
        let row = try #require(plan.mismatches.first)
        let selection = WorkspaceSetupExchange.SyncSelectionPayload(
            schemaVersion: WorkspaceSetupExchange.schemaVersion,
            rows: [.init(id: row.id, action: .repairConfig)]
        )

        _ = try Workspace.Sync.apply(selection, toWorkspaceRoot: root, currentPlan: plan)
        let updated = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)

        #expect(updated.envBindings == [.init(name: "API_KEY", reference: newReference)])
        #expect(!updated.envBindings.contains(.init(name: "API_KEY", reference: oldReference)))
    }

    @Test("workspace sync apply can create missing config for imported folder")
    func workspaceSyncApplyCanCreateMissingConfigForImportedFolder() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = workspaceSyncConfig(bindings: [])
        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(passwords: [
                password(id: "00000000-0000-0000-0000-000000000001", name: "API_KEY", folderPath: "Workspaces/api"),
            ])
        )
        let selection = WorkspaceSetupExchange.SyncSelectionPayload(
            schemaVersion: WorkspaceSetupExchange.schemaVersion,
            rows: plan.rows.map {
                WorkspaceSetupExchange.SyncRowSelection(id: $0.id, action: $0.action)
            }
        )

        let result = try Workspace.Sync.apply(selection, toWorkspaceRoot: root, currentPlan: plan)
        let updated = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        let raw = try read(".authsia/workspace.json", in: root)

        #expect(result.contains("Updated workspace env bindings: API_KEY"))
        #expect(updated.workspace.authsiaFolder == "Workspaces/api")
        #expect(updated.managedEnvFiles.isEmpty)
        #expect(updated.envBindings.map(\.name) == ["API_KEY"])
        #expect(updated.envBindings.first?.reference == "authsia://password/API_KEY/password?folder=Workspaces%2Fapi")
        #expect(!raw.contains("secret-value"))
    }

    @Test("workspace sync no-op apply guides refresh and row selection")
    func workspaceSyncNoOpApplyGuidesRefreshAndRowSelection() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = workspaceSyncConfig(bindings: [
            WorkspaceConfig.EnvBinding(
                name: "API_KEY",
                reference: "authsia://password/API_KEY/password?folder=Workspaces%2Fapi"
            ),
        ])
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(passwords: [])
        )
        let selection = WorkspaceSetupExchange.SyncSelectionPayload(
            schemaVersion: WorkspaceSetupExchange.schemaVersion,
            rows: plan.rows.map {
                WorkspaceSetupExchange.SyncRowSelection(id: $0.id, action: .skip)
            }
        )

        let result = try Workspace.Sync.apply(selection, toWorkspaceRoot: root, currentPlan: plan)

        #expect(result.contains("No workspace sync changes applied."))
        #expect(result.contains("Refresh preview with `authsia workspace sync --plan-json`"))
        #expect(result.contains("select at least one non-skip row"))
        #expect(result.contains("re-run `authsia workspace sync --apply-json <file>`"))
    }

    @Test("workspace sync rejects create rows without provided values")
    func workspaceSyncRejectsCreateRowsWithoutProvidedValues() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = workspaceSyncConfig(bindings: [
            WorkspaceConfig.EnvBinding(
                name: "API_KEY",
                reference: "authsia://password/API_KEY/password?folder=Workspaces%2Fapi"
            ),
        ])
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(passwords: [])
        )
        let selection = WorkspaceSetupExchange.SyncSelectionPayload(
            schemaVersion: WorkspaceSetupExchange.schemaVersion,
            rows: [
                WorkspaceSetupExchange.SyncRowSelection(id: plan.rows[0].id, action: .create),
            ]
        )

        do {
            _ = try Workspace.Sync.apply(selection, toWorkspaceRoot: root, currentPlan: plan)
            Issue.record("Expected create action to require app-mediated values.")
        } catch {
            let message = String(describing: error)
            #expect(message.contains("requires the Authsia app"))
            #expect(message.contains("Open Authsia > Workspace > Sync"))
            #expect(message.contains("repairConfig/addToConfig"))
        }
    }

    @Test("workspace sync apply guides missing local references")
    func workspaceSyncApplyGuidesMissingLocalReferences() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = workspaceSyncConfig(bindings: [
            WorkspaceConfig.EnvBinding(
                name: "API_KEY",
                reference: "authsia://password/API_KEY/password?folder=Workspaces%2Fapi"
            ),
        ])
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(passwords: [])
        )
        let selection = WorkspaceSetupExchange.SyncSelectionPayload(
            schemaVersion: WorkspaceSetupExchange.schemaVersion,
            rows: [
                WorkspaceSetupExchange.SyncRowSelection(id: plan.rows[0].id, action: .repairConfig),
            ]
        )

        do {
            _ = try Workspace.Sync.apply(selection, toWorkspaceRoot: root, currentPlan: plan)
            Issue.record("Expected missing local reference to block repair config.")
        } catch {
            let message = String(describing: error)
            #expect(message.contains("has no local Authsia reference to apply"))
            #expect(message.contains("Refresh with `authsia workspace sync --plan-json`"))
            #expect(message.contains("Open Authsia > Workspace > Sync"))
        }
    }

    @Test("workspace sync apply guides stale row selections")
    func workspaceSyncApplyGuidesStaleRowSelections() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = workspaceSyncConfig(bindings: [
            WorkspaceConfig.EnvBinding(
                name: "API_KEY",
                reference: "authsia://password/API_KEY/password?folder=Workspaces%2Fapi"
            ),
        ])
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(passwords: [])
        )
        let selection = WorkspaceSetupExchange.SyncSelectionPayload(
            schemaVersion: WorkspaceSetupExchange.schemaVersion,
            rows: [
                WorkspaceSetupExchange.SyncRowSelection(id: "stale-row-id", action: .repairConfig),
            ]
        )

        do {
            _ = try Workspace.Sync.apply(selection, toWorkspaceRoot: root, currentPlan: plan)
            Issue.record("Expected stale workspace sync selection to fail with recovery guidance.")
        } catch {
            let message = String(describing: error)
            #expect(message.contains("workspace sync preview is stale"))
            #expect(message.contains("authsia workspace sync --plan-json"))
            #expect(message.contains("authsia workspace sync --apply-json <file>"))
            #expect(message.contains("Open Authsia > Workspace > Sync"))
        }
    }

    @Test("workspace sync help shows importer bulk workflow")
    func workspaceSyncHelpShowsImporterBulkWorkflow() {
        let help = Workspace.Sync.helpMessage(columns: 160)

        #expect(help.contains("select all"))
        #expect(help.contains("apply one action to selected rows"))
        #expect(help.contains("create, import encrypted bundle, copy, move, or skip"))
        #expect(help.contains("--folder"))
    }
}

@Suite("Workspace guarded terminal")
struct WorkspaceGuardedTerminalTests {
    @Test("auto guard flag guides print env shell hook usage")
    func autoGuardFlagGuidesPrintEnvShellHookUsage() throws {
        let command = try Workspace.Guard.parse(["--auto"])

        do {
            try command.run()
            Issue.record("Expected --auto without --print-env to fail with guidance.")
        } catch let error as ValidationError {
            let message = String(describing: error)
            #expect(message.contains("--auto is only valid with --print-env"))
            #expect(message.contains("authsia workspace guard --print-env --auto"))
            #expect(message.contains("remove --auto"))
        }
    }

    @Test("default guarded tools exclude shell expansion and display tools")
    func defaultGuardedToolsExcludeShellExpansionAndDisplayTools() {
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("npm"))
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("npx"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("docker"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("aws"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("terraform"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("tofu"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("kubectl"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("helm"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("gcloud"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("az"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("ansible-playbook"))
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("curl"))
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("echo"))
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("env"))
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("printenv"))
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("sh"))
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("zsh"))
        #expect(WorkspaceGuardedTerminal.blockedDefaultTools.contains("vault"))
        #expect(WorkspaceGuardedTerminal.blockedDefaultTools.contains("op"))
    }

    @Test("default guarded tools exclude agent startup launchers")
    func defaultGuardedToolsExcludeBareJSRuntimes() {
        // These launchers are spawned recursively by agent harnesses, language servers,
        // MCP servers, and plugin hooks. Shimming them routes startup work through
        // `workspace run`, eagerly resolving workspace secrets before a task command.
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("node"))
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("bun"))
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("npx"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("npm"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("uv"))
    }

    @Test("guarded plan creates session exports without parent secrets")
    func guardedPlanCreatesSessionExportsWithoutParentSecrets() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let plan = try WorkspaceGuardedTerminal.plan(
            workspaceRoot: root,
            tools: ["npm"],
            baseTemporaryDirectory: root.appendingPathComponent(".tmp"),
            environment: [
                "PATH": "/opt/homebrew/bin:/usr/bin",
                "SUPER_SECRET_TOKEN": "AUTHSIA_FIXTURE_SECRET_workspaceabcdefghijklmnopqrstuvwxyz123456",
            ]
        )

        #expect(plan.workspaceRoot == root)
        #expect(plan.shimDirectory.path.contains(".tmp/authsia-guard-"))
        #expect(plan.tools == ["npm"])
        #expect(plan.originalSearchPaths == ["/opt/homebrew/bin", "/usr/bin"])
        #expect(plan.environment["AUTHSIA_WORKSPACE_GUARD"] == "1")
        #expect(plan.environment["AUTHSIA_WORKSPACE_ROOT"] == root.path)
        #expect(plan.environment["PATH"] == "\(plan.shimDirectory.path):$PATH")
        #expect(!plan.environment.keys.contains("SUPER_SECRET_TOKEN"))
        #expect(!plan.environment.values.contains { $0.contains("sk_live") })
    }

    @Test("print env adds Python wrappers that survive virtualenv path changes")
    func printEnvAddsPythonWrappersThatSurviveVirtualenvPathChanges() {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let plan = WorkspaceGuardedTerminalPlan(
            workspaceRoot: root,
            shimDirectory: URL(fileURLWithPath: "/tmp/authsia-guard-123", isDirectory: true),
            tools: ["python"],
            environment: [
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": "/tmp/authsia-guard-123",
                "AUTHSIA_WORKSPACE_ROOT": root.path,
                "PATH": "/tmp/authsia-guard-123:$PATH",
            ],
            originalSearchPaths: ["/usr/bin"]
        )

        let rendered = Workspace.Guard.renderShellExports(plan)

        #expect(rendered.contains("export AUTHSIA_WORKSPACE_GUARD_SHIM_DIR='/tmp/authsia-guard-123'"))
        #expect(rendered.contains("awk -v shim=\"$AUTHSIA_WORKSPACE_GUARD_SHIM_DIR\""))
        #expect(rendered.contains("PATH=\"$(_authsia_guard_path_without_shim)\""))
        #expect(rendered.contains("command 'authsia' workspace run -- \"$_authsia_guard_resolved\" \"$@\""))
        #expect(rendered.contains("function python { _authsia_guard_run python \"$@\"; }"))
        #expect(rendered.contains("function python3 { _authsia_guard_run python3 \"$@\"; }"))
        #expect(rendered.contains("function pip { _authsia_guard_run pip \"$@\"; }"))
        #expect(rendered.contains("function pip3 { _authsia_guard_run pip3 \"$@\"; }"))
    }

    @Test("print env routes Python wrappers through the guarded CLI path")
    func printEnvRoutesPythonWrappersThroughGuardedCLIPath() {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let plan = WorkspaceGuardedTerminalPlan(
            workspaceRoot: root,
            shimDirectory: URL(fileURLWithPath: "/tmp/authsia-guard-123", isDirectory: true),
            tools: ["python"],
            environment: [
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": "/tmp/authsia-guard-123",
                "AUTHSIA_WORKSPACE_ROOT": root.path,
                "PATH": "/tmp/authsia-guard-123:$PATH",
            ],
            originalSearchPaths: ["/usr/bin"]
        )

        let rendered = Workspace.Guard.renderShellExports(
            plan,
            authsiaExecutablePath: "/Applications/Authsia.app/Contents/MacOS/authsia"
        )

        #expect(rendered.contains(
            "command '/Applications/Authsia.app/Contents/MacOS/authsia' workspace run -- " +
                "\"$_authsia_guard_resolved\" \"$@\""
        ))
        #expect(!rendered.contains("command authsia workspace run -- \"$_authsia_guard_resolved\" \"$@\""))
    }

    @Test("print env is safe to eval in zsh when Python aliases exist")
    func printEnvIsSafeToEvalInZshWhenPythonAliasesExist() throws {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let plan = WorkspaceGuardedTerminalPlan(
            workspaceRoot: root,
            shimDirectory: URL(fileURLWithPath: "/tmp/authsia-guard-123", isDirectory: true),
            tools: ["python"],
            environment: [
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": "/tmp/authsia-guard-123",
                "AUTHSIA_WORKSPACE_ROOT": root.path,
                "PATH": "/tmp/authsia-guard-123:$PATH",
            ],
            originalSearchPaths: ["/usr/bin"]
        )
        let script = Workspace.Guard.renderShellExports(plan)
        let scriptURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-guard-\(UUID().uuidString).zsh")
        defer { try? FileManager.default.removeItem(at: scriptURL) }
        try script.write(to: scriptURL, atomically: true, encoding: .utf8)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/zsh")
        process.arguments = [
            "-fc",
            """
            alias python='python3'
            original_path="$PATH"
            eval "$(cat \(WorkspaceGuardedTerminal.shellQuoted(scriptURL.path)))"
            eval "$(cat \(WorkspaceGuardedTerminal.shellQuoted(scriptURL.path)))"
            [ "$AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH" = "$original_path" ] && echo guard-original-path-preserved
            whence -w python
            """,
        ]
        let output = Pipe()
        let error = Pipe()
        process.standardOutput = output
        process.standardError = error

        try process.run()
        process.waitUntilExit()

        let stdout = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        _ = error.fileHandleForReading.readDataToEndOfFile()
        #expect(process.terminationStatus == 0)
        #expect(stdout.contains("guard-original-path-preserved"))
        #expect(stdout.contains("python: function"))
    }

    @Test("custom guard tools are persisted and reused")
    func customGuardToolsArePersistedAndReused() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            guardSettings: WorkspaceConfig.GuardSettings(autoTabs: false, tools: ["poetry"])
        )

        let updated = Workspace.Guard.configPersistingRequestedTools(
            config,
            requestedTools: ["codex", "curl", " codex ", "npm"]
        )
        try WorkspaceConfigStore.write(updated, toWorkspaceRoot: root)
        let reloaded = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        let tools = Workspace.Guard.toolsForGuard(config: reloaded, requestedTools: [])

        #expect(reloaded.guardSettings.autoTabs == false)
        #expect(reloaded.guardSettings.tools == ["poetry", "codex"])
        #expect(tools.contains("poetry"))
        #expect(tools.contains("codex"))
        #expect(tools.contains("npm"))
        #expect(!reloaded.guardSettings.tools.contains("curl"))
        #expect(!reloaded.guardSettings.tools.contains("npm"))
    }

    @Test("workspace guard persists an explicit response mode")
    func workspaceGuardPersistsExplicitResponseMode() throws {
        let command = try Workspace.Guard.parse([
            "--response-mode", "block",
            "--dry-run",
        ])
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: WorkspaceConfig.Agents(rules: ["claude-code"]),
            guardSettings: WorkspaceConfig.GuardSettings(responseMode: .confirm)
        )

        let updated = try Workspace.Guard.configPersistingResponseMode(
            config,
            requestedMode: command.responseMode
        )

        #expect(updated.guardSettings.responseMode == .block)
        #expect(updated.guardSettings.autoTabs)
    }

    @Test("print env clears aliases for all shimmed tools")
    func printEnvClearsAliasesForAllShimmedTools() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let plan = try WorkspaceGuardedTerminal.plan(
            workspaceRoot: root,
            tools: ["npm", "aws", "curl", "npm"],
            baseTemporaryDirectory: root.appendingPathComponent(".tmp"),
            environment: ["PATH": "/opt/homebrew/bin:/usr/bin"]
        )
        let rendered = Workspace.Guard.renderShellExports(plan)

        #expect(plan.tools == ["npm", "aws"])
        #expect(plan.aliasTools == ["npm", "aws"])
        #expect(rendered.contains("unalias 'npm' 2>/dev/null || true"))
        #expect(rendered.contains("unalias 'aws' 2>/dev/null || true"))
        #expect(!rendered.contains("unalias 'curl'"))
    }

    @Test("print env clears aliases for custom guard tools")
    func printEnvClearsAliasesForCustomGuardTools() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-custom-alias-\(UUID().uuidString)", isDirectory: true)
        let shimDirectory = base.appendingPathComponent("authsia-guard-123", isDirectory: true)
        try FileManager.default.createDirectory(at: shimDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: base) }
        let codex = shimDirectory.appendingPathComponent("codex")
        try "#!/bin/sh\nexit 0\n".write(to: codex, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: codex.path)
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let plan = WorkspaceGuardedTerminalPlan(
            workspaceRoot: root,
            shimDirectory: shimDirectory,
            tools: ["codex"],
            aliasTools: ["codex"],
            environment: [
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": shimDirectory.path,
                "AUTHSIA_WORKSPACE_ROOT": root.path,
                "PATH": "\(shimDirectory.path):$PATH",
            ],
            originalSearchPaths: ["/usr/bin"]
        )
        let script = Workspace.Guard.renderShellExports(plan)
        let scriptURL = base.appendingPathComponent("guard.zsh")
        try script.write(to: scriptURL, atomically: true, encoding: .utf8)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/zsh")
        process.arguments = [
            "-fc",
            """
            alias codex='echo bypass'
            eval "$(cat \(WorkspaceGuardedTerminal.shellQuoted(scriptURL.path)))"
            command -v codex
            """,
        ]
        let output = Pipe()
        let error = Pipe()
        process.standardOutput = output
        process.standardError = error

        try process.run()
        process.waitUntilExit()

        let stdout = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        _ = error.fileHandleForReading.readDataToEndOfFile()
        #expect(process.terminationStatus == 0)
        #expect(stdout.trimmingCharacters(in: .whitespacesAndNewlines) == codex.path)
    }

    @Test("print env unsets workspace-managed parent env names but preserves Authsia refs")
    func printEnvUnsetsWorkspaceManagedParentEnvNamesButPreservesAuthsiaRefs() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try writeNestedFile(
            """
            STRIPE_KEY=authsia://password/STRIPE_KEY/password
            NODE_ENV=development
            PATH=authsia://password/PATH/password
            INVALID-NAME=authsia://password/INVALID/password
            """,
            relativePath: ".env",
            in: root
        )
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(
                    name: "API_KEY",
                    reference: "authsia://password/API_KEY/password"
                ),
            ]
        )

        let unsetNames = Workspace.Guard.environmentNamesToUnset(
            config: config,
            workspaceRoot: root
        )
        let plan = WorkspaceGuardedTerminalPlan(
            workspaceRoot: root,
            shimDirectory: URL(fileURLWithPath: "/tmp/authsia-guard-123", isDirectory: true),
            tools: ["npm"],
            unsetEnvironmentNames: unsetNames,
            environment: [
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": "/tmp/authsia-guard-123",
                "AUTHSIA_WORKSPACE_ROOT": root.path,
                "PATH": "/tmp/authsia-guard-123:$PATH",
            ],
            originalSearchPaths: ["/usr/bin"]
        )
        let rendered = Workspace.Guard.renderShellExports(plan)

        #expect(unsetNames == ["API_KEY", "STRIPE_KEY"])
        #expect(rendered.contains("case \"${API_KEY-}\" in authsia://*) ;; *) unset API_KEY 2>/dev/null || true ;; esac"))
        #expect(rendered.contains("case \"${STRIPE_KEY-}\" in authsia://*) ;; *) unset STRIPE_KEY 2>/dev/null || true ;; esac"))
        #expect(!rendered.contains("unset NODE_ENV"))
        #expect(!rendered.contains("unset PATH"))
        #expect(!rendered.contains("unset INVALID-NAME"))
    }

    @Test("guarded plan refuses to shim blocked tools even when explicitly requested")
    func guardedPlanRefusesToShimBlockedTools() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        // Blocked names (shells, secret-printing tools, third-party secret managers)
        // must never be shimmed — a name-based shim gives a false sense of safety
        // (shell expansion happens before the shim sees args) or routes secret output
        // outside Authsia's masking boundary. Enforced even via explicit `--tool`.
        let plan = try WorkspaceGuardedTerminal.plan(
            workspaceRoot: root,
            tools: ["npm", "vault", "sh", "curl", "op"],
            baseTemporaryDirectory: root.appendingPathComponent(".tmp"),
            environment: ["PATH": "/opt/homebrew/bin:/usr/bin"]
        )

        #expect(plan.tools.contains("npm"))
        #expect(!plan.tools.contains("vault"))
        #expect(!plan.tools.contains("sh"))
        #expect(!plan.tools.contains("curl"))
        #expect(!plan.tools.contains("op"))
    }

    @Test("blockedTools reports requested names that will not be shimmed")
    func blockedToolsReportsRequestedNamesThatWillNotBeShimmed() {
        let blocked = WorkspaceGuardedTerminal.blockedTools(in: ["npm", "vault", " sh ", "vault", "uv"])

        #expect(blocked == ["vault", "sh"])
    }

    @Test("cleanup removes stale guard dirs, keeps recent ones, current, and foreign dirs")
    func cleanupRemovesStaleGuardDirectories() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-cleanup-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: base) }

        let now = Date()
        func makeDir(_ name: String, ageSeconds: TimeInterval) throws -> URL {
            let url = base.appendingPathComponent(name, isDirectory: true)
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
            try FileManager.default.setAttributes(
                [.modificationDate: now.addingTimeInterval(-ageSeconds)],
                ofItemAtPath: url.path
            )
            return url
        }

        let stale = try makeDir("authsia-guard-\(UUID().uuidString)", ageSeconds: 7200)   // 2h old → remove
        let recent = try makeDir("authsia-guard-\(UUID().uuidString)", ageSeconds: 600)   // 10m old → keep
        let current = try makeDir("authsia-guard-\(UUID().uuidString)", ageSeconds: 7200) // old but current → keep
        let foreign = try makeDir("some-other-tmp-\(UUID().uuidString)", ageSeconds: 7200) // not ours → keep

        let removed = WorkspaceGuardedTerminal.cleanupStaleShimDirectories(
            in: base,
            keeping: current,
            olderThan: 3600,
            now: now
        )

        #expect(removed.map(\.lastPathComponent) == [stale.lastPathComponent])
        #expect(!FileManager.default.fileExists(atPath: stale.path))
        #expect(FileManager.default.fileExists(atPath: recent.path))
        #expect(FileManager.default.fileExists(atPath: current.path))
        #expect(FileManager.default.fileExists(atPath: foreign.path))
    }

    @Test("cleanup is a no-op when the base directory has no guard dirs")
    func cleanupNoOpWhenNoGuardDirectories() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-cleanup-empty-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: base) }

        let removed = WorkspaceGuardedTerminal.cleanupStaleShimDirectories(in: base, now: Date())

        #expect(removed.isEmpty)
    }

    @Test("shim script preserves caller working directory")
    func shimScriptPreservesCallerWorkingDirectory() {
        let script = WorkspaceGuardedTerminal.shimScript(
            authsiaExecutablePath: "/usr/local/bin/authsia",
            toolPath: "/opt/homebrew/bin/npm"
        )

        #expect(!script.contains("\ncd "))
        #expect(script.contains("exec '/usr/local/bin/authsia' workspace run -- '/opt/homebrew/bin/npm' \"$@\""))
        #expect(!script.contains("env npm"))
    }

    @Test("install writes executable shims for resolvable tools")
    func installWritesExecutableShimsForResolvableTools() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let toolBin = root.appendingPathComponent("bin", isDirectory: true)
        try FileManager.default.createDirectory(at: toolBin, withIntermediateDirectories: true)
        let npm = toolBin.appendingPathComponent("npm")
        try "#!/bin/sh\nexit 0\n".write(to: npm, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: npm.path)

        let plan = try WorkspaceGuardedTerminal.plan(
            workspaceRoot: root,
            tools: ["npm", "missing-tool"],
            baseTemporaryDirectory: root.appendingPathComponent(".tmp"),
            environment: ["PATH": toolBin.path]
        )

        let result = try WorkspaceGuardedTerminal.install(
            plan,
            authsiaExecutablePath: "/usr/local/bin/authsia",
            fileManager: .default
        )

        let shim = result.shimDirectory.appendingPathComponent("npm")
        let content = try String(contentsOf: shim, encoding: .utf8)
        let attributes = try FileManager.default.attributesOfItem(atPath: shim.path)
        #expect(FileManager.default.fileExists(atPath: shim.path))
        #expect(content.contains(npm.path))
        #expect(result.installedTools == ["npm"])
        #expect(result.skippedTools == ["missing-tool"])
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o755)
    }

    @Test("print env render emits shell exports and guarded banner")
    func printEnvRenderEmitsShellExportsAndGuardedBanner() {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let plan = WorkspaceGuardedTerminalPlan(
            workspaceRoot: root,
            shimDirectory: URL(fileURLWithPath: "/tmp/authsia-guard-123", isDirectory: true),
            tools: ["npm"],
            environment: [
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "AUTHSIA_WORKSPACE_ROOT": root.path,
                "PATH": "/tmp/authsia-guard-123:$PATH",
            ],
            originalSearchPaths: ["/usr/bin"]
        )

        let rendered = Workspace.Guard.renderShellExports(plan)

        #expect(rendered.contains("export PATH='/tmp/authsia-guard-123':$PATH"))
        #expect(rendered.contains("AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH"))
        #expect(rendered.contains("export AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH"))
        #expect(rendered.contains("export AUTHSIA_WORKSPACE_GUARD=1"))
        #expect(rendered.contains("export AUTHSIA_WORKSPACE_ROOT='/tmp/My Project'"))
        #expect(rendered.contains("Authsia guarded terminal active"))
        #expect(rendered.contains("Workspace-managed parent env names cleared"))
        #expect(!rendered.contains("Parent shell has no plaintext secrets"))
        #expect(!rendered.contains("curl $API_KEY"))
    }

    @Test("guarded shell banner identifies a named effective environment")
    func guardedShellBannerIdentifiesNamedEffectiveEnvironment() {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let plan = WorkspaceGuardedTerminalPlan(
            workspaceRoot: root,
            shimDirectory: URL(fileURLWithPath: "/tmp/authsia-guard-123", isDirectory: true),
            tools: ["npm"],
            environment: [
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "AUTHSIA_WORKSPACE_ROOT": root.path,
                "PATH": "/tmp/authsia-guard-123:$PATH",
            ],
            originalSearchPaths: ["/usr/bin"]
        )

        let named = Workspace.Guard.renderShellExports(plan, activeEnvironment: "Production")
        let defaultEnvironment = Workspace.Guard.renderShellExports(plan, activeEnvironment: nil)

        #expect(named.contains("Effective environment: Production."))
        #expect(named.contains("All-environment items remain available."))
        #expect(!defaultEnvironment.contains("Effective environment:"))
    }

    @Test("auto env prints only when enabled and outside a guarded shell")
    func autoEnvPrintsOnlyWhenEnabledAndOutsideGuardedShell() {
        let enabled = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil
        )
        let disabled = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            guardSettings: WorkspaceConfig.GuardSettings(autoTabs: false)
        )

        #expect(Workspace.Guard.shouldPrintAutoEnv(config: enabled, environment: [:]))
        #expect(Workspace.Guard.shouldPrintAutoEnv(
            config: enabled,
            environment: ["AUTHSIA_WORKSPACE_GUARD": "1"]
        ))
        #expect(!Workspace.Guard.shouldPrintAutoEnv(
            config: enabled,
            environment: [
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "PATH": "/tmp/authsia-guard-123:/usr/bin",
            ]
        ))
        #expect(!Workspace.Guard.shouldPrintAutoEnv(config: disabled, environment: [:]))
    }

    @Test("auto guard can recover workspace root from guarded shell environment")
    func autoGuardCanRecoverWorkspaceRootFromGuardedShellEnvironment() throws {
        let workspaceRoot = try makeWorkspaceRoot()
        let outsideRoot = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: workspaceRoot) }
        defer { try? FileManager.default.removeItem(at: outsideRoot) }
        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
                managedEnvFiles: [],
                agents: nil
            ),
            toWorkspaceRoot: workspaceRoot
        )
        let guardedEnvironment = [
            "AUTHSIA_WORKSPACE_GUARD": "1",
            "AUTHSIA_WORKSPACE_ROOT": workspaceRoot.path,
        ]

        #expect(Workspace.Guard.workspaceRootForGuard(
            auto: true,
            startingAt: outsideRoot,
            environment: guardedEnvironment
        ) == workspaceRoot.standardizedFileURL)
        #expect(Workspace.Guard.workspaceRootForGuard(
            auto: true,
            startingAt: outsideRoot,
            environment: ["AUTHSIA_WORKSPACE_ROOT": workspaceRoot.path]
        ) == nil)
        #expect(Workspace.Guard.workspaceRootForGuard(
            auto: false,
            startingAt: outsideRoot,
            environment: guardedEnvironment
        ) == nil)
    }

    @Test("shell expansion warning names curl variable boundary")
    func shellExpansionWarningNamesCurlVariableBoundary() {
        let warning = WorkspaceGuardedTerminal.shellExpansionWarning

        #expect(warning.contains("curl $API_KEY"))
        #expect(warning.contains("curl ${API_KEY}"))
        #expect(warning.contains("authsia workspace run --shell -- 'curl \"$API_KEY\"'"))
    }
}

@Suite("Workspace agent launch")
struct WorkspaceAgentLaunchTests {
    @Test("agent launch builds secret-free commands and open arguments")
    func agentLaunchBuildsSecretFreeCommandsAndOpenArguments() throws {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let defaultAgent = try Workspace.Agent.parse([])
        let guardedPrefix = "cd '/tmp/My Project' && __authsia_guard_env=\"$(authsia workspace guard --print-env)\" && " +
            "eval \"$__authsia_guard_env\" && unset __authsia_guard_env && "

        #expect(defaultAgent.tool == .claudeCode)
        #expect(WorkspaceAgentTool.allCases.map(\.title) == [
            "Codex",
            "Claude Code",
            "VS Code",
            "Cursor",
            "Windsurf",
        ])
        #expect(WorkspaceAgentTool.allCases.map(\.agentPlatform) == [
            "codex",
            "claude-code",
            "copilot",
            "cursor",
            "windsurf",
        ])
        #expect(
            WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .codex).launchCommand ==
                guardedPrefix + "env AUTHSIA_AGENT_PLATFORM=codex AUTHSIA_AGENT_INVOKES_AUTHSIA=1 codex"
        )
        #expect(
            WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .claudeCode).launchCommand ==
                guardedPrefix + "env AUTHSIA_AGENT_PLATFORM=claude-code AUTHSIA_AGENT_INVOKES_AUTHSIA=1 claude"
        )
        #expect(
            WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .vsCode).launchCommand ==
                guardedPrefix + "env AUTHSIA_AGENT_PLATFORM=copilot AUTHSIA_AGENT_INVOKES_AUTHSIA=1 code ."
        )
        #expect(
            WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .cursor).launchCommand ==
                guardedPrefix + "env AUTHSIA_AGENT_PLATFORM=cursor AUTHSIA_AGENT_INVOKES_AUTHSIA=1 cursor ."
        )
        #expect(
            WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .windsurf).launchCommand ==
                guardedPrefix + "env AUTHSIA_AGENT_PLATFORM=windsurf AUTHSIA_AGENT_INVOKES_AUTHSIA=1 windsurf ."
        )
        #expect(
            WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .vsCode).openArguments ==
                [
                    "-n",
                    "--env", "AUTHSIA_AGENT_PLATFORM=copilot",
                    "--env", "AUTHSIA_AGENT_INVOKES_AUTHSIA=1",
                    "-a", "Visual Studio Code",
                    "--args",
                    "/tmp/My Project",
                ]
        )
        #expect(
            WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .cursor).openArguments ==
                [
                    "-n",
                    "--env", "AUTHSIA_AGENT_PLATFORM=cursor",
                    "--env", "AUTHSIA_AGENT_INVOKES_AUTHSIA=1",
                    "-a", "Cursor",
                    "--args",
                    "/tmp/My Project",
                ]
        )
        #expect(
            WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .windsurf).openArguments ==
                [
                    "-n",
                    "--env", "AUTHSIA_AGENT_PLATFORM=windsurf",
                    "--env", "AUTHSIA_AGENT_INVOKES_AUTHSIA=1",
                    "-a", "Windsurf",
                    "--args",
                    "/tmp/My Project",
                ]
        )
    }

    @Test("terminal agents have no GUI app but are still launch-eligible")
    func terminalAgentsHaveNoGUIAppButAreStillLaunchEligible() {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        // codex and claude-code have no GUI app to `open -a`; previously this left them
        // print-only (never launched). They must now still be eligible to launch.
        #expect(WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .codex).openArguments == nil)
        #expect(WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .claudeCode).openArguments == nil)
        #expect(Workspace.Agent.shouldOpenTool(
            dryRun: false,
            printLaunchCommand: false,
            hasGoalHandoff: false
        ))
    }

    @Test("terminal agent launch uses exec request and repairs dumb TERM")
    func terminalAgentLaunchUsesExecRequestAndRepairsDumbTERM() {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)

        let request = WorkspaceAgentLauncher.currentTerminalLaunchRequest(
            tool: .codex,
            workingDirectory: root,
            environment: ["TERM": "dumb"]
        )
        let existingTerminal = WorkspaceAgentLauncher.currentTerminalLaunchRequest(
            tool: .claudeCode,
            workingDirectory: root,
            environment: ["TERM": "xterm-ghostty"]
        )

        #expect(request.executable == "codex")
        #expect(request.arguments == ["codex"])
        #expect(request.workingDirectory == root)
        #expect(request.environmentOverrides == [
            "TERM": "xterm-256color",
            "AUTHSIA_AGENT_PLATFORM": "codex",
            "AUTHSIA_AGENT_INVOKES_AUTHSIA": "1",
        ])
        #expect(existingTerminal.environmentOverrides == [
            "AUTHSIA_AGENT_PLATFORM": "claude-code",
            "AUTHSIA_AGENT_INVOKES_AUTHSIA": "1",
        ])
    }

    @Test("agent launch failures explain install PATH guarded terminal and print fallback")
    func agentLaunchFailuresExplainInstallPathGuardedTerminalAndPrintFallback() {
        let guiFailure = WorkspaceAgentLauncher.openFailureMessage()
        let enterDirectoryFailure = WorkspaceAgentLauncher.enterDirectoryFailureMessage(path: "/tmp/Missing Project")
        let missingProgram = WorkspaceAgentLauncher.missingProgramMessage(program: "codex")
        let launchFailure = WorkspaceAgentLauncher.launchFailureMessage(program: "claude", detail: "permission denied")

        #expect(guiFailure.contains("Make sure the app is installed"))
        #expect(guiFailure.contains("authsia workspace agent --print"))
        #expect(guiFailure.contains("guarded terminal"))
        #expect(enterDirectoryFailure.contains("Could not enter workspace folder /tmp/Missing Project"))
        #expect(enterDirectoryFailure.contains("Make sure the folder still exists"))
        #expect(enterDirectoryFailure.contains("authsia workspace status"))
        #expect(enterDirectoryFailure.contains("authsia workspace agent --print"))
        #expect(missingProgram.contains("Could not find codex on PATH"))
        #expect(missingProgram.contains("Install codex"))
        #expect(missingProgram.contains("same --tool"))
        #expect(missingProgram.contains("authsia workspace agent --print"))
        #expect(launchFailure.contains("Failed to launch claude: permission denied"))
        #expect(launchFailure.contains("same --tool"))
        #expect(launchFailure.contains("guarded terminal"))
    }

    @Test("agent launch render explains JIT boundary without secrets or shell")
    func agentLaunchRenderExplainsJITBoundaryWithoutSecretsOrShell() {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let rendered = WorkspaceAgentLaunchPlan.render(
            WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .codex)
        )

        #expect(rendered.contains("Agentic workspace launch: Codex"))
        #expect(rendered.contains("Command: cd '/tmp/My Project' && __authsia_guard_env="))
        #expect(rendered.contains("authsia workspace guard --print-env"))
        #expect(rendered.contains(
            "&& env AUTHSIA_AGENT_PLATFORM=codex AUTHSIA_AGENT_INVOKES_AUTHSIA=1 codex"
        ))
        #expect(rendered.contains("Authsia injects no managed secrets"))
        #expect(rendered.contains("guarded terminal"))
        #expect(rendered.contains("JIT/automation"))
        #expect(rendered.contains("authsia workspace run -- <command>"))
        #expect(!rendered.contains("authsia workspace shell"))
        #expect(!rendered.contains("SUPER_SECRET_TOKEN"))
    }

    @Test("agent goal handoff renders launch command and secret boundary")
    func agentGoalHandoffRendersLaunchCommandAndSecretBoundary() {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let guardedLaunch = "cd '/tmp/My Project' && __authsia_guard_env=\"$(authsia workspace guard --print-env)\" && " +
            "eval \"$__authsia_guard_env\" && unset __authsia_guard_env && " +
            "env AUTHSIA_AGENT_PLATFORM=codex AUTHSIA_AGENT_INVOKES_AUTHSIA=1 codex"
        let rendered = WorkspaceAgentLaunchPlan.renderHandoff(
            WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .codex),
            goal: "Fix checkout bug without printing $API_KEY"
        )

        #expect(rendered.contains("Agent goal"))
        #expect(rendered.contains("Workspace: My Project"))
        #expect(rendered.contains("Tool: Codex"))
        #expect(rendered.contains("Launch: \(guardedLaunch)"))
        #expect(rendered.contains("Fix checkout bug without printing $API_KEY"))
        #expect(rendered.contains("authsia workspace status"))
        #expect(rendered.contains("authsia workspace run --dry-run -- <command>"))
        #expect(rendered.contains("JIT or automation token"))
        #expect(rendered.contains("authsia workspace run -- <command>"))
        #expect(rendered.contains("authsia exec"))
        #expect(!rendered.contains("authsia://"))
        #expect(!rendered.contains("sk_live"))
        #expect(rendered == AgentWorkspaceGoalHandoff.make(
            workspaceName: "My Project",
            toolName: "Codex",
            launchCommand: guardedLaunch,
            goal: "Fix checkout bug without printing $API_KEY"
        )?.clipboardText)
    }

    @Test("agent goal validation rejects pasted secrets but allows placeholders")
    func agentGoalValidationRejectsPastedSecretsButAllowsPlaceholders() throws {
        let stripeKey = "sk_" + "live_51ABCDEF1234567890abcdef"

        #expect(try Workspace.Agent.validatedGoal("Fix checkout using $API_KEY and ${Var}") == "Fix checkout using $API_KEY and ${Var}")
        #expect(try Workspace.Agent.validatedGoal("Use authsia://password/API_KEY/password") == "Use authsia://password/API_KEY/password")

        do {
            _ = try Workspace.Agent.validatedGoal("Debug checkout with \(stripeKey)")
            Issue.record("Expected pasted secret goal to be rejected")
        } catch {
            #expect(String(describing: error).contains("appears to contain a secret"))
        }
    }

    @Test("agent goal file reads the same validated handoff text")
    func agentGoalFileReadsTheSameValidatedHandoffText() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let goalFile = root.appendingPathComponent("agent-goal.txt")
        try "  Fix checkout without printing $API_KEY\n".write(to: goalFile, atomically: true, encoding: .utf8)

        #expect(try Workspace.Agent.resolvedGoal(goal: nil, goalFile: goalFile.path) == "Fix checkout without printing $API_KEY")
    }

    @Test("agent goal file dash reads the same validated handoff text from stdin")
    func agentGoalFileDashReadsTheSameValidatedHandoffTextFromStdin() throws {
        #expect(try Workspace.Agent.resolvedGoal(
            goal: nil,
            goalFile: "-",
            standardInput: { "  Fix checkout from piped task brief using $API_KEY\n" }
        ) == "Fix checkout from piped task brief using $API_KEY")
    }

    @Test("agent goal file rejects ambiguous inline goal")
    func agentGoalFileRejectsAmbiguousInlineGoal() throws {
        do {
            _ = try Workspace.Agent.resolvedGoal(goal: "Fix checkout", goalFile: "/tmp/agent-goal.txt")
            Issue.record("Expected --goal and --goal-file to be mutually exclusive")
        } catch {
            #expect(String(describing: error).contains("Use either --goal or --goal-file"))
        }
    }

    @Test("agent goal handoff is print only")
    func agentGoalHandoffIsPrintOnly() {
        #expect(!Workspace.Agent.shouldOpenTool(
            dryRun: false,
            printLaunchCommand: false,
            hasGoalHandoff: true
        ))
        #expect(Workspace.Agent.shouldOpenTool(
            dryRun: false,
            printLaunchCommand: false,
            hasGoalHandoff: false
        ))
        #expect(!Workspace.Agent.shouldOpenTool(
            dryRun: true,
            printLaunchCommand: false,
            hasGoalHandoff: false
        ))
        #expect(!Workspace.Agent.shouldOpenTool(
            dryRun: false,
            printLaunchCommand: true,
            hasGoalHandoff: false
        ))
    }
}

@Suite("Workspace status")
struct WorkspaceStatusTests {
    @Test("status metadata request contains exact typed unverified references")
    func statusMetadataRequestContainsExactReferences() {
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        let status = WorkspaceStatus(
            config: config,
            envFiles: [],
            envBindings: [],
            agentRules: [],
            missingReferences: [],
            unverifiedReferences: [
                WorkspaceMissingReference(
                    relativePath: ".env",
                    itemType: "password",
                    item: "DB_PASSWORD",
                    folderPath: "Workspaces/api"
                ),
                WorkspaceMissingReference(
                    relativePath: ".env",
                    itemType: "certificate",
                    item: "Client Cert",
                    folderPath: "Workspaces/api"
                ),
            ]
        )

        let request = Workspace.workspaceStatusMetadataRequest(status)

        #expect(request.workspaceFolder == "Workspaces/api")
        #expect(request.mode == .status)
        #expect(request.references == [
            WorkspaceMetadataReference(
                itemType: .certificate,
                itemName: "Client Cert",
                folderPath: "Workspaces/api"
            ),
            WorkspaceMetadataReference(
                itemType: .password,
                itemName: "DB_PASSWORD",
                folderPath: "Workspaces/api"
            ),
        ])
    }

    @Test("status counts refs and reports agent rules")
    func statusCountsRefsAndReportsAgentRules() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env", ".env.local"],
            agents: WorkspaceConfig.Agents(rules: ["codex"])
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])

        let status = try await WorkspaceStatusReporter.build(workspaceRoot: root)
        let rendered = WorkspaceStatusReporter.renderTable(status)

        #expect(status.envFiles.first?.authsiaReferenceCount == 1)
        #expect(status.envFiles.last?.isMissing == true)
        #expect(status.agentRules.first?.isInstalled == true)
        #expect(rendered.contains("Workspace: api"))
        #expect(rendered.contains("Status: Needs attention"))
        #expect(rendered.contains("Health: 1 missing env file - 1 authsia:// ref"))
        #expect(rendered.contains("Managed env files: .env, .env.local"))
        #expect(rendered.contains("Agent rules: Codex installed"))
        #expect(rendered.contains("authsia workspace run --"))
        #expect(rendered.contains("authsia lock"))
        #expect(rendered.contains("Access Center"))
    }

    @Test("schema v2 status renders active environment and item environment properties")
    func schemaV2StatusRendersEnvironmentProperties() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let itemID = "00000000-0000-0000-0000-000000000001"
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(
                    name: "API_KEY",
                    reference: "authsia://password/\(itemID)/password"
                ),
            ]
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                password(
                    id: itemID,
                    name: "API_KEY",
                    folderPath: "Workspaces/api",
                    environments: ["Production"]
                ),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let status = try await WorkspaceStatusReporter.build(
            workspaceRoot: root,
            vaultIndex: WorkspaceVaultIndex(payload: payload),
            activeEnvironment: "Production"
        )
        let rendered = WorkspaceStatusReporter.renderTable(status)

        #expect(rendered.contains("Active environment: Production"))
        #expect(rendered.contains("Available environments: Production"))
        #expect(rendered.contains("Effective environment items: 0 default-environment, 1 tagged"))
        #expect(rendered.contains("API_KEY: Production · effective"))
    }

    @Test("schema v2 status keeps local active environment when vault metadata is unavailable")
    func schemaV2StatusKeepsActiveEnvironmentWithoutVaultMetadata() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let status = try await WorkspaceStatusReporter.build(
            workspaceRoot: root,
            vaultIndex: nil,
            activeEnvironment: "Production"
        )

        #expect(status.activeEnvironment == "Production")
        #expect(WorkspaceStatusReporter.renderTable(status).contains("Active environment: Production"))
    }

    @Test("status includes managed env scopes in environment health")
    func statusIncludesManagedEnvScopesInEnvironmentHealth() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env", "services/worker/.env.production"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        try writeNestedFile(
            "WORKER_KEY=authsia://password/WORKER_KEY/password?folder=Workspaces%2Fapi\n",
            relativePath: "services/worker/.env.production",
            in: root
        )
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                password(
                    id: "00000000-0000-0000-0000-000000000001",
                    name: "API_KEY",
                    folderPath: "Workspaces/api",
                    environments: ["All"]
                ),
                password(
                    id: "00000000-0000-0000-0000-000000000002",
                    name: "WORKER_KEY",
                    folderPath: "Workspaces/api",
                    environments: ["Production"]
                ),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let status = try await WorkspaceStatusReporter.build(
            workspaceRoot: root,
            vaultIndex: WorkspaceVaultIndex(payload: payload),
            activeEnvironment: "Production"
        )

        #expect(status.availableEnvironments == ["Production"])
        #expect(status.environmentIssueCount == 0)
        #expect(status.selectionHealth == "healthy")
        #expect(WorkspaceStatusReporter.renderTable(status).contains("Status: Ready"))
    }

    @Test("status health blocks on managed env environment conflicts")
    func statusHealthBlocksOnManagedEnvEnvironmentConflicts() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: ["services/worker/.env.production"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try writeNestedFile(
            "WORKER_KEY=authsia://password/WORKER_KEY/password?folder=Workspaces%2Fapi\n",
            relativePath: "services/worker/.env.production",
            in: root
        )
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                password(
                    id: "00000000-0000-0000-0000-000000000001",
                    name: "WORKER_KEY",
                    folderPath: "Workspaces/api",
                    environments: ["Production"]
                ),
                password(
                    id: "00000000-0000-0000-0000-000000000002",
                    name: "WORKER_KEY",
                    folderPath: "Workspaces/api",
                    environments: ["Production"]
                ),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let status = try await WorkspaceStatusReporter.build(
            workspaceRoot: root,
            vaultIndex: WorkspaceVaultIndex(payload: payload),
            activeEnvironment: "Production"
        )
        let rendered = WorkspaceStatusReporter.renderTable(status)

        #expect(status.environmentIssueCount == 1)
        #expect(status.conflictCount == 1)
        #expect(status.selectionHealth == "needsAttention")
        #expect(rendered.contains("Status: Needs attention"))
        #expect(rendered.contains("1 environment resolution issue"))
    }

    @Test("status command fallback loads the local active environment before metadata approval")
    func statusCommandFallbackLoadsLocalEnvironmentBeforeMetadataApproval() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        let store = WorkspaceEnvironmentSelectionStore(
            fileURL: root.appendingPathComponent("state/workspace-environments.json")
        )
        try store.setActiveEnvironment("Production", for: root)

        let context = try await Workspace.Status.initialStatusContext(
            workspaceRoot: root,
            selectionStore: store
        )

        #expect(context.activeEnvironment == "Production")
        #expect(context.status.activeEnvironment == "Production")
    }

    @Test("status reports workspace env bindings without managed env files")
    func statusReportsWorkspaceEnvBindingsWithoutManagedEnvFiles() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(
                    name: "API_KEY",
                    reference: "authsia://password/API_KEY/password?folder=Workspaces%2Fapi"
                ),
                WorkspaceConfig.EnvBinding(
                    name: "HF_TOKEN",
                    reference: "authsia://password/HF_TOKEN/password?folder=Workspaces%2Fapi"
                ),
            ]
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                password(id: "00000000-0000-0000-0000-000000000001", name: "API_KEY", folderPath: "Workspaces/api"),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let status = try await WorkspaceStatusReporter.build(
            workspaceRoot: root,
            vaultIndex: WorkspaceVaultIndex(payload: payload)
        )
        let rendered = WorkspaceStatusReporter.renderTable(status)

        #expect(status.envBindings.map(\.name) == ["API_KEY", "HF_TOKEN"])
        #expect(status.missingReferences.map(\.item) == ["HF_TOKEN"])
        #expect(rendered.contains("Status: Needs attention"))
        #expect(rendered.contains("Health: 1 missing Authsia reference - 2 authsia:// refs"))
        #expect(rendered.contains("Managed env files: none"))
        #expect(rendered.contains("Workspace env bindings: API_KEY, HF_TOKEN"))
        #expect(rendered.contains("- API_KEY: authsia ref"))
        #expect(rendered.contains("- HF_TOKEN: authsia ref"))
        #expect(rendered.contains(".authsia/workspace.json: env binding HF_TOKEN"))
        #expect(rendered.contains("authsia workspace env add HF_TOKEN"))
        #expect(!rendered.contains("replace the URI in .env"))
        #expect(!rendered.contains("authsia://password/API_KEY"))
    }

    @Test("same-name vault items only conflict when environment tiers overlap")
    func workspaceVaultIndexUsesEnvironmentAwareConflicts() {
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                password(
                    id: "00000000-0000-0000-0000-000000000001",
                    name: "DB_PASSWORD",
                    folderPath: "Workspaces/api",
                    environments: ["Production"]
                ),
                password(
                    id: "00000000-0000-0000-0000-000000000002",
                    name: "DB_PASSWORD",
                    folderPath: "Workspaces/api",
                    environments: []
                ),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )
        let index = WorkspaceVaultIndex(payload: payload)
        let secret = DetectedSecret(
            filePath: ".env.development",
            lineNumber: 1,
            originalLine: "DB_PASSWORD=redacted",
            key: "DB_PASSWORD",
            value: "redacted",
            rawContent: nil,
            confidence: .high,
            type: .password,
            entropy: 0,
            description: "test",
            sshMetadata: nil
        )

        #expect(index.existingItem(for: secret, folderPath: "Workspaces/api", environments: ["Development"]) == nil)
        #expect(index.existingItem(for: secret, folderPath: "Workspaces/api", environments: ["Production"]) != nil)
        #expect(index.existingItem(for: secret, folderPath: "Workspaces/api", environments: []) != nil)
        #expect(!WorkspaceSetupExchange.environmentTiersOverlap(["All"], []))
        #expect(!WorkspaceSetupExchange.environmentTiersOverlap(["All"], ["Production"]))
        #expect(WorkspaceSetupExchange.environmentTiersOverlap(["All"], ["All"]))
    }

    @Test("status does not report arbitrary rule files as installed")
    func statusDoesNotReportArbitraryRuleFilesAsInstalled() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: WorkspaceConfig.Agents(rules: ["codex"])
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        try "rules".write(to: root.appendingPathComponent(".authsia/agent-rules.md"), atomically: true, encoding: .utf8)
        try "agents".write(to: root.appendingPathComponent("AGENTS.md"), atomically: true, encoding: .utf8)

        let status = try await WorkspaceStatusReporter.build(workspaceRoot: root)

        #expect(status.agentRules.first?.isInstalled == false)
    }

    @Test("status reports authsia refs missing from vault with guidance")
    func statusReportsMissingVaultReferencesWithGuidance() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try """
        API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi
        RUNBOOK=authsia://note/Runbook/content?folder=Workspaces%2Fapi
        """.write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                password(id: "00000000-0000-0000-0000-000000000001", name: "API_KEY", folderPath: "Workspaces/api"),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let status = try await WorkspaceStatusReporter.build(
            workspaceRoot: root,
            vaultIndex: WorkspaceVaultIndex(payload: payload)
        )
        let rendered = WorkspaceStatusReporter.renderTable(status)

        #expect(status.missingReferences.map(\.item) == ["Runbook"])
        #expect(rendered.contains("Status: Needs attention"))
        #expect(rendered.contains("1 missing Authsia reference"))
        #expect(rendered.contains("Missing Authsia references:"))
        #expect(rendered.contains("note Runbook in folder Workspaces/api"))
        #expect(rendered.contains("replace the URI in .env with the raw value"))
        #expect(rendered.contains("then run `authsia workspace update --env-file .env`"))
        #expect(rendered.contains("Or edit the env file to point at an existing Authsia item"))
    }

    @Test("status reports password ref missing when metadata exists but secret is gone")
    func statusReportsPasswordReferenceMissingWhenSecretIsGone() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "DB_PASSWORD=authsia://password/DB_PASSWORD/password?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                password(
                    id: "00000000-0000-0000-0000-000000000001",
                    name: "DB_PASSWORD",
                    folderPath: "Workspaces/api",
                    hasSecret: false
                ),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let status = try await WorkspaceStatusReporter.build(
            workspaceRoot: root,
            vaultIndex: WorkspaceVaultIndex(payload: payload)
        )

        #expect(status.missingReferences.map(\.item) == ["DB_PASSWORD"])
    }

    @Test("status reports API key ref missing when metadata exists but secret is gone")
    func statusReportsAPIKeyReferenceMissingWhenSecretIsGone() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "API_KEY=authsia://api-key/API_KEY/key?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [],
            apiKeys: [
                apiKey(
                    id: "00000000-0000-0000-0000-000000000002",
                    name: "API_KEY",
                    folderPath: "Workspaces/api",
                    hasSecret: false
                ),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let status = try await WorkspaceStatusReporter.build(
            workspaceRoot: root,
            vaultIndex: WorkspaceVaultIndex(payload: payload)
        )

        #expect(status.missingReferences.map(\.item) == ["API_KEY"])
    }

    @Test("status warns when authsia refs cannot be validated against the vault")
    func statusWarnsWhenVaultReferencesCannotBeValidated() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try """
        API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi
        """.write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )

        let status = try await WorkspaceStatusReporter.build(workspaceRoot: root, vaultIndex: nil)
        let rendered = WorkspaceStatusReporter.renderTable(status)

        #expect(status.unverifiedReferences.map(\.item) == ["API_KEY"])
        #expect(rendered.contains("Unverified Authsia references:"))
        #expect(rendered.contains("password API_KEY in folder Workspaces/api"))
        #expect(rendered.contains("Open Authsia or run `authsia list passwords`, then rerun this command"))
        #expect(rendered.contains("If Authsia reports it cannot read the Keychain, open Authsia once"))
        #expect(rendered.contains("If an item is missing, restore the raw value"))
        #expect(!rendered.contains("Missing Authsia references:"))
    }
}

private final class RecordingWorkspaceSetupVaultClient: WorkspaceSetupVaultClient {
    private let ensureError: Error?
    private let exposeAddedPasswords: Bool
    private(set) var ensuredFolders: [String] = []
    private(set) var addedPasswords: [String] = []
    private(set) var addedPasswordFolders: [String?] = []
    private(set) var addedAPIKeys: [String] = []
    private(set) var addedAPIKeyFolders: [String?] = []
    private(set) var addedCertificates: [String] = []
    private(set) var addedNotes: [String] = []

    init(ensureError: Error? = nil, exposeAddedPasswords: Bool = true) {
        self.ensureError = ensureError
        self.exposeAddedPasswords = exposeAddedPasswords
    }

    func ensureVaultFolder(path: String) throws -> WriteResult {
        ensuredFolders.append(path)
        if let ensureError {
            throw ensureError
        }
        return WriteResult(id: path, message: "folder ensured")
    }

    func existingPasswordID(named name: String, folderPath: String?) throws -> String? {
        guard exposeAddedPasswords else { return nil }
        return zip(addedPasswords, addedPasswordFolders)
            .first { addedName, addedFolder in
                addedName == name && Self.sameFolder(addedFolder, folderPath)
            }?
            .0
    }
    func existingAPIKeyID(named name: String, folderPath: String?) throws -> String? {
        guard exposeAddedPasswords else { return nil }
        return zip(addedAPIKeys, addedAPIKeyFolders)
            .first { addedName, addedFolder in
                addedName == name && Self.sameFolder(addedFolder, folderPath)
            }?
            .0
    }

    func existingCertificateID(named name: String, folderPath: String?) throws -> String? { nil }
    func existingNoteID(title: String, folderPath: String?) throws -> String? { nil }

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
        addedPasswords.append(name)
        addedPasswordFolders.append(folderPath)
        return WriteResult(id: name, message: "password added")
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
        addedAPIKeys.append(name)
        addedAPIKeyFolders.append(folderPath)
        return WriteResult(id: name, message: "api key added")
    }

    private static func sameFolder(_ lhs: String?, _ rhs: String?) -> Bool {
        normalizeFolder(lhs) == normalizeFolder(rhs)
    }

    private static func normalizeFolder(_ folder: String?) -> String? {
        guard let folder else { return nil }
        let segments = folder
            .split(separator: "/")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        return segments.isEmpty ? nil : segments.joined(separator: "/")
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
        WriteResult(id: query, message: "password updated")
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
        WriteResult(id: query, message: "api key updated")
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
        addedCertificates.append(name)
        return WriteResult(id: name, message: "certificate added")
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
        WriteResult(id: query, message: "certificate updated")
    }

    func addNote(
        title: String,
        content: String,
        isScraped: Bool,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?
    ) throws -> WriteResult {
        addedNotes.append(title)
        return WriteResult(id: title, message: "note added")
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
        WriteResult(id: query, message: "note updated")
    }
}

private final class WorkspaceResetBackupVaultClient: BackupVaultClient, @unchecked Sendable {
    private var noteContents: [String: String] = [:]
    private var manifestContents: [String: String] = [:]

    func addNote(title: String, content: String, isScraped: Bool, folderPath: String?) throws -> WriteResult {
        if title.hasPrefix("authsia_scrape_backups") {
            manifestContents[title] = content
            return WriteResult(id: title, message: "added")
        }
        let id = "note-\(noteContents.count + 1)"
        noteContents[id] = content
        noteContents[title] = content
        return WriteResult(id: id, message: "added")
    }

    func updateNote(
        query: String,
        title: String?,
        content: String?,
        isScraped: Bool?,
        folderPath: String?
    ) throws -> WriteResult {
        if let content {
            manifestContents[query] = content
        }
        return WriteResult(id: query, message: "updated")
    }

    func getNote(query: String) throws -> NoteResult {
        if let content = manifestContents[query] {
            return noteResult(id: query, title: query, content: content)
        }
        if query.hasPrefix("authsia_scrape_backups") {
            throw BridgeClientError.bridgeError(code: "notFound", message: "not found", query: query)
        }
        if let content = noteContents[query] {
            return noteResult(id: query, title: query, content: content)
        }
        throw BridgeClientError.bridgeError(code: "notFound", message: "not found", query: query)
    }

    func deleteNote(query: String) throws -> WriteResult {
        noteContents.removeValue(forKey: query)
        manifestContents.removeValue(forKey: query)
        return WriteResult(id: query, message: "deleted")
    }

    func list() throws -> BridgeListPayload {
        BridgeListPayload(accounts: [], passwords: [], certificates: [], notes: [], sshKeys: [])
    }

    private func noteResult(id: String, title: String, content: String) -> NoteResult {
        NoteResult(
            id: id,
            title: title,
            content: content,
            createdAt: Date(timeIntervalSince1970: 0),
            modifiedAt: Date(timeIntervalSince1970: 0),
            isFavorite: false
        )
    }
}

private final class WorkspaceResetDenyingVaultClient: BackupVaultClient, @unchecked Sendable {
    private let error: BridgeClientError

    init(error: BridgeClientError) {
        self.error = error
    }

    func addNote(title: String, content: String, isScraped: Bool, folderPath: String?) throws -> WriteResult {
        throw error
    }

    func updateNote(
        query: String,
        title: String?,
        content: String?,
        isScraped: Bool?,
        folderPath: String?
    ) throws -> WriteResult {
        throw error
    }

    func getNote(query: String) throws -> NoteResult {
        throw error
    }

    func deleteNote(query: String) throws -> WriteResult {
        throw error
    }

    func list() throws -> BridgeListPayload {
        throw error
    }
}

private func makeWorkspaceRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("authsia-workspace-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    return root
}

private func read(_ path: String, in root: URL) throws -> String {
    try String(contentsOf: root.appendingPathComponent(path), encoding: .utf8)
}

private func writeNestedFile(_ content: String, relativePath: String, in root: URL) throws {
    let url = root.appendingPathComponent(relativePath)
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try content.write(to: url, atomically: true, encoding: .utf8)
}

private func workspaceSyncConfig(bindings: [WorkspaceConfig.EnvBinding]) -> WorkspaceConfig {
    WorkspaceConfig(
        workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
        managedEnvFiles: [],
        agents: nil,
        envBindings: bindings
    )
}

private func workspaceSyncPayload(passwords: [BridgePassword], apiKeys: [BridgeAPIKey] = []) -> BridgeListPayload {
    BridgeListPayload(
        accounts: [],
        passwords: passwords,
        apiKeys: apiKeys,
        certificates: [],
        notes: [],
        sshKeys: []
    )
}

private func apiKey(id: String, name: String, folderPath: String?, hasSecret: Bool? = nil) -> BridgeAPIKey {
    BridgeAPIKey(
        id: UUID(uuidString: id)!,
        name: name,
        website: nil,
        folderPath: folderPath,
        isFavorite: false,
        isCliEnabled: true,
        isScraped: false,
        createdAt: Date(),
        updatedAt: Date(),
        hasSecret: hasSecret
    )
}

private func workspaceDetectedSecret(
    key: String,
    confidence: SecretConfidence = .high,
    type: SecretType = .password,
    value: String? = nil,
    filePath: String = "/tmp/project/.env",
    lineNumber: Int = 1
) -> DetectedSecret {
    let value = value ?? "sk_live_\(key.lowercased())abcdefghijklmnopqrstuvwxyz123456"
    return DetectedSecret(
        filePath: filePath,
        lineNumber: lineNumber,
        originalLine: "\(key)=\(value)",
        key: key,
        value: value,
        rawContent: nil,
        confidence: confidence,
        type: type,
        entropy: 5.0,
        description: "test secret",
        sshMetadata: nil
    )
}

private func password(
    id: String,
    name: String,
    folderPath: String?,
    hasSecret: Bool? = nil,
    environments: [String] = []
) -> BridgePassword {
    BridgePassword(
        id: UUID(uuidString: id)!,
        name: name,
        username: "u",
        website: nil,
        folderPath: folderPath,
        isFavorite: false,
        isCliEnabled: true,
        isScraped: false,
        createdAt: Date(timeIntervalSince1970: 0),
        updatedAt: Date(timeIntervalSince1970: 0),
        hasSecret: hasSecret,
        environments: environments
    )
}
