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
        #expect(help.contains("Manage workspace env bindings and environment selection"))
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
        #expect(!runHelp.contains("--cleanup-secret-files"))
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
                    "authsia workspace env show",
                    "authsia workspace env use Production",
                    "authsia workspace env use Default",
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
            (
                "workspace env show",
                Env.WorkspaceShow.helpMessage(columns: 160),
                ["authsia workspace env show"]
            ),
            (
                "workspace env use",
                Env.WorkspaceUse.helpMessage(columns: 160),
                [
                    "authsia workspace env use Production",
                    "authsia workspace env use Default",
                ]
            ),
            (
                "workspace env clear",
                Env.WorkspaceClear.helpMessage(columns: 160),
                ["authsia workspace env clear"]
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
