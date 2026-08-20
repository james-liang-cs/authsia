import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
@testable import authsia

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

        #expect(rendered.contains("Remove workspace config"))
        #expect(rendered.contains(".authsia/workspace.json"))
        #expect(rendered.contains(".env"))
        #expect(rendered.contains("keep file"))
        #expect(rendered.contains(".env.local"))
        #expect(rendered.contains("missing"))
        #expect(rendered.contains("Agent rule artifacts:"))
        #expect(rendered.contains(".authsia/agent-rules.md"))
        #expect(rendered.contains("AGENTS.md"))
        #expect(rendered.contains("Env file restore:"))
        #expect(rendered.contains("Authsia scrape backup"))
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
        #expect(rendered.contains("Warning"))
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
