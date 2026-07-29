import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
@testable import authsia

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
