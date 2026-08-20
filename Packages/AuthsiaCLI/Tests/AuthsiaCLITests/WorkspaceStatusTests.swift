import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
@testable import authsia

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
        #expect(rendered.contains("| Field"))
        #expect(rendered.contains("| Value"))
        #expect(rendered.contains("| Path"))
        #expect(rendered.contains("| State"))
        #expect(rendered.contains("api"))
        #expect(rendered.contains("Needs attention"))
        #expect(rendered.contains("1 missing env file - 1 authsia:// ref"))
        #expect(rendered.contains(".env, .env.local"))
        #expect(rendered.contains("Codex installed"))
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

        #expect(rendered.contains("Production"))
        #expect(rendered.contains("0 default-environment, 1 tagged"))
        #expect(rendered.contains("API_KEY"))
        #expect(rendered.contains("effective"))
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
        #expect(WorkspaceStatusReporter.renderTable(status).contains("Production"))
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
        #expect(WorkspaceStatusReporter.renderTable(status).contains("Ready"))
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
        #expect(rendered.contains("Needs attention"))
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
        #expect(rendered.contains("Needs attention"))
        #expect(rendered.contains("1 missing Authsia reference - 2 authsia:// refs"))
        #expect(rendered.contains("none"))
        #expect(rendered.contains("API_KEY, HF_TOKEN"))
        #expect(rendered.contains("API_KEY"))
        #expect(rendered.contains("HF_TOKEN"))
        #expect(rendered.contains("authsia ref"))
        #expect(rendered.contains(".authsia/workspace.json"))
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
        #expect(rendered.contains("Needs attention"))
        #expect(rendered.contains("1 missing Authsia reference"))
        #expect(rendered.contains("Missing Authsia references:"))
        #expect(rendered.contains("Runbook"))
        #expect(rendered.contains("note"))
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
        #expect(rendered.contains("password"))
        #expect(rendered.contains("API_KEY"))
        #expect(rendered.contains("Open Authsia or run `authsia list passwords`, then rerun this command"))
        #expect(rendered.contains("If Authsia reports it cannot read the Keychain, open Authsia once"))
        #expect(rendered.contains("If an item is missing, restore the raw value"))
        #expect(!rendered.contains("Missing Authsia references:"))
    }
}
