import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
@testable import authsia

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
