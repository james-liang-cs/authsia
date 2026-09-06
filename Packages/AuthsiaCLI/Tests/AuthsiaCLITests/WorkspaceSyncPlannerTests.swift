import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
@testable import authsia

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

    @Test("sync treats an unscoped UUID in the workspace folder as satisfied")
    func syncSatisfiesUnscopedUUIDInWorkspaceFolder() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let itemID = "00000000-0000-0000-0000-000000000001"
        let config = workspaceSyncConfig(bindings: [
            WorkspaceConfig.EnvBinding(
                name: "API_KEY",
                reference: "authsia://password/\(itemID)/password"
            ),
        ])

        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(passwords: [
                password(id: itemID, name: "API_KEY", folderPath: "Workspaces/api"),
            ])
        )

        #expect(plan.satisfied.map(\.envName) == ["API_KEY"])
        #expect(plan.satisfied.first?.itemName == "API_KEY")
        #expect(plan.satisfied.allSatisfy { !$0.selected && $0.action == .none })
        #expect(plan.external.isEmpty)
        #expect(plan.mismatches.isEmpty)
    }

    @Test("sync satisfies an unscoped UUID whose item name is not a valid env name")
    func syncSatisfiesUnscopedUUIDWhenItemNameIsNotAnEnvName() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let itemID = "00000000-0000-0000-0000-000000000009"
        let config = workspaceSyncConfig(bindings: [
            WorkspaceConfig.EnvBinding(
                name: "Demo_API_Key",
                reference: "authsia://api-key/\(itemID)/key"
            ),
        ])

        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(
                passwords: [],
                apiKeys: [
                    apiKey(id: itemID, name: "Demo API Key", folderPath: "Workspaces/api"),
                ]
            )
        )

        #expect(plan.satisfied.map(\.envName) == ["Demo_API_Key"])
        #expect(plan.satisfied.first?.itemName == "Demo API Key")
        #expect(plan.external.isEmpty)
        #expect(plan.extras.isEmpty)
    }

    @Test("sync keeps a cross-folder unscoped UUID external and apply leaves it untouched")
    func syncKeepsCrossFolderUnscopedUUIDExternal() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let itemID = "00000000-0000-0000-0000-000000000007"
        let config = workspaceSyncConfig(bindings: [
            WorkspaceConfig.EnvBinding(
                name: "SHARED_TOKEN",
                reference: "authsia://password/\(itemID)/password"
            ),
        ])

        let plan = WorkspaceSyncPlanner.plan(
            workspaceRoot: root,
            config: config,
            vaultPayload: workspaceSyncPayload(passwords: [
                password(id: itemID, name: "SHARED_TOKEN", folderPath: "Shared/team"),
            ])
        )
        let applied = WorkspaceSyncPlanner.applying(.addToConfig, toSelectedRowsIn: plan)

        #expect(plan.external.map(\.envName) == ["SHARED_TOKEN"])
        #expect(plan.external.allSatisfy { !$0.selected && $0.action == .none })
        #expect(applied.external.allSatisfy { !$0.selected && $0.action == .none })
        #expect(plan.satisfied.isEmpty)
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
