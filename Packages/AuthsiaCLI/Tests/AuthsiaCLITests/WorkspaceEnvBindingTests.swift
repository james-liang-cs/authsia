import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
@testable import authsia

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
