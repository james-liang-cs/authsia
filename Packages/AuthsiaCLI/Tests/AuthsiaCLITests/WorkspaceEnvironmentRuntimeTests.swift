import AuthenticatorBridge
import Foundation
import Testing
@testable import authsia

@Suite("Workspace environment runtime")
struct WorkspaceEnvironmentRuntimeTests {
    @Test("conventional env filenames suggest but do not silently select tags")
    func filenameSuggestions() {
        #expect(WorkspaceEnvironmentSuggestion.from(path: ".env.production") == "Production")
        #expect(WorkspaceEnvironmentSuggestion.from(path: ".env.development.local") == "Development")
        #expect(WorkspaceEnvironmentSuggestion.from(path: ".env") == nil)
    }

    @Test("workspace run parses one-run environment choices")
    func runParsesEnvironmentChoices() throws {
        let named = try Workspace.Run.parse(["--environment", "Production", "--", "npm", "test"])
        let `default` = try Workspace.Run.parse(["--default-only", "--", "npm", "test"])

        #expect(named.environment == "Production")
        #expect(!named.defaultOnly)
        #expect(`default`.defaultOnly)
    }

    @Test("workspace run rejects the removed shared-only override")
    func runRejectsRemovedSharedOnlyOverride() {
        #expect(throws: (any Error).self) {
            _ = try Workspace.Run.parse(["--shared-only", "--", "npm", "test"])
        }
    }

    @Test("workspace run selection uses one stored environment unless a one-run choice overrides it")
    func runSelectionUsesStoredEnvironmentAndOneRunOverrides() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("workspace-run-selection-\(UUID().uuidString)", isDirectory: true)
        let store = WorkspaceEnvironmentSelectionStore(
            fileURL: root.appendingPathComponent("state/workspace-environments.json")
        )
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try store.setActiveEnvironment("Development", for: root)

        let stored = try Workspace.Run.environmentSelection(
            environment: nil,
            defaultOnly: false,
            workspaceRoot: root,
            store: store
        )
        let namedOverride = try Workspace.Run.environmentSelection(
            environment: "Production",
            defaultOnly: false,
            workspaceRoot: root,
            store: store
        )
        let defaultOverride = try Workspace.Run.environmentSelection(
            environment: nil,
            defaultOnly: true,
            workspaceRoot: root,
            store: store
        )

        #expect(stored == .named("Development"))
        #expect(namedOverride == .named("Production"))
        #expect(defaultOverride == .defaultOnly)
        #expect(try store.activeEnvironment(for: root) == "Development")
    }

    @Test("workspace run fails closed when the selected environment is stale")
    func runFailsClosedForStaleSelection() {
        let productionID = UUID(uuidString: "DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD")!
        let root = URL(fileURLWithPath: "/tmp/authsia-stale-environment-test", isDirectory: true)
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: .init(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                .init(name: "DATABASE_URL", reference: "authsia://api-key/\(productionID.uuidString)/key"),
            ]
        )
        let plan = WorkspaceRunPlan(
            workspaceRoot: root,
            config: config,
            envFiles: [],
            managedEnvFileCount: 0,
            envBindings: [:],
            activeEnvironment: nil,
            defaultOnly: true,
            commandArgs: ["/usr/bin/true"],
            usesShell: false
        )
        let timestamp = Date(timeIntervalSince1970: 0)
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [],
            apiKeys: [
                BridgeAPIKey(id: productionID, name: "DATABASE_URL", website: nil, folderPath: "Workspaces/api", isFavorite: false, isCliEnabled: true, isScraped: false, createdAt: timestamp, updatedAt: timestamp, environments: ["Production"]),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        #expect(throws: (any Error).self) {
            _ = try Workspace.Run.applyingEnvironment(
                to: plan,
                selection: .named("Staging"),
                payload: payload
            )
        }
    }

    @Test("schema v2 evaluation selects active tag and returns only effective overrides")
    func v2EvaluationReturnsEffectiveOverrides() throws {
        let productionID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
        let developmentID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: .init(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                .init(name: "DATABASE_URL", reference: "authsia://api-key/\(developmentID.uuidString)/key"),
                .init(name: "DATABASE_URL", reference: "authsia://api-key/\(productionID.uuidString)/key"),
            ]
        )
        let timestamp = Date(timeIntervalSince1970: 0)
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [],
            apiKeys: [
                BridgeAPIKey(id: developmentID, name: "DATABASE_URL", website: nil, isFavorite: false, isCliEnabled: true, isScraped: false, createdAt: timestamp, updatedAt: timestamp, environments: ["Development"]),
                BridgeAPIKey(id: productionID, name: "DATABASE_URL", website: nil, isFavorite: false, isCliEnabled: true, isScraped: false, createdAt: timestamp, updatedAt: timestamp, environments: ["Production"]),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let evaluation = WorkspaceEnvironmentEvaluation.evaluate(
            config: config,
            payload: payload,
            selection: .named("Production")
        )

        #expect(evaluation.resolution.issues.isEmpty)
        #expect(evaluation.environmentOverrides == [
            "DATABASE_URL": "authsia://api-key/\(productionID.uuidString)/key",
        ])
    }

    @Test("same-name name-and-folder references resolve by active environment through runtime secret fetch")
    func nameAndFolderReferencesResolveSameNameEnvironmentPair() throws {
        let developmentID = UUID(uuidString: "66666666-6666-6666-6666-666666666666")!
        let productionID = UUID(uuidString: "77777777-7777-7777-7777-777777777777")!
        let reference = "authsia://api-key/DATABASE_URL/key?folder=Workspaces%2Fapi"
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: .init(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                .init(name: "DATABASE_URL", reference: reference),
                .init(name: "DATABASE_URL", reference: reference),
            ]
        )
        let timestamp = Date(timeIntervalSince1970: 0)
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [],
            apiKeys: [
                BridgeAPIKey(id: developmentID, name: "DATABASE_URL", website: nil, folderPath: "Workspaces/api", isFavorite: false, isCliEnabled: true, isScraped: false, createdAt: timestamp, updatedAt: timestamp, environments: ["Development"]),
                BridgeAPIKey(id: productionID, name: "DATABASE_URL", website: nil, folderPath: "Workspaces/api", isFavorite: false, isCliEnabled: true, isScraped: false, createdAt: timestamp, updatedAt: timestamp, environments: ["Production"]),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let development = WorkspaceEnvironmentEvaluation.evaluate(config: config, payload: payload, selection: .named("Development"))
        let production = WorkspaceEnvironmentEvaluation.evaluate(config: config, payload: payload, selection: .named("Production"))
        let defaultOnly = WorkspaceEnvironmentEvaluation.evaluate(config: config, payload: payload, selection: .defaultOnly)

        var developmentClient = MockResolverClient()
        developmentClient.apiKeys[developmentID.uuidString] = "development-value"
        let resolvedDevelopment = try SecretReferenceResolver(client: developmentClient)
            .resolveEnvironment(development.environmentOverrides)

        var productionClient = MockResolverClient()
        productionClient.apiKeys[productionID.uuidString] = "production-value"
        let resolvedProduction = try SecretReferenceResolver(client: productionClient)
            .resolveEnvironment(production.environmentOverrides)

        #expect(development.resolution.issues.isEmpty)
        #expect(development.environmentOverrides == [
            "DATABASE_URL": "authsia://api-key/\(developmentID.uuidString)/key",
        ])
        #expect(resolvedDevelopment.resolved == ["DATABASE_URL": "development-value"])
        #expect(production.resolution.issues.isEmpty)
        #expect(production.environmentOverrides == [
            "DATABASE_URL": "authsia://api-key/\(productionID.uuidString)/key",
        ])
        #expect(resolvedProduction.resolved == ["DATABASE_URL": "production-value"])
        #expect(defaultOnly.resolution.issues.isEmpty)
        #expect(defaultOnly.environmentOverrides.isEmpty)
        #expect(config.envBindings.map(\.reference) == [reference, reference])
    }

    @Test("active environment precedence preserves the configured Authsia URI")
    func activeEnvironmentPrecedencePreservesURI() {
        let parentID = UUID(uuidString: "99999999-9999-9999-9999-999999999999")!
        let childID = UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!
        let parentReference = "authsia://api-key/DATABASE_URL/key?folder=Workspaces%2Fapi"
        let childReference = "authsia://api-key/DATABASE_URL/key?folder=Workspaces%2Fapi%2Fservices%2Fpayments"
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: .init(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                .init(name: "DATABASE_URL", reference: parentReference),
                .init(name: "DATABASE_URL", reference: childReference),
            ]
        )
        let timestamp = Date(timeIntervalSince1970: 0)
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [],
            apiKeys: [
                BridgeAPIKey(id: parentID, name: "DATABASE_URL", website: nil, folderPath: "Workspaces/api", isFavorite: false, isCliEnabled: true, isScraped: false, createdAt: timestamp, updatedAt: timestamp, environments: ["Production"]),
                BridgeAPIKey(id: childID, name: "DATABASE_URL", website: nil, folderPath: "Workspaces/api/services/payments", isFavorite: false, isCliEnabled: true, isScraped: false, createdAt: timestamp, updatedAt: timestamp, environments: []),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let evaluation = WorkspaceEnvironmentEvaluation.evaluate(
            config: config,
            payload: payload,
            selection: .named("Production")
        )

        #expect(evaluation.resolution.issues.isEmpty)
        #expect(evaluation.environmentOverrides == [
            "DATABASE_URL": "authsia://api-key/\(parentID.uuidString)/key",
        ])
        #expect(config.envBindings.map(\.reference) == [parentReference, childReference])
    }

    @Test("nested folder resolution uses item metadata for item-ID references")
    func nestedFolderResolutionUsesMetadataForItemIDReferences() {
        let parentID = UUID(uuidString: "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")!
        let childID = UUID(uuidString: "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC")!
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: .init(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                .init(name: "DATABASE_URL", reference: "authsia://api-key/\(parentID.uuidString)/key"),
                .init(name: "DATABASE_URL", reference: "authsia://api-key/\(childID.uuidString)/key"),
            ]
        )
        let timestamp = Date(timeIntervalSince1970: 0)
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [],
            apiKeys: [
                BridgeAPIKey(id: parentID, name: "DATABASE_URL", website: nil, folderPath: "Workspaces/api", isFavorite: false, isCliEnabled: true, isScraped: false, createdAt: timestamp, updatedAt: timestamp, environments: ["Production"]),
                BridgeAPIKey(id: childID, name: "DATABASE_URL", website: nil, folderPath: "Workspaces/api/services/payments", isFavorite: false, isCliEnabled: true, isScraped: false, createdAt: timestamp, updatedAt: timestamp, environments: ["Production"]),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let evaluation = WorkspaceEnvironmentEvaluation.evaluate(
            config: config,
            payload: payload,
            selection: .named("Production")
        )

        #expect(evaluation.resolution.issues.isEmpty)
        #expect(evaluation.environmentOverrides == [
            "DATABASE_URL": "authsia://api-key/\(childID.uuidString)/key",
        ])
    }

    @Test("managed env files exclude inactive environment references")
    func managedEnvFilesExcludeInactiveReferences() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let developmentID = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
        let productionID = UUID(uuidString: "44444444-4444-4444-4444-444444444444")!
        let developmentFile = root.appendingPathComponent(".env.development")
        let productionFile = root.appendingPathComponent(".env.production")
        try "DATABASE_URL=authsia://api-key/\(developmentID.uuidString)/key\n".write(to: developmentFile, atomically: true, encoding: .utf8)
        try "DATABASE_URL=authsia://api-key/\(productionID.uuidString)/key\n".write(to: productionFile, atomically: true, encoding: .utf8)
        let timestamp = Date(timeIntervalSince1970: 0)
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [],
            apiKeys: [
                BridgeAPIKey(id: developmentID, name: "DATABASE_URL", website: nil, isFavorite: false, isCliEnabled: true, isScraped: false, createdAt: timestamp, updatedAt: timestamp, environments: ["Development"]),
                BridgeAPIKey(id: productionID, name: "DATABASE_URL", website: nil, isFavorite: false, isCliEnabled: true, isScraped: false, createdAt: timestamp, updatedAt: timestamp, environments: ["Production"]),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: .init(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env.development", ".env.production"],
            agents: nil
        )

        let evaluation = try WorkspaceEnvironmentEvaluation.evaluate(
            config: config,
            envFiles: [developmentFile.path, productionFile.path],
            payload: payload,
            selection: .named("Production")
        )

        #expect(evaluation.environmentOverrides == [
            "DATABASE_URL": "authsia://api-key/\(productionID.uuidString)/key",
        ])
    }

    @Test("nearest managed env file wins within the active environment")
    func nearestManagedEnvFileWinsWithinActiveEnvironment() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let nested = root.appendingPathComponent("services/payments", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let rootID = UUID(uuidString: "77777777-7777-7777-7777-777777777777")!
        let nestedID = UUID(uuidString: "88888888-8888-8888-8888-888888888888")!
        let rootFile = root.appendingPathComponent(".env")
        let nestedFile = nested.appendingPathComponent(".env")
        try "DATABASE_URL=authsia://api-key/\(rootID.uuidString)/key\n".write(
            to: rootFile,
            atomically: true,
            encoding: .utf8
        )
        try "DATABASE_URL=authsia://api-key/\(nestedID.uuidString)/key\n".write(
            to: nestedFile,
            atomically: true,
            encoding: .utf8
        )
        let timestamp = Date(timeIntervalSince1970: 0)
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [],
            apiKeys: [
                BridgeAPIKey(id: rootID, name: "DATABASE_URL", website: nil, folderPath: "Workspaces/api", isFavorite: false, isCliEnabled: true, isScraped: false, createdAt: timestamp, updatedAt: timestamp, environments: ["Production"]),
                BridgeAPIKey(id: nestedID, name: "DATABASE_URL", website: nil, folderPath: "Workspaces/api", isFavorite: false, isCliEnabled: true, isScraped: false, createdAt: timestamp, updatedAt: timestamp, environments: ["Production"]),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: .init(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env", "services/payments/.env"],
            agents: nil
        )

        let evaluation = try WorkspaceEnvironmentEvaluation.evaluate(
            config: config,
            envFiles: [rootFile.path, nestedFile.path],
            payload: payload,
            selection: .named("Production")
        )

        #expect(evaluation.resolution.issues.isEmpty)
        #expect(evaluation.environmentOverrides == [
            "DATABASE_URL": "authsia://api-key/\(nestedID.uuidString)/key",
        ])
    }

    @Test("explicit one-run env files override configured tagged candidates")
    func explicitOneRunEnvOverridesConfiguredCandidate() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let explicitFile = root.appendingPathComponent("override.env")
        try "DATABASE_URL=local-test-value\n".write(to: explicitFile, atomically: true, encoding: .utf8)
        let productionID = UUID(uuidString: "55555555-5555-5555-5555-555555555555")!
        let timestamp = Date(timeIntervalSince1970: 0)
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: .init(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                .init(name: "DATABASE_URL", reference: "authsia://api-key/\(productionID.uuidString)/key"),
            ]
        )
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [],
            apiKeys: [
                BridgeAPIKey(id: productionID, name: "DATABASE_URL", website: nil, isFavorite: false, isCliEnabled: true, isScraped: false, createdAt: timestamp, updatedAt: timestamp, environments: ["Production"]),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let evaluation = try WorkspaceEnvironmentEvaluation.evaluate(
            config: config,
            envFiles: [],
            explicitEnvFiles: [explicitFile.path],
            payload: payload,
            selection: .named("Production")
        )

        #expect(evaluation.environmentOverrides == ["DATABASE_URL": "local-test-value"])
    }

    @Test("global env command includes workspace show without removing profile commands")
    func envCommandIncludesWorkspaceShow() {
        let help = Env.helpMessage(columns: 140)
        #expect(help.contains("show"))
        #expect(help.contains("add"))
        #expect(help.contains("use"))
        #expect(help.contains("clear"))
    }
}
