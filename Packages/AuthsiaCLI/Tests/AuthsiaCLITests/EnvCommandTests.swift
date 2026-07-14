import Testing
import Foundation
import AuthenticatorBridge
@testable import authsia

@Suite("Environment command")
struct EnvCommandTests {

    @Test("workspace environments include tags referenced only by managed env files")
    func workspaceEnvironmentsIncludeManagedEnvFileReferences() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("env-workspace-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let itemID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
        try "API_KEY=authsia://api-key/API_KEY/key?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env.production"),
            atomically: true,
            encoding: .utf8
        )
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: .init(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env.production"],
            agents: nil
        )
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [],
            apiKeys: [
                BridgeAPIKey(
                    id: itemID,
                    name: "API_KEY",
                    website: nil,
                    folderPath: "Workspaces/api",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: .distantPast,
                    updatedAt: .distantPast,
                    environments: ["Production"]
                ),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let evaluation = try Env.workspaceEnvironmentEvaluation(
            root: root,
            config: config,
            payload: payload,
            selection: .defaultOnly
        )

        #expect(evaluation.resolution.availableEnvironments == ["Production"])
    }

    @Test("add persists normalized folder mapping")
    func addPersistsNormalizedFolderMapping() throws {
        let (store, directory) = makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        let profile = try Env.addProfile(
            name: "  Production  ",
            folder: " Team / API / ",
            store: store
        )
        let loaded = try store.loadAll()

        #expect(profile.name == "Production")
        #expect(profile.folderPath == "Team/API")
        #expect(profile.scope == .folders(["Team/API"]))
        #expect(loaded == [profile])
    }

    @Test("add persists all scope")
    func addPersistsAllScope() throws {
        let (store, directory) = makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        let profile = try Env.addProfile(
            name: "Default",
            folders: [],
            all: true,
            store: store
        )

        #expect(profile.name == "Default")
        #expect(profile.scope == .all)
        #expect(profile.folderPaths.isEmpty)
    }

    @Test("add persists multiple normalized folders")
    func addPersistsMultipleNormalizedFolders() throws {
        let (store, directory) = makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        let profile = try Env.addProfile(
            name: "Production",
            folders: [" Team / API / ", "Team/Web", "Team/API"],
            all: false,
            store: store
        )

        #expect(profile.scope == .folders(["Team/API", "Team/Web"]))
        #expect(profile.folderPaths == ["Team/API", "Team/Web"])
    }

    @Test("list shows saved profiles and JSON decodes")
    func listShowsSavedProfilesAndJSONDecodes() throws {
        let (store, directory) = makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        _ = try Env.addProfile(name: "Production", folder: "Team/API", store: store)
        _ = try Env.addProfile(name: "Default", folders: [], all: true, store: store)
        _ = try Env.addProfile(name: "Staging", folder: "Team/Staging", store: store)
        _ = try Env.useProfile(name: "Staging", store: store)

        let items = try Env.listItems(store: store)
        let output = try Env.renderList(items: items, format: .json)
        let decoded = try JSONDecoder().decode([Env.ListItem].self, from: Data(output.utf8))

        #expect(decoded.count == 3)
        #expect(decoded.contains(where: { $0.name == "Default" && $0.scope == "all" }))
        #expect(decoded.contains(where: { $0.name == "Production" && $0.isActive == false }))
        #expect(decoded.contains(where: { $0.name == "Staging" && $0.isActive }))
    }

    @Test("use marks the active profile")
    func useMarksActiveProfile() throws {
        let (store, directory) = makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        _ = try Env.addProfile(name: "Production", folder: "Team/API", store: store)
        let used = try Env.useProfile(name: "Production", store: store)

        #expect(used.name == "Production")
        #expect(try store.loadActiveProfileName() == "Production")
        #expect(try store.loadActiveProfile()?.name == "Production")
    }

    @Test("clear removes the active profile without deleting profiles")
    func clearRemovesActiveProfile() throws {
        let (store, directory) = makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        let profile = try Env.addProfile(name: "Production", folder: "Team/API", store: store)
        _ = try Env.useProfile(name: "Production", store: store)

        let message = try Env.clearActiveProfile(store: store)

        #expect(message == "Active environment cleared.")
        #expect(try store.loadActiveProfileName() == nil)
        #expect(try store.loadAll() == [profile])
    }

    @Test("clear is idempotent when no active profile exists")
    func clearIsIdempotentWhenNoProfileIsActive() throws {
        let (store, directory) = makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        let message = try Env.clearActiveProfile(store: store)

        #expect(message == "No active environment profile.")
        #expect(try store.loadActiveProfileName() == nil)
    }

    @Test("store decodes legacy single-folder profiles")
    func storeDecodesLegacySingleFolderProfiles() throws {
        let (store, directory) = makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        let data = Data(
            """
            {
              "activeProfileName": "Production",
              "profiles": [
                {
                  "name": "Production",
                  "folderPath": "Team/API",
                  "defaultMachineId": null
                }
              ]
            }
            """.utf8
        )
        try data.write(to: store.fileURL, options: .atomic)

        let profile = try #require(try store.loadActiveProfile())

        #expect(profile.scope == .folders(["Team/API"]))
        #expect(profile.folderPaths == ["Team/API"])
    }

    @Test("store surfaces malformed data instead of clearing it")
    func malformedStoreDataThrows() throws {
        let (store, directory) = makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        try Data("not-json".utf8).write(to: store.fileURL, options: .atomic)

        #expect(throws: (any Error).self) {
            _ = try store.loadAll()
        }
    }

    @Test("store writes restricted permissions")
    func storeWritesRestrictedPermissions() throws {
        let (store, directory) = makeStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        _ = try Env.addProfile(name: "Production", folder: "Team/API", store: store)

        let attrs = try FileManager.default.attributesOfItem(atPath: store.fileURL.path)
        let perms = attrs[FileAttributeKey.posixPermissions] as? Int
        #expect(perms == 0o600)

        let dirAttrs = try FileManager.default.attributesOfItem(atPath: store.fileURL.deletingLastPathComponent().path)
        let dirPerms = dirAttrs[FileAttributeKey.posixPermissions] as? Int
        #expect(dirPerms == 0o700)
    }

    private func makeStore() -> (EnvironmentProfileStore, URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("env-store-\(UUID().uuidString)", isDirectory: true)
        try! FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return (
            EnvironmentProfileStore(
                fileURL: directory.appendingPathComponent("environment-profiles.json")
            ),
            directory
        )
    }
}
