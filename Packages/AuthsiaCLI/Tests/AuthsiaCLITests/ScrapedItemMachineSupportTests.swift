import Testing
import Foundation
import AuthenticatorBridge
@testable import authsia

@Suite("Scraped item machine support")
struct ScrapedItemMachineSupportTests {
    private let now = Date(timeIntervalSince1970: 0)

    private func makePassword(
        id: UUID = UUID(),
        name: String,
        isScraped: Bool,
        isCliEnabled: Bool = true,
        folderPath: String? = nil,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil
    ) -> BridgePassword {
        BridgePassword(
            id: id,
            name: name,
            username: "",
            website: nil,
            folderPath: folderPath,
            isFavorite: false,
            isCliEnabled: isCliEnabled,
            isScraped: isScraped,
            createdAt: now,
            updatedAt: now,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId
        )
    }

    private func makeNote(
        title: String,
        isScraped: Bool,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil
    ) -> BridgeNote {
        BridgeNote(
            id: UUID(),
            title: title,
            folderPath: nil,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: isScraped,
            createdAt: now,
            updatedAt: now,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId
        )
    }

    private func makeSSH(
        name: String,
        isScraped: Bool,
        scrapeMachineName: String? = nil,
        scrapeMachineId: String? = nil
    ) -> BridgeSSHKey {
        BridgeSSHKey(
            id: UUID(),
            name: name,
            comment: "laptop",
            fingerprint: "SHA256:abc",
            publicKey: "ssh-ed25519 AAAA",
            folderPath: nil,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: isScraped,
            createdAt: now,
            updatedAt: now,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId
        )
    }

    @Test("list passwords defaults to current machine for scraped items")
    func listPasswordsCurrentMachineDefault() throws {
        let output = try List.renderPasswords(
            [
                makePassword(name: "LOCAL_ONLY", isScraped: false),
                makePassword(name: "CURRENT_MACHINE", isScraped: true, scrapeMachineName: "jamess-mac-mini", scrapeMachineId: "MACHINE-A"),
                makePassword(name: "OTHER_MACHINE", isScraped: true, scrapeMachineName: "work-mbp", scrapeMachineId: "MACHINE-B"),
            ],
            favoritesOnly: false,
            folder: nil,
            format: .json,
            allMachines: false,
            currentMachineId: "MACHINE-A"
        )

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let items = try decoder.decode([OutputFormatter.PasswordListItem].self, from: Data(output.utf8))

        #expect(items.map { $0.name }.sorted() == ["CURRENT_MACHINE", "LOCAL_ONLY"])
        #expect(items.first(where: { $0.name == "CURRENT_MACHINE" })?.scrapeMachineName == "jamess-mac-mini")
    }

    @Test("legacy scraped items remain visible by default")
    func legacyScrapedItemsRemainVisible() throws {
        let output = try List.renderPasswords(
            [
                makePassword(name: "LEGACY_SCRAPED", isScraped: true),
            ],
            favoritesOnly: false,
            folder: nil,
            format: .table,
            allMachines: false,
            currentMachineId: "MACHINE-A"
        )

        #expect(output.contains("LEGACY_SCRAPED"))
        #expect(output.contains("legacy scrape"))
    }

    @Test("list passwords can filter to CLI-enabled items")
    func listPasswordsFiltersCLIEnabledItems() throws {
        let output = try List.renderPasswords(
            [
                makePassword(name: "CLI_ENABLED", isScraped: false, isCliEnabled: true),
                makePassword(name: "CLI_DISABLED", isScraped: false, isCliEnabled: false),
            ],
            favoritesOnly: false,
            cliEnabledOnly: true,
            folder: nil,
            format: .json,
            allMachines: false,
            currentMachineId: "MACHINE-A"
        )

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let items = try decoder.decode([OutputFormatter.PasswordListItem].self, from: Data(output.utf8))

        #expect(items.map { $0.name } == ["CLI_ENABLED"])
    }

    @Test("list parses CLI-enabled filter")
    func listParsesCLIEnabledFilter() throws {
        let command = try List.parse(["passwords", "--cli-enabled"])

        #expect(command.cliEnabledOnly)
    }

    @Test("list automation requires list capability")
    func listAutomationRequiresListCapability() throws {
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "list-access")
        defer { try? FileManager.default.removeItem(at: directory) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let credential = try Access.createCredential(
            name: "agent",
            scope: "Team/API",
            ttl: "15m",
            store: store,
            machineIdentity: MachineIdentity(machineId: "m", hostname: "h"),
            now: now,
            allowedCommands: [.exec]
        )

        #expect(throws: (any Error).self) {
            try List.authorizeAutomationAccess(
                environment: [
                    AutomationAccessResolver.environmentKey:
                        AccessCredentialStoreFixture.token(for: credential)
                ],
                store: store,
                now: now.addingTimeInterval(60)
            )
        }
    }

    @Test("list automation accepts list capability")
    func listAutomationAcceptsListCapability() throws {
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "list-access")
        defer { try? FileManager.default.removeItem(at: directory) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let credential = try Access.createCredential(
            name: "agent",
            scope: "Team/API",
            ttl: "15m",
            store: store,
            machineIdentity: MachineIdentity(machineId: "m", hostname: "h"),
            now: now,
            allowedCommands: [.list]
        )

        try List.authorizeAutomationAccess(
            environment: [
                AutomationAccessResolver.environmentKey:
                    AccessCredentialStoreFixture.token(for: credential)
            ],
            store: store,
            now: now.addingTimeInterval(60)
        )
    }

    @Test("load defaults to current machine for scraped items")
    func loadCurrentMachineDefault() throws {
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                makePassword(name: "LOCAL_ONLY", isScraped: false),
                makePassword(name: "CURRENT_MACHINE", isScraped: true, scrapeMachineName: "jamess-mac-mini", scrapeMachineId: "MACHINE-A"),
                makePassword(name: "OTHER_MACHINE", isScraped: true, scrapeMachineName: "work-mbp", scrapeMachineId: "MACHINE-B"),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let references = try Load.selectReferences(
            type: .password,
            scope: .global,
            payload: payload,
            allMachines: false,
            currentMachineId: "MACHINE-A"
        )

        #expect(references.map { $0.name }.sorted() == ["CURRENT_MACHINE", "LOCAL_ONLY"])
    }

    @Test("load single query prefers exact item name before substring matches")
    func loadSingleQueryPrefersExactItemName() throws {
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                makePassword(name: "APP-SPECIFIC-PASSWORD", isScraped: false),
                makePassword(name: "password", isScraped: false),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let references = try Load.selectReferences(
            type: .password,
            scope: .single("password"),
            payload: payload,
            allMachines: false,
            currentMachineId: "MACHINE-A"
        )

        #expect(references.map(\.name) == ["password"])
    }

    @Test("load treats matching machine name as current when machine id changed")
    func loadTreatsMatchingMachineNameAsCurrentWhenMachineIdChanged() throws {
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                makePassword(
                    name: "SERVICE_LOGIN",
                    isScraped: true,
                    scrapeMachineName: "jamess-mac-mini",
                    scrapeMachineId: "OLD-ID"
                ),
                makePassword(
                    name: "OTHER_MACHINE",
                    isScraped: true,
                    scrapeMachineName: "work-mbp",
                    scrapeMachineId: "MACHINE-B"
                ),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let references = try Load.selectReferences(
            type: .password,
            scope: .single("SERVICE_LOGIN"),
            payload: payload,
            allMachines: false,
            currentMachineId: "MACHINE-A",
            currentMachineName: "jamess-mac-mini"
        )

        #expect(references.map(\.name) == ["SERVICE_LOGIN"])
    }

    @Test("load multi-folder scope includes child folders")
    func loadMultiFolderScopeIncludesChildFolders() throws {
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                makePassword(name: "API_ROOT", isScraped: false, folderPath: "Team/API"),
                makePassword(name: "API_PROD", isScraped: false, folderPath: "Team/API/Prod"),
                makePassword(name: "WEB_ROOT", isScraped: false, folderPath: "Team/Web"),
                makePassword(name: "OTHER", isScraped: false, folderPath: "Team/Other"),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let references = try Load.selectReferences(
            type: .password,
            scope: .folders(["Team/API", "Team/Web"]),
            payload: payload,
            allMachines: false,
            currentMachineId: "MACHINE-A"
        )

        #expect(references.map { $0.name }.sorted() == ["API_PROD", "API_ROOT", "WEB_ROOT"])
    }

    @Test("load includes all machines when requested")
    func loadAllMachines() throws {
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                makePassword(name: "CURRENT_MACHINE", isScraped: true, scrapeMachineName: "jamess-mac-mini", scrapeMachineId: "MACHINE-A"),
                makePassword(name: "OTHER_MACHINE", isScraped: true, scrapeMachineName: "work-mbp", scrapeMachineId: "MACHINE-B"),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let references = try Load.selectReferences(
            type: .password,
            scope: .global,
            payload: payload,
            allMachines: true,
            currentMachineId: "MACHINE-A"
        )

        #expect(references.map { $0.name }.sorted() == ["CURRENT_MACHINE", "OTHER_MACHINE"])
    }

    @Test("note list table includes machine column")
    func noteTableIncludesMachineColumn() throws {
        let output = try List.renderNotes(
            [
                makeNote(title: "SCRAPED_NOTE", isScraped: true, scrapeMachineName: "jamess-mac-mini", scrapeMachineId: "MACHINE-A"),
            ],
            favoritesOnly: false,
            folder: nil,
            format: .table,
            allMachines: true,
            currentMachineId: "MACHINE-A"
        )

        #expect(output.contains("Machine"))
        #expect(output.contains("jamess-mac-mini"))
    }

    @Test("ssh list table includes machine column")
    func sshTableIncludesMachineColumn() throws {
        let output = try List.renderSSHKeys(
            [
                makeSSH(name: "SCRAPED_SSH", isScraped: true, scrapeMachineName: "jamess-mac-mini", scrapeMachineId: "MACHINE-A"),
            ],
            favoritesOnly: false,
            folder: nil,
            format: .table,
            allMachines: true,
            currentMachineId: "MACHINE-A"
        )

        #expect(output.contains("Machine"))
        #expect(output.contains("jamess-mac-mini"))
    }

    @Test("ssh list defaults to current machine for adopted keys")
    func sshListDefaultsToCurrentMachineForAdoptedKeys() throws {
        let output = try List.renderSSHKeys(
            [
                makeSSH(name: "CURRENT_MACHINE", isScraped: true, scrapeMachineName: "jamess-mac-mini", scrapeMachineId: "MACHINE-A"),
                makeSSH(name: "OTHER_MACHINE", isScraped: true, scrapeMachineName: "work-mbp", scrapeMachineId: "MACHINE-B"),
            ],
            favoritesOnly: false,
            folder: nil,
            format: .json,
            allMachines: false,
            currentMachineId: "MACHINE-A"
        )
        let rawItems = try JSONSerialization.jsonObject(with: Data(output.utf8)) as? [[String: Any]]
        let names = rawItems?.compactMap { $0["name"] as? String } ?? []

        #expect(names.sorted() == ["CURRENT_MACHINE"])
    }

    @Test("ssh list includes all machines when requested")
    func sshListIncludesAllMachinesWhenRequested() throws {
        let output = try List.renderSSHKeys(
            [
                makeSSH(name: "CURRENT_MACHINE", isScraped: true, scrapeMachineName: "jamess-mac-mini", scrapeMachineId: "MACHINE-A"),
                makeSSH(name: "OTHER_MACHINE", isScraped: true, scrapeMachineName: "work-mbp", scrapeMachineId: "MACHINE-B"),
            ],
            favoritesOnly: false,
            folder: nil,
            format: .json,
            allMachines: true,
            currentMachineId: "MACHINE-A"
        )
        let rawItems = try JSONSerialization.jsonObject(with: Data(output.utf8)) as? [[String: Any]]
        let names = rawItems?.compactMap { $0["name"] as? String } ?? []

        #expect(names.sorted() == ["CURRENT_MACHINE", "OTHER_MACHINE"])
    }

    @Test("ssh list treats matching machine name as current when machine id changed")
    func sshListTreatsMatchingMachineNameAsCurrentWhenMachineIdChanged() throws {
        let output = try List.renderSSHKeys(
            [
                makeSSH(name: "SAME_MACHINE_REGENERATED_ID", isScraped: true, scrapeMachineName: "jamess-mac-mini", scrapeMachineId: "OLD-ID"),
                makeSSH(name: "OTHER_MACHINE", isScraped: true, scrapeMachineName: "work-mbp", scrapeMachineId: "MACHINE-B"),
            ],
            favoritesOnly: false,
            folder: nil,
            format: .json,
            allMachines: false,
            currentMachineId: "MACHINE-A",
            currentMachineName: "jamess-mac-mini"
        )
        let rawItems = try JSONSerialization.jsonObject(with: Data(output.utf8)) as? [[String: Any]]
        let names = rawItems?.compactMap { $0["name"] as? String } ?? []

        #expect(names.sorted() == ["SAME_MACHINE_REGENERATED_ID"])
    }
}
