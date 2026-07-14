import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
@testable import authsia

@Suite("Get command help")
struct GetCommandHelpTests {
    @Test("help covers folder-qualified vault item examples")
    func helpCoversFolderQualifiedExamples() {
        let help = Get.helpMessage(columns: 160)

        #expect(help.contains("authsia get password DB_PASSWORD --folder Team/API"))
        #expect(help.contains("authsia get api-key Stripe --field key"))
        #expect(help.contains("authsia get cert TLS_CERT --folder Team/API"))
        #expect(help.contains("authsia get note Runbook --folder Team/Ops"))
        #expect(help.contains("authsia get ssh DeployKey --folder Infra/SSH"))
        #expect(help.contains("authsia get otp GitHub --copy"))
    }

    @Test("get parses folder-qualified password lookup")
    func getParsesFolderQualifiedPasswordLookup() throws {
        let command = try Get.parse(["password", "API_KEY", "--folder", "Team/API"])

        #expect(command.folder == "Team/API")
    }

    @Test("get parses API key field lookup")
    func getParsesAPIKeyFieldLookup() throws {
        let command = try Get.parse(["api-key", "Stripe", "--field", "key"])

        #expect(command.type == .apiKey)
        #expect(command.field == .key)
    }

    @Test("get parses hidden chrome native host marker")
    func getParsesHiddenChromeNativeHostMarker() throws {
        let command = try Get.parse(["password", "API_KEY", "--chrome-native-host"])
        let help = Get.helpMessage(columns: 160)

        #expect(command.chromeNativeHost == true)
        #expect(!help.contains("--chrome-native-host"))
    }

    @Test("chrome native host marker requires native host ancestry")
    func chromeNativeHostMarkerRequiresNativeHostAncestry() throws {
        let command = try Get.parse(["password", "API_KEY", "--chrome-native-host"])

        try command.validateChromeNativeHostMarker(processAncestry: [
            AgenticProcessReference(processName: "authsia", bundleIdentifier: nil),
            AgenticProcessReference(processName: "AuthsiaNativeHost", bundleIdentifier: nil),
        ])

        #expect(throws: ValidationError.self) {
            try command.validateChromeNativeHostMarker(processAncestry: [
                AgenticProcessReference(processName: "authsia", bundleIdentifier: nil),
                AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
            ])
        }
    }

    @Test("get resolves a specific item in an exact folder by id")
    func getResolvesSpecificItemInExactFolderByID() throws {
        let rootID = "00000000-0000-0000-0000-000000000001"
        let childID = "00000000-0000-0000-0000-000000000002"
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                password(id: rootID, name: "API_KEY", folderPath: "Team/API"),
                password(id: childID, name: "API_KEY", folderPath: "Team/API/Prod"),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let bridgeQuery = try Get.resolveBridgeQuery(
            type: .password,
            query: "API_KEY",
            folder: "Team/API",
            payload: payload,
            currentMachineId: "MACHINE-A"
        )

        #expect(bridgeQuery == rootID)
    }

    @Test("get resolves an API key in an exact folder by id")
    func getResolvesAPIKeyInExactFolderByID() throws {
        let rootID = "00000000-0000-0000-0000-000000000011"
        let childID = "00000000-0000-0000-0000-000000000012"
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [],
            apiKeys: [
                apiKey(id: rootID, name: "Stripe", folderPath: "Team/API"),
                apiKey(id: childID, name: "Stripe", folderPath: "Team/API/Prod"),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let bridgeQuery = try Get.resolveBridgeQuery(
            type: .apiKey,
            query: "Stripe",
            folder: "Team/API",
            payload: payload,
            currentMachineId: "MACHINE-A"
        )

        #expect(bridgeQuery == rootID)
    }

    @Test("get duplicate folder match explains exact id retry")
    func getDuplicateFolderMatchExplainsExactIDRetry() throws {
        let firstID = "00000000-0000-0000-0000-000000000001"
        let secondID = "00000000-0000-0000-0000-000000000002"
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                password(id: firstID, name: "First API Password", folderPath: "Personal/Authsia"),
                password(id: secondID, name: "First API Password", folderPath: "Personal/Authsia"),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        do {
            _ = try Get.resolveBridgeQuery(
                type: .password,
                query: "First API Password",
                folder: "Personal/Authsia",
                payload: payload,
                currentMachineId: "MACHINE-A"
            )
            Issue.record("Expected duplicate password names to require an exact ID retry.")
        } catch let error as CLIError {
            #expect(error.message.contains("Rerun with one exact ID"))
            #expect(error.message.contains("authsia get password \(firstID) --folder 'Personal/Authsia'"))
            #expect(error.message.contains("authsia get password \(secondID) --folder 'Personal/Authsia'"))
        }
    }

    private func password(id: String, name: String, folderPath: String?) -> BridgePassword {
        BridgePassword(
            id: UUID(uuidString: id)!,
            name: name,
            username: "u",
            website: nil,
            folderPath: folderPath,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            createdAt: Date(timeIntervalSince1970: 0),
            updatedAt: Date(timeIntervalSince1970: 0)
        )
    }

    private func apiKey(id: String, name: String, folderPath: String?) -> BridgeAPIKey {
        BridgeAPIKey(
            id: UUID(uuidString: id)!,
            name: name,
            website: nil,
            folderPath: folderPath,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            createdAt: Date(timeIntervalSince1970: 0),
            updatedAt: Date(timeIntervalSince1970: 0)
        )
    }
}
