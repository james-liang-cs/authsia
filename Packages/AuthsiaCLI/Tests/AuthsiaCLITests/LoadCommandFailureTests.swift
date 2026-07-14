import Testing
import Foundation
import AuthenticatorBridge
@testable import authsia

@Suite("Load command failure handling")
struct LoadCommandFailureTests {
    @Test("single selected item failure is not silently ignored")
    func singleSelectedItemFailureThrowsUnderlyingMessage() throws {
        let reference = Self.reference(id: "pw-1", name: "API Key")
        let client = LoadVaultClientStub(
            passwordErrors: [
                "pw-1": BridgeClientError.bridgeError(
                    code: "policyDenied",
                    message: "CLI access is disabled",
                    query: nil
                ),
            ]
        )

        do {
            _ = try Load.loadEntries(
                type: .password,
                references: [reference],
                field: nil,
                client: client
            )
            Issue.record("Expected single item load failure to throw.")
        } catch {
            #expect(error.localizedDescription.contains("CLI access is disabled"))
            #expect(error.localizedDescription.contains("Enable CLI Access"))
        }
    }

    @Test("all selected item failures return an explicit load failure")
    func allSelectedItemFailuresThrowExplicitFailure() throws {
        let references = [
            Self.reference(id: "pw-1", name: "API One"),
            Self.reference(id: "pw-2", name: "API Two"),
        ]
        let client = LoadVaultClientStub(
            passwordErrors: [
                "pw-1": BridgeClientError.bridgeError(code: "notAuthorized", message: "", query: "pw-1"),
                "pw-2": BridgeClientError.bridgeError(code: "notAuthorized", message: "", query: "pw-2"),
            ]
        )

        do {
            _ = try Load.loadEntries(
                type: .password,
                references: references,
                field: nil,
                client: client
            )
            Issue.record("Expected all-failed load to throw.")
        } catch {
            #expect(error.localizedDescription.contains("No password values were loaded"))
            #expect(error.localizedDescription.contains("Access denied"))
        }
    }

    @Test("exact folder reference selection excludes child folders")
    func exactFolderReferenceSelectionExcludesChildFolders() throws {
        let rootID = "00000000-0000-0000-0000-000000000001"
        let childID = "00000000-0000-0000-0000-000000000002"
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                Self.password(id: rootID, name: "API_KEY", folderPath: "Team/API"),
                Self.password(id: childID, name: "API_KEY", folderPath: "Team/API/Prod"),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let reference = try Load.selectExactFolderReference(
            type: .password,
            query: "API_KEY",
            folderPath: "Team/API",
            payload: payload,
            allMachines: true,
            currentMachineId: "MACHINE-A"
        )

        #expect(reference.id == rootID)
    }

    @Test("specific item in folder scope excludes child folders")
    func specificItemInFolderScopeExcludesChildFolders() throws {
        let rootID = "00000000-0000-0000-0000-000000000001"
        let childID = "00000000-0000-0000-0000-000000000002"
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                Self.password(id: rootID, name: "API_KEY", folderPath: "Team/API"),
                Self.password(id: childID, name: "API_KEY", folderPath: "Team/API/Prod"),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let references = try Load.selectReferences(
            type: .password,
            scope: .itemInFolder(query: "API_KEY", folderPath: "Team/API"),
            payload: payload,
            allMachines: true,
            currentMachineId: "MACHINE-A"
        )

        #expect(references.map { $0.id } == [rootID])
    }

    private static func reference(id: String, name: String) -> Load.ItemReference {
        Load.ItemReference(
            id: id,
            name: name,
            folderPath: nil,
            isCliEnabled: true,
            isScraped: false,
            scrapeMachineName: nil,
            scrapeMachineId: nil
        )
    }

    private static func password(id: String, name: String, folderPath: String?) -> BridgePassword {
        BridgePassword(
            id: UUID(uuidString: id)!,
            name: name,
            username: "u",
            website: nil,
            folderPath: folderPath,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            createdAt: Date(),
            updatedAt: Date()
        )
    }
}

private struct LoadVaultClientStub: LoadVaultClient {
    var passwordResults: [String: PasswordResult] = [:]
    var passwordErrors: [String: Error] = [:]

    func list() throws -> BridgeListPayload {
        BridgeListPayload(accounts: [], passwords: [], certificates: [], notes: [], sshKeys: [])
    }

    func getPassword(query: String, field: String?) throws -> PasswordResult {
        if let error = passwordErrors[query] {
            throw error
        }
        if let result = passwordResults[query] {
            return result
        }
        throw BridgeClientError.bridgeError(code: "notFound", message: "", query: query)
    }

    func getAPIKey(query: String, field: String?) throws -> APIKeyResult {
        throw BridgeClientError.bridgeError(code: "notFound", message: "", query: query)
    }

    func getCertificate(query: String, field: String?) throws -> CertificateResult {
        throw BridgeClientError.bridgeError(code: "notFound", message: "", query: query)
    }

    func getNote(query: String) throws -> NoteResult {
        throw BridgeClientError.bridgeError(code: "notFound", message: "", query: query)
    }

    func getSSH(query: String, field: String?) throws -> SSHKeyResult {
        throw BridgeClientError.bridgeError(code: "notFound", message: "", query: query)
    }
}
