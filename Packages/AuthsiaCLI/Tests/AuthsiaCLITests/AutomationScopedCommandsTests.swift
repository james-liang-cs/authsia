import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
@testable import authsia

@Suite("Automation-scoped commands")
struct AutomationScopedCommandsTests {

    @Test("load automation access rejects global scope")
    func loadAutomationRejectsGlobalScope() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory, environment) = try makeAutomationEnvironment(scope: "Team/API", now: now)
        defer { try? FileManager.default.removeItem(at: directory) }

        #expect(throws: (any Error).self) {
            _ = try Load.applyAutomationAccess(
                to: emptyPayload(),
                scope: .global,
                environment: environment,
                store: store,
                now: now
            )
        }
    }

    @Test("load automation access filters payload to allowed scope")
    func loadAutomationFiltersPayload() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory, environment) = try makeAutomationEnvironment(scope: "Team/API", now: now)
        defer { try? FileManager.default.removeItem(at: directory) }

        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                BridgePassword(
                    id: UUID(),
                    name: "InScope",
                    username: "u",
                    website: nil,
                    folderPath: "Team/API",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: Date(),
                    updatedAt: Date()
                ),
                BridgePassword(
                    id: UUID(),
                    name: "OutOfScope",
                    username: "u",
                    website: nil,
                    folderPath: "Team/Other",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: Date(),
                    updatedAt: Date()
                )
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        let filtered = try Load.applyAutomationAccess(
            to: payload,
            scope: .folder("Team/API"),
            environment: environment,
            store: store,
            now: now
        )

        #expect(filtered.passwords.map(\.name) == ["InScope"])
    }

    @Test("get automation access rejects otp")
    func getAutomationRejectsOTP() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory, environment) = try makeAutomationEnvironment(scope: "Team/API", now: now)
        defer { try? FileManager.default.removeItem(at: directory) }

        #expect(throws: (any Error).self) {
            try Get.authorizeAutomationAccess(
                type: .otp,
                query: "GitHub",
                payload: emptyPayload(),
                environment: environment,
                store: store,
                now: now
            )
        }
    }

    @Test("read automation access rejects out-of-scope secret references")
    func readAutomationRejectsOutOfScopeReference() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory, environment) = try makeAutomationEnvironment(scope: "Team/API", now: now)
        defer { try? FileManager.default.removeItem(at: directory) }

        let ref = try SecretReference.parse("authsia://password/ProdKey/password")
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                BridgePassword(
                    id: UUID(),
                    name: "ProdKey",
                    username: "u",
                    website: nil,
                    folderPath: "Team/Other",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: Date(),
                    updatedAt: Date()
                )
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        #expect(throws: (any Error).self) {
            try ReadCmd.authorizeAutomationAccess(
                ref: ref,
                payload: payload,
                environment: environment,
                store: store,
                now: now
            )
        }
    }

    @Test("read automation access uses URI folder to disambiguate duplicate names")
    func readAutomationUsesURIFolderForDuplicateNames() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory, environment) = try makeAutomationEnvironment(scope: "Team/API", now: now)
        defer { try? FileManager.default.removeItem(at: directory) }

        let ref = try SecretReference.parse("authsia://password/ProdKey/password?folder=Team/API")
        let payload = BridgeListPayload(
            accounts: [],
            passwords: [
                BridgePassword(
                    id: UUID(),
                    name: "ProdKey",
                    username: "u",
                    website: nil,
                    folderPath: "Team/API",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: Date(),
                    updatedAt: Date()
                ),
                BridgePassword(
                    id: UUID(),
                    name: "ProdKey",
                    username: "u",
                    website: nil,
                    folderPath: "Team/API/Prod",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: Date(),
                    updatedAt: Date()
                ),
            ],
            certificates: [],
            notes: [],
            sshKeys: []
        )

        try ReadCmd.authorizeAutomationAccess(
            ref: ref,
            payload: payload,
            environment: environment,
            store: store,
            now: now
        )
    }

    @Test("get rejects when credential is exec-only")
    func getRejectsExecOnlyCredential() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "automation-scoped")
        defer { try? FileManager.default.removeItem(at: directory) }

        let credential = try Access.createCredential(
            name: "exec-only",
            scope: "Team/API",
            ttl: "15m",
            store: store,
            machineIdentity: MachineIdentity(machineId: "m1", hostname: "h"),
            now: now,
            allowedCommands: [.exec]
        )
        let payload = BridgeListPayload(accounts: [], passwords: [], certificates: [], notes: [], sshKeys: [])

        do {
            try Get.authorizeAutomationAccess(
                type: .password,
                query: "anything",
                payload: payload,
                environment: [AutomationAccessResolver.environmentKey: credential.id.uuidString],
                store: store,
                now: now.addingTimeInterval(60),
                currentMachineId: "m1"
            )
            Issue.record("expected ValidationError")
        } catch let error as ValidationError {
            #expect(String(describing: error).contains("does not permit 'get'"))
        } catch {
            Issue.record("expected ValidationError, got \(error)")
        }
    }

    @Test("load rejects when credential omits .load")
    func loadRejectsWithoutLoadCapability() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "automation-scoped")
        defer { try? FileManager.default.removeItem(at: directory) }

        let credential = try Access.createCredential(
            name: "exec-only",
            scope: "Team/API",
            ttl: "15m",
            store: store,
            machineIdentity: MachineIdentity(machineId: "m", hostname: "h"),
            now: now,
            allowedCommands: [.exec]
        )
        let payload = BridgeListPayload(accounts: [], passwords: [], certificates: [], notes: [], sshKeys: [])

        do {
            _ = try Load.applyAutomationAccess(
                to: payload,
                scope: .folder("Team/API"),
                environment: [AutomationAccessResolver.environmentKey: credential.id.uuidString],
                store: store,
                now: now.addingTimeInterval(60)
            )
            Issue.record("expected ValidationError")
        } catch let error as ValidationError {
            #expect(String(describing: error).contains("does not permit 'load'"))
        } catch {
            Issue.record("expected ValidationError, got \(error)")
        }
    }

    private func makeAutomationEnvironment(
        scope: String,
        now: Date,
        allowedCommands: Set<CapabilityCommand> = Set(CapabilityCommand.allCases)
    ) throws -> (AccessCredentialStore, URL, [String: String]) {
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "automation-scoped")
        let machine = MachineIdentity(machineId: "machine-123", hostname: "Example-MacBook.local")
        let credential = try Access.createCredential(
            name: "Claude",
            scope: scope,
            ttl: "15m",
            store: store,
            machineIdentity: machine,
            now: now,
            allowedCommands: allowedCommands
        )
        let environment = [AutomationAccessResolver.environmentKey: credential.id.uuidString]
        return (store, directory, environment)
    }

    private func emptyPayload() -> BridgeListPayload {
        BridgeListPayload(accounts: [], passwords: [], certificates: [], notes: [], sshKeys: [])
    }
}
