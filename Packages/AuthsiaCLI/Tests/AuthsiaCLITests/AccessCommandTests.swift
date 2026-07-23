import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
@testable import authsia

@Suite("Access command")
struct AccessCommandTests {

    @Test("parseTTL accepts plain seconds and unit suffixes")
    func parseTTLAcceptsCommonUnits() throws {
        #expect(try Access.parseTTL("900") == 900)
        #expect(try Access.parseTTL("15m") == 900)
        #expect(try Access.parseTTL("2h") == 7_200)
        #expect(try Access.parseTTL("1d") == 86_400)
    }

    @Test("parseTTL rejects invalid input")
    func parseTTLRejectsInvalidInput() {
        #expect(throws: (any Error).self) {
            _ = try Access.parseTTL("ten minutes")
        }
    }

    @Test("create rejects empty or whitespace-only name")
    func createRejectsEmptyName() throws {
        let machine = MachineIdentity(machineId: "machine-123", hostname: "Example-MacBook.local")
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "access-store")
        defer { try? FileManager.default.removeItem(at: directory) }

        #expect(throws: (any Error).self) {
            _ = try Access.createCredential(
                name: "   ",
                scope: "Team/API",
                ttl: "15m",
                store: store,
                machineIdentity: machine
            )
        }
    }

    @Test("create parses without scope")
    func createParsesWithoutScope() throws {
        let command = try Access.Create.parse([
            "--name", "Claude",
            "--ttl", "15m",
            "--allow", "ssh",
        ])

        #expect(command.name == "Claude")
        #expect(command.ttl == "15m")
        #expect(command.allow == "ssh")
    }

    @Test("create parses env profile")
    func createParsesEnvProfile() throws {
        let command = try Access.Create.parse([
            "--name", "Claude",
            "--env", "Production",
            "--ttl", "15m",
            "--allow", "exec",
        ])

        #expect(command.env == "Production")
    }

    @Test("create parses the Default-environment restriction")
    func createParsesDefaultOnly() throws {
        let command = try Access.Create.parse([
            "--name", "Claude",
            "--default-only",
            "--ttl", "15m",
            "--allow", "exec",
        ])

        #expect(command.defaultOnly)
    }

    @Test("create defaults missing scope to all")
    func createDefaultsMissingScopeToAll() throws {
        let machine = MachineIdentity(machineId: "machine-123", hostname: "Example-MacBook.local")
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "access-store")
        defer { try? FileManager.default.removeItem(at: directory) }

        let created = try Access.createCredential(
            name: "Claude",
            scope: nil,
            ttl: "15m",
            store: store,
            machineIdentity: machine
        )

        #expect(created.scope == nil)
        #expect(Access.renderCreateMessage(created).contains("for scope all"))
    }

    @Test("create uses multi-folder env profile as credential scope")
    func createUsesMultiFolderEnvProfileAsCredentialScope() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let machine = MachineIdentity(machineId: "machine-123", hostname: "Example-MacBook.local")
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "access-store")
        let (environmentStore, environmentDirectory) = makeEnvironmentStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        defer { try? FileManager.default.removeItem(at: environmentDirectory) }

        _ = try Env.addProfile(
            name: "Production",
            folders: ["Team/API", "Team/Web"],
            all: false,
            store: environmentStore
        )

        let created = try Access.createCredential(
            name: "Claude",
            scope: nil,
            envName: "Production",
            ttl: "15m",
            store: store,
            environmentStore: environmentStore,
            machineIdentity: machine,
            now: now
        )

        let normalizedScope = try #require(AutomationCredentialScope.normalizeStored(created.scope))
        #expect(normalizedScope == .folders(["Team/API", "Team/Web"]))
        #expect(AutomationCredentialScope.displayName(created.scope) == "Team/API, Team/Web")
        #expect(AutomationCredentialScope.contains(itemFolderPath: "Team/Web/App", normalizedScope: normalizedScope))
        #expect(!AutomationCredentialScope.contains(itemFolderPath: "Team/Other", normalizedScope: normalizedScope))
    }

    @Test("create rejects scope and env together")
    func createRejectsScopeAndEnvTogether() throws {
        let machine = MachineIdentity(machineId: "machine-123", hostname: "Example-MacBook.local")
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "access-store")
        let (environmentStore, environmentDirectory) = makeEnvironmentStore()
        defer { try? FileManager.default.removeItem(at: directory) }
        defer { try? FileManager.default.removeItem(at: environmentDirectory) }

        _ = try Env.addProfile(name: "Production", folder: "Team/API", store: environmentStore)

        #expect(throws: (any Error).self) {
            _ = try Access.createCredential(
                name: "Claude",
                scope: "Team/API",
                envName: "Production",
                ttl: "15m",
                store: store,
                environmentStore: environmentStore,
                machineIdentity: machine
            )
        }
    }

    @Test("create rejects blank scope when explicitly provided")
    func createRejectsExplicitBlankScope() throws {
        let machine = MachineIdentity(machineId: "machine-123", hostname: "Example-MacBook.local")
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "access-store")
        defer { try? FileManager.default.removeItem(at: directory) }

        #expect(throws: (any Error).self) {
            _ = try Access.createCredential(
                name: "Claude",
                scope: "   ",
                ttl: "15m",
                store: store,
                machineIdentity: machine
            )
        }
    }

    @Test("create persists a credential with scope and machine metadata")
    func createPersistsCredential() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let machine = MachineIdentity(machineId: "machine-123", hostname: "Example-MacBook.local")
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "access-store")
        defer { try? FileManager.default.removeItem(at: directory) }

        let created = try Access.createCredential(
            name: "Claude",
            scope: "Team/API",
            ttl: "15m",
            store: store,
            machineIdentity: machine,
            now: now
        )

        let loaded = try store.loadAll()
        #expect(loaded.count == 1)
        #expect(loaded.first == created)
        #expect(created.scope == "Team/API")
        #expect(created.machineId == "machine-123")
        #expect(created.machineName == "Example-MacBook")
        #expect(created.expiresAt == now.addingTimeInterval(900))
        #expect(created.revokedAt == nil)
    }

    @Test("create with approval sends requested scope before persisting")
    func createWithApprovalSendsScopeBeforePersisting() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let machine = MachineIdentity(machineId: "machine-123", hostname: "Example-MacBook.local")
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "access-store")
        let approver = AccessCreateApprovalRecorder(result: .approved)
        defer { try? FileManager.default.removeItem(at: directory) }

        let created = try Access.createCredentialAfterApproval(
            name: " Claude ",
            scope: " Team/API ",
            ttl: "15m",
            store: store,
            machineIdentity: machine,
            now: now,
            allowedCommands: [.exec, .load],
            approvalClient: approver
        )

        #expect(approver.requests.count == 1)
        #expect(approver.requests.first?.name == "Claude")
        #expect(approver.requests.first?.scope == "Team/API")
        #expect(approver.requests.first?.ttlSeconds == 900)
        #expect(approver.requests.first?.expiresAt == created.expiresAt)
        #expect(approver.requests.first?.allowedCommands == [.exec, .load])
        #expect(created.bearerToken?.hasPrefix(AutomationCredentialToken.prefix) == true)
        let stored = try #require(store.loadAll().first)
        #expect(stored.id == created.id)
        #expect(stored.scope == created.scope)
        #expect(stored.bearerToken == nil)
    }

    @Test("create with approval does not persist when approval is denied")
    func createWithApprovalDoesNotPersistDeniedCredential() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let machine = MachineIdentity(machineId: "machine-123", hostname: "Example-MacBook.local")
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "access-store")
        let approver = AccessCreateApprovalRecorder(result: .denied)
        defer { try? FileManager.default.removeItem(at: directory) }

        #expect(throws: (any Error).self) {
            _ = try Access.createCredentialAfterApproval(
                name: "Claude",
                scope: "Team/API",
                ttl: "15m",
                store: store,
                machineIdentity: machine,
                now: now,
                allowedCommands: [.exec],
                approvalClient: approver
            )
        }

        #expect(approver.requests.count == 1)
        #expect(try store.loadAll().isEmpty)
    }

    @Test("listActive excludes revoked and expired credentials")
    func listActiveExcludesRevokedAndExpiredCredentials() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let machine = MachineIdentity(machineId: "machine-123", hostname: "Example-MacBook.local")
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "access-store")
        defer { try? FileManager.default.removeItem(at: directory) }

        let active = try Access.createCredential(
            name: "Active",
            scope: "Team/API",
            ttl: "1h",
            store: store,
            machineIdentity: machine,
            now: now
        )
        let revoked = try Access.createCredential(
            name: "Revoked",
            scope: "Team/API",
            ttl: "1h",
            store: store,
            machineIdentity: machine,
            now: now
        )
        _ = try Access.revokeCredential(id: revoked.id, store: store, now: now.addingTimeInterval(60))
        _ = try Access.createCredential(
            name: "Expired",
            scope: "Team/API",
            ttl: "1",
            store: store,
            machineIdentity: machine,
            now: now
        )

        let items = try Access.listItems(store: store, includeAll: false, now: now.addingTimeInterval(120))

        #expect(items.count == 1)
        #expect(items.first?.name == active.name)
        #expect(items.first?.status == .active)
    }

    @Test("listAll includes revoked credentials")
    func listAllIncludesRevokedCredentials() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let machine = MachineIdentity(machineId: "machine-123", hostname: "Example-MacBook.local")
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "access-store")
        defer { try? FileManager.default.removeItem(at: directory) }

        let active = try Access.createCredential(
            name: "Active",
            scope: "Team/API",
            ttl: "1h",
            store: store,
            machineIdentity: machine,
            now: now
        )
        let revoked = try Access.createCredential(
            name: "Revoked",
            scope: "Team/API",
            ttl: "1h",
            store: store,
            machineIdentity: machine,
            now: now
        )
        _ = try Access.revokeCredential(id: revoked.id, store: store, now: now.addingTimeInterval(60))

        let items = try Access.listItems(store: store, includeAll: true, now: now.addingTimeInterval(120))

        #expect(items.count == 2)
        #expect(items.contains(where: { $0.id == active.id }))
        #expect(items.contains(where: { $0.id == revoked.id && $0.status == .revoked }))
    }

    @Test("list all shows legacy records as disabled without overriding authority")
    func listAllShowsLegacyRecordsAsDisabled() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let authority = AccessCredential(
            id: UUID(),
            name: "current",
            scope: "Team/API",
            createdAt: now,
            expiresAt: now.addingTimeInterval(900),
            revokedAt: nil,
            machineId: "m",
            machineName: "h"
        )
        let duplicateLegacy = AccessCredential(
            id: authority.id,
            name: "forged replacement",
            scope: nil,
            createdAt: now,
            expiresAt: .distantFuture,
            revokedAt: nil,
            machineId: "m",
            machineName: "h"
        )
        let disabledLegacy = AccessCredential(
            id: UUID(),
            name: "old-ci",
            scope: "Legacy",
            createdAt: now,
            expiresAt: .distantFuture,
            revokedAt: nil,
            machineId: "m",
            machineName: "h"
        )

        let items = Access.listItems(
            credentials: [
                AutomationCredentialMetadata(
                    id: authority.id,
                    name: authority.name,
                    scope: authority.scope,
                    createdAt: authority.createdAt,
                    expiresAt: authority.expiresAt,
                    revokedAt: authority.revokedAt,
                    machineId: authority.machineId,
                    machineName: authority.machineName,
                    allowedCommands: authority.allowedCommands,
                    environmentScope: authority.environmentScope
                )
            ],
            disabledLegacy: [duplicateLegacy, disabledLegacy],
            includeAll: true,
            now: now
        )

        #expect(items.count == 2)
        let authorityItem = items.first { $0.id == authority.id }
        let legacyItem = items.first { $0.id == disabledLegacy.id }
        #expect(authorityItem?.name == "current")
        #expect(authorityItem?.status == Access.ListItem.Status.active)
        #expect(legacyItem?.status == Access.ListItem.Status.legacyDisabled)
    }

    @Test("revoke marks a credential as revoked")
    func revokeMarksCredentialAsRevoked() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let machine = MachineIdentity(machineId: "machine-123", hostname: "Example-MacBook.local")
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "access-store")
        defer { try? FileManager.default.removeItem(at: directory) }

        let created = try Access.createCredential(
            name: "Claude",
            scope: "Team/API",
            ttl: "1h",
            store: store,
            machineIdentity: machine,
            now: now
        )

        let revoked = try Access.revokeCredential(id: created.id, store: store, now: now.addingTimeInterval(60))

        #expect(revoked.revokedAt == now.addingTimeInterval(60))
        let loaded = try store.loadAll()
        #expect(loaded.first?.revokedAt == now.addingTimeInterval(60))
    }

    @Test("store writes credentials with restricted permissions")
    func storeWritesRestrictedPermissions() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let machine = MachineIdentity(machineId: "machine-123", hostname: "Example-MacBook.local")
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "access-store")
        defer { try? FileManager.default.removeItem(at: directory) }

        _ = try Access.createCredential(
            name: "Claude",
            scope: "Team/API",
            ttl: "1h",
            store: store,
            machineIdentity: machine,
            now: now
        )

        let attrs = try FileManager.default.attributesOfItem(atPath: store.fileURL.path)
        let perms = attrs[FileAttributeKey.posixPermissions] as? Int
        #expect(perms == 0o600)

        let dirAttrs = try FileManager.default.attributesOfItem(atPath: store.fileURL.deletingLastPathComponent().path)
        let dirPerms = dirAttrs[FileAttributeKey.posixPermissions] as? Int
        #expect(dirPerms == 0o700)
    }

    @Test("store surfaces malformed data instead of replacing it with an empty list")
    func malformedStoreDataThrows() throws {
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "access-store")
        defer { try? FileManager.default.removeItem(at: directory) }

        try Data("not-json".utf8).write(to: store.fileURL, options: .atomic)

        #expect(throws: (any Error).self) {
            _ = try store.loadAll()
        }
    }

    @Test("JSON list output decodes cleanly")
    func jsonListOutputDecodesCleanly() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let machine = MachineIdentity(machineId: "machine-123", hostname: "Example-MacBook.local")
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "access-store")
        defer { try? FileManager.default.removeItem(at: directory) }

        _ = try Access.createCredential(
            name: "Claude",
            scope: "Team/API",
            ttl: "1h",
            store: store,
            machineIdentity: machine,
            now: now
        )

        let items = try Access.listItems(store: store, includeAll: false, now: now)
        let output = try Access.renderList(items: items, format: .json)
        let decoded = try jsonDecoder().decode([Access.ListItem].self, from: Data(output.utf8))

        #expect(decoded.count == 1)
        #expect(decoded.first?.name == "Claude")
        #expect(decoded.first?.status == .active)
    }

    private func jsonDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    private func makeEnvironmentStore() -> (EnvironmentProfileStore, URL) {
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

    @Test("parseAllowedCommands parses comma list")
    func parseAllowedCommandsParsesComma() throws {
        let parsed = try Access.Create.parseAllowedCommands("exec,load")
        #expect(parsed == [.exec, .load])
    }

    @Test("parseAllowedCommands parses list capability")
    func parseAllowedCommandsParsesListCapability() throws {
        let parsed = try Access.Create.parseAllowedCommands("exec,list")
        #expect(parsed == [.exec, .list])
    }

    @Test("parseAllowedCommands rejects unknown token")
    func parseAllowedCommandsRejectsUnknown() {
        #expect(throws: (any Error).self) {
            try Access.Create.parseAllowedCommands("exec,bogus")
        }
    }

    @Test("parseAllowedCommands requires ssh to use a separate credential")
    func parseAllowedCommandsRejectsMixedSSHCapabilities() {
        #expect(throws: (any Error).self) {
            try Access.Create.parseAllowedCommands("exec,ssh")
        }
        let sshOnly = try? Access.Create.parseAllowedCommands("ssh")
        #expect(sshOnly == [.ssh])
    }

    @Test("parseAllowedCommands rejects empty string")
    func parseAllowedCommandsRejectsEmpty() {
        #expect(throws: (any Error).self) {
            try Access.Create.parseAllowedCommands("")
        }
    }

    @Test("parseAllowedCommands trims whitespace around tokens")
    func parseAllowedCommandsTrimsWhitespace() throws {
        let parsed = try Access.Create.parseAllowedCommands(" exec , load ")
        #expect(parsed == [.exec, .load])
    }

    @Test("createCredential stores allowedCommands")
    func createCredentialStoresAllowed() throws {
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "access-create")
        defer { try? FileManager.default.removeItem(at: directory) }

        let cred = try Access.createCredential(
            name: "ci",
            scope: "CI",
            ttl: "1h",
            store: store,
            machineIdentity: MachineIdentity(machineId: "m", hostname: "h"),
            now: Date(timeIntervalSince1970: 1_700_000_000),
            allowedCommands: [.exec, .load]
        )
        #expect(cred.allowedCommands == [.exec, .load])

        let reloaded = try store.load(id: cred.id)
        #expect(reloaded?.allowedCommands == [.exec, .load])
    }

    @Test("renderCreateMessage includes sorted allowedCommands")
    func renderCreateMessageShowsAllow() {
        let credential = makeCredential(allowedCommands: [.load, .exec])
        let message = Access.renderCreateMessage(credential)
        #expect(message.contains("allow=exec,load"))
    }

    @Test("renderCreateMessage shows access variable for non-SSH credentials")
    func renderCreateMessageShowsAccessVariableForNonSSHCredential() {
        let credential = makeCredential(allowedCommands: [.load, .read])
        let message = Access.renderCreateMessage(credential)

        #expect(message.contains("export AUTHSIA_ACCESS_CREDENTIAL=\(credential.bearerToken!)"))
        #expect(!message.contains("AUTHSIA_SSH_ACCESS_CREDENTIAL"))
    }

    @Test("renderCreateMessage does not export a mixed SSH credential")
    func renderCreateMessageDoesNotExportMixedSSHCredential() {
        let credential = makeCredential(allowedCommands: [.load, .ssh])
        let message = Access.renderCreateMessage(credential)

        #expect(!message.contains(credential.bearerToken!))
        #expect(!message.contains("AUTHSIA_ACCESS_CREDENTIAL"))
        #expect(!message.contains("AUTHSIA_SSH_ACCESS_CREDENTIAL"))
    }

    @Test("renderCreateMessage shows only SSH variable for SSH-only credentials")
    func renderCreateMessageShowsOnlySSHVariableForSSHOnlyCredential() {
        let credential = makeCredential(allowedCommands: [.ssh])
        let message = Access.renderCreateMessage(credential)

        #expect(!message.contains("AUTHSIA_ACCESS_CREDENTIAL"))
        #expect(message.contains("export AUTHSIA_SSH_ACCESS_CREDENTIAL=\(credential.bearerToken!)"))
    }

    @Test("list items include sorted allowedCommands")
    func listItemsIncludeAllowedCommands() throws {
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "access-list")
        defer { try? FileManager.default.removeItem(at: directory) }
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let cred = try Access.createCredential(
            name: "a",
            scope: "Team/API",
            ttl: "1h",
            store: store,
            machineIdentity: MachineIdentity(machineId: "m", hostname: "h"),
            now: now,
            allowedCommands: [.load, .exec]
        )
        let items = try Access.listItems(store: store, includeAll: false, now: now.addingTimeInterval(60))
        let match = items.first(where: { $0.id == cred.id })
        #expect(match?.allowedCommands == ["exec", "load"])
    }

    @Test("parseAllowedCommands rejects comma-only input")
    func parseAllowedCommandsRejectsCommaOnly() {
        #expect(throws: (any Error).self) {
            try Access.Create.parseAllowedCommands(",")
        }
        #expect(throws: (any Error).self) {
            try Access.Create.parseAllowedCommands(" , , ")
        }
    }

    private func makeCredential(allowedCommands: Set<CapabilityCommand>) -> AccessCredential {
        let id = UUID()
        let token = try! AutomationCredentialToken.issue(
            id: id,
            randomBytes: Data(repeating: 0x41, count: AutomationCredentialToken.randomByteCount)
        )
        return AccessCredential(
            id: id,
            name: "n",
            scope: "s",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresAt: Date(timeIntervalSince1970: 1_700_000_600),
            revokedAt: nil,
            machineId: "m",
            machineName: "h",
            allowedCommands: allowedCommands,
            bearerToken: token
        )
    }
}

private final class AccessCreateApprovalRecorder: AccessCreateApproving {
    enum Result {
        case approved
        case denied
    }

    let result: Result
    private(set) var requests: [AccessCreateApprovalRequest] = []

    init(result: Result) {
        self.result = result
    }

    func approveAccessCreate(
        _ request: AccessCreateApprovalRequest
    ) throws -> AutomationCredentialIssuedPayload {
        requests.append(request)
        if result == .denied {
            throw BridgeClientError.bridgeError(code: "notAuthorized", message: "Access denied", query: nil)
        }
        let id = UUID()
        return AutomationCredentialIssuedPayload(
            credential: AutomationCredentialMetadata(
                id: id,
                name: request.name,
                scope: request.scope,
                createdAt: request.expiresAt.addingTimeInterval(-request.ttlSeconds),
                expiresAt: request.expiresAt,
                revokedAt: nil,
                machineId: request.machineId,
                machineName: request.machineName,
                allowedCommands: request.allowedCommands,
                environmentScope: request.environmentScope
            ),
            token: try AutomationCredentialToken.issue(
                id: id,
                randomBytes: Data(repeating: 0x41, count: AutomationCredentialToken.randomByteCount)
            )
        )
    }
}
