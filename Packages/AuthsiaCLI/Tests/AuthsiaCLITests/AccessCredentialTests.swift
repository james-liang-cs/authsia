import Testing
import Foundation
import AuthenticatorBridge
@testable import authsia

@Suite("AccessCredential allowedCommands")
struct AccessCredentialTests {
    @Test("legacy credential decodes without environment scope")
    func legacyCredentialDecodesWithoutEnvironmentScope() throws {
        let credential = try JSONDecoder().decode(
            AccessCredential.self,
            from: Data("""
            {"id":"11111111-1111-1111-1111-111111111111","name":"legacy","scope":"Team/API","createdAt":0,"expiresAt":4102444800,"revokedAt":null,"machineId":"m","machineName":"M","allowedCommands":["exec"]}
            """.utf8)
        )
        #expect(credential.environmentScope == nil)
    }

    @Test("legacy JSON (no allowedCommands) decodes as [.exec]")
    func legacyDecodeDefaultsToExecOnly() throws {
        let legacyJSON = """
        {
          "id": "11111111-1111-1111-1111-111111111111",
          "name": "legacy",
          "scope": "Team/API",
          "createdAt": "2026-04-01T00:00:00Z",
          "expiresAt": "2099-01-01T00:00:00Z",
          "revokedAt": null,
          "machineId": "m1",
          "machineName": "Host"
        }
        """
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let credential = try decoder.decode(AccessCredential.self, from: Data(legacyJSON.utf8))

        #expect(credential.allowedCommands == [.exec])
    }

    @Test("explicit allowedCommands round-trips through encode/decode")
    func allowedCommandsRoundTrips() throws {
        let original = AccessCredential(
            id: UUID(),
            name: "ci",
            scope: "CI",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
            revokedAt: nil,
            machineId: "m1",
            machineName: "Host",
            allowedCommands: [.exec, .load]
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(original)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(AccessCredential.self, from: data)

        #expect(decoded.allowedCommands == [.exec, .load])
    }

    @Test("CapabilityCommand covers every agent-access surface")
    func capabilityCommandCoversAllSurfaces() {
        let expected: Set<CapabilityCommand> = [.exec, .load, .read, .get, .inject, .ssh, .list]
        #expect(Set(CapabilityCommand.allCases) == expected)
    }
}

@Suite("AccessCredentialStore revocation")
struct AccessCredentialStoreRevocationTests {
    @Test("legacy credential files are display-only and never populate the active cache")
    func legacyCredentialFilesAreDisplayOnly() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("acs-legacy-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let cacheURL = directory.appendingPathComponent("access-credential-metadata.json")
        let legacyURL = directory.appendingPathComponent("access-credentials.json")
        let legacy = AccessCredential(
            id: UUID(),
            name: "old-ci",
            scope: "Team/API",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
            revokedAt: nil,
            machineId: "m",
            machineName: "h",
            allowedCommands: [.exec]
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode([legacy]).write(to: legacyURL)
        let store = AccessCredentialStore(fileURL: cacheURL, legacyFileURL: legacyURL)

        #expect(try store.load(id: legacy.id) == nil)
        #expect(try store.loadDisabledLegacy().map(\.id) == [legacy.id])
    }

    @Test("authority snapshot replaces stale local metadata without persisting bearer tokens")
    func authoritySnapshotReplacesStaleMetadata() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("acs-snapshot-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = AccessCredentialStore(fileURL: directory.appendingPathComponent("cache.json"))
        let stale = AccessCredential(
            id: UUID(),
            name: "stale",
            scope: nil,
            createdAt: .distantPast,
            expiresAt: .distantFuture,
            revokedAt: nil,
            machineId: "m",
            machineName: "h"
        )
        try store.save(stale)
        let current = AccessCredential(
            id: UUID(),
            name: "current",
            scope: "Team/API",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
            revokedAt: nil,
            machineId: "m",
            machineName: "h",
            bearerToken: "must-not-persist"
        )

        try store.replaceAll(with: [current])

        #expect(try store.loadAll().map(\.id) == [current.id])
        #expect(try store.load(id: current.id)?.bearerToken == nil)
        let persisted = try Data(contentsOf: store.fileURL)
        #expect(!persisted.contains(Data("must-not-persist".utf8)))
    }

    @Test("revoke preserves allowedCommands")
    func revokePreservesAllowedCommands() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("acs-revoke-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = AccessCredentialStore(fileURL: directory.appendingPathComponent("creds.json"))

        let original = AccessCredential(
            id: UUID(),
            name: "ci",
            scope: "CI",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
            revokedAt: nil,
            machineId: "m",
            machineName: "h",
            allowedCommands: [.exec, .load]
        )
        try store.save(original)

        let revoked = try store.revoke(id: original.id, revokedAt: Date(timeIntervalSince1970: 1_750_000_000))

        #expect(revoked.allowedCommands == [.exec, .load])
        // And verify it persists through reload too
        let reloaded = try store.load(id: original.id)
        #expect(reloaded?.allowedCommands == [.exec, .load])
    }
}

@Suite("SSH automation grant command")
struct SSHAutomationGrantCommandTests {
    @Test("bearer credentials are never persisted as SSH session grants")
    func bearerCredentialsAreNeverPersistedAsSSHSessionGrants() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "ssh-grant-command")
        defer { try? FileManager.default.removeItem(at: directory) }

        let credential = try Access.createCredential(
            name: "agent",
            scope: "Team/API",
            ttl: "15m",
            store: store,
            machineIdentity: MachineIdentity(machineId: "m", hostname: "h"),
            now: now,
            allowedCommands: [.ssh]
        )
        let grantFileURL = directory.appendingPathComponent("ssh-automation-grants.json")

        try SSHAutomationGrantCommand.activateCurrentSessionGrant(
            environment: [
                AutomationAccessResolver.sshEnvironmentKey:
                    AccessCredentialStoreFixture.token(for: credential)
            ],
            store: store,
            now: now.addingTimeInterval(60),
            sessionScope: "tty:/dev/ttys001:sid:100",
            grantFileURL: grantFileURL
        )

        let grantCredentialID = SSHAutomationGrantStore.activeCredentialID(
            sessionScope: "tty:/dev/ttys001:sid:100",
            ancestryPIDs: [],
            currentDate: now.addingTimeInterval(61),
            fileURL: grantFileURL
        )

        #expect(grantCredentialID == nil)
        #expect(!FileManager.default.fileExists(atPath: grantFileURL.path))
    }

    @Test("activate rejects credentials without ssh capability")
    func activateRejectsCredentialWithoutSSHCapability() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "ssh-grant-command")
        defer { try? FileManager.default.removeItem(at: directory) }

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
            try SSHAutomationGrantCommand.activateCurrentSessionGrant(
                environment: [
                    AutomationAccessResolver.sshEnvironmentKey:
                        AccessCredentialStoreFixture.token(for: credential)
                ],
                store: store,
                now: now.addingTimeInterval(60),
                sessionScope: "tty:/dev/ttys001:sid:100",
                grantFileURL: directory.appendingPathComponent("ssh-automation-grants.json")
            )
        }
    }
}
