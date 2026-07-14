import Foundation
import Testing
@testable import AuthenticatorBridge

@Suite("SSH automation grant store")
struct SSHAutomationGrantStoreTests {
    @Test("session grant matches only the same terminal scope")
    func sessionGrantMatchesOnlySameScope() throws {
        let fileURL = temporaryFileURL()
        defer { try? FileManager.default.removeItem(at: fileURL.deletingLastPathComponent()) }

        let credentialID = UUID()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        try SSHAutomationGrantStore.saveGrant(
            credentialID: credentialID,
            sessionScope: "tty:/dev/ttys001:sid:100",
            rootProcessID: nil,
            expiresAt: now.addingTimeInterval(60),
            fileURL: fileURL,
            currentDate: now
        )

        let sameScope = SSHAutomationGrantStore.activeCredentialID(
            sessionScope: "tty:/dev/ttys001:sid:100",
            ancestryPIDs: [],
            currentDate: now.addingTimeInterval(1),
            fileURL: fileURL
        )
        let otherScope = SSHAutomationGrantStore.activeCredentialID(
            sessionScope: "tty:/dev/ttys002:sid:100",
            ancestryPIDs: [],
            currentDate: now.addingTimeInterval(1),
            fileURL: fileURL
        )

        #expect(sameScope == credentialID)
        #expect(otherScope == nil)
    }

    @Test("process grant matches descendant ancestry")
    func processGrantMatchesDescendantAncestry() throws {
        let fileURL = temporaryFileURL()
        defer { try? FileManager.default.removeItem(at: fileURL.deletingLastPathComponent()) }

        let credentialID = UUID()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        try SSHAutomationGrantStore.saveGrant(
            credentialID: credentialID,
            sessionScope: nil,
            rootProcessID: 42,
            expiresAt: now.addingTimeInterval(60),
            fileURL: fileURL,
            currentDate: now
        )

        let match = SSHAutomationGrantStore.activeCredentialID(
            sessionScope: nil,
            ancestryPIDs: [100, 99, 42, 1],
            currentDate: now.addingTimeInterval(1),
            fileURL: fileURL
        )
        let miss = SSHAutomationGrantStore.activeCredentialID(
            sessionScope: nil,
            ancestryPIDs: [100, 99, 1],
            currentDate: now.addingTimeInterval(1),
            fileURL: fileURL
        )

        #expect(match == credentialID)
        #expect(miss == nil)
    }

    @Test("expired grants are ignored and pruned")
    func expiredGrantsAreIgnoredAndPruned() throws {
        let fileURL = temporaryFileURL()
        defer { try? FileManager.default.removeItem(at: fileURL.deletingLastPathComponent()) }

        let credentialID = UUID()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        try SSHAutomationGrantStore.saveGrant(
            credentialID: credentialID,
            sessionScope: "tty:/dev/ttys001:sid:100",
            rootProcessID: nil,
            expiresAt: now.addingTimeInterval(-1),
            fileURL: fileURL,
            currentDate: now.addingTimeInterval(-10)
        )

        let match = SSHAutomationGrantStore.activeCredentialID(
            sessionScope: "tty:/dev/ttys001:sid:100",
            ancestryPIDs: [],
            currentDate: now,
            fileURL: fileURL
        )
        let records = SSHAutomationGrantStore.load(fileURL: fileURL)

        #expect(match == nil)
        #expect(records.isEmpty)
    }

    @Test("clear removes only the requested binding")
    func clearRemovesOnlyRequestedBinding() throws {
        let fileURL = temporaryFileURL()
        defer { try? FileManager.default.removeItem(at: fileURL.deletingLastPathComponent()) }

        let first = UUID()
        let second = UUID()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let firstGrant = try SSHAutomationGrantStore.saveGrant(
            credentialID: first,
            sessionScope: "tty:/dev/ttys001:sid:100",
            rootProcessID: nil,
            expiresAt: now.addingTimeInterval(60),
            fileURL: fileURL,
            currentDate: now
        )
        _ = try SSHAutomationGrantStore.saveGrant(
            credentialID: second,
            sessionScope: "tty:/dev/ttys002:sid:100",
            rootProcessID: nil,
            expiresAt: now.addingTimeInterval(60),
            fileURL: fileURL,
            currentDate: now
        )

        SSHAutomationGrantStore.clearGrant(id: firstGrant.id, fileURL: fileURL)

        let remaining = SSHAutomationGrantStore.load(fileURL: fileURL)

        #expect(remaining.map(\.credentialID) == [second])
    }

    private func temporaryFileURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-ssh-grants-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("ssh-automation-grants.json")
    }
}
