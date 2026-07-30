import Foundation
import Dispatch
import Testing
@testable import AuthenticatorBridge

@Suite("SSH automation grant store")
struct SSHAutomationGrantStoreTests {
    @Test("session grant matches only the same terminal scope")
    func sessionGrantMatchesOnlySameScope() throws {
        let fileURL = temporaryFileURL()
        defer { try? FileManager.default.removeItem(at: fileURL.deletingLastPathComponent()) }

        let leaseID = UUID()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        try SSHAutomationGrantStore.saveGrant(
            leaseID: leaseID,
            sessionScope: "tty:/dev/ttys001:sid:100",
            rootProcessID: nil,
            expiresAt: now.addingTimeInterval(60),
            fileURL: fileURL,
            currentDate: now
        )

        let sameScope = SSHAutomationGrantStore.activeLeaseIDs(
            sessionScope: "tty:/dev/ttys001:sid:100",
            ancestryPIDs: [],
            currentDate: now.addingTimeInterval(1),
            fileURL: fileURL
        )
        let otherScope = SSHAutomationGrantStore.activeLeaseIDs(
            sessionScope: "tty:/dev/ttys002:sid:100",
            ancestryPIDs: [],
            currentDate: now.addingTimeInterval(1),
            fileURL: fileURL
        )

        #expect(sameScope == [leaseID])
        #expect(otherScope.isEmpty)
    }

    @Test("process grant matches descendant ancestry")
    func processGrantMatchesDescendantAncestry() throws {
        let fileURL = temporaryFileURL()
        defer { try? FileManager.default.removeItem(at: fileURL.deletingLastPathComponent()) }

        let leaseID = UUID()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        try SSHAutomationGrantStore.saveGrant(
            leaseID: leaseID,
            sessionScope: nil,
            rootProcessID: 42,
            expiresAt: now.addingTimeInterval(60),
            fileURL: fileURL,
            currentDate: now
        )

        let match = SSHAutomationGrantStore.activeLeaseIDs(
            sessionScope: nil,
            ancestryPIDs: [100, 99, 42, 1],
            currentDate: now.addingTimeInterval(1),
            fileURL: fileURL
        )
        let miss = SSHAutomationGrantStore.activeLeaseIDs(
            sessionScope: nil,
            ancestryPIDs: [100, 99, 1],
            currentDate: now.addingTimeInterval(1),
            fileURL: fileURL
        )

        #expect(match == [leaseID])
        #expect(miss.isEmpty)
    }

    @Test("expired grants are ignored and pruned")
    func expiredGrantsAreIgnoredAndPruned() throws {
        let fileURL = temporaryFileURL()
        defer { try? FileManager.default.removeItem(at: fileURL.deletingLastPathComponent()) }

        let leaseID = UUID()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        try SSHAutomationGrantStore.saveGrant(
            leaseID: leaseID,
            sessionScope: "tty:/dev/ttys001:sid:100",
            rootProcessID: nil,
            expiresAt: now.addingTimeInterval(-1),
            fileURL: fileURL,
            currentDate: now.addingTimeInterval(-10)
        )

        let match = SSHAutomationGrantStore.activeLeaseIDs(
            sessionScope: "tty:/dev/ttys001:sid:100",
            ancestryPIDs: [],
            currentDate: now,
            fileURL: fileURL
        )
        let records = SSHAutomationGrantStore.load(fileURL: fileURL)

        #expect(match.isEmpty)
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
            leaseID: first,
            sessionScope: "tty:/dev/ttys001:sid:100",
            rootProcessID: nil,
            expiresAt: now.addingTimeInterval(60),
            fileURL: fileURL,
            currentDate: now
        )
        _ = try SSHAutomationGrantStore.saveGrant(
            leaseID: second,
            sessionScope: "tty:/dev/ttys002:sid:100",
            rootProcessID: nil,
            expiresAt: now.addingTimeInterval(60),
            fileURL: fileURL,
            currentDate: now
        )

        SSHAutomationGrantStore.clearGrant(id: firstGrant.id, fileURL: fileURL)

        let remaining = SSHAutomationGrantStore.load(fileURL: fileURL)

        #expect(remaining.map(\.leaseID) == [second])
    }

    @Test("concurrent grant updates preserve every binding")
    func concurrentGrantUpdatesPreserveEveryBinding() {
        let fileURL = temporaryFileURL()
        defer { try? FileManager.default.removeItem(at: fileURL.deletingLastPathComponent()) }

        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let grantCount = 32
        DispatchQueue.concurrentPerform(iterations: grantCount) { index in
            _ = try? SSHAutomationGrantStore.saveGrant(
                leaseID: UUID(),
                sessionScope: "tty:/dev/ttys\(index):sid:\(index)",
                rootProcessID: nil,
                expiresAt: now.addingTimeInterval(60),
                fileURL: fileURL,
                currentDate: now
            )
        }

        #expect(SSHAutomationGrantStore.load(fileURL: fileURL).count == grantCount)
    }

    private func temporaryFileURL() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-ssh-grants-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("ssh-automation-grants.json")
    }
}
