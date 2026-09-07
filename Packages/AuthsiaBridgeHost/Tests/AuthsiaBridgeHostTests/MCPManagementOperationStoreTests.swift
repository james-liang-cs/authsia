import AuthenticatorBridge
import Foundation
import XCTest
@testable import AuthsiaBridgeHost

final class MCPManagementOperationStoreTests: XCTestCase {
    func testLogoutDuringConfirmationFinishesWithoutApplying() async throws {
        let store = MCPManagementOperationStore()
        let prepared = try await store.prepare(owner: "owner", kind: .policy,
            change: .init(preview: "Policy", validate: {}, apply: { XCTFail("logged-out operation applied"); return "Unexpected" }))
        let result = try await store.confirm(prepared.id, owner: "owner", present: { _ in true }, sessionValid: { false })
        XCTAssertEqual(result.state, .denied)
        let repeated = try await store.confirm(prepared.id, owner: "owner", present: { _ in XCTFail("replayed prompt"); return true }, sessionValid: { true })
        XCTAssertEqual(repeated.state, .denied)
    }
    func testExpirationDuringValidationDoesNotLoseActiveEntry() async throws {
        let clock = OperationClock()
        let store = MCPManagementOperationStore(clock: { clock.now })
        let change = MCPPreparedManagementChange(preview: "Old", validate: {
            clock.advance()
            _ = try await store.prepare(owner: "other", kind: .policy, change: .init(preview: "New", validate: {}, apply: { "Done" }))
        }, apply: { XCTFail("expired operation applied"); return "Unexpected" })
        let prepared = try await store.prepare(owner: "owner", kind: .policy, change: change)
        let result = try await store.confirm(prepared.id, owner: "owner", present: { _ in true }, sessionValid: { true })
        XCTAssertEqual(result.state, .expired)
    }
    func testOwnerIsolationNativeDenialAndReplay() async throws {
        let store = MCPManagementOperationStore()
        let counter = OperationCounter()
        let change = MCPPreparedManagementChange(preview: "Policy", validate: {}, apply: { await counter.increment(); return "Applied" })
        let first = try await store.prepare(owner: "browser-a", kind: .policy, change: change)
        do { _ = try await store.get(first.id, owner: "browser-b"); XCTFail("owner mismatch") } catch {}
        let denied = try await store.confirm(first.id, owner: "browser-a", present: { _ in false }, sessionValid: { true })
        XCTAssertEqual(denied.state, .denied)
        let second = try await store.prepare(owner: "browser-a", kind: .policy, change: change)
        let applied = try await store.confirm(second.id, owner: "browser-a", present: { _ in true }, sessionValid: { true })
        XCTAssertEqual(applied.state, .succeeded)
        _ = try await store.confirm(second.id, owner: "browser-a", present: { _ in XCTFail("replayed approval"); return true }, sessionValid: { true })
        let count = await counter.value
        XCTAssertEqual(count, 1)
    }
    func testExternalEditAfterPreparationCannotBeOverwritten() async throws {
        let store = MCPManagementOperationStore()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("config.json")
        let original = Data("old".utf8), external = Data("external".utf8)
        try original.write(to: file)
        let mutation = MCPPreparedFileChange(fileURL: file, original: original, replacement: Data("planned".utf8))
        let operation = try await store.prepare(owner: "owner", kind: .policy,
            change: .init(preview: "Policy", validate: { try mutation.validate() }, apply: { try mutation.apply(); return "Done" }))
        try external.write(to: file)
        let result = try await store.confirm(operation.id, owner: "owner", present: { _ in true }, sessionValid: { true })
        XCTAssertEqual(result.state, .stale)
        XCTAssertEqual(try Data(contentsOf: file), external)
    }
    func testMissingIntentRecordFailsClosedBeforeApply() async throws {
        let store = MCPManagementOperationStore(audit: FailingAuditStore())
        let applied = OperationCounter()
        let prepared = try await store.prepare(owner: "owner", kind: .policy,
            change: .init(preview: "Policy", validate: {}, apply: { await applied.increment(); return "Applied" }))
        let result = try await store.confirm(prepared.id, owner: "owner", present: { _ in true }, sessionValid: { true })
        XCTAssertEqual(result.state, .failed)
        XCTAssertTrue(result.message?.contains("intent") == true)
        let count = await applied.value
        XCTAssertEqual(count, 0)
    }
}
private final class FailingAuditStore: MCPManagementAuditing, @unchecked Sendable {
    func record(_ event: MCPManagementAuditEvent) throws {
        throw MCPManagementError.auditUnavailable
    }
}
private actor OperationCounter { var value = 0; func increment() { value += 1 } }
private final class OperationClock: @unchecked Sendable {
    private let lock = NSLock()
    private var date = Date(timeIntervalSince1970: 1000)
    var now: Date { lock.withLock { date } }
    func advance() { lock.withLock { date = date.addingTimeInterval(600) } }
}
