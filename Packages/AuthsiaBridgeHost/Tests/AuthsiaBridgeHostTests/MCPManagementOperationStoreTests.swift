import AuthenticatorBridge
import Foundation
import XCTest
@testable import AuthsiaBridgeHost

final class MCPManagementOperationStoreTests: XCTestCase {
    func testApplyWaitsForAuditAcknowledgement() async throws {
        let entered = expectation(description: "intent write started")
        let audit = PausedAuditStore(entered: entered)
        let store = MCPManagementOperationStore(audit: audit)
        let applied = OperationCounter()
        let prepared = try await store.prepare(owner: "fixture", kind: .policy,
            change: .init(preview: "Fixture", validate: {}, apply: { await applied.increment(); return "Applied" }))
        let pending = Task { try await store.confirm(prepared.id, owner: "fixture", present: { _ in true }, sessionValid: { true }) }
        await fulfillment(of: [entered], timeout: 2)
        let before = await applied.value
        XCTAssertEqual(before, 0)
        await audit.release()
        let result = try await pending.value
        XCTAssertEqual(result.state, .succeeded)
        let after = await applied.value
        XCTAssertEqual(after, 1)
    }
    func testOutcomeFailureReportsAppliedWithIncompleteEvidence() async throws {
        let store = MCPManagementOperationStore(audit: OutcomeFailingAuditStore())
        let prepared = try await store.prepare(owner: "fixture", kind: .policy,
            change: .init(preview: "Fixture", validate: {}, apply: { "Applied" }))
        let result = try await store.confirm(prepared.id, owner: "fixture", present: { _ in true }, sessionValid: { true })
        XCTAssertEqual(result.state, .succeeded)
        XCTAssertTrue(result.message?.contains("incomplete") == true)
    }
    func testMissingAuditDependencyCannotApply() async throws {
        let store = MCPManagementOperationStore()
        let prepared = try await store.prepare(owner: "fixture", kind: .policy,
            change: .init(preview: "Fixture policy", validate: {}, apply: { XCTFail("unaudited operation applied"); return "Applied" }))
        let result = try await store.confirm(prepared.id, owner: "fixture", present: { _ in true }, sessionValid: { true })
        XCTAssertEqual(result.state, .failed)
    }
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
        let store = MCPManagementOperationStore(clock: { clock.now }, audit: SuccessfulAuditStore())
        let change = MCPPreparedManagementChange(preview: "Old", validate: {
            clock.advance()
            _ = try await store.prepare(owner: "other", kind: .policy, change: .init(preview: "New", validate: {}, apply: { "Done" }))
        }, apply: { XCTFail("expired operation applied"); return "Unexpected" })
        let prepared = try await store.prepare(owner: "owner", kind: .policy, change: change)
        let result = try await store.confirm(prepared.id, owner: "owner", present: { _ in true }, sessionValid: { true })
        XCTAssertEqual(result.state, .expired)
    }
    func testOwnerIsolationNativeDenialAndReplay() async throws {
        let store = MCPManagementOperationStore(audit: SuccessfulAuditStore())
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
        let store = MCPManagementOperationStore(audit: SuccessfulAuditStore())
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
    func testAppliedChangeJournalCarriesActivityIdentityAndProjectsOneRow() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let audit = MCPManagementAuditStore(fileURL: root.appendingPathComponent("journal.jsonl"))
        let store = MCPManagementOperationStore(audit: audit)
        let context = MCPManagementActivityContext(identity: .init(workspacePath: "/tmp/fixture", upstreamName: "fixture"), client: "codex", transport: .stdio)
        let prepared = try await store.prepare(owner: "owner", kind: .wrap,
            change: .init(preview: "Protect fixture", validate: {}, apply: { "Applied" }), context: context)
        let result = try await store.confirm(prepared.id, owner: "owner", present: { _ in true }, sessionValid: { true })
        XCTAssertEqual(result.state, .succeeded)
        let journal = try audit.load()
        XCTAssertEqual(journal.map(\.context), [context, context])
        let page = MCPActivityProjection.page(events: [], managementEvents: journal, query: .init(kind: "managementChange"))
        XCTAssertEqual(page.records.count, 1)
        XCTAssertEqual(page.records.first?.outcome, .succeeded)
        XCTAssertEqual(page.records.first?.id, prepared.id)
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
private final class SuccessfulAuditStore: MCPManagementAuditing, @unchecked Sendable {
    func record(_ event: MCPManagementAuditEvent) throws {}
}
private final class OutcomeFailingAuditStore: MCPManagementAuditing, @unchecked Sendable {
    func record(_ event: MCPManagementAuditEvent) throws {
        if event.phase == "outcome" { throw MCPManagementError.auditUnavailable }
    }
}
private actor PausedAuditStore: MCPManagementAuditing {
    let entered: XCTestExpectation
    var continuation: CheckedContinuation<Void, Never>?
    init(entered: XCTestExpectation) { self.entered = entered }
    func record(_ event: MCPManagementAuditEvent) async throws {
        if event.phase == "intent" {
            await withCheckedContinuation { continuation = $0; entered.fulfill() }
        }
    }
    func release() { continuation?.resume(); continuation = nil }
}
private actor OperationCounter { var value = 0; func increment() { value += 1 } }
private final class OperationClock: @unchecked Sendable {
    private let lock = NSLock()
    private var date = Date(timeIntervalSince1970: 1000)
    var now: Date { lock.withLock { date } }
    func advance() { lock.withLock { date = date.addingTimeInterval(600) } }
}
