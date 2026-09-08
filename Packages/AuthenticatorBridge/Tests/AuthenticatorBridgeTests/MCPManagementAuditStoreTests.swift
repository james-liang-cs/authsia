#if os(macOS)
import XCTest
@testable import AuthenticatorBridge

final class MCPManagementAuditStoreTests: XCTestCase {
    func testConcurrentStoreInstancesPreserveEveryEvent() async throws {
        let file = try fixture()
        let events = (0..<20).map { _ in event() }
        try await withThrowingTaskGroup(of: Void.self) { group in
            for event in events {
                group.addTask { try MCPManagementAuditStore(fileURL: file).record(event) }
            }
            try await group.waitForAll()
        }
        let snapshot = try MCPManagementAuditStore(fileURL: file).loadSnapshot()
        XCTAssertEqual(Set(snapshot.events.map(\.id)), Set(events.map(\.id)))
        XCTAssertFalse(snapshot.retentionLimited)
    }
    private func fixture() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        addTeardownBlock { try FileManager.default.removeItem(at: root) }
        return root.appendingPathComponent("fixture.jsonl")
    }
    private func event(at date: Date = Date()) -> MCPManagementAuditEvent {
        .init(operationID: UUID(), kind: "policy", phase: "intent", recordedAt: date,
              summary: "Synthetic policy change", result: "pending")
    }
    func testRollingRetentionSurvivesReopenAndReportsTruncation() throws {
        let file = try fixture()
        let store = MCPManagementAuditStore(fileURL: file, maximumEvents: 2)
        let events = (0..<5).map { _ in event() }
        for event in events { try store.record(event) }
        let snapshot = try MCPManagementAuditStore(fileURL: file).loadSnapshot()
        XCTAssertEqual(snapshot.events.map(\.id), events.suffix(2).map(\.id))
        XCTAssertTrue(snapshot.retentionLimited)
        let page = MCPActivityProjection.page(loading: { [] }, loadingManagementSnapshot: { snapshot })
        XCTAssertEqual(page.sources?["managementJournal"], .truncated)
        XCTAssertTrue(page.truncated)
        XCTAssertNotEqual(page.completeness, "complete")
    }
    func testByteLimitAndLegacyOversizedTailRemainBounded() throws {
        let file = try fixture()
        var legacy = Data()
        for _ in 0..<30 {
            legacy.append(try JSONEncoder.agentCommandHistoryLine.encode(event()))
            legacy.append(0x0A)
        }
        try legacy.write(to: file)
        let store = MCPManagementAuditStore(fileURL: file, maximumBytes: 1_024)
        XCTAssertTrue(try store.loadSnapshot().retentionLimited)
        let latest = event()
        try store.record(latest)
        XCTAssertLessThanOrEqual(try Data(contentsOf: file).count, 1_024)
        XCTAssertEqual(try store.load().last?.id, latest.id)
        XCTAssertTrue(try store.loadSnapshot().retentionLimited)
    }
    func testAgeRetentionAndPartialRecordsDoNotLookComplete() throws {
        let file = try fixture()
        let now = Date()
        let store = MCPManagementAuditStore(fileURL: file, retentionInterval: 60, clock: { now })
        var old = try JSONEncoder.agentCommandHistoryLine.encode(event(at: now.addingTimeInterval(-120)))
        old.append(0x0A)
        try old.write(to: file)
        XCTAssertTrue(try store.loadSnapshot().retentionLimited)
        XCTAssertTrue(try store.load().isEmpty)
        try Data("{partial".utf8).write(to: file)
        XCTAssertThrowsError(try store.loadSnapshot())
        XCTAssertThrowsError(try store.record(event()))
    }
    func testDuplicateAcknowledgementDoesNotDuplicateJournalRow() throws {
        let store = MCPManagementAuditStore(fileURL: try fixture())
        let value = event()
        try store.record(value); try store.record(value)
        XCTAssertEqual(try store.load().count, 1)
    }
    func testCatalogRefreshPreservesDecisionsAcrossTransports() throws {
        let policy = MCPUpstreamToolPolicy(allow: ["read"], approve: ["write"], deny: ["delete"])
        for transport in [MCPUpstreamTransport.stdio, .streamableHTTP] {
            for original in [policy, MCPUpstreamToolPolicy()] {
                let upstream = MCPUpstreamConfig(name: "fixture", transport: transport, tools: original)
                let updated = upstream.recordingCatalog([.init(name: "new_tool"), .init(name: "read")])
                XCTAssertEqual(updated.tools, original == MCPUpstreamToolPolicy()
                    ? MCPUpstreamToolPolicy(allow: ["new_tool", "read"]) : original)
                XCTAssertEqual(updated.catalog.map(\.name), ["new_tool", "read"])
                XCTAssertEqual(MCPToolPolicyEvaluator.decision(for: "new_tool", policy: updated.tools),
                    original == MCPUpstreamToolPolicy() ? .allow : .unlisted)
                XCTAssertNotNil(updated.catalogCapturedAt)
            }
        }
    }
}
#endif
