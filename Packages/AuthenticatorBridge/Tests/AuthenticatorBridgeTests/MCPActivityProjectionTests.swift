import XCTest
@testable import AuthenticatorBridge

final class MCPActivityProjectionTests: XCTestCase {
    func testIncompleteEvidenceInAnotherWorkspaceDoesNotWarnForFilteredWorkspace() {
        let events = [MCPHTTPActivityRecording.commandEvent(from: event(
            id: UUID(), workspace: "/tmp/quiet", tool: "read", outcome: .succeeded))]
        let pending = [event(id: UUID(), workspace: "/tmp/other", tool: "read", outcome: .started)]
        let query = MCPActivityQuery(workspacePath: "/tmp/quiet")
        let page = MCPActivityProjection.page(events: events, pendingEvidence: pending, query: query)
        XCTAssertEqual(page.sourceHealth, .ok)
        XCTAssertNil(page.message)
        XCTAssertEqual(MCPActivityProjection.page(events: events, pendingEvidence: pending).sourceHealth, .incomplete)
        XCTAssertEqual(MCPActivityProjection.page(events: events, evidenceOverflow: true, query: query).sourceHealth, .incomplete)
        XCTAssertEqual(MCPActivityProjection.page(events: events, unavailableSources: ["managementJournal"], query: query).sourceHealth, .incomplete)
    }

    func testHTTPWriterHistoryProjectionMergesOneCallAndKeepsRepeatedInvocationsSeparate() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("events.jsonl")
        let store = AgentCommandHistoryStore(fileURL: file)
        let first = UUID(), second = UUID()
        let workspace = "/tmp/activity-a"
        try store.record(MCPHTTPActivityRecording.commandEvent(from: event(id: first, workspace: workspace, tool: "read", outcome: .started)))
        try store.record(MCPHTTPActivityRecording.commandEvent(from: event(id: first, workspace: workspace, tool: "read", outcome: .succeeded, grants: [UUID()])))
        try store.record(MCPHTTPActivityRecording.commandEvent(from: event(id: second, workspace: workspace, tool: "read", outcome: .started)))
        try store.record(MCPHTTPActivityRecording.commandEvent(from: event(id: second, workspace: workspace, tool: "read", outcome: .succeeded)))
        let page = MCPActivityProjection.page(events: try store.loadAll())
        XCTAssertEqual(page.records.count, 2)
        XCTAssertEqual(Set(page.records.compactMap(\.callID)), [first.uuidString, second.uuidString])
        XCTAssertTrue(page.records.allSatisfy { $0.outcome == .succeeded && $0.kind == .toolCall })
        XCTAssertEqual(page.sourceHealth, .ok)
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(page), as: UTF8.self).contains("secret"))
    }

    func testDeniedAndBusyOutcomesStayToolCallsAndLifecycleIsNotUnavailable() throws {
        let recorded = [
            MCPHTTPActivityRecording.commandEvent(from: event(id: UUID(), workspace: "/tmp/a", tool: "delete", outcome: .denied)),
            MCPHTTPActivityRecording.commandEvent(from: event(id: UUID(), workspace: "/tmp/a", tool: "read", outcome: .busy)),
            AgentCommandEvent(
                recordedAt: Date(),
                agentPlatform: "codex",
                agentID: "proxy:filesystem",
                captureSource: .mcpProxy,
                workingDirectory: "/tmp/a",
                executable: "filesystem",
                arguments: ["mcp-tool", "spawn"],
                command: "MCP tool",
                mcpProxyOutcome: .childStarted
            ),
        ]
        let page = MCPActivityProjection.page(events: recorded)
        XCTAssertEqual(page.records.first { $0.outcome == .denied }?.kind, .toolCall)
        XCTAssertEqual(page.records.first { $0.outcome == .busy }?.kind, .toolCall)
        XCTAssertEqual(page.records.first { $0.outcome == .childStarted }?.kind, .serverLifecycle)
        XCTAssertFalse(page.records.contains { $0.outcome == .upstreamUnavailable })
    }

    func testHistoryReadFailureIsNotAnEmptyHealthyWindow() {
        let page = MCPActivityProjection.page(loading: { throw NSError(domain: "test", code: 1) })
        XCTAssertEqual(page.sourceHealth, .unavailable)
        XCTAssertTrue(page.records.isEmpty)
        XCTAssertNotNil(page.message)
        XCTAssertNotEqual(page.message, "No observed calls")
    }

    func testWorkspaceFilterRunsBeforePaginationSoAQuietWorkspaceIsNotHidden() throws {
        var events: [AgentCommandEvent] = []
        for index in 0..<180 {
            events.append(MCPHTTPActivityRecording.commandEvent(from: event(
                id: UUID(), workspace: "/tmp/busy", tool: "read", outcome: .succeeded,
                at: Date(timeIntervalSince1970: TimeInterval(index)))))
        }
        let quiet = UUID()
        events.append(MCPHTTPActivityRecording.commandEvent(from: event(
            id: quiet, workspace: "/tmp/quiet", tool: "search", outcome: .succeeded,
            at: Date(timeIntervalSince1970: 1))))
        let page = MCPActivityProjection.page(events: events, query: .init(workspacePath: "/tmp/quiet", limit: 50))
        XCTAssertEqual(page.records.count, 1)
        XCTAssertEqual(page.records.first?.callID, quiet.uuidString)
        XCTAssertEqual(page.sourceHealth, .ok)
        let truncated = MCPActivityProjection.page(events: events, query: .init(workspacePath: "/tmp/busy", limit: 50))
        XCTAssertEqual(truncated.records.count, 50)
        XCTAssertTrue(truncated.truncated)
        XCTAssertEqual(truncated.sourceHealth, .truncated)
    }

    func testEmptyActivityQueryParametersDoNotHideEveryWorkspace() throws {
        let query = MCPActivityQuery.parse(uri: "/api/v1/activity?workspace=&q=&kind=&outcome=")
        XCTAssertNil(query.workspacePath)
        XCTAssertNil(query.search)
        XCTAssertNil(query.kind)
        let page = MCPActivityProjection.page(
            events: [MCPHTTPActivityRecording.commandEvent(from: event(id: UUID(), workspace: "/tmp/a", tool: "read", outcome: .succeeded))],
            query: query
        )
        XCTAssertEqual(page.records.count, 1)
    }

    func testDuplicateActivityQueryKeysKeepTheFirstValueWithoutTrapping() {
        let query = MCPActivityQuery.parse(uri: "/api/v1/activity?outcome=denied&outcome=succeeded&limit=1&limit=50")
        XCTAssertEqual(query.outcome, "denied")
        XCTAssertEqual(query.limit, 1)
    }

    func testSameSecondActivityPagesByIdentityInsteadOfDroppingRows() throws {
        let instant = Date(timeIntervalSince1970: 1_700_000_000)
        let first = UUID(uuidString: "00000000-0000-0000-0000-00000000000a")!
        let second = UUID(uuidString: "00000000-0000-0000-0000-00000000000b")!
        let third = UUID(uuidString: "00000000-0000-0000-0000-00000000000c")!
        let events = [first, second, third].map { id in
            MCPHTTPActivityRecording.commandEvent(from: event(
                id: id, workspace: "/tmp/a", tool: "read", outcome: .succeeded, at: instant))
        }
        var seen: [UUID] = []
        var cursor: String?
        for index in 0..<3 {
            let page = MCPActivityProjection.page(events: events, query: .init(cursor: cursor, limit: 1))
            XCTAssertEqual(page.records.count, 1)
            seen.append(page.records[0].id)
            cursor = page.cursor
            if index < 2 {
                XCTAssertTrue(page.truncated)
                XCTAssertNotNil(cursor)
            } else {
                XCTAssertFalse(page.truncated)
                XCTAssertNil(cursor)
            }
        }
        XCTAssertEqual(Set(seen), [first, second, third])
    }

    func testOlderGrantJSONStillDecodesWithoutInventingWorkspaceIdentity() throws {
        let data = Data(#"{"id":"11111111-1111-1111-1111-111111111111","serverName":"codegraph","clientLabel":"Codex","transport":"stdio","expiresAt":0}"#.utf8)
        let grant = try JSONDecoder().decode(MCPManagerGrantView.self, from: data)
        XCTAssertNil(grant.workspacePath)
        XCTAssertNil(grant.serverID)
        XCTAssertEqual(grant.serverName, "codegraph")
    }

    func testManagementJournalMergesByOperationAndFiltersBeforePaging() throws {
        let operation = UUID()
        let context = MCPManagementActivityContext(identity: .init(workspacePath: "/tmp/quiet", upstreamName: "fixture"), client: "codex", transport: .stdio)
        let entries = [
            MCPManagementAuditEvent(operationID: operation, kind: "policy", phase: "intent", summary: "Policy", result: "pending", context: context),
            MCPManagementAuditEvent(operationID: operation, kind: "policy", phase: "outcome", summary: "Policy", result: "applied", context: context)
        ]
        let page = MCPActivityProjection.page(events: [], managementEvents: entries,
            query: .init(workspacePath: "/tmp/quiet", kind: "managementChange", limit: 1))
        XCTAssertEqual(page.records.count, 1)
        XCTAssertEqual(page.records.first?.id, operation)
        XCTAssertEqual(page.records.first?.outcome, .succeeded)
        XCTAssertEqual(page.records.first?.serverName, "fixture")
        XCTAssertEqual(page.records.first?.clientLabel, "codex")
        XCTAssertEqual(page.sourceHealth, .ok)
        let missing = MCPActivityProjection.page(events: [], managementEvents: [entries[0]])
        XCTAssertEqual(missing.records.first?.evidenceStatus, "incomplete")
        XCTAssertEqual(missing.sourceHealth, .incomplete)
    }

    func testOneUnreadableSourceDoesNotHideTheOtherOrClaimCompleteEvidence() {
        let call = event(id: UUID(), workspace: "/tmp/a", tool: "read", outcome: .succeeded)
        let page = MCPActivityProjection.page(loading: { [MCPHTTPActivityRecording.commandEvent(from: call)] },
            loadingManagement: { throw MCPManagementError.unavailable })
        XCTAssertEqual(page.records.count, 1)
        XCTAssertEqual(page.sourceHealth, .incomplete)
        XCTAssertEqual(page.sources?["managementJournal"], .unavailable)
        XCTAssertEqual(page.sources?["commandHistory"], .ok)
    }

    func testFailedEvidenceKeepsActualOutcomeAndSuccessfulRetryClearsFallback() {
        let id = UUID()
        let started = event(id: id, workspace: "/tmp/a", tool: "write", outcome: .started)
        let terminal = event(id: id, workspace: "/tmp/a", tool: "write", outcome: .succeeded)
        let buffer = MCPActivityEvidenceBuffer(limit: 1)
        buffer.retain(terminal)
        let page = MCPActivityProjection.page(events: [MCPHTTPActivityRecording.commandEvent(from: started)], pendingEvidence: buffer.snapshot().events)
        XCTAssertEqual(page.records.count, 1)
        XCTAssertEqual(page.records.first?.outcome, .succeeded)
        XCTAssertEqual(page.records.first?.evidenceStatus, "incomplete")
        XCTAssertEqual(page.sourceHealth, .incomplete)
        buffer.recorded(terminal)
        XCTAssertTrue(buffer.snapshot().events.isEmpty)
        XCTAssertFalse(buffer.snapshot().overflow)
        buffer.retain(terminal)
        buffer.retain(event(id: UUID(), workspace: "/tmp/a", tool: "write", outcome: .succeeded))
        XCTAssertEqual(buffer.snapshot().events.count, 1)
        XCTAssertTrue(buffer.snapshot().overflow)
    }

    func testUnfinishedCallDoesNotClaimCompleteEvidenceAfterRestart() {
        let started = event(id: UUID(), workspace: "/tmp/a", tool: "write", outcome: .started)
        let page = MCPActivityProjection.page(events: [MCPHTTPActivityRecording.commandEvent(from: started)])
        XCTAssertEqual(page.records.first?.outcome, .started)
        XCTAssertEqual(page.records.first?.evidenceStatus, "pending")
        XCTAssertEqual(page.sourceHealth, .incomplete)
    }

    func testAuthorityFailureSurvivesWireEncodingAndOlderRepliesStillDecode() throws {
        let reply = MCPHTTPAuthorityReply(valid: false, failure: .denied)
        XCTAssertEqual(try JSONDecoder().decode(MCPHTTPAuthorityReply.self, from: JSONEncoder().encode(reply)).failure, .denied)
        XCTAssertNil(try JSONDecoder().decode(MCPHTTPAuthorityReply.self, from: Data(#"{"valid":true}"#.utf8)).failure)
    }

    private func event(
        id: UUID,
        workspace: String,
        tool: String,
        outcome: MCPHTTPActivityOutcome,
        grants: [UUID] = [],
        at: Date = Date()
    ) -> MCPHTTPActivityEvent {
        MCPHTTPActivityEvent(
            id: id, recordedAt: at, serverID: MCPWorkspaceStore.serverID(.init(workspacePath: workspace, upstreamName: "codegraph")),
            serverName: "codegraph", workspacePath: workspace, toolName: tool, outcome: outcome,
            attribution: "codex", grantIDs: grants, transport: .streamableHTTP
        )
    }
}
