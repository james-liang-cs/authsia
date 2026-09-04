import XCTest
@testable import AuthenticatorBridge

final class AgentLineageTests: XCTestCase {
    func testStartAndStopMergeBySessionAndAgent() throws {
        let fileURL = try makeTempURL()
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let store = AgentLineageStore(fileURL: fileURL, now: { now })

        try store.record(AgentLineageRecord(
            platform: "claude-code",
            sessionID: "session-1",
            agentID: "agent-2",
            agentType: "Explore",
            workingDirectory: "/repo",
            startedAt: now,
            expiresAt: now.addingTimeInterval(AgentLineageStore.defaultTTL)
        ))
        try store.record(AgentLineageRecord(
            platform: "claude-code",
            sessionID: "session-1",
            agentID: "agent-2",
            agentType: "Explore",
            endedAt: now.addingTimeInterval(180),
            expiresAt: now.addingTimeInterval(AgentLineageStore.defaultTTL)
        ))

        let records = try store.loadAll()
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].startedAt, now)
        XCTAssertEqual(records[0].endedAt, now.addingTimeInterval(180))
        XCTAssertEqual(records[0].agentType, "Explore")
    }

    func testExpiredLineageRecordsAreDropped() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let records = AgentLineageStore.merged(
            [
                AgentLineageRecord(
                    sessionID: "session-1",
                    agentID: "agent-1",
                    agentType: "Explore",
                    startedAt: now.addingTimeInterval(-100),
                    expiresAt: now.addingTimeInterval(-1)
                ),
                AgentLineageRecord(
                    sessionID: "session-1",
                    agentID: "agent-2",
                    agentType: "Plan",
                    startedAt: now,
                    expiresAt: now.addingTimeInterval(60)
                ),
            ],
            now: now
        )

        XCTAssertEqual(records.map(\.agentType), ["Plan"])
    }

    func testSessionGroupingHeaderAndExport() {
        let grantA = makeGrant(
            id: UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!,
            sessionID: "session-abcdef",
            agentType: "Explore"
        )
        let grantB = makeGrant(
            id: UUID(uuidString: "BBBBBBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF")!,
            sessionID: "session-abcdef",
            agentType: "Plan"
        )
        let grantC = makeGrant(
            id: UUID(uuidString: "CCCCCCCC-DDDD-EEEE-FFFF-000000000000")!,
            sessionID: "session-other1",
            agentType: nil
        )

        XCTAssertTrue(AgentSessionGrouping.shouldShowSessionChrome(grants: [grantA, grantB, grantC]))
        let groups = AgentSessionGrouping.groups(grants: [grantA, grantB, grantC], lineage: [])
        XCTAssertEqual(groups.count, 2)
        XCTAssertEqual(
            groups[0].header,
            "Claude Code · session sess…ef · 2 grants · 2 sub-agents"
        )

        let summaries = AgentSessionGrouping.exportSummaries(
            grants: [grantA, grantB, grantC],
            events: [],
            lineage: [
                AgentLineageRecord(
                    sessionID: "session-abcdef",
                    agentID: "agent-2",
                    agentType: "Explore",
                    startedAt: Date(timeIntervalSince1970: 10),
                    expiresAt: Date(timeIntervalSince1970: 10_000)
                ),
            ]
        )
        XCTAssertEqual(summaries.first { $0.sessionID == "session-abcdef" }?.subAgentTypes, ["Explore", "Plan"])
    }

    func testMCPSessionsAreExcludedFromCodingChips() {
        let mcp = makeGrant(
            id: UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!,
            platform: "Codex",
            sessionID: "mcp:7E05890F-5C3A-44EF-9208-83A12F17D6CE",
            agentType: "authsia-mcp"
        )
        let coding = makeGrant(
            id: UUID(uuidString: "BBBBBBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF")!,
            sessionID: "session-1",
            agentType: "Explore"
        )

        XCTAssertFalse(AgentSessionGrouping.shouldShowSessionChrome(grants: [mcp, coding]))
        XCTAssertEqual(AgentSessionGrouping.chips(from: [mcp, coding]).map(\.id), ["session-1"])
        XCTAssertFalse(AgentSessionGrouping.matches(grant: mcp, selectedSessionID: "session-1"))
        XCTAssertTrue(AgentSessionGrouping.matches(grant: coding, selectedSessionID: "session-1"))
    }

    func testLineageCaptionFormatsStartAndEnd() {
        let started = Date(timeIntervalSince1970: 12 * 3600 + 60)
        let ended = Date(timeIntervalSince1970: 12 * 3600 + 4 * 60)
        XCTAssertEqual(
            AgentAttributionPresentation.lineageCaption(
                agentType: "Explore",
                startedAt: started,
                endedAt: ended,
                timeZone: TimeZone(secondsFromGMT: 0)!
            ),
            "Explore · started 12:01 · ended 12:04"
        )
    }

    private func makeTempURL() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-lineage-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("lineage.jsonl")
    }

    private func makeGrant(
        id: UUID,
        platform: String = "claude-code",
        sessionID: String,
        agentType: String?
    ) -> AgentJITGrant {
        AgentJITGrant(
            id: id,
            agentName: "Claude Code",
            callerFingerprint: AgentJITCallerFingerprint(
                processName: "authsia",
                bundleIdentifier: nil,
                signingTeamId: nil,
                signingIdentity: nil,
                parentProcessName: "claude",
                parentBundleIdentifier: nil,
                sessionScope: "tty:/dev/ttys002:sid:84",
                workingDirectory: "/tmp/project"
            ),
            folderScope: .folder("Team/API"),
            capabilities: [.exec, .list],
            createdAt: Date(timeIntervalSince1970: 50),
            expiresAt: Date(timeIntervalSince1970: 500),
            revokedAt: nil,
            lastUsedAt: nil,
            requestedItems: [],
            agentRuntimeContext: AgentRuntimeContext(
                platform: platform,
                sessionID: sessionID,
                agentType: agentType
            ),
            approvedBy: "biometric"
        )
    }
}
