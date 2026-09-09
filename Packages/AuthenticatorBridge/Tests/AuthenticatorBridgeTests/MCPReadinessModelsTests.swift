#if os(macOS)
import XCTest
@testable import AuthenticatorBridge

final class MCPReadinessModelsTests: XCTestCase {
    func testClientReadinessDoesNotBorrowAnotherClientsSuccessAndUsesLatestOutcome() {
        let finding = MCPClientServerFinding(source: .cursor, serverName: "example", commandLabel: "authsia",
            status: .admittedWrapped, declaredUpstreamName: "example", configPathLabel: "fixture/mcp.json")
        func call(_ client: String, _ time: Double, _ outcome: MCPHTTPActivityOutcome) -> MCPActivityRecord {
            .init(id: UUID(), kind: .toolCall, recordedAt: Date(timeIntervalSince1970: time),
                workspacePath: "/tmp/fixture", serverID: "example", serverName: "example", toolName: "read",
                clientLabel: client, outcome: outcome)
        }
        let unrelated = call("codex", 20, .succeeded)
        let waiting = MCPClientReadiness.evaluate(finding: finding, serverID: "example", activity: [unrelated], needsRepair: false)
        XCTAssertEqual(waiting.state, .awaitingClient)
        XCTAssertTrue(waiting.detail.contains("Customize > MCPs"))
        let success = call("cursor", 10, .succeeded), failure = call("cursor", 30, .upstreamUnavailable)
        let failed = MCPClientReadiness.evaluate(finding: finding, serverID: "example", activity: [failure, unrelated, success], needsRepair: false)
        XCTAssertEqual(failed.state, .callFailed)
        XCTAssertEqual(failed.lastObservedAt, failure.recordedAt)
        XCTAssertTrue(failed.detail.contains("Activity"))
        XCTAssertEqual(MCPClientReadiness.evaluate(finding: finding, serverID: "example", activity: [success], needsRepair: false).state, .callSucceeded)
        XCTAssertEqual(MCPClientReadiness.evaluate(finding: finding, serverID: "different-workspace", activity: [success], needsRepair: false).state, .awaitingClient)
        XCTAssertEqual(MCPClientReadiness.evaluate(finding: finding, serverID: "example", activity: [success], needsRepair: true).state, .repairRequired)
        for outcome in [MCPHTTPActivityOutcome.started, .incomplete] {
            XCTAssertEqual(MCPClientReadiness.evaluate(finding: finding, serverID: "example",
                activity: [success, call("cursor", 40, outcome)], needsRepair: false).state, .callPending)
        }
    }

    func testRepairTakesPriorityOverRecordedRoutingAndServerSetup() {
        let association = MCPClientAssociation(id: "fixture-cursor", source: .cursor, scope: .project,
            precedence: .effective, status: .admittedWrapped, configPathLabel: "fixture/mcp.json",
            readiness: .init(state: .repairRequired, detail: "Repair the workspace override."))
        let server = MCPServerSnapshot(id: "example", identity: .init(workspacePath: "/tmp/fixture", upstreamName: "example"),
            displayName: "example", transport: .stdio, policy: .init(), catalog: [], clientAssociations: [association])
        let readiness = MCPServerReadinessProjection.readiness(for: server)
        XCTAssertEqual(readiness.next?.label, "Repair Cursor")
        XCTAssertEqual(readiness.facts.first { $0.id == "clientRoute" }?.complete, false)
    }

    func testHTTPWithoutClientRecommendsEnrollment() {
        let server = MCPServerSnapshot(
            id: "fixture-http",
            identity: MCPServerIdentity(workspacePath: "/tmp/fixture", upstreamName: "fixture-http"),
            displayName: "fixture-http",
            transport: .http,
            endpointLabel: "http://127.0.0.1:9000/mcp",
            policy: .init(allow: ["read"]),
            catalog: []
        )
        let readiness = MCPServerReadinessProjection.readiness(for: server)
        XCTAssertEqual(readiness.next?.kind, "enrollHTTP")
    }

    func testCredentialedSTDIOCatalogBlockDoesNotResetLaunchOrProtectNext() {
        let association = MCPClientAssociation(
            id: "filesystem-codex",
            source: .codex,
            scope: .userGlobal,
            precedence: .effective,
            status: .admittedWrapped,
            configPathLabel: "~/.codex/config.toml"
        )
        let server = MCPServerSnapshot(
            id: "filesystem",
            identity: MCPServerIdentity(workspacePath: "/tmp/fixture", upstreamName: "filesystem"),
            displayName: "filesystem",
            transport: .stdio,
            commandLabel: "npx",
            policy: .init(allow: ["read"]),
            catalog: [MCPUpstreamToolDescriptor(name: "read")],
            clientAssociations: [association],
            launchCommand: "npx",
            catalogBlockReason: MCPManagementError.catalogEnvironmentRequired.localizedDescription
        )
        let readiness = MCPServerReadinessProjection.readiness(for: server)
        XCTAssertEqual(readiness.facts.first { $0.id == "launch" }?.complete, true)
        XCTAssertEqual(readiness.next?.kind, "observe")
        XCTAssertNotEqual(readiness.next?.kind, "configure")
    }

    func testMissingExecutableKeepsLaunchIncompleteAndRecommendsEditServer() {
        let server = MCPServerSnapshot(
            id: "missing-bin",
            identity: MCPServerIdentity(workspacePath: "/tmp/fixture", upstreamName: "missing-bin"),
            displayName: "missing-bin",
            transport: .stdio,
            commandLabel: "missing-bin",
            policy: .init(),
            catalog: [],
            launchCommand: "missing-bin",
            catalogBlockReason: MCPManagementError.catalogExecutableMissing.localizedDescription
        )
        let readiness = MCPServerReadinessProjection.readiness(for: server)
        XCTAssertEqual(readiness.facts.first { $0.id == "launch" }?.complete, false)
        XCTAssertEqual(readiness.facts.first { $0.id == "launch" }?.detail, MCPManagementError.catalogExecutableMissing.localizedDescription)
        XCTAssertEqual(readiness.next?.kind, "configure")
        XCTAssertEqual(readiness.next?.label, "Edit server")
        XCTAssertEqual(readiness.next?.reason, MCPManagementError.catalogExecutableMissing.localizedDescription)
        XCTAssertNotEqual(readiness.next?.kind, "policy")
    }

    func testIncompleteCatalogWithEnvironmentBlockRecommendsPolicyNotLaunchRepair() {
        let server = MCPServerSnapshot(
            id: "headless",
            identity: MCPServerIdentity(workspacePath: "/tmp/fixture", upstreamName: "headless"),
            displayName: "headless",
            transport: .stdio,
            commandLabel: "headless",
            policy: .init(),
            catalog: [],
            launchCommand: "headless",
            catalogBlockReason: MCPManagementError.catalogEnvironmentRequired.localizedDescription
        )
        let readiness = MCPServerReadinessProjection.readiness(for: server)
        XCTAssertEqual(readiness.next?.kind, "policy")
        XCTAssertEqual(readiness.next?.label, "Edit tool policy")
    }
}
#endif
