#if os(macOS)
import XCTest
@testable import AuthenticatorBridge

final class MCPReadinessModelsTests: XCTestCase {
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
