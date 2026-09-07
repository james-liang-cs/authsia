#if os(macOS)
import XCTest
@testable import AuthenticatorBridge

final class MCPReadinessModelsTests: XCTestCase {
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
