import XCTest
@testable import AuthenticatorBridge

final class MCPRegistryModelsTests: XCTestCase {
    func testServerIdentityStandardizesWorkspaceWithoutCollapsingNames() {
        let first = MCPServerIdentity(workspacePath: "/tmp/project/../project", upstreamName: "github")
        let same = MCPServerIdentity(workspacePath: "/tmp/project", upstreamName: "github")
        let other = MCPServerIdentity(workspacePath: "/tmp/project", upstreamName: "filesystem")

        XCTAssertEqual(first, same)
        XCTAssertNotEqual(first, other)
    }

    func testSanitizedRegistrySnapshotRoundTripsWithoutCredentialReferences() throws {
        let snapshot = MCPRegistrySnapshot(
            revision: "fixture-revision",
            servers: [
                MCPServerSnapshot(
                    id: "server-fixture",
                    identity: MCPServerIdentity(
                        workspacePath: "/tmp/fixture-workspace",
                        upstreamName: "github"
                    ),
                    displayName: "GitHub",
                    transport: .stdio,
                    commandLabel: "docker",
                    policy: MCPUpstreamToolPolicy(
                        allow: ["repositories/list"],
                        approve: ["issues/create"],
                        deny: ["repository/delete"]
                    ),
                    catalog: [MCPUpstreamToolDescriptor(name: "repositories/list")],
                    credentialLabels: ["github-work"],
                    clientAssociations: [
                        MCPClientAssociation(
                            id: "association-fixture",
                            source: .codex,
                            scope: .userGlobal,
                            precedence: .effective,
                            status: .admittedWrapped,
                            configPathLabel: "~/.codex/config.toml"
                        ),
                    ],
                    observedCallCount: 43
                ),
            ]
        )

        let data = try JSONEncoder().encode(snapshot)
        XCTAssertEqual(try JSONDecoder().decode(MCPRegistrySnapshot.self, from: data), snapshot)

        let json = try XCTUnwrap(String(data: data, encoding: .utf8))
        XCTAssertFalse(json.contains("authsia://"))
        XCTAssertFalse(json.localizedCaseInsensitiveContains("token"))
    }
}
