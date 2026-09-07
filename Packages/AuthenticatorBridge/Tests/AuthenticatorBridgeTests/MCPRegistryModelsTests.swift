import XCTest
@testable import AuthenticatorBridge

final class MCPRegistryModelsTests: XCTestCase {
    func testCredentialOptionsKeepDuplicateNamesDistinctWithScopeMetadata() throws {
        let options = [
            MCPCredentialOption(id: "api-key:00000000-0000-0000-0000-000000000001", label: "EXAMPLE_KEY", type: "api-key",
                folderPath: "Example/dev", environments: ["dev"], workspaceIDs: ["workspace-example"]),
            MCPCredentialOption(id: "api-key:00000000-0000-0000-0000-000000000002", label: "EXAMPLE_KEY", type: "api-key",
                folderPath: "Example/prod", environments: ["prod"], workspaceIDs: ["workspace-example"])
        ]
        let data = try JSONEncoder().encode(options)
        let decoded = try JSONDecoder().decode([MCPCredentialOption].self, from: data)
        XCTAssertNotEqual(decoded[0].id, decoded[1].id)
        XCTAssertEqual(decoded.map(\.folderPath), ["Example/dev", "Example/prod"])
        XCTAssertEqual(decoded[0].workspaceIDs, ["workspace-example"])
        XCTAssertEqual(decoded[1].environments, ["prod"])
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("authsia://"))
    }

    func testCredentialOptionsDecodeOlderMetadataWithoutGuessingScope() throws {
        let data = Data(#"{"id":"api-key:example","label":"EXAMPLE_KEY","type":"api-key"}"#.utf8)
        let option = try JSONDecoder().decode(MCPCredentialOption.self, from: data)
        XCTAssertNil(option.workspaceIDs)
        XCTAssertNil(option.folderPath)
        XCTAssertNil(option.environments)
    }

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
