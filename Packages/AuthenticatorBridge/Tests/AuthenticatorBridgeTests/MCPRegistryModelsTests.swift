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

    func testRegistrySnapshotRoundTripsProtectableClientsAndDecodesLegacyJSON() throws {
        let snapshot = MCPRegistrySnapshot(
            revision: "fixture-revision",
            servers: [],
            protectableClients: [.codex, .claude, .cursor, .vscode, .devin, .claudeDesktop]
        )
        let data = try JSONEncoder().encode(snapshot)
        XCTAssertEqual(
            try JSONDecoder().decode(MCPRegistrySnapshot.self, from: data).protectableClients,
            snapshot.protectableClients
        )
        XCTAssertTrue(String(decoding: data, as: UTF8.self).contains("\"vscode\""))
        XCTAssertTrue(String(decoding: data, as: UTF8.self).contains("\"devin\""))

        let legacy = try JSONDecoder().decode(
            MCPRegistrySnapshot.self,
            from: Data(#"{"revision":"x","servers":[],"diagnostics":[],"workspaces":[]}"#.utf8)
        )
        XCTAssertNil(legacy.protectableClients)
    }

    func testDisabledFindingsDoNotContributeObservedCatalogEnvironment() {
        let disabled = MCPClientServerFinding(
            source: .cursor,
            serverName: "playwright",
            commandLabel: "npx",
            status: .disabled,
            declaredUpstreamName: "playwright",
            configPathLabel: "~/.cursor/mcp.json",
            childEnvironmentCount: 2
        )
        let overridden = MCPClientServerFinding(
            source: .cursor,
            serverName: "playwright",
            commandLabel: "npx",
            status: .directBypass,
            declaredUpstreamName: "playwright",
            configPathLabel: "~/.cursor/mcp.json",
            precedence: .overridden,
            childEnvironmentCount: 2
        )
        let active = MCPClientServerFinding(
            source: .cursor,
            serverName: "playwright",
            commandLabel: "npx",
            status: .directBypass,
            declaredUpstreamName: "playwright",
            configPathLabel: "~/.cursor/mcp.json",
            childEnvironmentCount: 2
        )
        XCTAssertFalse(disabled.contributesObservedCatalogEnvironment)
        XCTAssertFalse(overridden.contributesObservedCatalogEnvironment)
        XCTAssertTrue(active.contributesObservedCatalogEnvironment)
    }

    func testCatalogQualityAndCaptureTimeRoundTripWithoutInventingTime() throws {
        XCTAssertEqual(
            MCPCatalogQuality.evaluate(catalog: [], policy: MCPUpstreamToolPolicy(allow: ["read"])),
            .nameOnly
        )
        let recorded = MCPUpstreamToolDescriptor(
            name: "read",
            description: "Read files",
            inputSchema: .object([
                "type": .string("object"),
                "properties": .object([:]),
            ])
        )
        XCTAssertEqual(
            MCPCatalogQuality.evaluate(catalog: [recorded], policy: MCPUpstreamToolPolicy(allow: ["read"])),
            .recorded
        )
        let captured = Date(timeIntervalSince1970: 1_700_000_000)
        let upstream = MCPUpstreamConfig(name: "internal", catalog: [MCPUpstreamToolDescriptor(name: "read")], catalogCapturedAt: captured)
        let encoded = try JSONEncoder().encode(upstream)
        let decoded = try JSONDecoder().decode(MCPUpstreamConfig.self, from: encoded)
        XCTAssertEqual(try XCTUnwrap(decoded.catalogCapturedAt).timeIntervalSince1970, captured.timeIntervalSince1970, accuracy: 1)
        XCTAssertTrue(String(decoding: encoded, as: UTF8.self).contains("catalogCapturedAt"))
        let legacy = try JSONDecoder().decode(MCPUpstreamConfig.self, from: Data(#"{"name":"internal"}"#.utf8))
        XCTAssertNil(legacy.catalogCapturedAt)
    }
}
