import AuthenticatorBridge
import Foundation
import Testing
@testable import authsia

@Suite("MCP workspace inspection")
struct MCPWorkspaceInspectionTests {
    @Test("Bridge readiness honors the optional live CLI access flag")
    func liveCLIAccessReadiness() {
        #expect(MCPWorkspaceInspectionService.bridgeState(for: BridgePingPayload(
            protocolVersion: "10",
            cliAccessEnabled: false
        )) == .cliAccessDisabled)
        #expect(MCPWorkspaceInspectionService.bridgeState(for: BridgePingPayload(
            protocolVersion: "10"
        )) == .ready)
    }

    @Test("status is non-secret and reports readiness without approval")
    func statusIsNonSecret() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let serverID = UUID(uuidString: "7E05890F-5C3A-44EF-9208-83A12F17D6CE")!
        let service = MCPWorkspaceInspectionService(
            runtimeContext: MCPRuntimeContext(
                startingDirectory: fixture.root,
                instanceID: serverID
            ),
            bridgeStateProvider: { .ready },
            selectionStore: fixture.selectionStore
        )

        let output = service.status()
        let encoded = String(decoding: try JSONEncoder().encode(output), as: UTF8.self)

        #expect(output.serverInstanceID == serverID.uuidString)
        #expect(output.bridgeState == "ready")
        #expect(output.ready)
        #expect(!encoded.localizedCaseInsensitiveContains("token"))
        #expect(!encoded.localizedCaseInsensitiveContains("sessionexpires"))
    }

    @Test("inspection returns only declared reference metadata")
    func declaredReferencesOnly() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        try """
            API_KEY=authsia://api-key/Synthetic/key?folder=Team%2FAPI
            ORDINARY_VALUE=must-never-appear
            API_KEY=authsia://api-key/Synthetic/key?folder=Team%2FAPI
            """.write(
                to: fixture.root.appendingPathComponent(".env.development"),
                atomically: true,
                encoding: .utf8
            )
        try fixture.selectionStore.setActiveEnvironment("Development", for: fixture.root)
        let service = MCPWorkspaceInspectionService(
            runtimeContext: MCPRuntimeContext(startingDirectory: fixture.root),
            bridgeStateProvider: { .unavailable },
            selectionStore: fixture.selectionStore
        )

        let output = try service.inspect(MCPWorkspaceInspectInput())
        let encoded = String(decoding: try JSONEncoder().encode(output), as: UTF8.self)

        #expect(output.workspaceName == "api")
        #expect(output.selectedEnvironment == "Development")
        #expect(output.availableEnvironments == ["Development"])
        #expect(output.references.count == 2)
        #expect(output.references.contains { $0.environmentVariable == "CONFIGURED_SECRET" })
        #expect(output.references.contains { $0.environmentVariable == "API_KEY" })
        #expect(!encoded.contains("must-never-appear"))
        #expect(!output.referencesTruncated)
    }

    @Test("missing files and symlink escapes become bounded diagnostics")
    func unsafeFilesAreDiagnosed() throws {
        let fixture = try makeFixture(managedFiles: ["missing.env", "linked.env"])
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let outside = fixture.root.deletingLastPathComponent()
            .appendingPathComponent("outside-\(UUID().uuidString).env")
        defer { try? FileManager.default.removeItem(at: outside) }
        try "SECRET=authsia://password/Outside/password".write(
            to: outside,
            atomically: true,
            encoding: .utf8
        )
        try FileManager.default.createSymbolicLink(
            at: fixture.root.appendingPathComponent("linked.env"),
            withDestinationURL: outside
        )
        let service = MCPWorkspaceInspectionService(
            runtimeContext: MCPRuntimeContext(startingDirectory: fixture.root),
            bridgeStateProvider: { .ready },
            selectionStore: fixture.selectionStore
        )

        let output = try service.inspect(MCPWorkspaceInspectInput())

        #expect(output.references.allSatisfy { !$0.uri.contains("Outside") })
        #expect(output.diagnostics.map(\.code).contains("managedFileMissing"))
        #expect(output.diagnostics.map(\.code).contains("managedFileOutsideWorkspace"))
    }

    @Test("inspection canonicalizes references without echoing unknown query data")
    func referencesAreCanonicalAndRedacted() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let syntheticMarker = "SYNTHETIC_QUERY_VALUE_MUST_NOT_APPEAR"
        try "SECRET=authsia://api-key/Synthetic/key?folder=Team%2FAPI&token=\(syntheticMarker)"
            .write(
                to: fixture.root.appendingPathComponent(".env.development"),
                atomically: true,
                encoding: .utf8
            )
        let service = MCPWorkspaceInspectionService(
            runtimeContext: MCPRuntimeContext(startingDirectory: fixture.root),
            bridgeStateProvider: { .ready },
            selectionStore: fixture.selectionStore
        )

        let output = try service.inspect(MCPWorkspaceInspectInput())
        let encoded = String(decoding: try JSONEncoder().encode(output), as: UTF8.self)
        let reference = try #require(
            output.references.first { $0.environmentVariable == "SECRET" }
        )

        #expect(reference.uri == "authsia://api-key/Synthetic/key?folder=Team%2FAPI")
        #expect(!encoded.contains(syntheticMarker))
        #expect(!encoded.contains("token="))
    }

    @Test("oversized managed files are rejected before parsing")
    func oversizedManagedFileIsRejected() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let content = "SECRET=authsia://password/Oversized/password\n#" +
            String(repeating: "x", count: 1_048_576)
        try content.write(
            to: fixture.root.appendingPathComponent(".env.development"),
            atomically: true,
            encoding: .utf8
        )
        let service = MCPWorkspaceInspectionService(
            runtimeContext: MCPRuntimeContext(startingDirectory: fixture.root),
            bridgeStateProvider: { .ready },
            selectionStore: fixture.selectionStore
        )

        let output = try service.inspect(MCPWorkspaceInspectInput())

        #expect(output.references.allSatisfy { $0.environmentVariable != "SECRET" })
        #expect(output.diagnostics.map(\.code).contains("managedFileTooLarge"))
    }

    @Test("reference output is capped at one thousand")
    func referenceLimit() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let content = (0..<1_010).map {
            "KEY_\($0)=authsia://password/Item\($0)/password"
        }.joined(separator: "\n")
        try content.write(
            to: fixture.root.appendingPathComponent(".env.development"),
            atomically: true,
            encoding: .utf8
        )
        let service = MCPWorkspaceInspectionService(
            runtimeContext: MCPRuntimeContext(startingDirectory: fixture.root),
            bridgeStateProvider: { .ready },
            selectionStore: fixture.selectionStore
        )

        let output = try service.inspect(MCPWorkspaceInspectInput())

        #expect(output.references.count == 1_000)
        #expect(output.referencesTruncated)
    }

    @Test("unknown requested environment is rejected")
    func unknownEnvironment() throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let service = MCPWorkspaceInspectionService(
            runtimeContext: MCPRuntimeContext(startingDirectory: fixture.root),
            bridgeStateProvider: { .ready },
            selectionStore: fixture.selectionStore
        )

        #expect(throws: MCPToolInputError.self) {
            _ = try service.inspect(MCPWorkspaceInspectInput(environment: "Production"))
        }
    }

    private func makeFixture(
        managedFiles: [String] = [".env.development"]
    ) throws -> (root: URL, selectionStore: WorkspaceEnvironmentSelectionStore) {
        let root = try makeWorkspaceRoot()
        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                workspace: .init(name: "api", authsiaFolder: "Workspaces/api"),
                managedEnvFiles: managedFiles,
                agents: nil,
                envBindings: [
                    .init(
                        name: "CONFIGURED_SECRET",
                        reference: "authsia://password/Configured/password"
                    ),
                ]
            ),
            toWorkspaceRoot: root
        )
        let selectionStore = WorkspaceEnvironmentSelectionStore(
            fileURL: root.appendingPathComponent("selection.json")
        )
        return (root, selectionStore)
    }
}
