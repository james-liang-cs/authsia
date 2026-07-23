import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge

#if os(macOS)
@MainActor
final class AgentLeakBoundaryContractTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    func testUnsignedJSONGrantCannotCreateBridgeAuthority() throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let fileURL = directory.appendingPathComponent("agent-jit-grants.json")
        let grant = makeGrant()
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode([grant]).write(to: fileURL)

        let loaded = try AgentJITGrantStore(
            authorityStore: TestAuthorityStore(),
            legacyFileURL: fileURL
        ).loadAll()

        XCTAssertEqual(loaded, [])
        XCTAssertTrue(FileManager.default.fileExists(atPath: fileURL.appendingPathExtension("legacy").path))
    }

    func testRequestedItemDoesNotRestrictAnotherItemInSameFolder() {
        let caller = callerFingerprint()
        let grant = makeGrant(
            requestedItems: [
                AgentJITGrantItemReference(
                    type: "apiKey",
                    id: "approved-item",
                    name: "Approved item",
                    folderPath: "Team/API"
                ),
            ]
        )

        XCTAssertTrue(grant.allows(
            capability: .exec,
            itemFolderPath: "Team/API",
            caller: caller,
            now: now.addingTimeInterval(60)
        ))
    }

    func testActiveGrantCanBeUsedByASecondCommandInvocation() throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = AgentJITGrantStore(
            authorityStore: TestAuthorityStore(),
            legacyFileURL: directory.appendingPathComponent("agent-jit-grants.json"),
            terminalSessionLiveness: { _ in .active }
        )
        let caller = callerFingerprint()
        try store.save(makeGrant())

        let firstUse = try store.markUsedIfAllowed(
            capability: .exec,
            itemFolderPath: "Team/API",
            itemEnvironments: [],
            caller: caller,
            now: now.addingTimeInterval(60)
        )
        let secondUse = try store.markUsedIfAllowed(
            capability: .exec,
            itemFolderPath: "Team/API",
            itemEnvironments: [],
            caller: caller,
            now: now.addingTimeInterval(61)
        )

        XCTAssertNotNil(firstUse)
        XCTAssertNotNil(secondUse)
    }

    func testValidatedHumanSessionIsClassifiedBeforeAgentAncestry() throws {
        let scope = "tty:/dev/ttys-agent-leak-contract"
        let session = try BridgeSessionManager.shared.createSession(ttlSeconds: 60, scope: scope)
        let request = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "",
            options: .init(field: nil, copy: false),
            context: BridgeContext(
                isTTY: true,
                isPiped: false,
                isSSH: false,
                isCI: false,
                timestamp: now,
                requestedCommand: "exec",
                sessionScope: scope,
                workingDirectory: "/synthetic/repository"
            ),
            sessionToken: session.sessionToken
        )
        let agentCaller = CallerIdentity(
            pid: 42,
            processName: "authsia",
            bundleIdentifier: "com.authsia.cli",
            signingTeamId: "SYNTHETIC",
            signingIdentity: "Synthetic Developer",
            parentProcess: ParentProcessInfo(
                pid: 41,
                processName: "Cursor Helper",
                bundleIdentifier: "com.example.cursor"
            )
        )

        XCTAssertFalse(XPCRequestHandler.isAgentJITCaller(
            request: request,
            callerIdentity: agentCaller
        ))
    }

    private func makeGrant(
        requestedItems: [AgentJITGrantItemReference] = []
    ) -> AgentJITGrant {
        AgentJITGrant(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
            agentName: "Synthetic agent",
            callerFingerprint: callerFingerprint(),
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            createdAt: now,
            expiresAt: now.addingTimeInterval(300),
            revokedAt: nil,
            lastUsedAt: nil,
            requestedItems: requestedItems,
            approvedBy: "synthetic-test"
        )
    }

    private func callerFingerprint() -> AgentJITCallerFingerprint {
        AgentJITCallerFingerprint(
            processName: "authsia",
            bundleIdentifier: "com.authsia.cli",
            signingTeamId: "SYNTHETIC",
            signingIdentity: "Synthetic Developer",
            parentProcessName: "Synthetic Agent",
            parentBundleIdentifier: "com.example.agent",
            sessionScope: "tty:/dev/ttys001:sid:10",
            workingDirectory: "/synthetic/repository"
        )
    }

    private func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("agent-leak-contract-\(UUID().uuidString)", isDirectory: true)
    }
}
#endif
