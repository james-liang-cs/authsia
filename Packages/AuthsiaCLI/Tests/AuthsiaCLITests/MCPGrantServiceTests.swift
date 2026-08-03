import AuthenticatorBridge
import Foundation
import Testing
@testable import authsia

@Suite("MCP grant service")
struct MCPGrantServiceTests {
    @Test("status includes only grants owned by the current MCP instance")
    func ownedStatusOnly() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let serverID = UUID(uuidString: "7E05890F-5C3A-44EF-9208-83A12F17D6CE")!
        let owned = grant(sessionID: "mcp:\(serverID.uuidString)", expiresAt: now.addingTimeInterval(60))
        let other = grant(sessionID: "mcp:other", expiresAt: now.addingTimeInterval(60))
        let direct = grant(
            sessionID: "direct",
            agentType: "codex",
            expiresAt: now.addingTimeInterval(60)
        )
        let client = GrantClient(snapshot: .init(active: [owned, other, direct], history: []))
        let service = MCPGrantService(serverInstanceID: serverID, client: client)

        let output = try service.status(now: now)

        #expect(output.grants.map(\.grantID) == [owned.id.uuidString])
        #expect(output.grants.first?.serverInstanceID == serverID.uuidString)
        #expect(output.grants.first?.status == "active")
    }

    @Test("revocation rejects malformed foreign direct and history grants")
    func revokeOwnershipChecks() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let serverID = UUID(uuidString: "7E05890F-5C3A-44EF-9208-83A12F17D6CE")!
        let other = grant(sessionID: "mcp:other", expiresAt: now.addingTimeInterval(60))
        let direct = grant(sessionID: "direct", agentType: "codex", expiresAt: now.addingTimeInterval(60))
        let expired = grant(
            id: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
            sessionID: "mcp:\(serverID.uuidString)",
            expiresAt: now.addingTimeInterval(-1)
        )
        let client = GrantClient(snapshot: .init(active: [other, direct], history: [expired]))
        let service = MCPGrantService(serverInstanceID: serverID, client: client)

        #expect(throws: MCPGrantServiceError.self) { try service.revoke("not-a-uuid", now: now) }
        #expect(throws: MCPGrantServiceError.self) { try service.revoke(other.id.uuidString, now: now) }
        #expect(throws: MCPGrantServiceError.self) { try service.revoke(direct.id.uuidString, now: now) }
        #expect(throws: MCPGrantServiceError.self) { try service.revoke(expired.id.uuidString, now: now) }
        #expect(client.revokedIDs.isEmpty)
    }

    @Test("owned revocation is idempotent and shutdown revokes active owned grants")
    func revokeAndCleanup() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let serverID = UUID(uuidString: "7E05890F-5C3A-44EF-9208-83A12F17D6CE")!
        let active = grant(sessionID: "mcp:\(serverID.uuidString)", expiresAt: now.addingTimeInterval(60))
        let alreadyRevoked = grant(
            id: UUID(uuidString: "33333333-3333-3333-3333-333333333333")!,
            sessionID: "mcp:\(serverID.uuidString)",
            expiresAt: now.addingTimeInterval(60),
            revokedAt: now.addingTimeInterval(-1)
        )
        let client = GrantClient(snapshot: .init(active: [active], history: [alreadyRevoked]))
        let service = MCPGrantService(serverInstanceID: serverID, client: client)

        let repeated = try service.revoke(alreadyRevoked.id.uuidString, now: now)
        #expect(repeated.status == "revoked")
        #expect(client.revokedIDs.isEmpty)

        service.revokeActiveOwnedGrants(now: now)
        #expect(client.revokedIDs == [active.id])
    }

    private func grant(
        id: UUID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
        sessionID: String,
        agentType: String = "authsia-mcp",
        expiresAt: Date,
        revokedAt: Date? = nil
    ) -> AgentJITGrant {
        AgentJITGrant(
            id: id,
            agentName: "Codex",
            callerFingerprint: AgentJITCallerFingerprint(
                processName: "authsia",
                bundleIdentifier: "com.authsia.cli",
                signingTeamId: "TEAM",
                signingIdentity: "Developer ID",
                parentProcessName: "Codex",
                parentBundleIdentifier: nil,
                sessionScope: nil,
                workingDirectory: "/tmp/project"
            ),
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            createdAt: Date(timeIntervalSince1970: 1_699_999_900),
            expiresAt: expiresAt,
            revokedAt: revokedAt,
            lastUsedAt: nil,
            requestedItems: [],
            agentRuntimeContext: AgentRuntimeContext(
                platform: "Codex",
                sessionID: sessionID,
                turnID: "mcp-call:test",
                agentType: agentType,
                toolUseID: "mcp-call:test"
            ),
            approvedBy: "local",
            environmentScope: .named("Development")
        )
    }
}

private final class GrantClient: MCPGrantClient, @unchecked Sendable {
    var snapshot: AgentJITGrantSnapshotPayload
    private(set) var revokedIDs: [UUID] = []

    init(snapshot: AgentJITGrantSnapshotPayload) {
        self.snapshot = snapshot
    }

    func agentJITSnapshot(agentRuntimeContext: AgentRuntimeContext) throws -> AgentJITGrantSnapshotPayload {
        snapshot
    }

    func revokeAgentJITGrant(
        id: UUID,
        agentRuntimeContext: AgentRuntimeContext
    ) throws -> AgentJITGrantMutationPayload {
        revokedIDs.append(id)
        return AgentJITGrantMutationPayload(revokedGrantIDs: [id])
    }
}
