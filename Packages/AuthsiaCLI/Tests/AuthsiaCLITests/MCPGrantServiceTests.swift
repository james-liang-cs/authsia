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

    @Test("active ownership is narrowed to the current MCP instance")
    func activeOwnedGrantIDsAreInstanceNarrowed() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let serverID = UUID(uuidString: "7E05890F-5C3A-44EF-9208-83A12F17D6CE")!
        let owned = grant(sessionID: "mcp:\(serverID.uuidString)", expiresAt: now.addingTimeInterval(60))
        let client = GrantClient(snapshot: .init(active: [owned], history: []))

        let current = MCPGrantService(serverInstanceID: serverID, client: client)
        let replacement = MCPGrantService(serverInstanceID: UUID(), client: client)

        #expect(try current.activeOwnedGrantIDs(now: now) == [owned.id])
        #expect(try replacement.activeOwnedGrantIDs(now: now).isEmpty)
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
        let context = AgentRuntimeContext(
            sessionID: "mcp:\(serverID.uuidString)",
            agentType: "authsia-mcp"
        )

        #expect(throws: MCPGrantServiceError.self) {
            try service.revoke("not-a-uuid", agentRuntimeContext: context, now: now)
        }
        #expect(throws: MCPGrantServiceError.self) {
            try service.revoke(other.id.uuidString, agentRuntimeContext: context, now: now)
        }
        #expect(throws: MCPGrantServiceError.self) {
            try service.revoke(direct.id.uuidString, agentRuntimeContext: context, now: now)
        }
        #expect(throws: MCPGrantServiceError.self) {
            try service.revoke(expired.id.uuidString, agentRuntimeContext: context, now: now)
        }
        #expect(client.revokedIDs.isEmpty)
    }

    @Test("owned revocation is idempotent and shutdown revokes active owned grants")
    func revokeAndCleanup() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let serverID = UUID(uuidString: "7E05890F-5C3A-44EF-9208-83A12F17D6CE")!
        let active = grant(sessionID: "mcp:\(serverID.uuidString)", expiresAt: now.addingTimeInterval(60))
        let cleanupOnly = grant(
            id: UUID(uuidString: "55555555-5555-5555-5555-555555555555")!,
            sessionID: "mcp:\(serverID.uuidString)",
            expiresAt: now.addingTimeInterval(60)
        )
        let alreadyRevoked = grant(
            id: UUID(uuidString: "33333333-3333-3333-3333-333333333333")!,
            sessionID: "mcp:\(serverID.uuidString)",
            expiresAt: now.addingTimeInterval(60),
            revokedAt: now.addingTimeInterval(-1)
        )
        let client = GrantClient(snapshot: .init(active: [active, cleanupOnly], history: [alreadyRevoked]))
        let service = MCPGrantService(serverInstanceID: serverID, client: client)
        let revocationContext = AgentRuntimeContext(
            platform: "Codex",
            sessionID: "mcp:\(serverID.uuidString)",
            turnID: "mcp-call:44444444-4444-4444-4444-444444444444",
            agentType: "authsia-mcp",
            toolUseID: "mcp-call:44444444-4444-4444-4444-444444444444"
        )

        let repeated = try service.revoke(
            alreadyRevoked.id.uuidString,
            agentRuntimeContext: revocationContext,
            now: now
        )
        #expect(repeated.status == "revoked")
        #expect(client.revokedIDs.isEmpty)

        _ = try service.revoke(
            active.id.uuidString,
            agentRuntimeContext: revocationContext,
            now: now
        )
        #expect(client.revocationContexts == [revocationContext])

        service.revokeActiveOwnedGrants(now: now)
        #expect(client.revokedIDs == [active.id, active.id, cleanupOnly.id])
        #expect(client.revocationContexts.last?.sessionID == revocationContext.sessionID)
        #expect(client.revocationContexts.last?.toolUseID == nil)
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
    private(set) var revocationContexts: [AgentRuntimeContext] = []

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
        revocationContexts.append(agentRuntimeContext)
        return AgentJITGrantMutationPayload(revokedGrantIDs: [id])
    }
}
