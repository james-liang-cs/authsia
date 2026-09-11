import AuthenticatorBridge
import Foundation
import XCTest
@testable import AuthsiaBridgeHost

final class MemoryHTTPAuthorityBlob: AuthorityBlobStoring, @unchecked Sendable {
    var data: Data?
    func load() throws -> Data? { data }
    func save(_ data: Data) throws { self.data = data }
}

@MainActor
final class MCPHTTPAuthorityTests: XCTestCase {
    private func definition(_ name: String = "secret") throws -> MCPServerDefinition {
        let upstream = MCPUpstreamConfig(name: "internal", transport: .streamableHTTP, url: "http://127.0.0.1:9000/mcp",
            tools: .init(allow: ["read"], approve: ["write"]), credentialHeaders: [.init(headerName: "X-Key", reference: "authsia://api-key/\(name)/key", format: .raw)])
        let object: [String: Any] = ["schemaVersion":3, "workspace":["name":"test","authsiaFolder":"Workspaces/test"],
                                   "mcpUpstreams":[try JSONSerialization.jsonObject(with: JSONEncoder().encode(upstream))]]
        return try MCPWorkspaceStore.decode(JSONSerialization.data(withJSONObject: object), root: URL(fileURLWithPath: "/tmp/mcp-fixture"))[0]
    }
    private func enroll(_ authority: MCPHTTPAuthority, definition: MCPServerDefinition, client: MCPClientConfigSource = .codex) async throws -> (MCPHTTPPrincipal,String) {
        let ticket = try await authority.execute(.prepareEnrollment(.init(serverID: definition.serverID, identity: definition.identity, client: client))).enrollment!
        let principal = try await authority.execute(.commitEnrollment(ticket.id)).principal!
        return (principal,ticket.token)
    }
    func testChangedDeclarationDuringApprovalNeverReadsSecret() async throws {
        var current = try definition(), reads = 0
        let original = current
        let changed = try definition("other")
        let authority = MCPHTTPAuthority(storage: MemoryHTTPAuthorityBlob(), definition: { _ in current }, items: { _ in [] },
            secret: { _ in reads += 1; return "synthetic" }, approve: { _,_,_,_ in current = changed; return true }, recordAdmission: { _ in }, enabled: { true })
        let (principal,_) = try await enroll(authority, definition: original)
        do { _ = try await authority.execute(.authorize(principal: principal, sessionID: UUID().uuidString, revision: original.revision, tool: "read")); XCTFail("must reject changed declaration") }
        catch { XCTAssertEqual(error as? MCPManagementError, .stale) }
        XCTAssertEqual(reads, 0)
    }
    func testBackgroundStreamCannotCreateOrRenewAdmission() async throws {
        let server = try definition()
        var prompts: [String] = []
        let authority = MCPHTTPAuthority(storage: MemoryHTTPAuthorityBlob(), definition: { _ in server },
            items: { _ in [] }, secret: { _ in XCTFail("no credential needed"); return "" },
            approve: { _, _, tool, _ in prompts.append(tool); return true },
            recordAdmission: { _ in }, enabled: { true })
        let (principal, _) = try await enroll(authority, definition: server)
        let session = UUID().uuidString
        let background = MCPHTTPAuthorityCommand.authorizeExisting(principal: principal, sessionID: session, revision: server.revision, tool: "initialize")
        do { _ = try await authority.execute(background); XCTFail("startup GET must not admit") }
        catch { XCTAssertEqual(error as? MCPManagementError, .denied) }
        XCTAssertTrue(prompts.isEmpty)
        let call = try await authority.execute(.authorize(principal: principal, sessionID: session, revision: server.revision, tool: "read"))
        let stream = try await authority.execute(background)
        XCTAssertEqual(stream.lease?.grant.id, call.lease?.grant.id)
        _ = try await authority.execute(.revoke(grantID: call.lease?.grant.id))
        do { _ = try await authority.execute(background); XCTFail("GET must not renew revoked admission") }
        catch { XCTAssertEqual(error as? MCPManagementError, .denied) }
        XCTAssertEqual(prompts, ["read"])
    }
    func testAssociationsAndSessionsCannotBorrowAnotherGrant() async throws {
        let server = try definition(); var approvals = 0
        let authority = MCPHTTPAuthority(storage: MemoryHTTPAuthorityBlob(), definition: { _ in server }, items: { _ in [] },
            secret: { _ in XCTFail("no secret required"); return "" }, approve: { _,_,_,_ in approvals += 1; return true }, recordAdmission: { _ in }, enabled: { true })
        let (codex,_) = try await enroll(authority, definition: server)
        let (claude,_) = try await enroll(authority, definition: server, client: .claude)
        let session = UUID().uuidString
        let first = try await authority.execute(.authorize(principal: codex, sessionID: session, revision: server.revision, tool: "read")).lease!
        let reused = try await authority.execute(.authorize(principal: codex, sessionID: session, revision: server.revision, tool: "read")).lease!
        XCTAssertEqual(first.grant.id, reused.grant.id)
        let other = try await authority.execute(.authorize(principal: claude, sessionID: session, revision: server.revision, tool: "read")).lease!
        XCTAssertNotEqual(first.grant.id, other.grant.id)
        XCTAssertEqual(approvals, 2)
        let validation = try await authority.execute(.validate(grantID: first.grant.id, principal: claude, sessionID: session, revision: server.revision))
        XCTAssertFalse(validation.valid)
    }
    func testApproveToolsPromptForEachInvocationEvenWithAnAdmittedSession() async throws {
        let server = try definition()
        var prompts: [String] = [], permitWrite = true
        let authority = MCPHTTPAuthority(storage: MemoryHTTPAuthorityBlob(), definition: { _ in server },
            items: { _ in [] }, secret: { _ in XCTFail("no credential needed"); return "" },
            approve: { _, _, tool, _ in prompts.append(tool); return tool != "write" || permitWrite },
            recordAdmission: { _ in }, enabled: { true })
        let (principal, _) = try await enroll(authority, definition: server)
        let session = UUID().uuidString
        let allowed = try await authority.execute(.authorize(principal: principal, sessionID: session, revision: server.revision, tool: "read"))
        for _ in 0..<2 {
            let approved = try await authority.execute(.authorize(principal: principal, sessionID: session, revision: server.revision, tool: "write"))
            XCTAssertEqual(approved.lease?.grant.id, allowed.lease?.grant.id)
        }
        permitWrite = false
        do {
            _ = try await authority.execute(.authorize(principal: principal, sessionID: session, revision: server.revision, tool: "write"))
            XCTFail("declined invocation must not receive a lease")
        } catch { XCTAssertEqual(error as? MCPManagementError, .denied) }
        _ = try await authority.execute(.authorize(principal: principal, sessionID: session, revision: server.revision, tool: "read"))
        XCTAssertEqual(prompts, ["read", "write", "write", "write"])
    }

    func testDiscardedReplacementDoesNotRevokeWorkingToken() async throws {
        let server = try definition()
        let authority = MCPHTTPAuthority(storage: MemoryHTTPAuthorityBlob(), definition: { _ in server }, items: { _ in [] }, secret: { _ in "" }, approve: { _,_,_,_ in true }, recordAdmission: { _ in }, enabled: { true })
        let (principal,token) = try await enroll(authority, definition: server)
        let pending = try await authority.execute(.prepareEnrollment(principal.binding)).enrollment!
        _ = try await authority.execute(.discardEnrollment(pending.id))
        let result = try await authority.execute(.authenticate(serverID: server.serverID, token: token))
        XCTAssertEqual(result.principal, principal)
    }
    func testDeniedItemResolutionNeverPromptsOrReads() async throws {
        let server = try definition(); var approvals = 0, reads = 0
        let authority = MCPHTTPAuthority(storage: MemoryHTTPAuthorityBlob(), definition: { _ in server },
            items: { _ in throw MCPManagementError.denied }, secret: { _ in reads += 1; return "" },
            approve: { _,_,_,_ in approvals += 1; return true }, recordAdmission: { _ in }, enabled: { true })
        let (principal,_) = try await enroll(authority, definition: server)
        do { _ = try await authority.execute(.authorize(principal: principal, sessionID: UUID().uuidString, revision: server.revision, tool: "read")); XCTFail("expected denial") } catch {}
        XCTAssertEqual(approvals, 0); XCTAssertEqual(reads, 0)
    }
    func testMissingAdmissionAuditPreventsGrantAndSecretRelease() async throws {
        let server = try definition(); var reads = 0
        let storage = MemoryHTTPAuthorityBlob()
        let authority = MCPHTTPAuthority(storage: storage, definition: { _ in server }, items: { _ in [] },
            secret: { _ in reads += 1; return "synthetic" }, approve: { _,_,_,_ in true }, enabled: { true })
        let (principal, _) = try await enroll(authority, definition: server)
        do { _ = try await authority.execute(.authorize(principal: principal, sessionID: UUID().uuidString, revision: server.revision, tool: "read")); XCTFail("expected audit failure") }
        catch { XCTAssertEqual(error as? MCPManagementError, .auditUnavailable) }
        XCTAssertEqual(reads, 0)
        let state = try JSONDecoder().decode(MCPHTTPAuthorityState.self, from: storage.data!)
        XCTAssertTrue(state.grants.isEmpty)
    }
    func testEnrollmentCommitCanBeRetriedAfterLostReply() async throws {
        let server = try definition()
        let authority = MCPHTTPAuthority(storage: MemoryHTTPAuthorityBlob(), definition: { _ in server }, items: { _ in [] },
            secret: { _ in "" }, approve: { _,_,_,_ in true }, recordAdmission: { _ in }, enabled: { true })
        let ticket = try await authority.execute(.prepareEnrollment(.init(serverID: server.serverID, identity: server.identity, client: .codex))).enrollment!
        let first = try await authority.execute(.commitEnrollment(ticket.id))
        let retry = try await authority.execute(.commitEnrollment(ticket.id))
        let status = try await authority.execute(.enrollmentStatus(ticket.id))
        XCTAssertEqual(first.principal, retry.principal)
        XCTAssertEqual(status.principal, first.principal)
    }
    func testCatalogCaptureMissingAdmissionAuditPreventsGrantAndSecretRelease() async throws {
        let server = try definition()
        var reads = 0
        let storage = MemoryHTTPAuthorityBlob()
        let item = MCPHTTPResolvedItem(
            header: server.upstream.credentialHeaders[0], id: UUID(), type: "api-key", field: "key",
            label: "secret", revision: "1")
        let authority = MCPHTTPAuthority(storage: storage, definition: { _ in server }, items: { _ in [item] },
            secret: { _ in reads += 1; return "synthetic" }, approve: { _,_,_,_ in true }, enabled: { true })
        do {
            _ = try await authority.execute(.catalogCapture(identity: server.identity, revision: server.revision))
            XCTFail("expected audit failure")
        } catch {
            XCTAssertEqual(error as? MCPManagementError, .auditUnavailable)
        }
        XCTAssertEqual(reads, 0)
        XCTAssertNil(storage.data)
    }
    func testCatalogCapturePersistsManagerGrantAndHonorsRevocationEpoch() async throws {
        let server = try definition()
        let item = MCPHTTPResolvedItem(
            header: server.upstream.credentialHeaders[0], id: UUID(), type: "api-key", field: "key",
            label: "secret", revision: "1")
        final class Box: @unchecked Sendable { var authority: MCPHTTPAuthority! }
        let box = Box()
        var reads = 0
        box.authority = MCPHTTPAuthority(storage: MemoryHTTPAuthorityBlob(), definition: { _ in server }, items: { _ in [item] },
            secret: { _ in reads += 1; return "synthetic" }, approve: { _,_,_,_ in
                do { _ = try await box.authority.execute(.revoke(grantID: nil)) } catch { }
                return true
            }, recordAdmission: { _ in }, enabled: { true })
        do {
            _ = try await box.authority.execute(.catalogCapture(identity: server.identity, revision: server.revision))
            XCTFail("revocation during approval must deny capture")
        } catch {
            XCTAssertEqual(error as? MCPManagementError, .denied)
        }
        XCTAssertEqual(reads, 0)

        let storage = MemoryHTTPAuthorityBlob()
        let authority = MCPHTTPAuthority(storage: storage, definition: { _ in server }, items: { _ in [item] },
            secret: { _ in "synthetic" }, approve: { _,_,_,_ in true }, recordAdmission: { _ in }, enabled: { true })
        let reply = try await authority.execute(.catalogCapture(identity: server.identity, revision: server.revision))
        let grant = try XCTUnwrap(reply.lease?.grant)
        XCTAssertEqual(grant.principal.binding.client, .authsiaCatalog)
        let snapshot = try await authority.execute(.snapshot)
        XCTAssertEqual(snapshot.grants?.map(\.id), [grant.id])
        let valid = try await authority.execute(.validate(
            grantID: grant.id, principal: grant.principal, sessionID: grant.sessionID, revision: server.revision))
        XCTAssertTrue(valid.valid)
        _ = try await authority.execute(.revoke(grantID: grant.id))
        let revoked = try await authority.execute(.validate(
            grantID: grant.id, principal: grant.principal, sessionID: grant.sessionID, revision: server.revision))
        XCTAssertFalse(revoked.valid)
    }
}
