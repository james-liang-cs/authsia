#if os(macOS)
import Foundation
import CryptoKit
import XCTest
import AuthenticatorBridge
import AuthenticatorData
@testable import AuthsiaBridgeHost

@MainActor
final class XPCRequestHandlerAutomationCredentialTests: XCTestCase {
    func testListValidateAndRevokeUseBridgeOwnedAuthority() async throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let authority = AutomationCredentialAuthority(
            authorityStore: TestAuthorityStore(),
            digestKey: Data(repeating: 0x42, count: 32),
            randomBytes: { count in Data(repeating: 0x41, count: count) }
        )
        let issued = try authority.create(
            payload: AccessCreateApprovalPayload(
                name: "Synthetic CI",
                scope: "Team/API",
                ttlSeconds: 900,
                expiresAt: now.addingTimeInterval(900),
                machineId: "machine-1",
                machineName: "Synthetic Mac",
                allowedCommands: ["exec"]
            ),
            now: now
        )
        let auditURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathComponent("audit.log")
        let auditLogger = BridgeAuditLogger(
            fileURL: auditURL,
            hmacKeyProvider: { SymmetricKey(data: Data(repeating: 0x24, count: 32)) }
        )
        let handler = XPCRequestHandler(
            approver: AutomationCredentialApprover(),
            automationCredentialAuthorityProvider: { authority },
            currentMachineIdProvider: { "machine-1" },
            agentJITApprovalClock: { now },
            auditLogger: auditLogger
        )

        let listResponse: BridgeResponse<AutomationCredentialListPayload> = try await invoke(
            request: request(
                type: .listAccess,
                body: AutomationCredentialListRequestPayload(includeAll: false),
                now: now
            ),
            call: handler.listAccessCredentials
        )
        XCTAssertEqual(listResponse.payload?.credentials, [issued.credential])
        XCTAssertFalse(String(describing: listResponse.payload).contains(issued.token))

        let validationResponse: BridgeResponse<AutomationCredentialValidationPayload> = try await invoke(
            request: request(
                type: .validateAccess,
                body: AutomationCredentialValidatePayload(
                    token: issued.token,
                    requestedCommand: .exec
                ),
                now: now
            ),
            call: handler.validateAccessCredential
        )
        XCTAssertEqual(validationResponse.payload?.credential.id, issued.credential.id)

        let revokeResponse: BridgeResponse<AutomationCredentialMetadata> = try await invoke(
            request: request(
                type: .revokeAccess,
                body: AutomationCredentialRevokePayload(id: issued.credential.id),
                now: now
            ),
            call: handler.revokeAccessCredential
        )
        XCTAssertEqual(revokeResponse.payload?.status(asOf: now), .revoked)

        let auditRecords = try auditLogger.loadRecords()
        XCTAssertEqual(auditRecords.map(\.command), [.validateAccess, .revokeAccess])
        XCTAssertEqual(
            auditRecords.map(\.itemId),
            [issued.credential.id.uuidString, issued.credential.id.uuidString]
        )
        let encodedAudit = String(
            decoding: try JSONEncoder().encode(auditRecords),
            as: UTF8.self
        )
        XCTAssertFalse(encodedAudit.contains(issued.token))
        XCTAssertFalse(encodedAudit.contains("digest"))
    }

    func testAgentCallerCannotListCredentialsByOmittingItsCredentialContext() async throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let handler = XPCRequestHandler(
            approver: AutomationCredentialApprover(),
            automationCredentialAuthorityProvider: {
                AutomationCredentialAuthority(
                    authorityStore: TestAuthorityStore(),
                    digestKey: Data(repeating: 0x42, count: 32)
                )
            },
            callerIdentityProvider: {
                CallerIdentity(
                    pid: 42,
                    processName: "authsia",
                    bundleIdentifier: "com.authsia.cli",
                    signingTeamId: "TEAM",
                    signingIdentity: "Developer ID Application",
                    parentProcess: ParentProcessInfo(
                        pid: 41,
                        processName: "Claude",
                        bundleIdentifier: "com.anthropic.claude"
                    )
                )
            }
        )

        let response: BridgeResponse<AutomationCredentialListPayload> = try await invoke(
            request: request(
                type: .listAccess,
                body: AutomationCredentialListRequestPayload(includeAll: true),
                now: now,
                isTTY: false,
                requestedCommand: "access"
            ),
            call: handler.listAccessCredentials
        )

        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertNil(response.payload)
    }

    private func request<Body: Codable>(
        type: BridgeRequestType,
        body: Body,
        now: Date,
        isTTY: Bool = true,
        requestedCommand: String? = nil
    ) throws -> BridgeRequest {
        BridgeRequest(
            id: UUID(),
            type: type,
            query: "",
            options: .init(field: nil, copy: false),
            context: .init(
                isTTY: isTTY,
                isPiped: false,
                isSSH: false,
                isCI: false,
                timestamp: now,
                requestedCommand: requestedCommand
            ),
            body: try BridgeCoder.encode(body)
        )
    }

    private func invoke<Response: Codable & Equatable>(
        request: BridgeRequest,
        call: (Data, @escaping (Data?, NSError?) -> Void) -> Void
    ) async throws -> BridgeResponse<Response> {
        let expectation = XCTestExpectation(description: request.type.rawValue)
        var result: Result<BridgeResponse<Response>, Error>?
        call(try BridgeCoder.encode(request)) { data, error in
            defer { expectation.fulfill() }
            do {
                if let error { throw error }
                result = .success(
                    try BridgeCoder.decode(BridgeResponse<Response>.self, from: data ?? Data())
                )
            } catch {
                result = .failure(error)
            }
        }
        await fulfillment(of: [expectation], timeout: 1)
        return try XCTUnwrap(result).get()
    }
}

@MainActor
private final class AutomationCredentialApprover: BridgeApprover {
    func requestApproval(
        prompt: String,
        command: BridgeRequestType,
        itemLabel: String?,
        field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?,
        remoteRequests: [RemoteJITApprovalRequest]
    ) async -> RemoteJITApprovalOutcome {
        .approved(source: .macBiometric)
    }
}
#endif
