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

    func testValidateIssuesKeychainBackedSSHExecutionLeaseWithoutConsumingBearer() async throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let store = TestAuthorityStore()
        let authority = AutomationCredentialAuthority(
            authorityStore: store,
            digestKey: Data(repeating: 0x42, count: 32),
            randomBytes: { count in Data(repeating: 0x41, count: count) }
        )
        let issued = try authority.create(
            payload: AccessCreateApprovalPayload(
                name: "Synthetic SSH",
                scope: "Team/API",
                ttlSeconds: 900,
                expiresAt: now.addingTimeInterval(900),
                machineId: "machine-1",
                machineName: "Synthetic Mac",
                allowedCommands: ["ssh"],
                maximumUses: 2
            ),
            now: now
        )
        let auditDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: auditDirectory) }
        let handler = XPCRequestHandler(
            approver: AutomationCredentialApprover(),
            automationCredentialAuthorityProvider: { authority },
            currentMachineIdProvider: { "machine-1" },
            authorityStore: store,
            agentJITApprovalClock: { now },
            auditLogger: BridgeAuditLogger(
                fileURL: auditDirectory.appendingPathComponent("audit.log"),
                hmacKeyProvider: {
                    SymmetricKey(data: Data(repeating: 0x24, count: 32))
                }
            )
        )

        let response: BridgeResponse<AutomationCredentialValidationPayload> =
            try await invoke(
                request: request(
                    type: .validateAccess,
                    body: AutomationCredentialValidatePayload(
                        token: issued.token,
                        requestedCommand: .ssh,
                        sshExecutionLeaseBinding: SSHAutomationExecutionLeaseBinding(
                            sessionScope: "tty:/dev/ttys001:sid:100"
                        )
                    ),
                    now: now
                ),
                call: handler.validateAccessCredential
            )

        let leaseID = try XCTUnwrap(response.payload?.sshExecutionLeaseID)
        XCTAssertEqual(response.payload?.credential.consumedUses, 0)
        if case .credentialNotFound =
            SSHAutomationExecutionLeaseAuthority(authorityStore: store).lookup(
                leaseID: leaseID,
                sessionScope: "tty:/dev/ttys999:sid:999",
                ancestryPIDs: [],
                now: now.addingTimeInterval(1)
            ) {
            // Expected: the Keychain-owned binding, not the user-writable hint, is authoritative.
        } else {
            XCTFail("execution lease must reject a different terminal binding")
        }
        guard case .found(let credential) =
            SSHAutomationExecutionLeaseAuthority(authorityStore: store).lookup(
                leaseID: leaseID,
                sessionScope: "tty:/dev/ttys001:sid:100",
                ancestryPIDs: [],
                now: now.addingTimeInterval(1)
            ) else {
            return XCTFail("issued execution lease should resolve")
        }
        XCTAssertEqual(credential.id, issued.credential.id)
        XCTAssertTrue(
            SSHAutomationExecutionLeaseAuthority(authorityStore: store).consume(
                leaseID: leaseID,
                now: now.addingTimeInterval(1)
            )
        )
        XCTAssertEqual(try authority.list(includeAll: true, now: now).first?.consumedUses, 1)

        let retirementResponse: BridgeResponse<AutomationCredentialValidationPayload> =
            try await invoke(
                request: request(
                    type: .validateAccess,
                    body: AutomationCredentialValidatePayload(
                        token: issued.token,
                        requestedCommand: .ssh,
                        sshExecutionLeaseRetirementID: leaseID
                    ),
                    now: now
                ),
                call: handler.validateAccessCredential
            )

        XCTAssertNotNil(retirementResponse.payload)
        XCTAssertTrue(store.allRecords().filter { $0.type == .executionLease }.isEmpty)
        XCTAssertEqual(try authority.list(includeAll: true, now: now).first?.consumedUses, 1)
    }

    func testExecutionLeaseAuthorityReusesBindingAndPrunesExpiredLease() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let store = TestAuthorityStore()
        let authority = SSHAutomationExecutionLeaseAuthority(authorityStore: store)
        let firstCredential = AutomationCredentialMetadata(
            id: UUID(),
            name: "First",
            scope: "Team/API",
            createdAt: now,
            expiresAt: now.addingTimeInterval(10),
            revokedAt: nil,
            machineId: "machine-1",
            machineName: "Synthetic Mac",
            allowedCommands: [.ssh],
            environmentScope: nil
        )
        let binding = SSHAutomationExecutionLeaseBinding(
            sessionScope: "tty:/dev/ttys001:sid:100"
        )

        let firstLeaseID = try authority.create(
            credential: firstCredential,
            binding: binding,
            now: now
        )
        let reusedLeaseID = try authority.create(
            credential: firstCredential,
            binding: binding,
            now: now.addingTimeInterval(1)
        )

        XCTAssertEqual(reusedLeaseID, firstLeaseID)

        let later = now.addingTimeInterval(11)
        let secondCredential = AutomationCredentialMetadata(
            id: UUID(),
            name: "Second",
            scope: "Team/API",
            createdAt: later,
            expiresAt: later.addingTimeInterval(10),
            revokedAt: nil,
            machineId: "machine-1",
            machineName: "Synthetic Mac",
            allowedCommands: [.ssh],
            environmentScope: nil
        )
        let replacementLeaseID = try authority.create(
            credential: secondCredential,
            binding: SSHAutomationExecutionLeaseBinding(rootProcessID: 4242),
            now: later
        )

        XCTAssertNotEqual(replacementLeaseID, firstLeaseID)
        XCTAssertEqual(store.allRecords().filter { $0.type == .executionLease }.count, 1)

        XCTAssertThrowsError(
            try authority.retire(
                leaseID: replacementLeaseID,
                credentialID: firstCredential.id
            )
        ) {
            XCTAssertEqual(
                $0 as? SSHAutomationExecutionLeaseError,
                .invalidCredential
            )
        }
        XCTAssertEqual(store.allRecords().filter { $0.type == .executionLease }.count, 1)

        try authority.retire(
            leaseID: replacementLeaseID,
            credentialID: secondCredential.id
        )

        XCTAssertTrue(store.allRecords().filter { $0.type == .executionLease }.isEmpty)
    }

    func testExecutionLeaseAuthorityCapsUniqueActiveBindingsPerCredential() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let store = TestAuthorityStore()
        let authority = SSHAutomationExecutionLeaseAuthority(authorityStore: store)
        let credential = AutomationCredentialMetadata(
            id: UUID(),
            name: "Bounded",
            scope: "Team/API",
            createdAt: now,
            expiresAt: now.addingTimeInterval(86_400),
            revokedAt: nil,
            machineId: "machine-1",
            machineName: "Synthetic Mac",
            allowedCommands: [.ssh],
            environmentScope: nil
        )
        for rootProcessID in 2..<66 {
            _ = try authority.create(
                credential: credential,
                binding: SSHAutomationExecutionLeaseBinding(
                    rootProcessID: Int32(rootProcessID)
                ),
                now: now
            )
        }

        XCTAssertThrowsError(
            try authority.create(
                credential: credential,
                binding: SSHAutomationExecutionLeaseBinding(rootProcessID: 66),
                now: now
            )
        ) {
            XCTAssertEqual(
                $0 as? SSHAutomationExecutionLeaseError,
                .tooManyActiveLeases
            )
        }
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
