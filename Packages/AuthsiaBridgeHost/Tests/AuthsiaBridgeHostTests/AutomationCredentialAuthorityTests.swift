#if os(macOS)
import Foundation
import XCTest
import AuthenticatorBridge
@testable import AuthsiaBridgeHost

final class AutomationCredentialAuthorityTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)
    private let key = Data(repeating: 0x42, count: 32)

    func testCreateReturnsVersionedTokenButPersistsOnlyDigestAndMetadata() throws {
        let store = TestAuthorityStore()
        let authority = makeAuthority(store: store)

        let issued = try authority.create(payload: payload(), now: now)

        XCTAssertTrue(issued.token.hasPrefix("authsia_ac1_"))
        XCTAssertEqual(issued.credential.name, "Synthetic CI")
        let record = try XCTUnwrap(store.allRecords().first)
        XCTAssertEqual(record.type, .automationCredential)
        XCTAssertFalse(record.payload?.contains(Data(issued.token.utf8)) == true)
        XCTAssertNotEqual(record.bindingDigest, Data(issued.token.utf8))
    }

    func testForgedLegacyFileCannotCreateUsableCredential() throws {
        let directory = temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let legacyURL = directory.appendingPathComponent("access-credentials.json")
        try Data(#"[{"id":"00000000-0000-0000-0000-000000000001"}]"#.utf8).write(to: legacyURL)
        let authority = makeAuthority(
            store: TestAuthorityStore()
        )
        let forgedToken = try AutomationCredentialToken.issue(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
            randomBytes: Data(repeating: 0x99, count: 32)
        )

        XCTAssertThrowsError(
            try authority.validate(
                token: forgedToken,
                requestedCommand: .exec,
                currentMachineId: "machine-1",
                now: now
            )
        ) { error in
            XCTAssertEqual(error as? AutomationCredentialAuthorityError, .notFound)
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: legacyURL.path))
    }

    func testRestartValidatesTokenAndEnforcesMachineCommandAndRevocation() throws {
        let store = TestAuthorityStore()
        let issued = try makeAuthority(store: store).create(payload: payload(), now: now)
        let restarted = makeAuthority(store: store)

        let validated = try restarted.validate(
            token: issued.token,
            requestedCommand: .exec,
            currentMachineId: "machine-1",
            now: now
        )
        XCTAssertEqual(validated.id, issued.credential.id)
        XCTAssertThrowsError(
            try restarted.validate(
                token: issued.token,
                requestedCommand: .get,
                currentMachineId: "machine-1",
                now: now
            )
        )
        XCTAssertThrowsError(
            try restarted.validate(
                token: issued.token,
                requestedCommand: .exec,
                currentMachineId: "machine-2",
                now: now
            )
        )

        let revoked = try restarted.revoke(id: issued.credential.id, at: now)
        XCTAssertEqual(revoked.status(asOf: now), .revoked)
        XCTAssertThrowsError(
            try restarted.validate(
                token: issued.token,
                requestedCommand: .exec,
                currentMachineId: "machine-1",
                now: now
            )
        )
    }

    func testListIsTokenFreeAndIncludesLegacyRecordsOnlyAsDisabled() throws {
        let store = TestAuthorityStore()
        let authority = makeAuthority(store: store)
        let issued = try authority.create(payload: payload(), now: now)

        let active = try authority.list(includeAll: false, now: now)
        let all = try authority.list(includeAll: true, now: now)

        XCTAssertEqual(active, [issued.credential])
        XCTAssertEqual(all, [issued.credential])
        XCTAssertFalse(String(describing: all).contains(issued.token))
    }

    func testRepeatedInvalidTokensAreRateLimitedWithoutPersistingSuppliedValues() throws {
        let store = TestAuthorityStore()
        let authority = AutomationCredentialAuthority(
            authorityStore: store,
            digestKey: key,
            invalidAttemptLimiter: AutomationCredentialInvalidAttemptLimiter(
                maximumAttempts: 2,
                window: 60
            ),
            randomBytes: { count in Data(repeating: 0x7a, count: count) }
        )
        let issued = try authority.create(payload: payload(), now: now)
        let invalidToken = try AutomationCredentialToken.issue(
            id: issued.credential.id,
            randomBytes: Data(repeating: 0x41, count: AutomationCredentialToken.randomByteCount)
        )

        for _ in 0..<2 {
            XCTAssertThrowsError(
                try authority.validate(
                    token: invalidToken,
                    requestedCommand: .exec,
                    currentMachineId: "machine-1",
                    now: now
                )
            ) {
                XCTAssertEqual($0 as? AutomationCredentialAuthorityError, .invalidToken)
            }
        }
        XCTAssertThrowsError(
            try authority.validate(
                token: invalidToken,
                requestedCommand: .exec,
                currentMachineId: "machine-1",
                now: now
            )
        ) {
            XCTAssertEqual($0 as? AutomationCredentialAuthorityError, .rateLimited)
        }
        XCTAssertNoThrow(
            try authority.validate(
                token: issued.token,
                requestedCommand: .exec,
                currentMachineId: "machine-1",
                now: now
            )
        )
    }

    func testValidCredentialDoesNotResetAnotherCredentialsInvalidAttemptLimit() throws {
        let authority = AutomationCredentialAuthority(
            authorityStore: TestAuthorityStore(),
            digestKey: key,
            invalidAttemptLimiter: AutomationCredentialInvalidAttemptLimiter(
                maximumAttempts: 1,
                window: 60
            ),
            randomBytes: { count in Data(repeating: 0x7a, count: count) }
        )
        let first = try authority.create(payload: payload(), now: now)
        let second = try authority.create(payload: payload(), now: now)
        let forgedFirst = try AutomationCredentialToken.issue(
            id: first.credential.id,
            randomBytes: Data(repeating: 0x41, count: AutomationCredentialToken.randomByteCount)
        )

        XCTAssertThrowsError(
            try authority.validate(
                token: forgedFirst,
                requestedCommand: .exec,
                currentMachineId: "machine-1",
                now: now
            )
        )
        _ = try authority.validate(
            token: second.token,
            requestedCommand: .exec,
            currentMachineId: "machine-1",
            now: now
        )
        XCTAssertThrowsError(
            try authority.validate(
                token: forgedFirst,
                requestedCommand: .exec,
                currentMachineId: "machine-1",
                now: now
            )
        ) {
            XCTAssertEqual($0 as? AutomationCredentialAuthorityError, .rateLimited)
        }
    }

    func testMaximumUsesFromApprovalPayloadIsEnforced() throws {
        let authority = makeAuthority(store: TestAuthorityStore())
        let limitedPayload = AccessCreateApprovalPayload(
            name: "Synthetic CI",
            scope: "Team/API",
            ttlSeconds: 900,
            expiresAt: now.addingTimeInterval(900),
            machineId: "machine-1",
            machineName: "Synthetic Mac",
            allowedCommands: ["exec"],
            maximumUses: 1
        )
        let issued = try authority.create(payload: limitedPayload, now: now)

        _ = try authority.validate(
            token: issued.token,
            requestedCommand: .exec,
            currentMachineId: "machine-1",
            now: now
        )

        XCTAssertThrowsError(
            try authority.validate(
                token: issued.token,
                requestedCommand: .exec,
                currentMachineId: "machine-1",
                now: now
            )
        ) {
            XCTAssertEqual($0 as? AutomationCredentialAuthorityError, .consumed)
        }
    }

    func testCreateRejectsExpiryLongerThanApprovedTTL() {
        let authority = makeAuthority(store: TestAuthorityStore())
        let mismatchedPayload = AccessCreateApprovalPayload(
            name: "Synthetic CI",
            scope: "Team/API",
            ttlSeconds: 900,
            expiresAt: now.addingTimeInterval(86_400),
            machineId: "machine-1",
            machineName: "Synthetic Mac",
            allowedCommands: ["exec"]
        )

        XCTAssertThrowsError(
            try authority.create(payload: mismatchedPayload, now: now)
        ) {
            XCTAssertEqual($0 as? AutomationCredentialAuthorityError, .corruptedStore)
        }
    }

    func testCreateRejectsSSHCombinedWithOtherCapabilities() {
        let authority = makeAuthority(store: TestAuthorityStore())
        let mixedPayload = AccessCreateApprovalPayload(
            name: "Synthetic CI",
            scope: "Team/API",
            ttlSeconds: 900,
            expiresAt: now.addingTimeInterval(900),
            machineId: "machine-1",
            machineName: "Synthetic Mac",
            allowedCommands: ["exec", "ssh"]
        )

        XCTAssertThrowsError(
            try authority.create(payload: mixedPayload, now: now)
        ) {
            XCTAssertEqual($0 as? AutomationCredentialAuthorityError, .commandDenied)
        }
    }

    private func makeAuthority(store: AuthorityStoring) -> AutomationCredentialAuthority {
        AutomationCredentialAuthority(
            authorityStore: store,
            digestKey: key,
            randomBytes: { count in Data(repeating: 0x7a, count: count) }
        )
    }

    private func payload() -> AccessCreateApprovalPayload {
        AccessCreateApprovalPayload(
            name: "Synthetic CI",
            scope: "Team/API",
            ttlSeconds: 900,
            expiresAt: now.addingTimeInterval(900),
            machineId: "machine-1",
            machineName: "Synthetic Mac",
            allowedCommands: ["exec", "list"],
            environmentScope: .named("Production")
        )
    }

    private func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("AutomationCredentialAuthorityTests-\(UUID().uuidString)", isDirectory: true)
    }
}
#endif
