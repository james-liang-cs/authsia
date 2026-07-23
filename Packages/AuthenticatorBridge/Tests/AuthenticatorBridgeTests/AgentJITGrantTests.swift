import XCTest
@testable import AuthenticatorBridge

final class AgentJITGrantTests: XCTestCase {
    func testEnvironmentScopeAllowsExactAndAllButRejectsDefaultAndOtherTags() {
        let named = EnvironmentAccessScope.named("Production")
        XCTAssertFalse(named.allows(itemEnvironments: []))
        XCTAssertTrue(named.allows(itemEnvironments: ["All"]))
        XCTAssertTrue(named.allows(itemEnvironments: ["Production"]))
        XCTAssertFalse(named.allows(itemEnvironments: ["Development"]))
    }

    func testGrantAllowsOnlyItsNamedEnvironmentPlusAllEnvironmentItems() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let caller = AgentJITCallerFingerprint.fixture()
        let grant = AgentJITGrant.fixture(
            expiresAt: now.addingTimeInterval(60),
            callerFingerprint: caller,
            environmentScope: .named("Production")
        )

        XCTAssertFalse(grant.allows(capability: .exec, itemFolderPath: "Team/API", itemEnvironments: [], caller: caller, now: now))
        XCTAssertTrue(grant.allows(capability: .exec, itemFolderPath: "Team/API", itemEnvironments: ["All"], caller: caller, now: now))
        XCTAssertTrue(grant.allows(capability: .exec, itemFolderPath: "Team/API", itemEnvironments: ["Production"], caller: caller, now: now))
        XCTAssertFalse(grant.allows(capability: .exec, itemFolderPath: "Team/API", itemEnvironments: ["Development"], caller: caller, now: now))
    }
    func testRootScopeMatchesOnlyRoot() {
        let scope = AgentJITFolderScope.root

        XCTAssertTrue(scope.matches(itemFolderPath: nil))
        XCTAssertTrue(scope.matches(itemFolderPath: " / "))
        XCTAssertFalse(scope.matches(itemFolderPath: "Team/API"))
    }

    func testNamedFolderScopeMatchesFolderAndDescendants() {
        let scope = AgentJITFolderScope.folder("Team/API")

        XCTAssertTrue(scope.matches(itemFolderPath: "Team/API"))
        XCTAssertTrue(scope.matches(itemFolderPath: "Team/API/Prod"))
        XCTAssertTrue(scope.matches(itemFolderPath: "Team/API/Prod/Blue"))
        XCTAssertFalse(scope.matches(itemFolderPath: "Team"))
        XCTAssertFalse(scope.matches(itemFolderPath: "Team/Web"))
        XCTAssertFalse(scope.matches(itemFolderPath: "Team/API2"))
        XCTAssertFalse(scope.matches(itemFolderPath: nil))
    }

    func testDirectFolderScopeNormalizesStoredPathForMatchingAndStorage() {
        let scope = AgentJITFolderScope.folder(" Team / API ")

        XCTAssertTrue(scope.matches(itemFolderPath: "Team/API"))
        XCTAssertEqual(scope.storageValue, "Team/API")
        XCTAssertTrue(scope.matches(itemFolderPath: "Team/API/Prod"))
    }

    func testDirectFolderScopeNormalizesDisplayEqualityAndHashing() {
        let unnormalized = AgentJITFolderScope.folder(" Team / API ")
        let normalized = AgentJITFolderScope.folder("Team/API")
        let scopes: Set<AgentJITFolderScope> = [unnormalized, normalized]

        XCTAssertEqual(unnormalized.displayName, "Team/API")
        XCTAssertEqual(unnormalized, normalized)
        XCTAssertEqual(scopes.count, 1)
    }

    func testFolderScopeEncodingNormalizesDirectFolderCase() throws {
        let data = try JSONEncoder().encode(AgentJITFolderScope.folder(" Team / API "))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: String])
        let decoded = try JSONDecoder().decode(AgentJITFolderScope.self, from: data)

        XCTAssertEqual(object["path"], "Team/API")
        XCTAssertEqual(decoded, .folder("Team/API"))
    }

    func testGrantStatusHonorsRevocationAndExpiry() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let active = AgentJITGrant.fixture(expiresAt: now.addingTimeInterval(60))
        let expired = AgentJITGrant.fixture(expiresAt: now.addingTimeInterval(-1))
        let revoked = AgentJITGrant.fixture(
            expiresAt: now.addingTimeInterval(60),
            revokedAt: now
        )

        XCTAssertEqual(active.status(asOf: now), .active)
        XCTAssertEqual(expired.status(asOf: now), .expired)
        XCTAssertEqual(revoked.status(asOf: now), .revoked)
    }

    func testAllowsActiveGrantWithMatchingCapabilityNamedFolderAndCaller() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let caller = AgentJITCallerFingerprint.fixture()
        let grant = AgentJITGrant.fixture(
            expiresAt: now.addingTimeInterval(60),
            callerFingerprint: caller
        )

        XCTAssertTrue(
            grant.allows(
                capability: .exec,
                itemFolderPath: " Team / API ",
                caller: caller,
                now: now
            )
        )
        XCTAssertTrue(
            grant.allows(
                capability: .exec,
                itemFolderPath: "Team/API/Prod",
                caller: caller,
                now: now
            )
        )
    }

    func testAllowsDeniesExpiredGrant() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let caller = AgentJITCallerFingerprint.fixture()
        let grant = AgentJITGrant.fixture(
            expiresAt: now.addingTimeInterval(-1),
            callerFingerprint: caller
        )

        XCTAssertFalse(
            grant.allows(
                capability: .exec,
                itemFolderPath: "Team/API",
                caller: caller,
                now: now
            )
        )
    }

    func testAllowsDeniesRevokedGrant() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let caller = AgentJITCallerFingerprint.fixture()
        let grant = AgentJITGrant.fixture(
            expiresAt: now.addingTimeInterval(60),
            revokedAt: now,
            callerFingerprint: caller
        )

        XCTAssertFalse(
            grant.allows(
                capability: .exec,
                itemFolderPath: "Team/API",
                caller: caller,
                now: now
            )
        )
    }

    func testAllowsDeniesWrongCapability() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let caller = AgentJITCallerFingerprint.fixture()
        let grant = AgentJITGrant.fixture(
            expiresAt: now.addingTimeInterval(60),
            capabilities: [.list],
            callerFingerprint: caller
        )

        XCTAssertFalse(
            grant.allows(
                capability: .exec,
                itemFolderPath: "Team/API",
                caller: caller,
                now: now
            )
        )
    }

    func testAllowsNamedFolderGrantIncludesDescendantButDeniesAncestorSiblingAndRoot() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let caller = AgentJITCallerFingerprint.fixture()
        let grant = AgentJITGrant.fixture(
            expiresAt: now.addingTimeInterval(60),
            callerFingerprint: caller
        )

        XCTAssertTrue(
            grant.allows(
                capability: .exec,
                itemFolderPath: "Team/API/Prod",
                caller: caller,
                now: now
            )
        )
        XCTAssertFalse(
            grant.allows(
                capability: .exec,
                itemFolderPath: "Team",
                caller: caller,
                now: now
            )
        )
        XCTAssertFalse(
            grant.allows(
                capability: .exec,
                itemFolderPath: "Team/Web",
                caller: caller,
                now: now
            )
        )
        XCTAssertFalse(
            grant.allows(
                capability: .exec,
                itemFolderPath: nil,
                caller: caller,
                now: now
            )
        )
    }

    func testItemScopeUsesStableTypeAndUUIDAcrossFolderMoves() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let caller = AgentJITCallerFingerprint.fixture()
        let approvedID = UUID()
        let grant = AgentJITGrant.fixture(
            expiresAt: now.addingTimeInterval(60),
            callerFingerprint: caller,
            requestedItems: [
                AgentJITGrantItemReference(
                    type: "api-key",
                    id: approvedID.uuidString,
                    name: "Shared",
                    folderPath: "Team/API"
                ),
            ],
            environmentScope: .named("Production")
        )

        XCTAssertTrue(grant.allows(
            capability: .exec,
            itemIdentity: AgentJITItemIdentity(type: "apiKey", id: approvedID),
            itemFolderPath: "Renamed/Folder",
            itemEnvironments: ["Production"],
            caller: caller,
            now: now
        ))
        XCTAssertFalse(grant.allows(
            capability: .exec,
            itemIdentity: AgentJITItemIdentity(type: "api-key", id: UUID()),
            itemFolderPath: "Team/API",
            itemEnvironments: ["Production"],
            caller: caller,
            now: now
        ))
        XCTAssertFalse(grant.allows(
            capability: .exec,
            itemIdentity: AgentJITItemIdentity(type: "password", id: approvedID),
            itemFolderPath: "Team/API",
            itemEnvironments: ["Production"],
            caller: caller,
            now: now
        ))
        XCTAssertFalse(grant.allows(
            capability: .exec,
            itemIdentity: AgentJITItemIdentity(type: "api-key", id: approvedID),
            itemFolderPath: "Team/API",
            itemEnvironments: ["Development"],
            caller: caller,
            now: now
        ))
    }

    func testMalformedRequestedItemIdentityDoesNotFallBackToFolderScope() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let caller = AgentJITCallerFingerprint.fixture()
        let grant = AgentJITGrant.fixture(
            expiresAt: now.addingTimeInterval(60),
            callerFingerprint: caller,
            requestedItems: [
                AgentJITGrantItemReference(
                    type: "password",
                    id: "not-a-uuid",
                    name: "Malformed",
                    folderPath: "Team/API"
                ),
            ]
        )

        XCTAssertFalse(grant.allows(
            capability: .exec,
            itemIdentity: AgentJITItemIdentity(type: "password", id: UUID()),
            itemFolderPath: "Team/API",
            caller: caller,
            now: now
        ))
    }

    func testAllowsDeniesWrongCaller() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let caller = AgentJITCallerFingerprint.fixture()
        let grant = AgentJITGrant.fixture(
            expiresAt: now.addingTimeInterval(60),
            callerFingerprint: caller
        )
        let differentCaller = AgentJITCallerFingerprint.fixture(parentProcessName: "Terminal")

        XCTAssertFalse(
            grant.allows(
                capability: .exec,
                itemFolderPath: "Team/API",
                caller: differentCaller,
                now: now
            )
        )
    }

    func testFingerprintDoesNotMatchDifferentParentProcess() {
        let stored = AgentJITCallerFingerprint(
            processName: "authsia",
            bundleIdentifier: nil,
            signingTeamId: "TEAM",
            signingIdentity: "Developer ID Application",
            parentProcessName: "Claude",
            parentBundleIdentifier: "com.anthropic.claude",
            hostProcessName: nil,
            hostBundleIdentifier: nil,
            sessionScope: "tty:/dev/ttys001:sid:10",
            workingDirectory: "/repo"
        )
        let current = AgentJITCallerFingerprint(
            processName: "authsia",
            bundleIdentifier: nil,
            signingTeamId: "TEAM",
            signingIdentity: "Developer ID Application",
            parentProcessName: "Terminal",
            parentBundleIdentifier: "com.apple.Terminal",
            hostProcessName: nil,
            hostBundleIdentifier: nil,
            sessionScope: "tty:/dev/ttys001:sid:10",
            workingDirectory: "/repo"
        )

        XCTAssertFalse(stored.matches(current))
    }

    func testFingerprintDisplayNameIncludesIDEHost() {
        let fingerprint = AgentJITCallerFingerprint.fixture(
            parentProcessName: "claude",
            parentBundleIdentifier: "com.anthropic.claude",
            hostProcessName: "Code Helper",
            hostBundleIdentifier: "com.microsoft.VSCode"
        )

        XCTAssertEqual(fingerprint.displayName, "Claude via Visual Studio Code")
    }

    func testFingerprintDoesNotMatchDifferentHostProcess() {
        let stored = AgentJITCallerFingerprint.fixture(
            hostProcessName: "Code Helper",
            hostBundleIdentifier: "com.microsoft.VSCode"
        )
        let current = AgentJITCallerFingerprint.fixture(
            hostProcessName: "Cursor Helper",
            hostBundleIdentifier: "com.todesktop.230313mzl4w4u92"
        )

        XCTAssertFalse(stored.matches(current))
    }

    func testFingerprintRequiresIdentityFieldsToMatch() {
        func fingerprint(
            processName: String = "authsia",
            bundleIdentifier: String? = "com.authsia.cli",
            signingTeamId: String? = "TEAM",
            signingIdentity: String? = "Developer ID Application",
            parentBundleIdentifier: String? = "com.anthropic.claude"
        ) -> AgentJITCallerFingerprint {
            AgentJITCallerFingerprint.fixture(
                processName: processName,
                bundleIdentifier: bundleIdentifier,
                signingTeamId: signingTeamId,
                signingIdentity: signingIdentity,
                parentBundleIdentifier: parentBundleIdentifier
            )
        }

        let stored = fingerprint()
        let mismatches: [(String, AgentJITCallerFingerprint)] = [
            ("processName", fingerprint(processName: "other")),
            ("bundleIdentifier", fingerprint(bundleIdentifier: "com.example.other")),
            ("signingTeamId", fingerprint(signingTeamId: "OTHER")),
            ("signingIdentity", fingerprint(signingIdentity: "Other Identity")),
            ("parentBundleIdentifier", fingerprint(parentBundleIdentifier: "com.apple.Terminal")),
        ]

        for (field, current) in mismatches {
            XCTAssertFalse(stored.matches(current), field)
        }
    }

    func testFingerprintMissingStoredOptionalIdentityFieldsAreNonBlocking() {
        let stored = AgentJITCallerFingerprint.fixture(
            bundleIdentifier: nil,
            signingTeamId: nil,
            signingIdentity: nil,
            parentProcessName: nil,
            parentBundleIdentifier: nil
        )
        let current = AgentJITCallerFingerprint.fixture(
            bundleIdentifier: "com.authsia.cli",
            signingTeamId: "TEAM",
            signingIdentity: "Developer ID Application",
            parentProcessName: "Claude",
            parentBundleIdentifier: "com.anthropic.claude"
        )

        XCTAssertTrue(stored.matches(current))
    }

    func testFingerprintEmptyStoredOptionalIdentityFieldsMustMatchLiterally() {
        let stored = AgentJITCallerFingerprint.fixture(
            bundleIdentifier: "",
            signingTeamId: "",
            signingIdentity: "",
            parentProcessName: "",
            parentBundleIdentifier: ""
        )
        let emptyCurrent = AgentJITCallerFingerprint.fixture(
            bundleIdentifier: "",
            signingTeamId: "",
            signingIdentity: "",
            parentProcessName: "",
            parentBundleIdentifier: ""
        )
        let missingCurrent = AgentJITCallerFingerprint.fixture(
            bundleIdentifier: nil,
            signingTeamId: nil,
            signingIdentity: nil,
            parentProcessName: nil,
            parentBundleIdentifier: nil
        )
        let currentValues: [(String, AgentJITCallerFingerprint)] = [
            ("bundleIdentifier", .fixture(bundleIdentifier: "com.authsia.cli")),
            ("signingTeamId", .fixture(signingTeamId: "TEAM")),
            ("signingIdentity", .fixture(signingIdentity: "Developer ID Application")),
            ("parentProcessName", .fixture(parentProcessName: "Claude")),
            ("parentBundleIdentifier", .fixture(parentBundleIdentifier: "com.anthropic.claude")),
        ]

        XCTAssertTrue(stored.matches(emptyCurrent))
        XCTAssertFalse(stored.matches(missingCurrent))
        for (field, current) in currentValues {
            XCTAssertFalse(stored.matches(current), field)
        }
    }

    func testFingerprintMissingStoredSessionAndWorkingDirectoryMatchesMissingCurrentScope() {
        let stored = AgentJITCallerFingerprint.fixture(sessionScope: nil, workingDirectory: nil)
        let current = AgentJITCallerFingerprint.fixture(sessionScope: nil, workingDirectory: nil)

        XCTAssertTrue(stored.matches(current))
    }

    func testFingerprintMissingStoredSessionAndWorkingDirectoryRejectsPresentCurrentScope() {
        let stored = AgentJITCallerFingerprint.fixture(sessionScope: nil, workingDirectory: nil)
        let current = AgentJITCallerFingerprint.fixture(
            sessionScope: "tty:/dev/ttys002:sid:20",
            workingDirectory: "/other-repo"
        )

        XCTAssertFalse(stored.matches(current))
    }

    func testFingerprintStoredSessionAndWorkingDirectoryMustMatch() {
        let stored = AgentJITCallerFingerprint.fixture(
            sessionScope: "tty:/dev/ttys001:sid:10",
            workingDirectory: "/repo"
        )
        let differentSession = AgentJITCallerFingerprint.fixture(
            sessionScope: "tty:/dev/ttys002:sid:20",
            workingDirectory: "/repo"
        )
        let differentWorkingDirectory = AgentJITCallerFingerprint.fixture(
            sessionScope: "tty:/dev/ttys001:sid:10",
            workingDirectory: "/other-repo"
        )

        XCTAssertFalse(stored.matches(differentSession))
        XCTAssertFalse(stored.matches(differentWorkingDirectory))
    }

    func testFingerprintEmptyStoredSessionAndWorkingDirectoryMustMatchLiterally() {
        let stored = AgentJITCallerFingerprint.fixture(sessionScope: "", workingDirectory: "")
        let emptyCurrent = AgentJITCallerFingerprint.fixture(sessionScope: "", workingDirectory: "")
        let nonEmptySession = AgentJITCallerFingerprint.fixture(
            sessionScope: "tty:/dev/ttys001:sid:10",
            workingDirectory: ""
        )
        let nonEmptyWorkingDirectory = AgentJITCallerFingerprint.fixture(
            sessionScope: "",
            workingDirectory: "/repo"
        )
        let missingSession = AgentJITCallerFingerprint.fixture(sessionScope: nil, workingDirectory: "")
        let missingWorkingDirectory = AgentJITCallerFingerprint.fixture(sessionScope: "", workingDirectory: nil)

        XCTAssertTrue(stored.matches(emptyCurrent))
        XCTAssertFalse(stored.matches(nonEmptySession))
        XCTAssertFalse(stored.matches(nonEmptyWorkingDirectory))
        XCTAssertFalse(stored.matches(missingSession))
        XCTAssertFalse(stored.matches(missingWorkingDirectory))
    }

    func testFingerprintCodableRoundTrips() throws {
        let fingerprint = AgentJITCallerFingerprint.fixture(
            bundleIdentifier: "com.authsia.cli",
            signingTeamId: "TEAM",
            signingIdentity: "Developer ID Application",
            parentBundleIdentifier: "com.anthropic.claude"
        )
        let data = try JSONEncoder().encode(fingerprint)
        let decoded = try JSONDecoder().decode(AgentJITCallerFingerprint.self, from: data)

        XCTAssertEqual(decoded, fingerprint)
    }

    func testGrantCodableRoundTrips() throws {
        let grant = AgentJITGrant(
            id: try XCTUnwrap(UUID(uuidString: "11111111-2222-3333-4444-555555555555")),
            agentName: "Claude",
            callerFingerprint: AgentJITCallerFingerprint.fixture(
                bundleIdentifier: "com.authsia.cli",
                signingTeamId: "TEAM",
                signingIdentity: "Developer ID Application",
                parentBundleIdentifier: "com.anthropic.claude"
            ),
            folderScope: .folder(" Team / API "),
            capabilities: [.exec, .list],
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresAt: Date(timeIntervalSince1970: 1_700_000_600),
            revokedAt: Date(timeIntervalSince1970: 1_700_000_300),
            lastUsedAt: Date(timeIntervalSince1970: 1_700_000_120),
            requestedItems: [
                AgentJITGrantItemReference(
                    type: "password",
                    id: "password-id",
                    name: "API",
                    folderPath: "Team/API"
                ),
            ],
            agentRuntimeContext: AgentRuntimeContext(
                platform: "claude-code",
                sessionID: "session-1",
                turnID: nil,
                agentID: "agent-1",
                agentType: "Explore",
                toolUseID: "tool-1"
            ),
            approvedBy: "biometric"
        )
        let data = try JSONEncoder().encode(grant)
        let decoded = try JSONDecoder().decode(AgentJITGrant.self, from: data)

        XCTAssertEqual(decoded, grant)
        XCTAssertEqual(decoded.folderScope, .folder("Team/API"))
        XCTAssertEqual(decoded.requestedItems.map(\.name), ["API"])
        XCTAssertEqual(decoded.agentRuntimeContext?.agentType, "Explore")
    }

    func testGrantDecodeDefaultsMissingRequestedItemsToEmpty() throws {
        let json = """
        {
          "id": "11111111-2222-3333-4444-555555555555",
          "agentName": "Claude",
          "callerFingerprint": {
            "processName": "authsia",
            "bundleIdentifier": null,
            "signingTeamId": null,
            "signingIdentity": null,
            "parentProcessName": "Claude",
            "parentBundleIdentifier": null,
            "hostProcessName": null,
            "hostBundleIdentifier": null,
            "sessionScope": "tty:/dev/ttys001:sid:10",
            "workingDirectory": "/repo"
          },
          "folderScope": { "kind": "folder", "path": "Team/API" },
          "capabilities": ["exec", "list"],
          "createdAt": "2023-11-14T22:13:20Z",
          "expiresAt": "2023-11-14T22:23:20Z",
          "revokedAt": null,
          "lastUsedAt": null,
          "approvedBy": "biometric"
        }
        """

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(AgentJITGrant.self, from: Data(json.utf8))

        XCTAssertEqual(decoded.requestedItems, [])
    }

    func testGrantDecodeDefaultsMissingAgentRuntimeContextToNil() throws {
        let json = """
        {
          "id": "11111111-2222-3333-4444-555555555555",
          "agentName": "Claude",
          "callerFingerprint": {
            "processName": "authsia",
            "bundleIdentifier": null,
            "signingTeamId": null,
            "signingIdentity": null,
            "parentProcessName": "Claude",
            "parentBundleIdentifier": null,
            "hostProcessName": null,
            "hostBundleIdentifier": null,
            "sessionScope": "tty:/dev/ttys001:sid:10",
            "workingDirectory": "/repo"
          },
          "folderScope": { "kind": "folder", "path": "Team/API" },
          "capabilities": ["exec", "list"],
          "createdAt": "2023-11-14T22:13:20Z",
          "expiresAt": "2023-11-14T22:23:20Z",
          "revokedAt": null,
          "lastUsedAt": null,
          "requestedItems": [],
          "approvedBy": "biometric"
        }
        """

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(AgentJITGrant.self, from: Data(json.utf8))

        XCTAssertNil(decoded.agentRuntimeContext)
    }
}

private extension AgentJITGrant {
    static func fixture(
        expiresAt: Date,
        revokedAt: Date? = nil,
        folderScope: AgentJITFolderScope = .folder("Team/API"),
        capabilities: Set<AgentJITCapability> = [.exec, .list],
        callerFingerprint: AgentJITCallerFingerprint? = nil,
        requestedItems: [AgentJITGrantItemReference] = [],
        agentRuntimeContext: AgentRuntimeContext? = nil,
        environmentScope: EnvironmentAccessScope? = nil
    ) -> AgentJITGrant {
        AgentJITGrant(
            id: UUID(),
            agentName: "Claude",
            callerFingerprint: callerFingerprint ?? .fixture(),
            folderScope: folderScope,
            capabilities: capabilities,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresAt: expiresAt,
            revokedAt: revokedAt,
            lastUsedAt: nil,
            requestedItems: requestedItems,
            agentRuntimeContext: agentRuntimeContext,
            approvedBy: "biometric",
            environmentScope: environmentScope
        )
    }
}

private extension AgentJITCallerFingerprint {
    static func fixture(
        processName: String = "authsia",
        bundleIdentifier: String? = nil,
        signingTeamId: String? = nil,
        signingIdentity: String? = nil,
        parentProcessName: String? = "Claude",
        parentBundleIdentifier: String? = nil,
        hostProcessName: String? = nil,
        hostBundleIdentifier: String? = nil,
        sessionScope: String? = "tty:/dev/ttys001:sid:10",
        workingDirectory: String? = "/repo"
    ) -> AgentJITCallerFingerprint {
        AgentJITCallerFingerprint(
            processName: processName,
            bundleIdentifier: bundleIdentifier,
            signingTeamId: signingTeamId,
            signingIdentity: signingIdentity,
            parentProcessName: parentProcessName,
            parentBundleIdentifier: parentBundleIdentifier,
            hostProcessName: hostProcessName,
            hostBundleIdentifier: hostBundleIdentifier,
            sessionScope: sessionScope,
            workingDirectory: workingDirectory
        )
    }
}
