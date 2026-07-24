import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
import CryptoKit

@MainActor
final class XPCRequestHandlerJITGrantTests: XCTestCase {
    private var isolatedAuditDirectories: [URL] = []

    private let callerIdentity = CallerIdentity(
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

    private let humanCallerIdentity = CallerIdentity(
        pid: 42,
        processName: "authsia",
        bundleIdentifier: "com.authsia.cli",
        signingTeamId: "TEAM",
        signingIdentity: "Developer ID Application",
        parentProcess: ParentProcessInfo(
            pid: 41,
            processName: "Terminal",
            bundleIdentifier: "com.apple.Terminal",
            isPlatformBinary: true
        )
    )

    private let appCallerIdentity = CallerIdentity(
        pid: 40,
        processName: "Authsia",
        bundleIdentifier: "app.authsia",
        signingTeamId: "TEAM",
        signingIdentity: "Developer ID Application"
    )

    private let vscodeTerminalCallerIdentity = CallerIdentity(
        pid: 42,
        processName: "authsia",
        bundleIdentifier: "com.authsia.cli",
        signingTeamId: "TEAM",
        signingIdentity: "Developer ID Application",
        parentProcess: ParentProcessInfo(
            pid: 41,
            processName: "zsh",
            bundleIdentifier: nil
        ),
        hostProcess: ParentProcessInfo(
            pid: 40,
            processName: "Code Helper",
            bundleIdentifier: "com.microsoft.VSCode"
        )
    )

    private let ideHelperCallerIdentity = CallerIdentity(
        pid: 42,
        processName: "authsia",
        bundleIdentifier: "com.authsia.cli",
        signingTeamId: "TEAM",
        signingIdentity: "Developer ID Application",
        parentProcess: ParentProcessInfo(
            pid: 41,
            processName: "Cursor Helper",
            bundleIdentifier: "com.todesktop.230313mzl4w4u92"
        )
    )

    private let claudeViaVSCodeCallerIdentity = CallerIdentity(
        pid: 42,
        processName: "authsia",
        bundleIdentifier: "com.authsia.cli",
        signingTeamId: "TEAM",
        signingIdentity: "Developer ID Application",
        parentProcess: ParentProcessInfo(
            pid: 41,
            processName: "claude",
            bundleIdentifier: "com.anthropic.claude"
        ),
        hostProcess: ParentProcessInfo(
            pid: 40,
            processName: "Code Helper",
            bundleIdentifier: "com.microsoft.VSCode"
        )
    )

    private let unknownInteractiveCallerIdentity = CallerIdentity(
        pid: 42,
        processName: "authsia",
        bundleIdentifier: "com.authsia.cli",
        signingTeamId: "TEAM",
        signingIdentity: "Developer ID Application",
        parentProcess: ParentProcessInfo(
            pid: 41,
            processName: "zsh",
            bundleIdentifier: nil
        ),
        hostProcess: ParentProcessInfo(
            pid: 40,
            processName: "ExampleTerm",
            bundleIdentifier: "example.terminal"
        )
    )

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    func testGrantSnapshotSeparatesActiveFromHistoryWithoutSessionToken() async throws {
        let active = AgentJITGrant.fixture(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
            callerFingerprint: callerFingerprint(requestedCommand: "exec"),
            folderScope: .folder("Team/One"),
            capabilities: [.exec],
            createdAt: now.addingTimeInterval(-60),
            expiresAt: now.addingTimeInterval(300)
        )
        let revoked = AgentJITGrant.fixture(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!,
            callerFingerprint: callerFingerprint(requestedCommand: "exec"),
            folderScope: .folder("Team/Two"),
            capabilities: [.exec],
            createdAt: now.addingTimeInterval(-60),
            expiresAt: now.addingTimeInterval(300),
            revokedAt: now.addingTimeInterval(-1)
        )
        let handler = makeHandler(
            store: MemoryAgentJITGrantStore([active, revoked]),
            callerIdentity: appCallerIdentity,
            clock: AgentJITApprovalClockSpy([now]).callAsFunction
        )

        let response: BridgeResponse<AgentJITGrantSnapshotPayload> = try await grantSnapshot(handler)

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.active, [active])
        XCTAssertEqual(response.payload?.history, [revoked])
        XCTAssertNil(response.sessionToken)
    }

    func testRevokeGrantAndRevokeAllUseBridgeOwnedStore() async throws {
        let first = AgentJITGrant.fixture(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
            callerFingerprint: callerFingerprint(requestedCommand: "exec"),
            folderScope: .folder("Team/One"),
            capabilities: [.exec],
            createdAt: now.addingTimeInterval(-60),
            expiresAt: now.addingTimeInterval(300)
        )
        let second = AgentJITGrant.fixture(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!,
            callerFingerprint: callerFingerprint(requestedCommand: "exec"),
            folderScope: .folder("Team/Two"),
            capabilities: [.exec],
            createdAt: now.addingTimeInterval(-60),
            expiresAt: now.addingTimeInterval(300)
        )
        let store = MemoryAgentJITGrantStore([first, second])
        let handler = makeHandler(
            store: store,
            callerIdentity: appCallerIdentity,
            clock: AgentJITApprovalClockSpy([now, now.addingTimeInterval(1)]).callAsFunction
        )

        let single: BridgeResponse<AgentJITGrantMutationPayload> = try await revokeGrant(handler, id: first.id)
        let all: BridgeResponse<AgentJITGrantMutationPayload> = try await revokeAllGrants(handler)

        XCTAssertNil(single.error)
        XCTAssertEqual(single.payload?.revokedGrantIDs, [first.id])
        XCTAssertNil(all.error)
        XCTAssertEqual(all.payload?.revokedGrantIDs, [second.id])
        XCTAssertEqual(store.grants.filter { $0.revokedAt != nil }.count, 2)
    }

    func testGrantControlRejectsCLICaller() async throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore())

        let response: BridgeResponse<AgentJITGrantSnapshotPayload> = try await grantSnapshot(handler)

        XCTAssertEqual(response.error?.code, .policyDenied)
    }

    func testRemoteBuilderReceivesExactMappedAuthorityAndFixedTiming() async throws {
        let restoreTTL = setCLIApprovalTTL(15)
        defer { restoreTTL() }
        let issued = Date(timeIntervalSince1970: 1_700_000_000.1239)
        let clock = AgentJITApprovalClockSpy([issued, issued.addingTimeInterval(1)])
        let builder = RemoteRequestBuilderSpy()
        let approver = JITApprovalTracker(result: true)
        let store = MemoryAgentJITGrantStore()
        let handler = makeHandler(
            store: store,
            approver: approver,
            requestBuilder: builder,
            clock: clock.callAsFunction
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
            ],
            environmentScope: .named("Production")
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        let input = try XCTUnwrap(builder.inputBatches.first?.first)
        XCTAssertEqual(builder.inputBatches.map(\.count), [1])
        XCTAssertEqual(input.requestIssuedAtMilliseconds, 1_700_000_000_123)
        XCTAssertEqual(input.grantExpiresAtMilliseconds, 1_700_000_015_123)
        XCTAssertEqual(input.capabilities, [.exec, .list])
        XCTAssertEqual(input.folderScope, .folder("Team/API"))
        XCTAssertEqual(input.environmentScope, .named("Production"))
        XCTAssertEqual(input.requestedItems.count, 1)
        XCTAssertEqual(input.requestedItems.first?.kind, .password)
        XCTAssertEqual(input.requestedItems.first?.id, stableUUID("password:API:Team/API"))
        XCTAssertEqual(input.requestedItems.first?.folderPath, "Team/API")
        let approvalDescriptor = try XCTUnwrap(approver.requests.first?.approvalDescriptors.first)
        XCTAssertEqual(approvalDescriptor.callerDisplayName, "Claude")
        XCTAssertEqual(approvalDescriptor.workspaceLabel, "repo")
        XCTAssertEqual(approvalDescriptor.environmentScope, .named("Production"))
        XCTAssertEqual(approvalDescriptor.reuseDescription, "Exact items only")
        XCTAssertEqual(approvalDescriptor.requestedItems.map(\.name), ["API"])
        XCTAssertEqual(approvalDescriptor.requestedItems.map(\.type), ["Password"])
        XCTAssertEqual(approver.requests.first?.remoteRequests.map(\.descriptor.input), [input])
        XCTAssertEqual(store.grants.first?.createdAt, Date(timeIntervalSince1970: 1_700_000_000.123))
        XCTAssertEqual(store.grants.first?.expiresAt, Date(timeIntervalSince1970: 1_700_000_015.123))
        XCTAssertEqual(clock.callCount, 2)
    }

    func testDisabledICloudSyncSkipsRemoteBuilderAndKeepsLocalApproval() async throws {
        let builder = RemoteRequestBuilderSpy()
        let approver = JITApprovalTracker(result: true)
        let store = MemoryAgentJITGrantStore()
        let handler = makeHandler(
            store: store,
            approver: approver,
            requestBuilder: builder,
            remoteJITApprovalEnabled: { false },
            clock: AgentJITApprovalClockSpy([now, now]).callAsFunction
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            handler,
            body: payload
        )

        XCTAssertNil(response.error)
        XCTAssertTrue(builder.inputBatches.isEmpty)
        XCTAssertEqual(approver.requests.first?.remoteRequests, [])
        XCTAssertEqual(store.grants.count, 1)
    }

    func testBroadRemoteApprovalBuildsAndPassesAllRequestsInResolverOrder() async throws {
        let builder = RemoteRequestBuilderSpy()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(
            store: MemoryAgentJITGrantStore(),
            approver: approver,
            requestBuilder: builder,
            clock: AgentJITApprovalClockSpy([now, now]).callAsFunction
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [AgentJITPreflightReference(
                type: "password",
                query: "",
                folderPath: nil,
                isFolderScoped: false
            )]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            handler,
            body: payload,
            requestedCommand: "list"
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(builder.inputBatches.count, 1)
        XCTAssertEqual(builder.inputBatches[0].map(\.folderScope), [
            .root, .folder("Team/API"), .folder("Team/Web"),
        ])
        XCTAssertEqual(builder.inputBatches[0].map(\.capabilities), Array(repeating: [.list], count: 3))
        XCTAssertEqual(approver.requests.count, 1)
        XCTAssertEqual(approver.requests[0].remoteRequests.count, 3)
    }

    func testBroadPairedIPhoneApprovalAttributesEveryResolutionAndAuditRecord() async throws {
        let builder = RemoteRequestBuilderSpy()
        let remoteSource = try RemoteJITApprovalPairedIPhoneSource(
            pairingGenerationID: builder.pairing.pairingGenerationID,
            signingKeyFingerprint: builder.pairing.iphoneSigningKeyFingerprint
        )
        let store = MemoryAgentJITGrantStore()
        let (auditLogger, auditURL, tempDir) = try makeAuditLogger()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let handler = makeHandler(
            store: store,
            approver: JITApprovalTracker(outcome: .approved(source: .pairedIPhone(remoteSource))),
            auditLogger: auditLogger,
            requestBuilder: builder,
            clock: AgentJITApprovalClockSpy([now, now]).callAsFunction
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [AgentJITPreflightReference(
                type: "password",
                query: "",
                folderPath: nil,
                isFolderScoped: false
            )]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            handler,
            body: payload,
            requestedCommand: "list"
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(store.grants.count, 3)
        XCTAssertEqual(store.grants.map(\.approvedBy), Array(repeating: builder.remoteAttribution, count: 3))
        XCTAssertEqual(
            try auditRecords(at: auditURL).map(\.approvedBy),
            Array(repeating: builder.remoteAttribution, count: 3)
        )
    }

    func testPerScopeRemoteApprovalBuildsOneRequestAtATimeAndKeepsMixedAttribution() async throws {
        let builder = RemoteRequestBuilderSpy()
        let remoteSource = try RemoteJITApprovalPairedIPhoneSource(
            pairingGenerationID: builder.pairing.pairingGenerationID,
            signingKeyFingerprint: builder.pairing.iphoneSigningKeyFingerprint
        )
        let approver = JITApprovalTracker(outcomes: [
            .approved(source: .macPanel),
            .approved(source: .pairedIPhone(remoteSource)),
        ])
        let store = MemoryAgentJITGrantStore()
        let (auditLogger, auditURL, tempDir) = try makeAuditLogger()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let handler = makeHandler(
            store: store,
            approver: approver,
            auditLogger: auditLogger,
            requestBuilder: builder,
            clock: AgentJITApprovalClockSpy([now, now]).callAsFunction
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
                AgentJITPreflightReference(type: "cert", query: "Web Cert", folderPath: "Team/Web"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(builder.inputBatches.map(\.count), [1, 1])
        XCTAssertEqual(builder.inputBatches.compactMap(\.first).map(\.folderScope), [
            .folder("Team/API"), .folder("Team/Web"),
        ])
        XCTAssertEqual(approver.requests.map(\.remoteRequests).map(\.count), [1, 1])
        XCTAssertEqual(store.grants.map(\.approvedBy), ["mac-panel", builder.remoteAttribution])
        XCTAssertEqual(try auditRecords(at: auditURL).map(\.approvedBy), [
            "mac-panel", builder.remoteAttribution,
        ])
        XCTAssertEqual(store.saveAllCallCount, 1)
        XCTAssertEqual(store.savedBatches.map(\.count), [2])
    }

    func testHostDeniesPairedIPhoneApprovalWithWrongGenerationOrFingerprint() async throws {
        let builder = RemoteRequestBuilderSpy()
        let invalidSources = [
            try RemoteJITApprovalPairedIPhoneSource(
                pairingGenerationID: UUID(uuidString: "dddddddd-dddd-dddd-dddd-dddddddddddd")!,
                signingKeyFingerprint: builder.pairing.iphoneSigningKeyFingerprint
            ),
            try RemoteJITApprovalPairedIPhoneSource(
                pairingGenerationID: builder.pairing.pairingGenerationID,
                signingKeyFingerprint: Data(repeating: 0x99, count: 32)
            ),
        ]
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
            ]
        )

        for source in invalidSources {
            let store = MemoryAgentJITGrantStore()
            let handler = makeHandler(
                store: store,
                approver: JITApprovalTracker(outcome: .approved(source: .pairedIPhone(source))),
                requestBuilder: builder,
                clock: AgentJITApprovalClockSpy([now]).callAsFunction
            )

            let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
                handler,
                body: payload
            )

            XCTAssertEqual(response.error?.code, .notAuthorized)
            XCTAssertEqual(store.grants, [])
        }
    }

    func testInvalidBuilderOutputsFallBackToMacApprovalWithoutPartialRemoteRequests() async throws {
        let modes: [RemoteRequestBuilderSpy.Mode] = [.throwError, .wrongCount, .reversed, .mismatchedAuthority]
        for mode in modes {
            let builder = RemoteRequestBuilderSpy(mode: mode)
            let approver = JITApprovalTracker(result: true)
            let store = MemoryAgentJITGrantStore()
            let handler = makeHandler(
                store: store,
                approver: approver,
                requestBuilder: builder,
                clock: AgentJITApprovalClockSpy([now, now]).callAsFunction
            )
            let payload = AgentJITPreflightPayload(
                requestedCommand: "list",
                references: [AgentJITPreflightReference(
                    type: "password",
                    query: "",
                    folderPath: nil,
                    isFolderScoped: false
                )]
            )

            let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
                handler,
                body: payload,
                requestedCommand: "list"
            )

            XCTAssertNil(response.error, "mode: \(mode)")
            XCTAssertEqual(approver.requests.first?.remoteRequests, [], "mode: \(mode)")
            XCTAssertEqual(store.grants.count, 3, "mode: \(mode)")
        }
    }

    func testCheckedTimingRejectsInvalidClockAndTTLAndTruncatesTowardZero() throws {
        XCTAssertNil(XPCRequestHandler.fixedAgentJITApprovalTiming(
            now: Date(timeIntervalSince1970: .nan),
            ttl: 15
        ))
        XCTAssertNil(XPCRequestHandler.fixedAgentJITApprovalTiming(
            now: Date(timeIntervalSince1970: -0.001),
            ttl: 15
        ))
        XCTAssertNil(XPCRequestHandler.fixedAgentJITApprovalTiming(
            now: Date(timeIntervalSince1970: 253_402_300_800),
            ttl: 15
        ))
        XCTAssertNil(XPCRequestHandler.fixedAgentJITApprovalTiming(now: now, ttl: .infinity))
        XCTAssertNil(XPCRequestHandler.fixedAgentJITApprovalTiming(now: now, ttl: .greatestFiniteMagnitude))
        XCTAssertNil(XPCRequestHandler.fixedAgentJITApprovalTiming(
            now: now,
            ttl: Double(Int64.max) / 1_000
        ))
        XCTAssertNil(XPCRequestHandler.fixedAgentJITApprovalTiming(now: now, ttl: 0.0009))
        XCTAssertNil(XPCRequestHandler.fixedAgentJITApprovalTiming(now: now, ttl: 86_400.001))
        XCTAssertEqual(
            XPCRequestHandler.checkedAgentJITMilliseconds(
                Date(timeIntervalSince1970: 253_402_300_799.9995)
            ),
            253_402_300_799_999
        )

        let maximumTTLTiming = try XCTUnwrap(XPCRequestHandler.fixedAgentJITApprovalTiming(
            now: now,
            ttl: 86_400.0009
        ))
        XCTAssertEqual(
            maximumTTLTiming.grantExpiresAtMilliseconds - maximumTTLTiming.issuedAtMilliseconds,
            86_400_000
        )

        let timing = try XCTUnwrap(XPCRequestHandler.fixedAgentJITApprovalTiming(
            now: Date(timeIntervalSince1970: 1_700_000_000.1239),
            ttl: 15.9999
        ))
        XCTAssertEqual(timing.issuedAtMilliseconds, 1_700_000_000_123)
        XCTAssertEqual(timing.grantExpiresAtMilliseconds, 1_700_000_016_122)
        XCTAssertEqual(timing.requestExpiresAtMilliseconds, 1_700_000_090_123)
    }

    func testApprovalAtExpiryBoundaryFailsBeforeBatchSave() async throws {
        let restoreTTL = setCLIApprovalTTL(120)
        defer { restoreTTL() }
        let store = MemoryAgentJITGrantStore()
        let clock = AgentJITApprovalClockSpy([now, now.addingTimeInterval(90)])
        let handler = makeHandler(store: store, clock: clock.callAsFunction)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API")]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertEqual(response.error?.code, .notAuthorized)
        XCTAssertEqual(store.saveAllCallCount, 0)
        XCTAssertEqual(store.grants, [])
    }

    func testApprovalAtGrantExpiryBoundaryFailsBeforeBatchSave() async throws {
        let restoreTTL = setCLIApprovalTTL(15)
        defer { restoreTTL() }
        let store = MemoryAgentJITGrantStore()
        let clock = AgentJITApprovalClockSpy([now, now.addingTimeInterval(15)])
        let handler = makeHandler(store: store, clock: clock.callAsFunction)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API")]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertEqual(response.error?.code, .notAuthorized)
        XCTAssertEqual(store.saveAllCallCount, 0)
        XCTAssertEqual(store.grants, [])
    }

    func testClockRollbackAndGlobalCLIDisableFailBeforeBatchSave() async throws {
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API")]
        )
        let rollbackStore = MemoryAgentJITGrantStore()
        let rollbackHandler = makeHandler(
            store: rollbackStore,
            clock: AgentJITApprovalClockSpy([now, now.addingTimeInterval(-0.001)]).callAsFunction
        )
        let rollbackResponse: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            rollbackHandler,
            body: payload
        )
        XCTAssertEqual(rollbackResponse.error?.code, .notAuthorized)
        XCTAssertEqual(rollbackStore.saveAllCallCount, 0)

        let defaults = BridgeSettings.appDefaults
        let key = BridgeSettings.cliAccessEnabledKey
        let previous = defaults.object(forKey: key)
        defaults.set(true, forKey: key)
        defer {
            if let previous {
                defaults.set(previous, forKey: key)
            } else {
                defaults.removeObject(forKey: key)
            }
        }
        let disabledStore = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        approver.onRequest = { defaults.set(false, forKey: key) }
        let disabledHandler = makeHandler(
            store: disabledStore,
            approver: approver,
            clock: AgentJITApprovalClockSpy([now, now]).callAsFunction
        )
        let disabledResponse: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            disabledHandler,
            body: payload
        )
        XCTAssertEqual(disabledResponse.error?.code, .notAuthorized)
        XCTAssertEqual(disabledStore.saveAllCallCount, 0)
    }

    func testTimedOutAndSupersededApprovalsRecordExactDenialAttribution() async throws {
        for (outcome, expectedAttribution) in [
            (RemoteJITApprovalOutcome.timedOut, "denied:timeout"),
            (.superseded, "denied:superseded"),
        ] {
            let store = MemoryAgentJITGrantStore()
            let (auditLogger, auditURL, tempDir) = try makeAuditLogger()
            defer { try? FileManager.default.removeItem(at: tempDir) }
            let handler = makeHandler(
                store: store,
                approver: JITApprovalTracker(outcome: outcome),
                auditLogger: auditLogger,
                clock: AgentJITApprovalClockSpy([now]).callAsFunction
            )
            let payload = AgentJITPreflightPayload(
                requestedCommand: "exec",
                references: [
                    AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
                ]
            )

            let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

            XCTAssertEqual(response.error?.code, .notAuthorized)
            XCTAssertEqual(try auditRecords(at: auditURL).map(\.approvedBy), [expectedAttribution])
            XCTAssertEqual(store.saveAllCallCount, 0)
        }
    }

    func testRemoteProjectionMapsEverySupportedListItemKindWithoutNames() async throws {
        let builder = RemoteRequestBuilderSpy()
        let handler = makeHandler(
            store: MemoryAgentJITGrantStore(),
            requestBuilder: builder,
            clock: AgentJITApprovalClockSpy([now, now]).callAsFunction
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
                AgentJITPreflightReference(type: "api-key", query: "API Key", folderPath: "Team/API"),
                AgentJITPreflightReference(type: "cert", query: "API Cert", folderPath: "Team/API"),
                AgentJITPreflightReference(type: "note", query: "API Note", folderPath: "Team/API"),
                AgentJITPreflightReference(type: "ssh", query: "API SSH", folderPath: "Team/API"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            handler,
            body: payload,
            requestedCommand: "list"
        )

        XCTAssertNil(response.error)
        let input = try XCTUnwrap(builder.inputBatches.first?.first)
        XCTAssertEqual(input.capabilities, [.list])
        XCTAssertEqual(input.requestedItems.map(\.kind), [
            .password, .apiKey, .certificate, .note, .ssh,
        ])
        XCTAssertEqual(Set(input.requestedItems.map(\.id)), Set([
            stableUUID("password:API:Team/API"),
            stableUUID("api-key:API Key:Team/API"),
            stableUUID("certificate:API Cert:Team/API"),
            stableUUID("note:API Note:Team/API"),
            stableUUID("ssh:API SSH:Team/API"),
        ]))
    }

    func testMissingOrChangedFreshCallerFailsBeforeBatchSave() async throws {
        let providers: [CallerIdentityRevalidationProvider] = [
            { _ in nil },
            { _ in self.humanCallerIdentity },
        ]
        for provider in providers {
            let store = MemoryAgentJITGrantStore()
            let handler = makeHandler(
                store: store,
                callerIdentityRevalidationProvider: provider,
                clock: AgentJITApprovalClockSpy([now, now]).callAsFunction
            )
            let payload = AgentJITPreflightPayload(
                requestedCommand: "exec",
                references: [
                    AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
                ]
            )

            let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

            XCTAssertEqual(response.error?.code, .notAuthorized)
            XCTAssertEqual(store.saveAllCallCount, 0)
        }
    }

    func testFreshListAuthorityChangesFailBeforeBatchSave() async throws {
        let original = listPayload()
        let api = try XCTUnwrap(original.passwords.first { $0.name == "API" })
        let retyped = BridgeListPayload(
            accounts: original.accounts,
            passwords: original.passwords.filter { $0.id != api.id },
            apiKeys: original.apiKeys,
            certificates: original.certificates,
            notes: original.notes + [BridgeNote(
                id: api.id,
                title: api.name,
                folderPath: api.folderPath,
                isFavorite: false,
                isCliEnabled: true,
                isScraped: false,
                createdAt: api.createdAt,
                updatedAt: api.updatedAt
            )],
            sshKeys: original.sshKeys
        )
        let variants = [
            listPayload(replacingPasswords: original.passwords.filter { $0.id != api.id }),
            listPayload(replacingPasswords: original.passwords.map {
                $0.id == api.id ? copyPassword($0, folderPath: "Team/Web") : $0
            }),
            listPayload(replacingPasswords: original.passwords.map {
                $0.id == api.id ? copyPassword($0, isCliEnabled: false) : $0
            }),
            listPayload(replacingPasswords: Array(original.passwords.reversed())),
            retyped,
        ]
        for changed in variants {
            let provider = ListProviderSequence([.success(original), .success(changed)])
            let store = MemoryAgentJITGrantStore()
            let handler = makeHandler(
                store: store,
                listProvider: provider.callAsFunction,
                clock: AgentJITApprovalClockSpy([now, now]).callAsFunction
            )
            let payload = AgentJITPreflightPayload(
                requestedCommand: "list",
                references: [AgentJITPreflightReference(
                    type: "password",
                    query: "",
                    folderPath: "Team/API",
                    isFolderScoped: true
                )]
            )

            let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
                handler,
                body: payload,
                requestedCommand: "list"
            )

            XCTAssertEqual(response.error?.code, .notAuthorized)
            XCTAssertEqual(store.saveAllCallCount, 0)
        }
    }

    func testRenameOnlyDoesNotChangeLocalOrRemoteAuthority() async throws {
        let original = listPayload()
        let api = try XCTUnwrap(original.passwords.first { $0.name == "API" })
        let renamed = listPayload(replacingPasswords: original.passwords.map {
            $0.id == api.id ? copyPassword($0, name: "Renamed API") : $0
        })
        let provider = ListProviderSequence([.success(original), .success(renamed)])
        let builder = RemoteRequestBuilderSpy()
        let store = MemoryAgentJITGrantStore()
        let handler = makeHandler(
            store: store,
            listProvider: provider.callAsFunction,
            requestBuilder: builder,
            clock: AgentJITApprovalClockSpy([now, now]).callAsFunction
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [AgentJITPreflightReference(
                type: "password",
                query: api.id.uuidString,
                folderPath: "Team/API"
            )]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(store.grants.first?.requestedItems.first?.name, "API")
        XCTAssertEqual(store.saveAllCallCount, 1)
    }

    func testFreshListOrGrantLoadFailureFailsBeforeBatchSave() async throws {
        let listProvider = ListProviderSequence([
            .success(listPayload()),
            .failure(AgentJITGrantStoreError.corruptedStore),
        ])
        let listStore = MemoryAgentJITGrantStore()
        let listHandler = makeHandler(
            store: listStore,
            listProvider: listProvider.callAsFunction,
            clock: AgentJITApprovalClockSpy([now, now]).callAsFunction
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API")]
        )

        let listResponse: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            listHandler,
            body: payload
        )
        XCTAssertEqual(listResponse.error?.code, .notAuthorized)
        XCTAssertEqual(listStore.saveAllCallCount, 0)

        let grantStore = MemoryAgentJITGrantStore()
        grantStore.loadErrorOnCall = 2
        let grantHandler = makeHandler(
            store: grantStore,
            clock: AgentJITApprovalClockSpy([now, now]).callAsFunction
        )
        let grantResponse: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            grantHandler,
            body: payload
        )
        XCTAssertEqual(grantResponse.error?.code, .notAuthorized)
        XCTAssertEqual(grantStore.saveAllCallCount, 0)
    }

    func testNewlyCoveringOrRevokedInitiallyCoveringGrantFailsRevalidation() async throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let newlyCoveringStore = MemoryAgentJITGrantStore()
        let newlyCoveringApprover = JITApprovalTracker(result: true)
        newlyCoveringApprover.onRequest = {
            newlyCoveringStore.grants.append(.fixture(
                callerFingerprint: caller,
                folderScope: .folder("Team/API"),
                capabilities: [.exec, .list],
                createdAt: self.now,
                expiresAt: self.now.addingTimeInterval(600)
            ))
        }
        let newlyCoveringHandler = makeHandler(
            store: newlyCoveringStore,
            approver: newlyCoveringApprover,
            clock: AgentJITApprovalClockSpy([now, now]).callAsFunction
        )
        let apiPayload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API")]
        )
        let newlyCovered: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            newlyCoveringHandler,
            body: apiPayload
        )
        XCTAssertEqual(newlyCovered.error?.code, .notAuthorized)
        XCTAssertEqual(newlyCoveringStore.saveAllCallCount, 0)

        let active = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec, .list],
            createdAt: now,
            expiresAt: now.addingTimeInterval(600)
        )
        let revokedStore = MemoryAgentJITGrantStore([active])
        let revokedApprover = JITApprovalTracker(result: true)
        revokedApprover.onRequest = {
            revokedStore.grants[0] = revokedStore.grants[0].copy(revokedAt: self.now)
        }
        let revokedHandler = makeHandler(
            store: revokedStore,
            approver: revokedApprover,
            clock: AgentJITApprovalClockSpy([now, now]).callAsFunction
        )
        let mixedPayload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
                AgentJITPreflightReference(type: "cert", query: "Web Cert", folderPath: "Team/Web"),
            ]
        )
        let revoked: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            revokedHandler,
            body: mixedPayload
        )
        XCTAssertEqual(revoked.error?.code, .notAuthorized)
        XCTAssertEqual(revokedStore.savedBatches.filter { $0.contains { $0.folderScope == .folder("Team/Web") } }, [])
    }

    func testInitiallyCoveringGrantThatExpiresDuringApprovalFailsRevalidation() async throws {
        let restoreTTL = setCLIApprovalTTL(15)
        defer { restoreTTL() }
        let store = MemoryAgentJITGrantStore([.fixture(
            callerFingerprint: callerFingerprint(requestedCommand: "exec"),
            folderScope: .folder("Team/API"),
            capabilities: [.exec, .list],
            createdAt: now.addingTimeInterval(-60),
            expiresAt: now.addingTimeInterval(1)
        )])
        let handler = makeHandler(
            store: store,
            clock: AgentJITApprovalClockSpy([now, now.addingTimeInterval(2)]).callAsFunction
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
                AgentJITPreflightReference(type: "cert", query: "Web Cert", folderPath: "Team/Web"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertEqual(response.error?.code, .notAuthorized)
        XCTAssertEqual(store.grants.count, 1)
        XCTAssertEqual(
            store.savedBatches.filter { $0.contains { $0.folderScope == .folder("Team/Web") } },
            []
        )
    }

    func testConcreteStoreRevokesClosedTerminalGrantBeforePreflightAndDoesNotReuseIt() async throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = AgentJITGrantStore(
            authorityStore: TestAuthorityStore(),
            legacyFileURL: tempDir.appendingPathComponent("grants.json"),
            terminalSessionLiveness: { _ in .closed }
        )
        let existing = AgentJITGrant.fixture(
            callerFingerprint: callerFingerprint(requestedCommand: "exec"),
            folderScope: .folder("Team/API"),
            capabilities: [.exec, .list],
            createdAt: now,
            expiresAt: now.addingTimeInterval(600)
        )
        try store.save(existing)
        let approver = JITApprovalTracker(result: false)
        let handler = makeHandler(
            store: store,
            approver: approver,
            clock: AgentJITApprovalClockSpy([now]).callAsFunction
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API")]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertEqual(response.error?.code, .notAuthorized)
        XCTAssertEqual(approver.requests.count, 1)
        XCTAssertEqual(try store.loadAll().first?.revokedAt, now)
    }

    func testConcreteStoreTerminalClosingDuringApprovalInvalidatesSnapshotWithoutSavingNewGrant() async throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        var liveness = TerminalSessionLiveness.active
        let store = AgentJITGrantStore(
            authorityStore: TestAuthorityStore(),
            legacyFileURL: tempDir.appendingPathComponent("grants.json"),
            terminalSessionLiveness: { _ in liveness }
        )
        let existing = AgentJITGrant.fixture(
            callerFingerprint: callerFingerprint(requestedCommand: "exec"),
            folderScope: .folder("Team/API"),
            capabilities: [.exec, .list],
            createdAt: now,
            expiresAt: now.addingTimeInterval(600)
        )
        try store.save(existing)
        let approver = JITApprovalTracker(result: true)
        approver.onRequest = { liveness = .closed }
        let handler = makeHandler(
            store: store,
            approver: approver,
            clock: AgentJITApprovalClockSpy([now, now]).callAsFunction
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
                AgentJITPreflightReference(type: "cert", query: "Web Cert", folderPath: "Team/Web"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertEqual(response.error?.code, .notAuthorized)
        let stored = try store.loadAll()
        XCTAssertEqual(stored.count, 1)
        XCTAssertEqual(stored.first?.id, existing.id)
        XCTAssertEqual(stored.first?.revokedAt, now)
    }

    func testConcreteStoreActiveReuseUpdatesLastUsedAndMergesRenamedItemMetadata() async throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let store = AgentJITGrantStore(
            authorityStore: TestAuthorityStore(),
            legacyFileURL: tempDir.appendingPathComponent("grants.json"),
            terminalSessionLiveness: { _ in .active }
        )
        let existing = AgentJITGrant.fixture(
            callerFingerprint: callerFingerprint(requestedCommand: "exec"),
            folderScope: .folder("Team/API"),
            capabilities: [.exec, .list],
            createdAt: now.addingTimeInterval(-60),
            expiresAt: now.addingTimeInterval(600)
        )
        try store.save(existing)
        let original = listPayload()
        let api = try XCTUnwrap(original.passwords.first { $0.name == "API" })
        let renamed = listPayload(replacingPasswords: original.passwords.map {
            $0.id == api.id ? copyPassword($0, name: "Renamed API") : $0
        })
        let approver = JITApprovalTracker(result: false)
        let handler = makeHandler(
            store: store,
            approver: approver,
            listProvider: { renamed },
            clock: AgentJITApprovalClockSpy([now]).callAsFunction
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [AgentJITPreflightReference(
                type: "password",
                query: api.id.uuidString,
                folderPath: "Team/API"
            )]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.grantIDs, [existing.id])
        XCTAssertEqual(approver.requests, [])
        let reused = try XCTUnwrap(try store.loadAll().first)
        XCTAssertEqual(reused.lastUsedAt, now)
        XCTAssertEqual(reused.requestedItems.map(\.name), ["Renamed API"])
    }

    func testActiveGrantReuseSucceedsWhenRequestedItemMetadataSaveFails() async throws {
        let existing = AgentJITGrant.fixture(
            callerFingerprint: callerFingerprint(requestedCommand: "exec"),
            folderScope: .folder("Team/API"),
            capabilities: [.exec, .list],
            createdAt: now.addingTimeInterval(-60),
            expiresAt: now.addingTimeInterval(600)
        )
        let store = MemoryAgentJITGrantStore([existing])
        store.saveAllError = AgentJITGrantStoreError.corruptedStore
        let approver = JITApprovalTracker(result: false)
        let handler = makeHandler(
            store: store,
            approver: approver,
            clock: AgentJITApprovalClockSpy([now]).callAsFunction
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.grantIDs, [existing.id])
        XCTAssertEqual(approver.requests, [])
        XCTAssertEqual(store.saveAllCallCount, 1)
    }

    func testOversizedProjectionWithNoRemoteBuilderKeepsMacApprovalPath() async throws {
        let oversizedList = listPayloadWithRootPasswords(count: 1_025)
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(
            store: store,
            approver: approver,
            listProvider: { oversizedList },
            requestBuilder: nil,
            clock: AgentJITApprovalClockSpy([now, now]).callAsFunction
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [AgentJITPreflightReference(
                type: "password",
                query: "",
                folderPath: nil,
                isFolderScoped: true
            )]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            handler,
            body: payload,
            requestedCommand: "list"
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(approver.requests.first?.remoteRequests, [])
        XCTAssertEqual(store.grants.first?.requestedItems.count, 1_025)
    }

    func testOversizedRemoteProjectionKeepsMacPathButDeniesPairedIPhone() async throws {
        let oversizedList = listPayloadWithRootPasswords(count: 1_025)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [AgentJITPreflightReference(
                type: "password",
                query: "",
                folderPath: nil,
                isFolderScoped: true
            )]
        )

        let macBuilder = RemoteRequestBuilderSpy()
        let macApprover = JITApprovalTracker(result: true)
        let macStore = MemoryAgentJITGrantStore()
        let macHandler = makeHandler(
            store: macStore,
            approver: macApprover,
            listProvider: { oversizedList },
            requestBuilder: macBuilder,
            clock: AgentJITApprovalClockSpy([now, now]).callAsFunction
        )
        let macResponse: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            macHandler,
            body: payload,
            requestedCommand: "list"
        )
        XCTAssertNil(macResponse.error)
        XCTAssertEqual(macBuilder.inputBatches, [])
        XCTAssertEqual(macApprover.requests.first?.remoteRequests, [])
        XCTAssertEqual(macStore.grants.first?.requestedItems.count, 1_025)

        let remoteBuilder = RemoteRequestBuilderSpy()
        let remoteSource = try RemoteJITApprovalPairedIPhoneSource(
            pairingGenerationID: remoteBuilder.pairing.pairingGenerationID,
            signingKeyFingerprint: remoteBuilder.pairing.iphoneSigningKeyFingerprint
        )
        let remoteStore = MemoryAgentJITGrantStore()
        let remoteHandler = makeHandler(
            store: remoteStore,
            approver: JITApprovalTracker(outcome: .approved(source: .pairedIPhone(remoteSource))),
            listProvider: { oversizedList },
            requestBuilder: remoteBuilder,
            clock: AgentJITApprovalClockSpy([now]).callAsFunction
        )
        let remoteResponse: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            remoteHandler,
            body: payload,
            requestedCommand: "list"
        )
        XCTAssertEqual(remoteResponse.error?.code, .notAuthorized)
        XCTAssertEqual(remoteStore.saveAllCallCount, 0)
    }

    func testBatchSaveFailureProducesNoApprovalAudit() async throws {
        let store = MemoryAgentJITGrantStore()
        store.saveAllError = AgentJITGrantStoreError.corruptedStore
        let (auditLogger, auditURL, tempDir) = try makeAuditLogger()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let handler = makeHandler(
            store: store,
            auditLogger: auditLogger,
            clock: AgentJITApprovalClockSpy([now, now]).callAsFunction
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API")]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertEqual(response.error?.code, .appUnavailable)
        XCTAssertEqual(store.grants, [])
        XCTAssertFalse(FileManager.default.fileExists(atPath: auditURL.path))
    }

    override func tearDown() {
        for directory in isolatedAuditDirectories {
            try? FileManager.default.removeItem(at: directory)
        }
        isolatedAuditDirectories.removeAll()
        super.tearDown()
    }

    func testPreflightGroupsRootReferencesIntoOneGrant() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "RootOne", folderPath: nil),
                AgentJITPreflightReference(type: "note", query: "RootNote", folderPath: nil),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.grantIDs.count, 1)
        XCTAssertEqual(store.grants.count, 1)
        XCTAssertEqual(store.grants.first?.folderScope, .root)
        XCTAssertEqual(store.grants.first?.capabilities, [.exec, .list])
        XCTAssertEqual(store.grants.first?.approvedBy, "biometric")
        XCTAssertEqual(store.grants.first?.agentName, "Claude")
        XCTAssertEqual(approver.requests.map(\.command), [.agentJITPreflight])
        XCTAssertEqual(approver.requests.map(\.remoteRequests), [[]])
        XCTAssertEqual(approver.requests.first?.itemLabel, "Root")
        XCTAssertEqual(approver.requests.first?.prompt.contains(
            "Allow Claude temporary access to CLI-enabled password, API key, certificate, and note items in Root only"
        ), true)
        XCTAssertEqual(approver.requests.first?.prompt.contains(
            "plus scoped list access."
        ), true)
        XCTAssertEqual(approver.requests.first?.prompt.contains("all folders"), false)
    }

    func testListPreflightCreatesListOnlyGrant() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "",
                    folderPath: "Team/API",
                    isFolderScoped: true
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            handler,
            body: payload,
            requestedCommand: "list"
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.grantIDs.count, 1)
        XCTAssertEqual(store.grants.count, 1)
        XCTAssertEqual(store.grants.first?.folderScope, .folder("Team/API"))
        XCTAssertEqual(store.grants.first?.capabilities, [.list])
        XCTAssertEqual(store.grants.first?.requestedItems.map(\.name).sorted(), ["API", "API Nested", "Shared"])
        XCTAssertEqual(approver.requests.map(\.command), [.agentJITPreflight])
        XCTAssertEqual(approver.requests.first?.itemLabel, "Team/API")
        XCTAssertEqual(approver.requests.first?.prompt.contains("temporary scoped list access"), true)
    }

    func testBroadListPreflightApprovesOnceForAllResolvedFolderGrants() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "",
                    folderPath: nil,
                    isFolderScoped: false
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            handler,
            body: payload,
            requestedCommand: "list"
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(approver.requests.count, 1)
        XCTAssertEqual(approver.requests.first?.command, .agentJITPreflight)
        XCTAssertEqual(approver.requests.first?.itemLabel, "All folders")
        XCTAssertEqual(
            store.grants.map(\.folderScope),
            [.root, .folder("Team/API"), .folder("Team/Web")]
        )
        XCTAssertEqual(store.grants.map(\.capabilities), Array(repeating: [.list], count: 3))
        XCTAssertEqual(response.payload?.grantIDs.count, 3)
        let apiGrant = try XCTUnwrap(store.grants.first { $0.folderScope == .folder("Team/API") })
        XCTAssertEqual(Set(apiGrant.requestedItems.compactMap(\.folderPath)), ["Team/API", "Team/API/Prod"])
    }

    func testListPreflightSupportsSSHMetadataScope() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [
                AgentJITPreflightReference(
                    type: "ssh",
                    query: "",
                    folderPath: "Team/API",
                    isFolderScoped: true
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            handler,
            body: payload,
            requestedCommand: "list"
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.grantIDs.count, 1)
        XCTAssertEqual(store.grants.first?.capabilities, [.list])
        XCTAssertEqual(store.grants.first?.requestedItems.map(\.name).sorted(), ["API SSH", "Nested SSH"])
    }

    func testListPreflightSupportsAPIKeyMetadataScope() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [
                AgentJITPreflightReference(
                    type: "api-key",
                    query: "",
                    folderPath: "Team/API",
                    isFolderScoped: true
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            handler,
            body: payload,
            requestedCommand: "list"
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.grantIDs.count, 1)
        XCTAssertEqual(store.grants.first?.capabilities, [.list])
        XCTAssertEqual(store.grants.first?.requestedItems.map(\.type), ["api-key"])
        XCTAssertEqual(store.grants.first?.requestedItems.map(\.name), ["API Key"])
    }


    func testPreflightRecordsAuditForCreatedGrant() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let (auditLogger, auditURL, tempDir) = try makeAuditLogger()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let handler = makeHandler(store: store, approver: approver, auditLogger: auditLogger)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
            ],
            environmentScope: .named("Production")
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        let grant = try XCTUnwrap(store.grants.first)
        let records = try auditRecords(at: auditURL)
        XCTAssertNil(response.error)
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].command, .agentJITPreflight)
        XCTAssertEqual(records[0].itemId, grant.id.uuidString)
        XCTAssertEqual(records[0].itemName, "Team/API")
        XCTAssertEqual(records[0].approvedBy, "biometric")
        XCTAssertEqual(records[0].requestedCommand, "exec")
        XCTAssertEqual(records[0].agentJITGrantID, grant.id)
        XCTAssertEqual(records[0].environmentScope, .named("Production"))
        XCTAssertTrue(approver.requests[0].prompt.contains("Environment: Production."))
    }

    func testMacPanelPreflightAttributesStoredGrantAndAudit() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(outcome: .approved(source: .macPanel))
        let (auditLogger, auditURL, tempDir) = try makeAuditLogger()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let handler = makeHandler(store: store, approver: approver, auditLogger: auditLogger)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        let grant = try XCTUnwrap(store.grants.first)
        let records = try auditRecords(at: auditURL)
        XCTAssertNil(response.error)
        XCTAssertEqual(grant.approvedBy, "mac-panel")
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].approvedBy, "mac-panel")
        XCTAssertEqual(records[0].agentJITGrantID, grant.id)
    }

    func testPreflightStoresAgentNameWithIDEHost() async throws {
        let store = MemoryAgentJITGrantStore()
        let handler = makeHandler(
            store: store,
            approver: JITApprovalTracker(result: true),
            callerIdentity: claudeViaVSCodeCallerIdentity
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(store.grants.first?.agentName, "Claude via Visual Studio Code")
    }

    func testPreflightStoresResolvedVaultItemsOnGrant() async throws {
        let store = MemoryAgentJITGrantStore()
        let handler = makeHandler(
            store: store,
            approver: JITApprovalTracker(result: true)
        )
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
                AgentJITPreflightReference(type: "api-key", query: "API Key", folderPath: "Team/API"),
                AgentJITPreflightReference(type: "note", query: "API Note", folderPath: "Team/API"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        let grant = try XCTUnwrap(store.grants.first)
        XCTAssertEqual(grant.requestedItems.map(\.type), ["password", "api-key", "note"])
        XCTAssertEqual(grant.requestedItems.map(\.name), ["API", "API Key", "API Note"])
        XCTAssertEqual(grant.requestedItems.map(\.folderPath), ["Team/API", "Team/API", "Team/API"])
    }

    func testPreflightRecordsAuditForDeniedApproval() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: false)
        let (auditLogger, auditURL, tempDir) = try makeAuditLogger()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let handler = makeHandler(store: store, approver: approver, auditLogger: auditLogger)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        let records = try auditRecords(at: auditURL)
        XCTAssertEqual(response.error?.code, .notAuthorized)
        XCTAssertEqual(store.grants, [])
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].command, .agentJITPreflight)
        XCTAssertEqual(records[0].itemId, "Team/API")
        XCTAssertEqual(records[0].itemName, "Team/API")
        XCTAssertEqual(records[0].approvedBy, "denied:biometric")
        XCTAssertEqual(records[0].requestedCommand, "exec")
        XCTAssertNil(records[0].agentJITGrantID)
    }

    func testPreflightKeepsSiblingScopesSeparate() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
                AgentJITPreflightReference(type: "cert", query: "Web Cert", folderPath: "Team/Web"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.grantIDs.count, 2)
        XCTAssertEqual(Set(store.grants.map(\.folderScope)), [.folder("Team/API"), .folder("Team/Web")])
        XCTAssertEqual(approver.requests.map(\.itemLabel), ["Team/API", "Team/Web"])
        XCTAssertEqual(approver.requests.first?.prompt.contains(
            "Allow Claude temporary access to CLI-enabled password, API key, certificate, and note items " +
                "in folder 'Team/API' and its descendants"
        ), true)
    }

    func testPreflightDisambiguatesDuplicateNamesByRequestedFolder() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "Shared", folderPath: "Team/API"),
                AgentJITPreflightReference(type: "password", query: "Shared", folderPath: "Team/Web"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(Set(store.grants.map(\.folderScope)), [.folder("Team/API"), .folder("Team/Web")])
    }

    func testPreflightRootRequestDoesNotMatchNonRootDuplicate() async throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore())
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "Shared", folderPath: nil),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertEqual(response.error?.code, .notFound)
        XCTAssertNil(response.payload)
    }

    func testPreflightUnscopedRequestGrantsResolvedItemFolder() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "API",
                    folderPath: nil,
                    isFolderScoped: false
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(store.grants.map(\.folderScope), [.folder("Team/API")])
        XCTAssertEqual(approver.requests.map(\.itemLabel), ["Team/API"])
    }

    func testPreflightDescendantReusesActiveAncestorGrantWithoutApproval() async throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec, .list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let store = MemoryAgentJITGrantStore([grant])
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "API Nested",
                    folderPath: nil,
                    isFolderScoped: false
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.grantIDs, [grant.id])
        XCTAssertEqual(store.grants.count, 1)
        XCTAssertEqual(approver.requests, [])
    }

    func testPreflightReusesExactItemGrantWhenRequestOmitsEnvironmentScope() async throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let original = listPayload()
        let nested = try XCTUnwrap(original.passwords.first { $0.name == "API Nested" })
        let tagged = listPayload(replacingPasswords: original.passwords.map {
            $0.id == nested.id
                ? BridgePassword(
                    id: $0.id,
                    name: $0.name,
                    username: $0.username,
                    website: $0.website,
                    folderPath: $0.folderPath,
                    isFavorite: $0.isFavorite,
                    isCliEnabled: $0.isCliEnabled,
                    isScraped: $0.isScraped,
                    createdAt: $0.createdAt,
                    updatedAt: $0.updatedAt,
                    environments: ["validation-x"]
                )
                : $0
        })
        let grant = AgentJITGrant(
            id: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
            agentName: "Codex",
            callerFingerprint: caller,
            folderScope: .folder("Team/API/Prod"),
            capabilities: [.exec, .list],
            createdAt: Date(),
            expiresAt: Date().addingTimeInterval(60),
            revokedAt: nil,
            lastUsedAt: nil,
            requestedItems: [
                AgentJITGrantItemReference(
                    type: "password",
                    id: nested.id.uuidString,
                    name: nested.name,
                    folderPath: nested.folderPath
                ),
            ],
            approvedBy: "biometric",
            environmentScope: .named("validation-x")
        )
        let store = MemoryAgentJITGrantStore([grant])
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver, listProvider: { tagged })
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "API Nested",
                    folderPath: nil,
                    isFolderScoped: false
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.grantIDs, [grant.id])
        XCTAssertEqual(store.grants.count, 1)
        XCTAssertEqual(approver.requests, [])
    }

    func testPreflightExplainsSeparateExecCapabilityForCoveredDescendant() async throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder(" Team//API "),
            capabilities: [.list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let store = MemoryAgentJITGrantStore([grant])
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "API Nested",
                    folderPath: "Team/API/Prod"
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        let prompt = try XCTUnwrap(approver.requests.first?.prompt)
        XCTAssertTrue(prompt.contains("Separate approval required"))
        XCTAssertTrue(prompt.contains("allows list access"))
        XCTAssertTrue(prompt.contains("exec capability requires separate approval"))
        XCTAssertTrue(prompt.contains("Team/API and its descendants"))
        XCTAssertFalse(prompt.contains("API Nested"))
    }

    func testPreflightExplainsUnrelatedFolderScope() async throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec, .list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let store = MemoryAgentJITGrantStore([grant])
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "cert", query: "Web Cert", folderPath: "Team/Web"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        let prompt = try XCTUnwrap(approver.requests.first?.prompt)
        XCTAssertTrue(prompt.contains("Separate approval required"))
        XCTAssertTrue(prompt.contains("Team/Web and its descendants"))
        XCTAssertTrue(prompt.contains("Team/API and its descendants"))
        XCTAssertTrue(prompt.contains("unrelated folder trees are isolated"))
        XCTAssertFalse(prompt.contains("Web Cert"))
    }

    func testPreflightExplainsBroaderAncestorScope() async throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API/Prod"),
            capabilities: [.exec, .list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let store = MemoryAgentJITGrantStore([grant])
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "API Nested",
                    folderPath: "Team/API",
                    isFolderScoped: true
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        let prompt = try XCTUnwrap(approver.requests.first?.prompt)
        XCTAssertTrue(prompt.hasPrefix("Separate approval required"))
        XCTAssertTrue(prompt.contains(
            "requested scope Team/API and its descendants is broader than the active grant scope " +
                "Team/API/Prod and its descendants"
        ))
        XCTAssertTrue(prompt.contains("extends access beyond the active subtree to additional descendants"))
        XCTAssertFalse(prompt.contains("unrelated"))
        XCTAssertFalse(prompt.contains("API Nested"))
    }

    func testBroadListPromptExplainsOnlyNewUnrelatedScopes() async throws {
        let caller = callerFingerprint(requestedCommand: "list")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let store = MemoryAgentJITGrantStore([grant])
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "",
                    folderPath: nil,
                    isFolderScoped: false
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            handler,
            body: payload,
            requestedCommand: "list"
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(approver.requests.count, 1)
        let prompt = try XCTUnwrap(approver.requests.first?.prompt)
        XCTAssertTrue(prompt.contains("This request adds folder scopes Root only, Team/Web and its descendants"))
        XCTAssertTrue(prompt.contains("The active grant covers Team/API and its descendants"))
        XCTAssertTrue(prompt.contains("unrelated folder trees are isolated"))
        XCTAssertFalse(prompt.contains("RootOne"))
        XCTAssertFalse(prompt.contains("API Nested"))
        XCTAssertFalse(prompt.contains("Shared"))
        XCTAssertEqual(
            Set(store.grants.map(\.folderScope)),
            [.root, .folder("Team/API"), .folder("Team/Web")]
        )
    }

    func testBroadListPromptDistinguishesBroaderAncestorAndUncoveredScopes() async throws {
        let caller = callerFingerprint(requestedCommand: "list")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API/Prod"),
            capabilities: [.list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let store = MemoryAgentJITGrantStore([grant])
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "",
                    folderPath: nil,
                    isFolderScoped: false
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(
            handler,
            body: payload,
            requestedCommand: "list"
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(approver.requests.count, 1)
        let prompt = try XCTUnwrap(approver.requests.first?.prompt)
        XCTAssertTrue(prompt.hasPrefix("Separate approval required"))
        XCTAssertTrue(prompt.contains(
            "Broader ancestor expansions Team/API and its descendants extend access beyond active child subtrees " +
                "Team/API/Prod and its descendants to additional descendants"
        ))
        XCTAssertTrue(prompt.contains(
            "Separate uncovered scopes Root only, Team/Web and its descendants require approval because unrelated " +
                "folder trees are isolated"
        ))
        XCTAssertTrue(prompt.contains("The active grant covers Team/API/Prod and its descendants"))
        XCTAssertFalse(prompt.contains("RootOne"))
        XCTAssertFalse(prompt.contains("API Nested"))
        XCTAssertFalse(prompt.contains("Shared"))
    }

    func testExpiredGrantUsesOrdinaryFirstApprovalWording() async throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.list],
            expiresAt: Date().addingTimeInterval(-60)
        )
        let store = MemoryAgentJITGrantStore([grant])
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API Nested", folderPath: "Team/API/Prod"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        let prompt = try XCTUnwrap(approver.requests.first?.prompt)
        XCTAssertTrue(prompt.contains("folder 'Team/API/Prod' and its descendants"))
        XCTAssertFalse(prompt.contains("Separate approval required"))
        XCTAssertFalse(prompt.contains("API Nested"))
    }

    func testPreflightFolderScopeReferenceIncludesDescendantItems() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "",
                    folderPath: "Team/API",
                    isFolderScoped: true
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(store.grants.map(\.folderScope), [.folder("Team/API")])
        XCTAssertEqual(store.grants.first?.requestedItems.map(\.name).sorted(), ["API", "API Nested", "Shared"])
        XCTAssertEqual(approver.requests.map(\.itemLabel), ["Team/API"])
    }

    func testNamedQueryInDescendantUsesRequestedAncestorScope() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "API Nested",
                    folderPath: "Team/API",
                    isFolderScoped: true
                ),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertNil(response.error)
        XCTAssertEqual(response.payload?.grantIDs.count, 1)
        XCTAssertEqual(store.grants.map(\.folderScope), [.folder("Team/API")])
        XCTAssertEqual(store.grants.first?.requestedItems.map(\.name), ["API Nested"])
        XCTAssertEqual(approver.requests.map(\.itemLabel), ["Team/API"])
    }

    func testPreflightMismatchedFolderFailsClosed() async throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore())
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/Web"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertEqual(response.error?.code, .notFound)
        XCTAssertNil(response.payload)
    }

    func testExecGrantMatchesExactFolder() throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            expiresAt: Date().addingTimeInterval(60)
        )
        let handler = makeHandler(store: MemoryAgentJITGrantStore([grant]))
        let request = makeRequest(type: .getPassword, requestedCommand: "exec")

        let result = try handler.agentJITGrant(capability: .exec, itemFolderPath: "Team/API", request: request)

        XCTAssertEqual(result?.id, grant.id)
    }

    func testAgentRuntimeContextDoesNotParticipateInGrantMatching() throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            expiresAt: Date().addingTimeInterval(60)
        )
        let handler = makeHandler(store: MemoryAgentJITGrantStore([grant]))
        let request = makeRequest(
            type: .getPassword,
            requestedCommand: "exec",
            agentRuntimeContext: AgentRuntimeContext(
                platform: "codex",
                sessionID: "new-session",
                turnID: "new-turn",
                agentID: "different-agent",
                agentType: "different",
                toolUseID: nil
            )
        )

        let result = try handler.agentJITGrant(capability: .exec, itemFolderPath: "Team/API", request: request)

        XCTAssertEqual(result?.id, grant.id)
    }


    func testExecGrantAllowsDescendantFolder() throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            expiresAt: Date().addingTimeInterval(60)
        )
        let handler = makeHandler(store: MemoryAgentJITGrantStore([grant]))
        let request = makeRequest(type: .getPassword, requestedCommand: "exec")

        let result = try handler.agentJITGrant(capability: .exec, itemFolderPath: "Team/API/Prod", request: request)

        XCTAssertEqual(result?.id, grant.id)
    }

    func testExecGrantRejectsListRequestedCommand() throws {
        let caller = callerFingerprint(requestedCommand: "list")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            expiresAt: Date().addingTimeInterval(60)
        )
        let handler = makeHandler(store: MemoryAgentJITGrantStore([grant]))
        let request = makeRequest(type: .getPassword, requestedCommand: "list")

        let result = try handler.agentJITGrant(capability: .exec, itemFolderPath: "Team/API", request: request)

        XCTAssertNil(result)
    }

    func testKnownAgentCannotReuseValidInteractiveSession() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore())
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: execContext(requestedCommand: "exec").sessionScope,
            origin: XPCRequestHandler.sessionOrigin(from: callerIdentity)
        )
        let request = makeRequest(type: .getPassword, requestedCommand: "exec", sessionToken: session.sessionToken)

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(
            decision,
            .denied(
                code: .policyDenied,
                message: "Agent exec secret reads require a valid JIT preflight grant for this item scope."
            )
        )
    }

    func testHumanExecSecretReadWithoutJITKeepsSessionBehavior() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: humanCallerIdentity)
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: execContext(requestedCommand: "exec").sessionScope,
            origin: XPCRequestHandler.sessionOrigin(from: humanCallerIdentity)
        )
        let request = makeRequest(type: .getPassword, requestedCommand: "exec", sessionToken: session.sessionToken)

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .allowed(approvedBy: "session", needsApproval: false, agentJITGrantID: nil))
    }

    func testIDEHelperExecSecretReadWithValidSessionCannotReuseHumanAuthority() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: ideHelperCallerIdentity)
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: execContext(requestedCommand: "exec").sessionScope,
            origin: XPCRequestHandler.sessionOrigin(from: ideHelperCallerIdentity)
        )
        let request = makeRequest(type: .getPassword, requestedCommand: "exec", sessionToken: session.sessionToken)

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(
            decision,
            .denied(
                code: .policyDenied,
                message: "Agent exec secret reads require a valid JIT preflight grant for this item scope."
            )
        )
    }

    func testIDEHelperTTYAncestryWithoutSessionRemainsAgentClassified() {
        let request = makeRequest(type: .getPassword, requestedCommand: "exec")

        XCTAssertTrue(XPCRequestHandler.isAgentJITCaller(
            request: request,
            callerIdentity: ideHelperCallerIdentity
        ))
    }

    func testIDEHelperTTYWithCurrentMatchingSessionRemainsAgentClassified() throws {
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: execContext(requestedCommand: "exec").sessionScope,
            origin: XPCRequestHandler.sessionOrigin(from: ideHelperCallerIdentity)
        )
        let request = makeRequest(
            type: .getPassword,
            requestedCommand: "exec",
            sessionToken: session.sessionToken
        )

        XCTAssertTrue(XPCRequestHandler.isAgentJITCaller(
            request: request,
            callerIdentity: ideHelperCallerIdentity
        ))
    }

    func testIDEHelperTTYWithCurrentSessionAndRuntimeContextRemainsAgentClassified() throws {
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: execContext(requestedCommand: "exec").sessionScope
        )
        let request = makeRequest(
            type: .getPassword,
            requestedCommand: "exec",
            sessionToken: session.sessionToken,
            agentRuntimeContext: agentRuntimeContext()
        )

        XCTAssertTrue(XPCRequestHandler.isAgentJITCaller(
            request: request,
            callerIdentity: ideHelperCallerIdentity
        ))
    }

    func testIDEHelperNoninteractiveWithCurrentSessionRemainsAgentClassified() throws {
        let context = nonInteractiveExecContext()
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: context.sessionScope
        )
        let request = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "",
            options: .init(field: nil, copy: false),
            context: context,
            sessionToken: session.sessionToken
        )

        XCTAssertTrue(XPCRequestHandler.isAgentJITCaller(
            request: request,
            callerIdentity: ideHelperCallerIdentity
        ))
    }

    func testIDEHelperExecSecretReadWithoutSessionRequiresJIT() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: ideHelperCallerIdentity)
        let request = makeRequest(type: .getPassword, requestedCommand: "exec")

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(
            decision,
            .denied(
                code: .policyDenied,
                message: "Agent exec secret reads require a valid JIT preflight grant for this item scope."
            )
        )
    }

    func testIDEHelperRedirectedStdoutExecSecretReadRequiresJIT() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: ideHelperCallerIdentity)
        let request = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "",
            options: .init(field: nil, copy: false),
            context: redirectedExecContext()
        )

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(
            decision,
            .denied(
                code: .policyDenied,
                message: "Agent exec secret reads require a valid JIT preflight grant for this item scope."
            )
        )
    }

    func testIDEHelperRedirectedStdoutWithRuntimeContextRemainsJITOnly() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: ideHelperCallerIdentity)
        var context = redirectedExecContext()
        context = BridgeContext(
            isTTY: context.isTTY,
            isPiped: context.isPiped,
            isSSH: context.isSSH,
            isCI: context.isCI,
            timestamp: context.timestamp,
            requestedCommand: context.requestedCommand,
            sessionScope: context.sessionScope,
            workingDirectory: context.workingDirectory,
            agentRuntimeContext: agentRuntimeContext()
        )
        let request = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "",
            options: .init(field: nil, copy: false),
            context: context
        )

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .denied(
            code: .policyDenied,
            message: "Agent exec secret reads require a valid JIT preflight grant for this item scope."
        ))
    }

    func testAgentRuntimeContextExecSecretReadIgnoresSessionOverride() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: ideHelperCallerIdentity)
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: execContext(requestedCommand: "exec").sessionScope
        )
        let request = makeRequest(
            type: .getPassword,
            requestedCommand: "exec",
            sessionToken: session.sessionToken,
            agentRuntimeContext: AgentRuntimeContext(
                platform: "codex",
                sessionID: "s1",
                turnID: nil,
                agentID: nil,
                agentType: nil,
                toolUseID: nil
            )
        )

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .denied(
            code: .policyDenied,
            message: "Agent exec secret reads require a valid JIT preflight grant for this item scope."
        ))
    }

    func testIDEHelperNonInteractiveExecSecretReadFailsClosedEvenWithSession() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: ideHelperCallerIdentity)
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: nonInteractiveExecContext().sessionScope
        )
        let request = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "",
            options: .init(field: nil, copy: false),
            context: nonInteractiveExecContext(),
            sessionToken: session.sessionToken
        )

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .denied(
            code: .policyDenied,
            message: "Agent exec secret reads require a valid JIT preflight grant for this item scope."
        ))
    }

    func testNonInteractiveAgenticExecSecretReadFailsClosed() throws {
        // A piped (non-interactive) agent with agentic ancestry and no JIT grant must fail closed
        // even though it presents no agentRuntimeContext — the isTTY==false path classifies it as agent.
        let handler = makeHandler(store: MemoryAgentJITGrantStore())  // default caller = Claude parent (agentic)
        let request = BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "",
            options: .init(field: nil, copy: false),
            context: BridgeContext(
                isTTY: false,
                isPiped: true,
                isSSH: false,
                isCI: false,
                timestamp: now,
                requestedCommand: "exec",
                sessionScope: execContext(requestedCommand: "exec").sessionScope,
                workingDirectory: "/tmp/project"
            )
        )

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .denied(
            code: .policyDenied,
            message: "Agent exec secret reads require a valid JIT preflight grant for this item scope."
        ))
    }

    func testExecSecretReadWithJITGrantCarriesGrantID() throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            expiresAt: Date().addingTimeInterval(60)
        )
        let handler = makeHandler(store: MemoryAgentJITGrantStore([grant]))
        // A confirmed agent (agentRuntimeContext) stays on the JIT path regardless of the TTY, so
        // the grant is consulted and its ID flows through. The runtime context does not participate
        // in grant matching, so the fixture grant still resolves.
        let request = makeRequest(
            type: .getPassword,
            requestedCommand: "exec",
            agentRuntimeContext: agentRuntimeContext()
        )

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .allowed(approvedBy: "jit", needsApproval: false, agentJITGrantID: grant.id))
    }

    func testJITSecretReadAuditInfersEnvironmentFromGrant() throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            expiresAt: Date().addingTimeInterval(60),
            environmentScope: .named("Production")
        )
        let (auditLogger, auditURL, tempDir) = try makeAuditLogger()
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let handler = makeHandler(
            store: MemoryAgentJITGrantStore([grant]),
            auditLogger: auditLogger
        )

        handler.recordAudit(
            command: .getPassword,
            itemId: "item-1",
            approvedBy: "jit",
            caller: callerIdentity,
            requestedCommand: "exec",
            agentJITGrantID: grant.id
        )

        XCTAssertEqual(try auditRecords(at: auditURL).first?.environmentScope, .named("Production"))
    }

    func testAPIKeySecretReadUsesPasswordJITDecisionRules() throws {
        let directHandler = makeHandler(store: MemoryAgentJITGrantStore())
        // A confirmed agent (agentRuntimeContext) keeps the direct "get" on the JIT path so the
        // "authsia get is not allowed" denial is still exercised. Without it, ancestry remains
        // agentic, but stdin-TTY/no-runtime separately permits biometric bootstrap; that eligibility
        // is not human-session authorization.
        let directRequest = makeRequest(
            type: .getAPIKey,
            requestedCommand: "get",
            agentRuntimeContext: agentRuntimeContext()
        )

        let directDecision = directHandler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: directRequest,
            bypassApproval: false
        )

        XCTAssertEqual(directDecision, .denied(
            code: .policyDenied,
            message: "Agent JIT grants do not allow authsia get. Use authsia exec with an approved JIT grant to inject secrets into a command."
        ))

        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.exec],
            expiresAt: Date().addingTimeInterval(60)
        )
        let execHandler = makeHandler(store: MemoryAgentJITGrantStore([grant]))
        let execRequest = makeRequest(
            type: .getAPIKey,
            requestedCommand: "exec",
            agentRuntimeContext: agentRuntimeContext()
        )

        let execDecision = execHandler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: execRequest,
            bypassApproval: false
        )

        XCTAssertEqual(execDecision, .allowed(approvedBy: "jit", needsApproval: false, agentJITGrantID: grant.id))
    }

    func testAgentDirectSecretReadCannotReuseValidInteractiveSession() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore())
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: execContext(requestedCommand: "get").sessionScope,
            origin: XPCRequestHandler.sessionOrigin(from: callerIdentity)
        )
        let request = makeRequest(type: .getPassword, requestedCommand: "get", sessionToken: session.sessionToken)

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(
            decision,
            .denied(
                code: .policyDenied,
                message: "Agent JIT grants do not allow authsia get. Use authsia exec with an approved JIT grant to inject secrets into a command."
            )
        )
    }

    func testAgentDirectSecretReadWithRuntimeContextFailsClosed() throws {
        // A confirmed agent (agentRuntimeContext) running `authsia get` stays on the JIT path and
        // is denied — direct secret reads are never allowed for agents. Without runtime context,
        // ancestry remains agentic, while stdin-TTY/no-runtime separately allows only biometric
        // bootstrap and does not establish a human session.
        let handler = makeHandler(store: MemoryAgentJITGrantStore())
        let request = makeRequest(
            type: .getPassword,
            requestedCommand: "get",
            agentRuntimeContext: agentRuntimeContext()
        )

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .denied(
            code: .policyDenied,
            message: "Agent JIT grants do not allow authsia get. Use authsia exec with an approved JIT grant to inject secrets into a command."
        ))
    }

    func testHumanDirectSecretReadWithoutJITKeepsSessionBehavior() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: humanCallerIdentity)
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: execContext(requestedCommand: "get").sessionScope,
            origin: XPCRequestHandler.sessionOrigin(from: humanCallerIdentity)
        )
        let request = makeRequest(type: .getPassword, requestedCommand: "get", sessionToken: session.sessionToken)

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .allowed(approvedBy: "session", needsApproval: false, agentJITGrantID: nil))
    }

    func testVSCodeTerminalDirectOTPReadWithoutJITFailsClosed() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: vscodeTerminalCallerIdentity)
        let request = makeRequest(type: .getOTP, requestedCommand: "get")

        let decision = handler.unsupportedAgentJITSecretReadDecision(
            request: request,
            itemKind: "otp"
        )

        XCTAssertEqual(
            decision,
            .denied(
                code: .policyDenied,
                message: "Agent JIT grants do not allow authsia get. Use authsia exec with an approved JIT grant to inject secrets into a command."
            )
        )
    }

    func testAgentExecOTPAndSSHReadsFailClosedWithoutJITSupport() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore())
        // A confirmed agent (agentRuntimeContext) stays agentic regardless of the interactive TTY,
        // so exec OTP/SSH reads keep hitting the "not supported" denial. Without runtime context,
        // ancestry remains agentic; stdin-TTY/no-runtime separately permits the biometric bootstrap
        // path and is not session authorization.
        let request = makeRequest(
            type: .getOTP,
            requestedCommand: "exec",
            agentRuntimeContext: agentRuntimeContext()
        )

        let otpDecision = handler.unsupportedAgentJITSecretReadDecision(
            request: request,
            itemKind: "otp"
        )
        let sshDecision = handler.unsupportedAgentJITSecretReadDecision(
            request: makeRequest(
                type: .getSSH,
                requestedCommand: "exec",
                agentRuntimeContext: agentRuntimeContext()
            ),
            itemKind: "ssh key"
        )

        XCTAssertEqual(otpDecision, .denied(
            code: .policyDenied,
            message: "Agent exec JIT does not support otp items."
        ))
        XCTAssertEqual(sshDecision, .denied(
            code: .policyDenied,
            message: "Agent exec JIT does not support ssh key items."
        ))
    }

    func testAutomationBypassStillAllowsExecSecretReadWithoutJIT() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore())
        let request = makeRequest(type: .getPassword, requestedCommand: "exec")

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: true
        )

        XCTAssertEqual(decision, .allowed(approvedBy: "automation", needsApproval: false, agentJITGrantID: nil))
    }

    func testListFilteringUsesActiveSubtreeGrantAndCliEnabledItems() throws {
        let caller = callerFingerprint(requestedCommand: "list")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let handler = makeHandler(store: MemoryAgentJITGrantStore([grant]))
        let request = makeRequest(
            type: .list,
            requestedCommand: "list",
            agentRuntimeContext: agentRuntimeContext()
        )

        let filtered = handler.filteredListPayload(listPayload(), for: request)

        XCTAssertEqual(filtered.accounts, [])
        XCTAssertEqual(filtered.passwords.map(\.name), ["API", "API Nested", "Shared"])
        XCTAssertEqual(filtered.apiKeys.map(\.name), ["API Key"])
        XCTAssertEqual(filtered.certificates.map(\.name), ["API Cert"])
        XCTAssertEqual(filtered.notes.map(\.title), ["API Note"])
        XCTAssertEqual(filtered.sshKeys.map(\.name), ["API SSH", "Nested SSH"])
    }

    func testListWithoutActiveJITGrantKeepsExistingListBehavior() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore())
        let request = makeRequest(type: .list, requestedCommand: "list")
        let payload = listPayload()

        let filtered = handler.filteredListPayload(payload, for: request)

        XCTAssertEqual(filtered, payload)
    }

    func testAgentListWithoutJITGrantRequiresPreflight() async throws {
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), approver: approver)

        // Interactive callers can now bootstrap a session via biometric, so this denial requires a
        // confirmed agent marker (agentRuntimeContext) — the unforgeable "this is really an agent"
        // signal that keeps a real agent on the JIT path regardless of the interactive TTY.
        let response = try await list(
            handler,
            requestedCommand: "list",
            agentRuntimeContext: agentRuntimeContext()
        )

        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertEqual(
            response.error?.message,
            "Agent list requests require a valid JIT preflight grant for a supported Vault scope."
        )
        XCTAssertEqual(approver.requests, [])
        XCTAssertNil(response.payload)
    }

    func testListPathWithActiveJITGrantSkipsApprovalAndReturnsScopedItems() async throws {
        let caller = callerFingerprint(requestedCommand: "list")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: MemoryAgentJITGrantStore([grant]), approver: approver)
        let response = try await list(
            handler,
            requestedCommand: "list",
            agentRuntimeContext: agentRuntimeContext()
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(approver.requests, [])
        XCTAssertEqual(response.payload?.accounts, [])
        XCTAssertEqual(response.payload?.passwords.map(\.name), ["API", "API Nested", "Shared"])
        XCTAssertEqual(response.payload?.apiKeys.map(\.name), ["API Key"])
        XCTAssertEqual(response.payload?.certificates.map(\.name), ["API Cert"])
        XCTAssertEqual(response.payload?.notes.map(\.title), ["API Note"])
        XCTAssertEqual(response.payload?.sshKeys.map(\.name), ["API SSH", "Nested SSH"])
    }

    func testExecInternalListPathWithActiveJITGrantSkipsApprovalAndReturnsScopedItems() async throws {
        let caller = callerFingerprint(requestedCommand: "exec")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: MemoryAgentJITGrantStore([grant]), approver: approver)
        let response = try await list(
            handler,
            requestedCommand: "exec",
            agentRuntimeContext: agentRuntimeContext()
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(approver.requests, [])
        XCTAssertEqual(response.payload?.accounts, [])
        XCTAssertEqual(response.payload?.passwords.map(\.name), ["API", "API Nested", "Shared"])
        XCTAssertEqual(response.payload?.apiKeys.map(\.name), ["API Key"])
        XCTAssertEqual(response.payload?.certificates.map(\.name), ["API Cert"])
        XCTAssertEqual(response.payload?.notes.map(\.title), ["API Note"])
        XCTAssertEqual(response.payload?.sshKeys.map(\.name), ["API SSH", "Nested SSH"])
    }

    func testUnknownInteractiveCallerGetsOneRequestBiometricWithoutReusableSession() async throws {
        let caller = callerFingerprint(requestedCommand: "list")
        let grant = AgentJITGrant.fixture(
            callerFingerprint: caller,
            folderScope: .folder("Team/API"),
            capabilities: [.list],
            expiresAt: Date().addingTimeInterval(60)
        )
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(
            store: MemoryAgentJITGrantStore([grant]),
            approver: approver,
            callerIdentity: unknownInteractiveCallerIdentity
        )

        let response = try await list(handler, requestedCommand: "list")

        XCTAssertNil(response.error)
        XCTAssertEqual(approver.requests.map(\.command), [.list])
        XCTAssertNil(response.sessionToken)
        XCTAssertEqual(response.payload?.accounts.map(\.issuer), ["OTP"])
        XCTAssertEqual(
            response.payload?.passwords.map(\.name),
            ["RootOne", "API", "API Nested", "API Disabled", "Web", "Shared", "Shared"]
        )
        XCTAssertEqual(response.payload?.apiKeys.map(\.name), ["API Key", "API Key Disabled", "Web Key"])
        XCTAssertEqual(response.payload?.certificates.map(\.name), ["API Cert", "Web Cert"])
        XCTAssertEqual(response.payload?.notes.map(\.title), ["RootNote", "API Note", "API Disabled Note"])
        XCTAssertEqual(response.payload?.sshKeys.map(\.name), ["API SSH", "Nested SSH"])
    }

    func testAgentExecInternalListWithoutJITGrantReturnsNoVaultMetadata() async throws {
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), approver: approver)

        // A confirmed agent (agentRuntimeContext) stays on the JIT path and is not offered the
        // interactive bootstrap, so its ungranted exec-internal list yields no vault metadata.
        let response = try await list(
            handler,
            requestedCommand: "exec",
            agentRuntimeContext: agentRuntimeContext()
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(approver.requests, [])
        XCTAssertEqual(response.payload, BridgeListPayload(accounts: [], passwords: [], certificates: [], notes: [], sshKeys: []))
    }

    func testAgentLoadInternalListWithoutJITGrantExplainsUnsupportedCommand() async throws {
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), approver: approver)

        let response = try await list(
            handler,
            requestedCommand: "load",
            agentRuntimeContext: agentRuntimeContext()
        )

        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertEqual(
            response.error?.message,
            "Agent JIT grants do not allow authsia load. Use authsia exec with an approved JIT grant to inject secrets into a command."
        )
        XCTAssertEqual(approver.requests, [])
        XCTAssertNil(response.payload)
    }

    func testAgentRuntimeLoadInternalListWithoutJITGrantExplainsUnsupportedCommand() async throws {
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(
            store: MemoryAgentJITGrantStore(),
            approver: approver,
            callerIdentity: humanCallerIdentity
        )

        let response = try await list(
            handler,
            requestedCommand: "load",
            agentRuntimeContext: agentRuntimeContext()
        )

        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertEqual(
            response.error?.message,
            "Agent JIT grants do not allow authsia load. Use authsia exec with an approved JIT grant to inject secrets into a command."
        )
        XCTAssertEqual(approver.requests, [])
        XCTAssertNil(response.payload)
    }

    func testAutomationCredentialLoadInternalListFromAgentBypassesJITDenial() async throws {
        let credentialID = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
        let credential = AutomationCredentialLookup.CredentialRecord(
            id: credentialID,
            scope: "Team/API",
            expiresAt: Date().addingTimeInterval(60),
            revokedAt: nil,
            machineId: "machine-1",
            allowedCommands: [.load]
        )
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(
            store: MemoryAgentJITGrantStore(),
            approver: approver,
            automationCredentialValidationProvider: { token, command, _ in
                token == "authsia_ac1_test" && command == .load
                    ? .found(credential)
                    : .credentialNotFound
            },
            currentMachineIdProvider: { "machine-1" }
        )

        let response = try await list(
            handler,
            requestedCommand: "load",
            automationCredentialID: credentialID.uuidString,
            automationCredentialToken: "authsia_ac1_test"
        )

        XCTAssertNil(response.error)
        XCTAssertEqual(approver.requests, [])
        XCTAssertEqual(response.payload?.accounts, [])
        XCTAssertEqual(response.payload?.passwords.map(\.name), ["API", "API Nested", "Shared"])
        XCTAssertEqual(response.payload?.certificates.map(\.name), ["API Cert"])
        XCTAssertEqual(response.payload?.notes.map(\.title), ["API Note"])
        XCTAssertEqual(response.payload?.sshKeys.map(\.name), ["API SSH", "Nested SSH"])
    }

    func testAgentGetInternalListWithoutJITGrantExplainsUnsupportedCommand() async throws {
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), approver: approver)

        let response = try await list(
            handler,
            requestedCommand: "get",
            agentRuntimeContext: agentRuntimeContext()
        )

        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertEqual(
            response.error?.message,
            "Agent JIT grants do not allow authsia get. Use authsia exec with an approved JIT grant to inject secrets into a command."
        )
        XCTAssertEqual(approver.requests, [])
        XCTAssertNil(response.payload)
    }

    func testAutomationCredentialSkipsJITOnlySSHReadDenial() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore())
        let request = makeRequest(
            type: .getSSH,
            requestedCommand: "get",
            automationCredentialID: UUID().uuidString
        )

        let decision = handler.unsupportedAgentJITSecretReadDecision(
            request: request,
            itemKind: "ssh key"
        )

        XCTAssertEqual(decision, .allowed(approvedBy: "automation", needsApproval: false, agentJITGrantID: nil))
    }

    func testAgentRuntimeDirectSecretReadWithSessionButNoJITGrantFailsClosed() throws {
        let handler = makeHandler(store: MemoryAgentJITGrantStore(), callerIdentity: humanCallerIdentity)
        let session = try BridgeSessionManager.shared.createSession(
            ttlSeconds: 60,
            scope: execContext(requestedCommand: "get").sessionScope
        )
        let request = makeRequest(
            type: .getPassword,
            requestedCommand: "get",
            sessionToken: session.sessionToken,
            agentRuntimeContext: agentRuntimeContext()
        )

        let decision = handler.secretReadApprovalDecision(
            itemFolderPath: "Team/API",
            request: request,
            bypassApproval: false
        )

        XCTAssertEqual(decision, .denied(
            code: .policyDenied,
            message: "Agent JIT grants do not allow authsia get. Use authsia exec with an approved JIT grant to inject secrets into a command."
        ))
    }

    func testAgentRuntimeUnlockIsDeniedBeforeApproval() async throws {
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(
            store: MemoryAgentJITGrantStore(),
            approver: approver,
            callerIdentity: humanCallerIdentity
        )
        let request = makeRequest(
            type: .unlock,
            requestedCommand: nil,
            agentRuntimeContext: agentRuntimeContext()
        )

        let response: BridgeResponse<UnlockPayload> = try await bridgeResponse(
            for: request,
            description: "unlock reply"
        ) { requestData, reply in
            handler.unlock(requestData, reply)
        }

        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertEqual(
            response.error?.message,
            "Agent JIT grants do not allow authsia unlock. JIT grants only permit authsia list and authsia exec."
        )
        XCTAssertEqual(approver.requests, [])
        XCTAssertNil(response.payload)
    }

    func testIDEHelperTTYUnlockWithoutSessionIsDeniedBeforeApproval() async throws {
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(
            store: MemoryAgentJITGrantStore(),
            approver: approver,
            callerIdentity: ideHelperCallerIdentity
        )
        let request = makeRequest(type: .unlock, requestedCommand: nil)

        let response: BridgeResponse<UnlockPayload> = try await bridgeResponse(
            for: request,
            description: "bootstrap unlock reply"
        ) { requestData, reply in
            handler.unlock(requestData, reply)
        }

        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertNil(response.payload)
        XCTAssertEqual(approver.requests, [])
    }

    func testAgentRuntimeWriteAndExportCommandsAreDeniedBeforeApproval() async throws {
        let password = passwordMetadata(name: "API")
        let repository = EmptyVaultRepository(passwords: [password])
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(
            store: MemoryAgentJITGrantStore(),
            approver: approver,
            repository: repository,
            callerIdentity: humanCallerIdentity
        )
        let cases: [(BridgeRequestType, String?, String, String, Data?, (Data, @escaping (Data?, NSError?) -> Void) -> Void)] = [
            (
                .addPassword,
                nil,
                "add",
                "",
                try BridgeCoder.encode(PasswordWritePayload(
                    name: "New",
                    username: "user",
                    password: "secret",
                    website: nil,
                    notes: nil
                )),
                { requestData, reply in handler.addItem(requestData, reply) }
            ),
            (
                .updatePassword,
                nil,
                "edit",
                "API",
                try BridgeCoder.encode(PasswordWritePayload(
                    name: "Renamed",
                    username: nil,
                    password: nil,
                    website: nil,
                    notes: nil
                )),
                { requestData, reply in handler.updateItem(requestData, reply) }
            ),
            (
                .deletePassword,
                nil,
                "delete",
                "API",
                nil,
                { requestData, reply in handler.deleteItem(requestData, reply) }
            ),
            (
                .exportAccounts,
                nil,
                "export",
                "",
                try BridgeCoder.encode(ExportAccountsRequestPayload(password: nil)),
                { requestData, reply in handler.exportAccounts(requestData, reply) }
            ),
        ]

        for (type, requestedCommand, expectedCommand, query, body, route) in cases {
            let request = makeRequest(
                type: type,
                query: query,
                requestedCommand: requestedCommand,
                body: body,
                agentRuntimeContext: agentRuntimeContext()
            )
            let response: BridgeResponse<WriteResultPayload> = try await bridgeResponse(
                for: request,
                description: "\(expectedCommand) reply",
                route: route
            )

            XCTAssertEqual(response.error?.code, .policyDenied, "expected policy denial for \(expectedCommand)")
            XCTAssertEqual(
                response.error?.message,
                "Agent JIT grants do not allow authsia \(expectedCommand). JIT grants only permit authsia list and authsia exec."
            )
            XCTAssertNil(response.payload)
        }
        XCTAssertEqual(approver.requests, [])
    }

    func testAgentRuntimeCreateAccessIsDeniedBeforeApproval() async throws {
        let approver = JITApprovalTracker(result: true)
        let handler = makeHandler(
            store: MemoryAgentJITGrantStore(),
            approver: approver,
            callerIdentity: humanCallerIdentity
        )
        let payload = AccessCreateApprovalPayload(
            name: "Agent",
            scope: "Team/API",
            ttlSeconds: 900,
            expiresAt: now.addingTimeInterval(900),
            machineId: "machine",
            machineName: "Mac",
            allowedCommands: ["exec"]
        )
        let request = makeRequest(
            type: .createAccess,
            query: "Team/API",
            requestedCommand: "access",
            body: try BridgeCoder.encode(payload),
            agentRuntimeContext: agentRuntimeContext()
        )

        let response: BridgeResponse<WriteResultPayload> = try await bridgeResponse(
            for: request,
            description: "create access reply"
        ) { requestData, reply in
            handler.addItem(requestData, reply)
        }

        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertEqual(
            response.error?.message,
            "Agent JIT grants do not allow authsia access. JIT grants only permit authsia list and authsia exec."
        )
        XCTAssertEqual(approver.requests, [])
        XCTAssertNil(response.payload)
    }

    func testListPathFailsClosedWhenActiveJITScopeLookupThrows() async throws {
        let store = MemoryAgentJITGrantStore()
        store.markUsedScopesError = AgentJITGrantStoreError.corruptedStore
        let handler = makeHandler(store: store)

        let response = try await list(
            handler,
            requestedCommand: "list",
            agentRuntimeContext: agentRuntimeContext()
        )

        XCTAssertEqual(response.error?.code, .policyDenied)
        XCTAssertNil(response.payload)
    }

    func testPreflightDoesNotSavePartialGrantWhenLaterScopeDenied() async throws {
        let store = MemoryAgentJITGrantStore()
        let approver = JITApprovalTracker(results: [true, false])
        let handler = makeHandler(store: store, approver: approver)
        let payload = AgentJITPreflightPayload(
            requestedCommand: "exec",
            references: [
                AgentJITPreflightReference(type: "password", query: "API", folderPath: "Team/API"),
                AgentJITPreflightReference(type: "cert", query: "Web Cert", folderPath: "Team/Web"),
            ]
        )

        let response: BridgeResponse<AgentJITPreflightResultPayload> = try await addItem(handler, body: payload)

        XCTAssertEqual(response.error?.code, .notAuthorized)
        XCTAssertEqual(store.grants, [])
        XCTAssertEqual(approver.requests.map(\.itemLabel), ["Team/API", "Team/Web"])
    }

    private func makeHandler(
        store: AgentJITGrantStoring,
        approver: JITApprovalTracker = JITApprovalTracker(result: true),
        repository: VaultRepositoryProviding? = nil,
        automationCredentialLookupProvider: @escaping XPCRequestHandler.AutomationCredentialLookupProvider = {
            _ in .fileMissing
        },
        automationCredentialValidationProvider: @escaping XPCRequestHandler.AutomationCredentialValidationProvider = {
            _, _, _ in .fileMissing
        },
        currentMachineIdProvider: @escaping XPCRequestHandler.CurrentMachineIdProvider = {
            nil
        },
        auditLogger: BridgeAuditLogger? = nil,
        callerIdentity: CallerIdentity? = nil,
        listProvider: XPCRequestHandler.ListProvider? = nil,
        requestBuilder: RemoteJITApprovalRequestBuilding? = nil,
        remoteJITApprovalEnabled: @escaping @Sendable () -> Bool = { true },
        callerIdentityRevalidationProvider: CallerIdentityRevalidationProvider? = nil,
        clock: @escaping AgentJITApprovalClock = Date.init
    ) -> XPCRequestHandler {
        let resolvedCallerIdentity = callerIdentity ?? self.callerIdentity
        return XPCRequestHandler(
            listProvider: listProvider ?? listPayload,
            approver: approver,
            repository: repository ?? EmptyVaultRepository(),
            automationCredentialLookupProvider: automationCredentialLookupProvider,
            automationCredentialValidationProvider: automationCredentialValidationProvider,
            currentMachineIdProvider: currentMachineIdProvider,
            agentJITGrantStore: store,
            callerIdentityProvider: { resolvedCallerIdentity },
            callerIdentityRevalidationProvider: callerIdentityRevalidationProvider ?? { _ in
                resolvedCallerIdentity
            },
            remoteJITApprovalRequestBuilder: requestBuilder,
            remoteJITApprovalEnabled: remoteJITApprovalEnabled,
            agentJITApprovalClock: clock,
            auditLogger: auditLogger ?? makeIsolatedAuditLogger()
        )
    }

    private func setCLIApprovalTTL(_ ttl: TimeInterval) -> () -> Void {
        let defaults = BridgeSettings.appDefaults
        let key = BridgeSettings.cliSessionTTLKey
        let previous = defaults.object(forKey: key)
        defaults.set(ttl, forKey: key)
        return {
            if let previous {
                defaults.set(previous, forKey: key)
            } else {
                defaults.removeObject(forKey: key)
            }
        }
    }

    private func makeIsolatedAuditLogger() -> BridgeAuditLogger {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        isolatedAuditDirectories.append(tempDir)
        return BridgeAuditLogger(
            fileURL: tempDir.appendingPathComponent("bridge_audit.log"),
            hmacKeyProvider: { SymmetricKey(data: Data(repeating: 0xA5, count: 32)) }
        )
    }

    private func makeAuditLogger() throws -> (BridgeAuditLogger, URL, URL) {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        let fileURL = tempDir.appendingPathComponent("bridge_audit.log")
        return (
            BridgeAuditLogger(
                fileURL: fileURL,
                hmacKeyProvider: { SymmetricKey(data: Data(repeating: 0xA5, count: 32)) }
            ),
            fileURL,
            tempDir
        )
    }

    private func auditRecords(at fileURL: URL) throws -> [BridgeAuditRecord] {
        let data = try Data(contentsOf: fileURL)
        return try data.split(separator: 0x0A).map { line in
            try BridgeCoder.decode(AuditLineFixture.self, from: Data(line)).record
        }
    }

    private func addItem<T: Codable & Equatable>(
        _ handler: XPCRequestHandler,
        body: T,
        requestedCommand: String = "exec"
    ) async throws -> BridgeResponse<AgentJITPreflightResultPayload> {
        let request = BridgeRequest(
            id: UUID(),
            type: .agentJITPreflight,
            query: "",
            options: .init(field: nil, copy: false),
            context: execContext(requestedCommand: requestedCommand),
            body: try BridgeCoder.encode(body)
        )
        let requestData = try BridgeCoder.encode(request)
        let expectation = XCTestExpectation(description: "preflight reply")
        var responseData: Data?
        handler.addItem(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)
        return try BridgeCoder.decode(
            BridgeResponse<AgentJITPreflightResultPayload>.self,
            from: try XCTUnwrap(responseData)
        )
    }

    private func grantSnapshot(
        _ handler: XPCRequestHandler
    ) async throws -> BridgeResponse<AgentJITGrantSnapshotPayload> {
        try await invokeGrantControl(
            handler,
            type: .agentJITSnapshot,
            body: Optional<String>.none,
            action: handler.agentJITSnapshot
        )
    }

    private func revokeGrant(
        _ handler: XPCRequestHandler,
        id: UUID
    ) async throws -> BridgeResponse<AgentJITGrantMutationPayload> {
        try await invokeGrantControl(
            handler,
            type: .agentJITRevoke,
            body: AgentJITGrantRevokePayload(id: id),
            action: handler.revokeAgentJITGrant
        )
    }

    private func revokeAllGrants(
        _ handler: XPCRequestHandler
    ) async throws -> BridgeResponse<AgentJITGrantMutationPayload> {
        try await invokeGrantControl(
            handler,
            type: .agentJITRevokeAll,
            body: Optional<String>.none,
            action: handler.revokeAllAgentJITGrants
        )
    }

    private func invokeGrantControl<Response: Codable & Equatable, Body: Codable>(
        _ handler: XPCRequestHandler,
        type: BridgeRequestType,
        body: Body?,
        action: (Data, @escaping (Data?, NSError?) -> Void) -> Void
    ) async throws -> BridgeResponse<Response> {
        let request = BridgeRequest(
            id: UUID(),
            type: type,
            query: "",
            options: .init(field: nil, copy: false),
            context: execContext(requestedCommand: type.rawValue),
            body: try body.map(BridgeCoder.encode)
        )
        let expectation = XCTestExpectation(description: "\(type.rawValue) reply")
        var responseData: Data?
        action(try BridgeCoder.encode(request)) { data, _ in
            responseData = data
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)
        return try BridgeCoder.decode(
            BridgeResponse<Response>.self,
            from: try XCTUnwrap(responseData)
        )
    }

    private func list(
        _ handler: XPCRequestHandler,
        requestedCommand: String,
        automationCredentialID: String? = nil,
        automationCredentialToken: String? = nil,
        agentRuntimeContext: AgentRuntimeContext? = nil
    ) async throws -> BridgeResponse<BridgeListPayload> {
        let request = makeRequest(
            type: .list,
            requestedCommand: requestedCommand,
            automationCredentialID: automationCredentialID,
            automationCredentialToken: automationCredentialToken,
            agentRuntimeContext: agentRuntimeContext
        )
        let requestData = try BridgeCoder.encode(request)
        let expectation = XCTestExpectation(description: "list reply")
        var responseData: Data?
        handler.list(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)
        return try BridgeCoder.decode(
            BridgeResponse<BridgeListPayload>.self,
            from: try XCTUnwrap(responseData)
        )
    }

    private func bridgeResponse<T: Codable & Equatable>(
        for request: BridgeRequest,
        description: String,
        route: (_ requestData: Data, _ reply: @escaping (Data?, NSError?) -> Void) -> Void
    ) async throws -> BridgeResponse<T> {
        let requestData = try BridgeCoder.encode(request)
        let expectation = XCTestExpectation(description: description)
        var responseData: Data?
        route(requestData) { data, _ in
            responseData = data
            expectation.fulfill()
        }
        await fulfillment(of: [expectation], timeout: 1)
        return try BridgeCoder.decode(
            BridgeResponse<T>.self,
            from: try XCTUnwrap(responseData)
        )
    }

    private func makeRequest(
        type: BridgeRequestType,
        query: String = "",
        requestedCommand: String?,
        body: Data? = nil,
        sessionToken: String? = nil,
        automationCredentialID: String? = nil,
        automationCredentialToken: String? = nil,
        agentRuntimeContext: AgentRuntimeContext? = nil
    ) -> BridgeRequest {
        BridgeRequest(
            id: UUID(),
            type: type,
            query: query,
            options: .init(field: nil, copy: false),
            context: execContext(
                requestedCommand: requestedCommand,
                automationCredentialID: automationCredentialID,
                automationCredentialToken: automationCredentialToken,
                agentRuntimeContext: agentRuntimeContext
            ),
            body: body,
            sessionToken: sessionToken
        )
    }

    private func execContext(
        requestedCommand: String? = "exec",
        automationCredentialID: String? = nil,
        automationCredentialToken: String? = nil,
        agentRuntimeContext: AgentRuntimeContext? = nil
    ) -> BridgeContext {
        BridgeContext(
            isTTY: true,
            isPiped: false,
            isSSH: false,
            isCI: false,
            timestamp: now,
            automationCredentialID: automationCredentialID,
            automationCredentialToken: automationCredentialToken,
            requestedCommand: requestedCommand,
            sessionScope: "tty:/dev/ttys001",
            workingDirectory: "/repo",
            agentRuntimeContext: agentRuntimeContext
        )
    }

    private func nonInteractiveExecContext(requestedCommand: String? = "exec") -> BridgeContext {
        BridgeContext(
            isTTY: false,
            isPiped: true,
            isSSH: false,
            isCI: false,
            timestamp: now,
            requestedCommand: requestedCommand,
            sessionScope: execContext(requestedCommand: requestedCommand).sessionScope,
            workingDirectory: "/tmp/project"
        )
    }

    private func redirectedExecContext(requestedCommand: String? = "exec") -> BridgeContext {
        BridgeContext(
            isTTY: true,
            isPiped: true,
            isSSH: false,
            isCI: false,
            timestamp: now,
            requestedCommand: requestedCommand,
            sessionScope: execContext(requestedCommand: requestedCommand).sessionScope,
            workingDirectory: "/tmp/project"
        )
    }

    private func agentRuntimeContext() -> AgentRuntimeContext {
        AgentRuntimeContext(
            platform: "claude-code",
            sessionID: "session",
            turnID: "turn",
            agentID: "agent",
            agentType: "assistant",
            toolUseID: "tool-use"
        )
    }

    private func callerFingerprint(requestedCommand: String) -> AgentJITCallerFingerprint {
        let context = execContext(requestedCommand: requestedCommand)
        return AgentJITCallerFingerprint(
            processName: callerIdentity.processName,
            bundleIdentifier: callerIdentity.bundleIdentifier,
            signingTeamId: callerIdentity.signingTeamId,
            signingIdentity: callerIdentity.signingIdentity,
            parentProcessName: callerIdentity.parentProcess?.processName,
            parentBundleIdentifier: callerIdentity.parentProcess?.bundleIdentifier,
            hostProcessName: callerIdentity.hostProcess?.processName,
            hostBundleIdentifier: callerIdentity.hostProcess?.bundleIdentifier,
            sessionScope: context.sessionScope,
            workingDirectory: context.workingDirectory
        )
    }

    private func listPayload() -> BridgeListPayload {
        BridgeListPayload(
            accounts: [
                BridgeAccount(
                    id: stableUUID("account:OTP"),
                    issuer: "OTP",
                    label: "otp",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: now,
                    updatedAt: now
                ),
            ],
            passwords: [
                password("RootOne", folderPath: nil),
                password("API", folderPath: "Team/API"),
                password("API Nested", folderPath: "Team/API/Prod"),
                password("API Disabled", folderPath: "Team/API", isCliEnabled: false),
                password("Web", folderPath: "Team/Web"),
                password("Shared", folderPath: "Team/API"),
                password("Shared", folderPath: "Team/Web"),
            ],
            apiKeys: [
                apiKey("API Key", folderPath: "Team/API"),
                apiKey("API Key Disabled", folderPath: "Team/API", isCliEnabled: false),
                apiKey("Web Key", folderPath: "Team/Web"),
            ],
            certificates: [
                certificate("API Cert", folderPath: "Team/API"),
                certificate("Web Cert", folderPath: "Team/Web"),
            ],
            notes: [
                note("RootNote", folderPath: nil),
                note("API Note", folderPath: "Team/API"),
                note("API Disabled Note", folderPath: "Team/API", isCliEnabled: false),
            ],
            sshKeys: [
                sshKey("API SSH", folderPath: "Team/API"),
                sshKey("Nested SSH", folderPath: "Team/API/Prod"),
            ]
        )
    }

    private func listPayload(replacingPasswords passwords: [BridgePassword]) -> BridgeListPayload {
        let payload = listPayload()
        return BridgeListPayload(
            accounts: payload.accounts,
            passwords: passwords,
            apiKeys: payload.apiKeys,
            certificates: payload.certificates,
            notes: payload.notes,
            sshKeys: payload.sshKeys
        )
    }

    private func copyPassword(
        _ password: BridgePassword,
        name: String? = nil,
        folderPath: String? = nil,
        isCliEnabled: Bool? = nil
    ) -> BridgePassword {
        BridgePassword(
            id: password.id,
            name: name ?? password.name,
            username: password.username,
            website: password.website,
            folderPath: folderPath ?? password.folderPath,
            isFavorite: password.isFavorite,
            isCliEnabled: isCliEnabled ?? password.isCliEnabled,
            isScraped: password.isScraped,
            createdAt: password.createdAt,
            updatedAt: password.updatedAt,
            expiresAt: password.expiresAt,
            scrapeMachineName: password.scrapeMachineName,
            scrapeMachineId: password.scrapeMachineId,
            hasSecret: password.hasSecret,
            environments: password.environments
        )
    }

    private func listPayloadWithRootPasswords(count: Int) -> BridgeListPayload {
        BridgeListPayload(
            accounts: [],
            passwords: (0..<count).map { index in
                password("Root \(index)", folderPath: nil)
            },
            apiKeys: [],
            certificates: [],
            notes: [],
            sshKeys: []
        )
    }

    private func password(
        _ name: String,
        folderPath: String?,
        isCliEnabled: Bool = true
    ) -> BridgePassword {
        BridgePassword(
            id: stableUUID("password:\(name):\(folderPath ?? "root")"),
            name: name,
            username: "user",
            website: nil,
            folderPath: folderPath,
            isFavorite: false,
            isCliEnabled: isCliEnabled,
            isScraped: false,
            createdAt: now,
            updatedAt: now
        )
    }

    private func apiKey(
        _ name: String,
        folderPath: String?,
        isCliEnabled: Bool = true
    ) -> BridgeAPIKey {
        BridgeAPIKey(
            id: stableUUID("api-key:\(name):\(folderPath ?? "root")"),
            name: name,
            website: nil,
            folderPath: folderPath,
            isFavorite: false,
            isCliEnabled: isCliEnabled,
            isScraped: false,
            createdAt: now,
            updatedAt: now
        )
    }

    private func passwordMetadata(name: String, folderPath: String? = nil) -> PasswordMetadata {
        PasswordMetadata(
            id: stableUUID("metadata-password:\(name):\(folderPath ?? "root")"),
            name: name,
            username: "user",
            website: nil,
            notes: nil,
            folderPath: folderPath,
            createdAt: now,
            modifiedAt: now,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false
        )
    }

    private func certificate(_ name: String, folderPath: String?) -> BridgeCertificate {
        BridgeCertificate(
            id: stableUUID("certificate:\(name):\(folderPath ?? "root")"),
            name: name,
            issuer: nil,
            subject: nil,
            expirationDate: nil,
            folderPath: folderPath,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            createdAt: now,
            updatedAt: now
        )
    }

    private func note(
        _ title: String,
        folderPath: String?,
        isCliEnabled: Bool = true
    ) -> BridgeNote {
        BridgeNote(
            id: stableUUID("note:\(title):\(folderPath ?? "root")"),
            title: title,
            folderPath: folderPath,
            isFavorite: false,
            isCliEnabled: isCliEnabled,
            isScraped: false,
            createdAt: now,
            updatedAt: now
        )
    }

    private func sshKey(_ name: String, folderPath: String?) -> BridgeSSHKey {
        BridgeSSHKey(
            id: stableUUID("ssh:\(name):\(folderPath ?? "root")"),
            name: name,
            comment: "",
            fingerprint: "SHA256:\(name)",
            publicKey: "ssh-ed25519 AAAA",
            folderPath: folderPath,
            isFavorite: false,
            isCliEnabled: true,
            isScraped: false,
            createdAt: now,
            updatedAt: now
        )
    }

    private func stableUUID(_ value: String) -> UUID {
        let hex = SHA256.hash(data: Data(value.utf8))
            .prefix(16)
            .map { String(format: "%02x", $0) }
            .joined()
        let start = hex.startIndex
        let i8 = hex.index(start, offsetBy: 8)
        let i12 = hex.index(start, offsetBy: 12)
        let i16 = hex.index(start, offsetBy: 16)
        let i20 = hex.index(start, offsetBy: 20)
        return UUID(uuidString: [
            String(hex[start..<i8]),
            String(hex[i8..<i12]),
            String(hex[i12..<i16]),
            String(hex[i16..<i20]),
            String(hex[i20...]),
        ].joined(separator: "-"))!
    }
}

private struct AuditLineFixture: Decodable {
    let record: BridgeAuditRecord
}

@MainActor
private final class ListProviderSequence {
    private var results: [Result<BridgeListPayload, Error>]

    init(_ results: [Result<BridgeListPayload, Error>]) {
        self.results = results
    }

    func callAsFunction() throws -> BridgeListPayload {
        let result: Result<BridgeListPayload, Error>
        if results.count > 1 {
            result = results.removeFirst()
        } else {
            result = results[0]
        }
        return try result.get()
    }
}

@MainActor
private final class AgentJITApprovalClockSpy {
    private var dates: [Date]
    private(set) var callCount = 0

    init(_ dates: [Date]) {
        self.dates = dates
    }

    func callAsFunction() -> Date {
        callCount += 1
        if dates.count > 1 {
            return dates.removeFirst()
        }
        return dates.first ?? Date(timeIntervalSince1970: 0)
    }
}

@MainActor
private final class RemoteRequestBuilderSpy: RemoteJITApprovalRequestBuilding {
    enum Mode: Equatable {
        case valid
        case throwError
        case wrongCount
        case reversed
        case mismatchedAuthority
    }

    struct BuilderError: Error {}

    let pairing = try! RemoteJITApprovalPairingBinding(
        pairingGenerationID: UUID(uuidString: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")!,
        macDeviceID: UUID(uuidString: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")!,
        iphoneDeviceID: UUID(uuidString: "cccccccc-cccc-cccc-cccc-cccccccccccc")!,
        macSigningKeyFingerprint: Data(repeating: 0x11, count: 32),
        iphoneSigningKeyFingerprint: Data(repeating: 0x22, count: 32)
    )
    let mode: Mode
    private(set) var inputBatches: [[RemoteJITApprovalDescriptorInput]] = []

    init(mode: Mode = .valid) {
        self.mode = mode
    }

    var remoteAttribution: String {
        var generationUUID = pairing.pairingGenerationID.uuid
        let generationBytes = withUnsafeBytes(of: &generationUUID) { Data($0) }
        let digest = SHA256.hash(data: generationBytes + pairing.iphoneSigningKeyFingerprint)
        let suffix = digest.prefix(6).map { String(format: "%02x", $0) }.joined()
        return "ios-remote:\(suffix)"
    }

    func buildRequests(
        for inputs: [RemoteJITApprovalDescriptorInput]
    ) async throws -> [RemoteJITApprovalRequest] {
        inputBatches.append(inputs)
        if mode == .throwError {
            throw BuilderError()
        }

        var requests = try inputs.enumerated().map { offset, input in
            try request(for: input, offset: offset)
        }
        switch mode {
        case .valid, .throwError:
            break
        case .wrongCount:
            _ = requests.popLast()
        case .reversed:
            requests.reverse()
        case .mismatchedAuthority:
            guard let first = inputs.first else { break }
            let mismatched = try RemoteJITApprovalDescriptorInput(
                bridgeRequestID: UUID(uuidString: "dddddddd-dddd-dddd-dddd-dddddddddddd")!,
                requestIssuedAtMilliseconds: first.requestIssuedAtMilliseconds,
                callerFingerprint: first.callerFingerprint,
                capabilities: first.capabilities,
                folderScope: first.folderScope,
                environmentScope: first.environmentScope,
                requestedItems: first.requestedItems,
                grantExpiresAtMilliseconds: first.grantExpiresAtMilliseconds
            )
            requests[0] = try request(for: mismatched, offset: 99)
        }
        return requests
    }

    private func request(
        for input: RemoteJITApprovalDescriptorInput,
        offset: Int
    ) throws -> RemoteJITApprovalRequest {
        let descriptor = try RemoteJITApprovalDescriptor(
            input: input,
            approvalID: UUID(),
            approvalNonce: Data(repeating: UInt8(offset & 0xff), count: 32),
            pairing: pairing
        )
        return try RemoteJITApprovalRequest(
            descriptor: descriptor,
            requestDigest: Data(repeating: 0x33, count: 32),
            requestSignature: Data(repeating: 0x44, count: 64)
        )
    }
}

private final class MemoryAgentJITGrantStore: AgentJITGrantStoring {
    var grants: [AgentJITGrant]
    var markUsedScopesError: Error?
    var loadError: Error?
    var loadErrorOnCall: Int?
    var saveAllError: Error?
    private(set) var loadCallCount = 0
    private(set) var saveAllCallCount = 0
    private(set) var savedBatches: [[AgentJITGrant]] = []

    init(_ grants: [AgentJITGrant] = []) {
        self.grants = grants
    }

    func loadAll() throws -> [AgentJITGrant] {
        loadCallCount += 1
        if loadCallCount == loadErrorOnCall {
            throw AgentJITGrantStoreError.corruptedStore
        }
        if let loadError { throw loadError }
        return grants
    }

    func save(_ grant: AgentJITGrant) throws {
        try saveAll([grant])
    }

    func saveAll(_ newGrants: [AgentJITGrant]) throws {
        saveAllCallCount += 1
        savedBatches.append(newGrants)
        if let saveAllError { throw saveAllError }
        var updatedGrants = grants
        for grant in newGrants {
            if let index = updatedGrants.firstIndex(where: { $0.id == grant.id }) {
                updatedGrants[index] = grant
            } else {
                updatedGrants.append(grant)
            }
        }
        grants = updatedGrants
    }

    func markUsed(id: UUID, at date: Date) throws -> AgentJITGrant {
        guard let index = grants.firstIndex(where: { $0.id == id }) else {
            throw AgentJITGrantStoreError.notFound(id)
        }
        let updated = grants[index].copy(lastUsedAt: date)
        grants[index] = updated
        return updated
    }

    func revoke(id: UUID, revokedAt date: Date) throws -> AgentJITGrant {
        guard let index = grants.firstIndex(where: { $0.id == id }) else {
            throw AgentJITGrantStoreError.notFound(id)
        }
        let updated = grants[index].copy(revokedAt: date)
        grants[index] = updated
        return updated
    }

    func revokeClosedTerminalGrants(now: Date) throws -> [AgentJITGrant] {
        []
    }

    func markUsedIfAllowed(
        capability: AgentJITCapability,
        itemIdentity: AgentJITItemIdentity?,
        itemFolderPath: String?,
        itemEnvironments: [String],
        caller: AgentJITCallerFingerprint,
        now: Date
    ) throws -> AgentJITGrant? {
        guard let grant = grants.first(where: {
            $0.allows(
                capability: capability,
                itemIdentity: itemIdentity,
                itemFolderPath: itemFolderPath,
                itemEnvironments: itemEnvironments,
                caller: caller,
                now: now
            )
        }) else {
            return nil
        }
        return try markUsed(id: grant.id, at: now)
    }

    func markUsedScopes(
        capability: AgentJITCapability,
        caller: AgentJITCallerFingerprint,
        now: Date
    ) throws -> [AgentJITFolderScope] {
        if let markUsedScopesError {
            throw markUsedScopesError
        }
        let matchingIDs = grants.filter {
            $0.status(asOf: now) == .active
                && $0.capabilities.contains(capability)
                && $0.callerFingerprint.matches(caller)
        }.map(\.id)

        for id in matchingIDs {
            _ = try markUsed(id: id, at: now)
        }

        return grants.filter { matchingIDs.contains($0.id) }.map(\.folderScope)
    }
}

private final class JITApprovalTracker: AgentJITDescriptorApproving {
    struct Request: Equatable {
        let prompt: String
        let command: BridgeRequestType
        let itemLabel: String?
        let field: String?
        let approvalDescriptors: [AgentJITApprovalDescriptor]
        let remoteRequests: [RemoteJITApprovalRequest]
    }

    private var results: [RemoteJITApprovalOutcome]
    private(set) var requests: [Request] = []
    var onRequest: (() -> Void)?

    init(result: Bool) {
        self.results = [Self.outcome(for: result)]
    }

    init(results: [Bool]) {
        self.results = results.map(Self.outcome(for:))
    }

    init(outcome: RemoteJITApprovalOutcome) {
        self.results = [outcome]
    }

    init(outcomes: [RemoteJITApprovalOutcome]) {
        self.results = outcomes
    }

    func requestApproval(
        prompt: String,
        command: BridgeRequestType,
        itemLabel: String?,
        field: String?,
        callback: AuthsiaBridgeApprovalCallbackProtocol?,
        approvalDescriptors: [AgentJITApprovalDescriptor],
        remoteRequests: [RemoteJITApprovalRequest]
    ) async -> RemoteJITApprovalOutcome {
        requests.append(
            Request(
                prompt: prompt,
                command: command,
                itemLabel: itemLabel,
                field: field,
                approvalDescriptors: approvalDescriptors,
                remoteRequests: remoteRequests
            )
        )
        onRequest?()
        if results.count > 1 {
            return results.removeFirst()
        }
        return results.first ?? .denied(source: .macBiometric)
    }

    private static func outcome(for result: Bool) -> RemoteJITApprovalOutcome {
        result ? .approved(source: .macBiometric) : .denied(source: .macBiometric)
    }
}

@MainActor
private final class EmptyVaultRepository: VaultRepositoryProviding {
    var passwords: [PasswordMetadata]
    var apiKeys: [APIKeyMetadata] { [] }
    var certificates: [CertificateMetadata] { [] }
    var notes: [SecureNoteMetadata] { [] }
    var sshKeys: [SSHKeyMetadata] { [] }
    var hasLoadedVaultState = false

    init(passwords: [PasswordMetadata] = []) {
        self.passwords = passwords
    }

    func load() throws {}
    func addPassword(_ item: PasswordItem) throws {}
    func updatePassword(_ item: PasswordItem) throws {}
    func deletePassword(id: UUID) throws {}
    func convertPasswordToAPIKey(id: UUID, modifiedAt: Date) throws -> APIKeyItem? { nil }
    func getFullPassword(metadata: PasswordMetadata) throws -> PasswordItem { fatalError("unused") }
    func addAPIKey(_ item: APIKeyItem) throws {}
    func updateAPIKey(_ item: APIKeyItem) throws {}
    func deleteAPIKey(id: UUID) throws {}
    func getFullAPIKey(metadata: APIKeyMetadata) throws -> APIKeyItem { fatalError("unused") }
    func addCertificate(_ item: CertificateItem) throws {}
    func updateCertificate(_ item: CertificateItem) throws {}
    func deleteCertificatePrivateKey(id: UUID) {}
    func deleteCertificate(id: UUID) throws {}
    func getFullCertificate(metadata: CertificateMetadata) throws -> CertificateItem { fatalError("unused") }
    func addNote(_ item: SecureNoteItem) throws {}
    func updateNote(_ item: SecureNoteItem) throws {}
    func deleteNote(id: UUID) throws {}
    func getFullNote(metadata: SecureNoteMetadata) throws -> SecureNoteItem { fatalError("unused") }
    func addSSHKey(_ item: SSHKeyItem) throws {}
    func updateSSHKey(_ item: SSHKeyItem) throws {}
    func deleteSSHKey(id: UUID) throws {}
    func getFullSSHKey(metadata: SSHKeyMetadata) throws -> SSHKeyItem { fatalError("unused") }
    func addFolder(_ path: String, type: VaultItemType) throws {}
}

private extension AgentJITGrant {
    static func fixture(
        id: UUID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
        callerFingerprint: AgentJITCallerFingerprint,
        folderScope: AgentJITFolderScope,
        capabilities: Set<AgentJITCapability>,
        createdAt: Date = Date(timeIntervalSince1970: 1_700_000_000),
        expiresAt: Date,
        revokedAt: Date? = nil,
        lastUsedAt: Date? = nil,
        environmentScope: EnvironmentAccessScope? = nil
    ) -> AgentJITGrant {
        AgentJITGrant(
            id: id,
            agentName: "Codex",
            callerFingerprint: callerFingerprint,
            folderScope: folderScope,
            capabilities: capabilities,
            createdAt: createdAt,
            expiresAt: expiresAt,
            revokedAt: revokedAt,
            lastUsedAt: lastUsedAt,
            requestedItems: [],
            agentRuntimeContext: nil,
            approvedBy: "biometric",
            environmentScope: environmentScope
        )
    }

    func copy(revokedAt: Date? = nil, lastUsedAt: Date? = nil) -> AgentJITGrant {
        AgentJITGrant(
            id: id,
            agentName: agentName,
            callerFingerprint: callerFingerprint,
            folderScope: folderScope,
            capabilities: capabilities,
            createdAt: createdAt,
            expiresAt: expiresAt,
            revokedAt: revokedAt ?? self.revokedAt,
            lastUsedAt: lastUsedAt ?? self.lastUsedAt,
            requestedItems: requestedItems,
            agentRuntimeContext: agentRuntimeContext,
            approvedBy: approvedBy,
            environmentScope: environmentScope
        )
    }
}
