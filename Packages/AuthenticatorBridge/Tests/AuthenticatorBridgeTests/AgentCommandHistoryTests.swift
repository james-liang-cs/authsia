import XCTest
@testable import AuthenticatorBridge

final class AgentCommandHistoryTests: XCTestCase {
    func testCommandEventRedactsSensitiveFlagsAndEnvironmentAssignments() throws {
        let event = AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 10),
            agentPlatform: "claude-code",
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys001:sid:42",
            executable: "deploy",
            arguments: [
                "deploy",
                "--password",
                "hunter2",
                "--token=abc123",
                "AWS_SECRET_ACCESS_KEY=raw-secret",
                "--safe",
                "value",
            ],
            command: "AWS_SECRET_ACCESS_KEY=raw-secret deploy --password hunter2 --token=abc123 --safe value",
            exitStatus: 0
        )

        XCTAssertEqual(event.arguments[1...3], ["--password", "[REDACTED]", "--token=[REDACTED]"])
        XCTAssertEqual(event.arguments[4], "AWS_SECRET_ACCESS_KEY=[REDACTED]")
        XCTAssertTrue(event.command?.contains("AWS_SECRET_ACCESS_KEY=[REDACTED]") == true)
        XCTAssertTrue(event.command?.contains("--password [REDACTED]") == true)
        XCTAssertTrue(event.command?.contains("--token=[REDACTED]") == true)
        XCTAssertFalse(event.command?.contains("hunter2") == true)
        XCTAssertFalse(event.command?.contains("raw-secret") == true)
        XCTAssertFalse(event.command?.contains("abc123") == true)
    }

    func testStorePersistsLoadsAndExportsEventsAsJSON() throws {
        let fileURL = try makeTempURL()
        let store = AgentCommandHistoryStore(fileURL: fileURL)
        let grantID = UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!
        let first = AgentCommandEvent(
            id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            recordedAt: Date(timeIntervalSince1970: 20),
            agentPlatform: "codex",
            agentJITGrantID: grantID,
            captureSource: .process,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            executable: "npm",
            arguments: ["npm", "test"],
            command: "npm test",
            exitStatus: 0
        )
        let second = AgentCommandEvent(
            id: UUID(uuidString: "22222222-3333-4444-5555-666666666666")!,
            recordedAt: Date(timeIntervalSince1970: 10),
            agentPlatform: "codex",
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            executable: "swift",
            arguments: ["swift", "test"],
            command: "swift test",
            exitStatus: nil
        )

        try store.record(first)
        try store.record(second)

        let loaded = try store.loadAll()
        XCTAssertEqual(loaded.map(\.id), [second.id, first.id])

        let exported = try store.exportJSON(loaded)
        let decoded = try JSONDecoder.agentCommandHistory.decode([AgentCommandEvent].self, from: exported)
        XCTAssertEqual(decoded.map(\.command), ["swift test", "npm test"])
    }

    func testRecordingSameHookToolUseMergesExitStatusInsteadOfDuplicating() throws {
        let fileURL = try makeTempURL()
        let store = AgentCommandHistoryStore(fileURL: fileURL)
        let pending = AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 10),
            agentPlatform: "claude-code",
            sessionID: "session-1",
            toolUseID: "tool-1",
            captureSource: .hook,
            executable: "swift",
            arguments: ["swift", "test"],
            command: "swift test",
            exitStatus: nil
        )
        let completed = AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 12),
            agentPlatform: "claude-code",
            sessionID: "session-1",
            toolUseID: "tool-1",
            captureSource: .hook,
            executable: "swift",
            arguments: ["swift", "test"],
            command: "swift test",
            exitStatus: 1
        )

        try store.record(pending)
        try store.record(completed)

        let loaded = try store.loadAll()
        XCTAssertEqual(loaded.count, 1)
        XCTAssertEqual(loaded[0].recordedAt, completed.recordedAt)
        XCTAssertEqual(loaded[0].exitStatus, 1)
    }

    func testEventsForGrantMatchByGrantIDRuntimeContextOrTerminalScope() {
        let grantID = UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!
        let grant = AgentJITGrant(
            id: grantID,
            agentName: "Codex",
            callerFingerprint: AgentJITCallerFingerprint(
                processName: "authsia",
                bundleIdentifier: nil,
                signingTeamId: nil,
                signingIdentity: nil,
                parentProcessName: "codex",
                parentBundleIdentifier: nil,
                sessionScope: "tty:/dev/ttys002:sid:84",
                workingDirectory: "/tmp/project"
            ),
            folderScope: .folder("Team/API"),
            capabilities: [.exec, .list],
            createdAt: Date(timeIntervalSince1970: 50),
            expiresAt: Date(timeIntervalSince1970: 500),
            revokedAt: nil,
            lastUsedAt: nil,
            requestedItems: [],
            agentRuntimeContext: AgentRuntimeContext(
                platform: "codex",
                sessionID: "session-1",
                turnID: "turn-1",
                agentID: nil,
                agentType: nil,
                toolUseID: nil
            ),
            approvedBy: "biometric"
        )
        let matchedByContext = AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 20),
            agentPlatform: "codex",
            sessionID: "session-1",
            turnID: "turn-1",
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            terminalSessionScope: nil,
            executable: "swift",
            arguments: ["swift", "test"],
            command: "swift test"
        )
        let matchedByScope = AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 70),
            agentPlatform: "codex",
            captureSource: .process,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            executable: "npm",
            arguments: ["npm", "test"],
            command: "npm test"
        )
        let matchedByGrantID = AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 80),
            agentPlatform: "claude-code",
            agentJITGrantID: grantID,
            captureSource: .hook,
            executable: "make",
            arguments: ["make", "ship"],
            command: "make ship"
        )
        let unrelated = AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 90),
            agentPlatform: "codex",
            sessionID: "other-session",
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            executable: "whoami",
            arguments: ["whoami"],
            command: "whoami"
        )

        let matched = AgentCommandHistoryQuery.events(
            for: grant,
            from: [unrelated, matchedByGrantID, matchedByScope, matchedByContext]
        )

        XCTAssertEqual(matched.map(\.command), ["swift test", "npm test", "make ship"])
    }

    func testFileActivityEventSanitizesPathsAndRedactsSensitiveArguments() {
        let event = AgentFileActivityEvent(
            recordedAt: Date(timeIntervalSince1970: 10),
            agentPlatform: " claude-\u{0}code ",
            sessionID: " \u{0} ",
            turnID: " turn-\u{0}1 ",
            agentID: " ",
            agentType: " coding-\u{7}agent ",
            toolUseID: " tool-\u{8}1 ",
            captureSource: .hook,
            workingDirectory: " /tmp/pro\u{0}ject ",
            terminalSessionScope: " \n\t ",
            workspaceRoot: " /tmp/pro\u{0}ject ",
            path: " /tmp/pro\u{0}ject/.env ",
            kind: .file,
            action: .read,
            status: .succeeded,
            confidence: .direct,
            detail: " Read\u{8} file "
        )

        XCTAssertEqual(event.path, "/tmp/project/.env")
        XCTAssertEqual(event.workspaceRelativePath, ".env")
        XCTAssertEqual(event.agentPlatform, "claude-code")
        XCTAssertNil(event.sessionID)
        XCTAssertEqual(event.turnID, "turn-1")
        XCTAssertNil(event.agentID)
        XCTAssertEqual(event.agentType, "coding-agent")
        XCTAssertEqual(event.toolUseID, "tool-1")
        XCTAssertEqual(event.workingDirectory, "/tmp/project")
        XCTAssertNil(event.terminalSessionScope)
        XCTAssertEqual(event.workspaceRoot, "/tmp/project")
        XCTAssertEqual(event.kind, .file)
        XCTAssertEqual(event.action, .read)
        XCTAssertEqual(event.status, .succeeded)
        XCTAssertEqual(event.confidence, .direct)
        XCTAssertEqual(event.detail, "Read file")
    }

    func testFileActivityStorePersistsLoadsAndExportsJSON() throws {
        let fileURL = try makeTempURL()
        let store = AgentFileActivityStore(fileURL: fileURL)
        let first = AgentFileActivityEvent(
            id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            recordedAt: Date(timeIntervalSince1970: 20),
            agentPlatform: "codex",
            sessionID: "session-1",
            toolUseID: "tool-2",
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project/Sources/App.swift",
            kind: .file,
            action: .modify,
            status: .succeeded,
            confidence: .direct
        )
        let second = AgentFileActivityEvent(
            id: UUID(uuidString: "22222222-3333-4444-5555-666666666666")!,
            recordedAt: Date(timeIntervalSince1970: 10),
            agentPlatform: "codex",
            sessionID: "session-1",
            toolUseID: "tool-1",
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project/Sources",
            kind: .directory,
            action: .list,
            status: .succeeded,
            confidence: .direct
        )

        try store.record(first)
        try store.record(second)

        let loaded = try store.loadAll()
        XCTAssertEqual(loaded.map(\.id), [second.id, first.id])

        let directoryAttributes = try FileManager.default.attributesOfItem(atPath: fileURL.deletingLastPathComponent().path)
        let fileAttributes = try FileManager.default.attributesOfItem(atPath: fileURL.path)
        XCTAssertEqual((directoryAttributes[.posixPermissions] as? NSNumber)?.intValue, 0o700)
        XCTAssertEqual((fileAttributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)

        let exported = try store.exportJSON(loaded)
        let decoded = try XCTUnwrap(JSONSerialization.jsonObject(with: exported) as? [[String: Any]])
        XCTAssertEqual(decoded.compactMap { $0["workspaceRelativePath"] as? String }, ["Sources", "Sources/App.swift"])
        XCTAssertNil(decoded[0]["path"])
        XCTAssertNil(decoded[0]["workingDirectory"])
        XCTAssertNil(decoded[0]["workspaceRoot"])
    }

    func testFileActivityEventsForGrantMatchByGrantIDRuntimeContextOrTerminalScope() {
        let grant = makeGrant()
        let matchedByContext = AgentFileActivityEvent(
            recordedAt: Date(timeIntervalSince1970: 20),
            agentPlatform: "claude-code",
            sessionID: "session-1",
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project/Package.swift",
            kind: .file,
            action: .read,
            status: .succeeded,
            confidence: .direct
        )
        let matchedByGrantID = AgentFileActivityEvent(
            recordedAt: Date(timeIntervalSince1970: 25),
            agentPlatform: "codex",
            sessionID: "other-session",
            agentJITGrantID: grant.id,
            captureSource: .hook,
            workingDirectory: "/tmp/other",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project/Granted.swift",
            kind: .file,
            action: .modify,
            status: .succeeded,
            confidence: .direct
        )
        let matchedByScope = AgentFileActivityEvent(
            recordedAt: Date(timeIntervalSince1970: 30),
            agentPlatform: "claude-code",
            captureSource: .workspaceDiff,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project/Sources",
            kind: .directory,
            action: .list,
            status: .succeeded,
            confidence: .fallback
        )
        let conflictingContext = AgentFileActivityEvent(
            recordedAt: Date(timeIntervalSince1970: 32),
            agentPlatform: "claude-code",
            sessionID: "other-session",
            turnID: "turn-1",
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project/Conflicting.swift",
            kind: .file,
            action: .read,
            status: .succeeded,
            confidence: .direct
        )
        let scopeWithoutWorkingDirectory = AgentFileActivityEvent(
            recordedAt: Date(timeIntervalSince1970: 33),
            agentPlatform: "claude-code",
            captureSource: .workspaceDiff,
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project/MissingCWD.swift",
            kind: .file,
            action: .read,
            status: .succeeded,
            confidence: .fallback
        )
        let hookScopeOnly = AgentFileActivityEvent(
            recordedAt: Date(timeIntervalSince1970: 35),
            agentPlatform: "claude-code",
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project/HookOnly.swift",
            kind: .file,
            action: .read,
            status: .succeeded,
            confidence: .direct
        )
        let unrelated = AgentFileActivityEvent(
            recordedAt: Date(timeIntervalSince1970: 40),
            agentPlatform: "claude-code",
            sessionID: "other-session",
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project/README.md",
            kind: .file,
            action: .read,
            status: .succeeded,
            confidence: .direct
        )

        let matched = AgentFileActivityQuery.events(
            for: grant,
            from: [
                unrelated,
                hookScopeOnly,
                scopeWithoutWorkingDirectory,
                conflictingContext,
                matchedByScope,
                matchedByGrantID,
                matchedByContext,
            ]
        )

        XCTAssertEqual(matched.map(\.workspaceRelativePath), ["Package.swift", "Granted.swift", "Sources"])
    }

    func testFindingSeverityEncodingUsesOnlyInfoReviewAndWarning() throws {
        XCTAssertEqual(
            Set(AgentCommandFindingSeverity.allCases.map(\.rawValue)),
            ["info", "review", "warning"]
        )
    }

    func testFindingDetectorReturnsNoFindingsForNormalHookCapturedCommand() {
        let grant = makeGrant()
        let event = AgentCommandEvent(
            id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            recordedAt: Date(timeIntervalSince1970: 100),
            agentPlatform: "claude-code",
            agentJITGrantID: grant.id,
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            executable: "swift",
            arguments: ["swift", "test"],
            command: "swift test",
            exitStatus: 0
        )

        let findings = AgentCommandFindingDetector.findings(for: grant, events: [event], auditRecords: [])

        XCTAssertTrue(findings.isEmpty)
    }

    func testFindingDetectorWarnsWhenCommandRunsAfterGrantEnded() {
        let grant = makeGrant(expiresAt: Date(timeIntervalSince1970: 100))
        let event = AgentCommandEvent(
            id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            recordedAt: Date(timeIntervalSince1970: 120),
            agentPlatform: "claude-code",
            agentJITGrantID: grant.id,
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            executable: "swift",
            arguments: ["swift", "test"],
            command: "swift test",
            exitStatus: 0
        )

        let findings = AgentCommandFindingDetector.findings(for: grant, events: [event], auditRecords: [])

        XCTAssertEqual(findings.map(\.type), [.commandAfterGrantEnded])
        XCTAssertEqual(findings.map(\.severity), [.warning])
        XCTAssertEqual(findings.first?.evidenceEventIDs, [event.id])
        XCTAssertEqual(findings.first?.fileEvidenceEventIDs, [])
    }

    func testFindingDetectorWarnsWhenCommandRunsAfterGrantRevoked() {
        let grant = makeGrant(revokedAt: Date(timeIntervalSince1970: 100))
        let event = AgentCommandEvent(
            id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            recordedAt: Date(timeIntervalSince1970: 120),
            agentPlatform: "claude-code",
            agentJITGrantID: grant.id,
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            executable: "swift",
            arguments: ["swift", "test"],
            command: "swift test",
            exitStatus: 0
        )

        let findings = AgentCommandFindingDetector.findings(for: grant, events: [event], auditRecords: [])

        XCTAssertEqual(findings.map(\.type), [.commandAfterGrantEnded])
        XCTAssertEqual(findings.map(\.severity), [.warning])
    }

    func testFindingDetectorRecordsProcessOnlyCaptureAsInfoForHookCapableAgent() {
        let grant = makeGrant()
        let event = AgentCommandEvent(
            id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            recordedAt: Date(timeIntervalSince1970: 100),
            agentPlatform: "claude-code",
            agentJITGrantID: grant.id,
            captureSource: .process,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            executable: "npm",
            arguments: ["npm", "test"],
            command: "npm test",
            exitStatus: nil
        )

        let findings = AgentCommandFindingDetector.findings(for: grant, events: [event], auditRecords: [])

        XCTAssertEqual(findings.map(\.type), [.processOnlyCapture])
        XCTAssertEqual(findings.map(\.severity), [.info])
    }

    func testFindingDetectorDoesNotReviewProcessCaptureWhenMatchingHookExists() {
        let grant = makeGrant()
        let processEvent = AgentCommandEvent(
            id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            recordedAt: Date(timeIntervalSince1970: 100),
            agentPlatform: "claude-code",
            agentJITGrantID: grant.id,
            captureSource: .process,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            executable: "npm",
            arguments: ["npm", "test"],
            command: "npm test"
        )
        let hookEvent = AgentCommandEvent(
            id: UUID(uuidString: "22222222-3333-4444-5555-666666666666")!,
            recordedAt: Date(timeIntervalSince1970: 104),
            agentPlatform: "claude-code",
            sessionID: "session-1",
            toolUseID: "tool-1",
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            executable: "npm",
            arguments: ["npm", "test"],
            command: "npm test"
        )

        let findings = AgentCommandFindingDetector.findings(
            for: grant,
            events: [processEvent, hookEvent],
            auditRecords: []
        )

        XCTAssertFalse(findings.contains { $0.type == .processOnlyCapture })
    }

    func testFindingDetectorReviewsDeniedDirectSecretReadAttempts() {
        let grant = makeGrant()
        let event = AgentCommandEvent(
            id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            recordedAt: Date(timeIntervalSince1970: 100),
            agentPlatform: "claude-code",
            agentJITGrantID: grant.id,
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            executable: "/usr/local/bin/authsia",
            arguments: ["/usr/local/bin/authsia", "get", "password", "API_KEY"],
            command: "/usr/local/bin/authsia get password API_KEY",
            exitStatus: 1
        )

        let findings = AgentCommandFindingDetector.findings(for: grant, events: [event], auditRecords: [])

        XCTAssertEqual(findings.map(\.type), [.deniedDirectSecretRead])
        XCTAssertEqual(findings.map(\.severity), [.review])
    }

    func testFindingDetectorReviewsPossibleEnvironmentExposure() {
        let grant = makeGrant()
        let event = AgentCommandEvent(
            id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            recordedAt: Date(timeIntervalSince1970: 100),
            agentPlatform: "claude-code",
            agentJITGrantID: grant.id,
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            executable: "printenv",
            arguments: ["printenv"],
            command: "printenv",
            exitStatus: 0
        )

        let findings = AgentCommandFindingDetector.findings(for: grant, events: [event], auditRecords: [])

        XCTAssertEqual(findings.map(\.type), [.possibleEnvironmentExposure])
        XCTAssertEqual(findings.map(\.severity), [.review])
    }

    func testFindingDetectorReviewsSensitiveFileActivity() {
        let grant = makeGrant()
        let sensitivePaths = [
            ".env.production",
            ".envrc",
            ".npmrc",
            ".pypirc",
            ".netrc",
            ".aws/credentials",
            "credentials",
            "id_ecdsa",
            "identity.p12",
            "identity.pfx",
        ]
        let sensitiveEvents = sensitivePaths.enumerated().map { offset, path in
            AgentFileActivityEvent(
                recordedAt: Date(timeIntervalSince1970: TimeInterval(100 + offset)),
                agentPlatform: "claude-code",
                agentJITGrantID: grant.id,
                captureSource: .hook,
                workingDirectory: "/tmp/project",
                workspaceRoot: "/tmp/project",
                path: "/tmp/project/\(path)",
                kind: .file,
                action: .read,
                status: .succeeded,
                confidence: .direct
            )
        }
        let benignEvent = AgentFileActivityEvent(
            id: UUID(uuidString: "22222222-3333-4444-5555-666666666666")!,
            recordedAt: Date(timeIntervalSince1970: 200),
            agentPlatform: "claude-code",
            agentJITGrantID: grant.id,
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project/README.md",
            kind: .file,
            action: .read,
            status: .succeeded,
            confidence: .direct
        )

        let findings = AgentCommandFindingDetector.findings(
            for: grant,
            events: [],
            fileEvents: [benignEvent] + sensitiveEvents,
            auditRecords: []
        )

        XCTAssertEqual(
            findings.map(\.type),
            Array(repeating: .sensitiveFileActivity, count: sensitiveEvents.count)
        )
        XCTAssertEqual(findings.map(\.severity), Array(repeating: .review, count: sensitiveEvents.count))
        XCTAssertEqual(findings.map(\.evidenceEventIDs), Array(repeating: [], count: sensitiveEvents.count))
        XCTAssertEqual(findings.map(\.fileEvidenceEventIDs), sensitiveEvents.map { [$0.id] })
    }

    func testFindingDetectorReviewsOutsideWorkspaceFileActivity() {
        let grant = makeGrant()
        let outsideEvent = AgentFileActivityEvent(
            id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            recordedAt: Date(timeIntervalSince1970: 100),
            agentPlatform: "claude-code",
            agentJITGrantID: grant.id,
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            workspaceRoot: "/tmp/project",
            path: "/tmp/other/README.md",
            kind: .file,
            action: .read,
            status: .succeeded,
            confidence: .direct
        )
        let relativeInsideEvent = AgentFileActivityEvent(
            id: UUID(uuidString: "33333333-4444-5555-6666-777777777777")!,
            recordedAt: Date(timeIntervalSince1970: 105),
            agentPlatform: "claude-code",
            agentJITGrantID: grant.id,
            captureSource: .hook,
            workingDirectory: "/tmp/other",
            workspaceRoot: "/tmp/project",
            path: "Sources/App.swift",
            kind: .file,
            action: .read,
            status: .succeeded,
            confidence: .direct
        )
        let workspaceRootEvent = AgentFileActivityEvent(
            id: UUID(uuidString: "22222222-3333-4444-5555-666666666666")!,
            recordedAt: Date(timeIntervalSince1970: 110),
            agentPlatform: "claude-code",
            agentJITGrantID: grant.id,
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project",
            kind: .directory,
            action: .list,
            status: .succeeded,
            confidence: .direct
        )

        let findings = AgentCommandFindingDetector.findings(
            for: [grant],
            events: [],
            fileEvents: [workspaceRootEvent, relativeInsideEvent, outsideEvent],
            auditRecords: []
        )

        XCTAssertEqual(findings.map(\.type), [.outsideWorkspaceFileActivity])
        XCTAssertEqual(findings.map(\.severity), [.review])
        XCTAssertEqual(findings.first?.evidenceEventIDs, [])
        XCTAssertEqual(findings.first?.fileEvidenceEventIDs, [outsideEvent.id])
    }

    func testFindingDetectorMarksCodexProcessFallbackAsInfo() {
        let grant = makeGrant(agentName: "Codex")
        let event = AgentCommandEvent(
            id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            recordedAt: Date(timeIntervalSince1970: 100),
            agentPlatform: "codex",
            agentJITGrantID: grant.id,
            captureSource: .process,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            executable: "swift",
            arguments: ["swift", "test"],
            command: "swift test",
            exitStatus: nil
        )

        let findings = AgentCommandFindingDetector.findings(for: grant, events: [event], auditRecords: [])

        XCTAssertEqual(findings.map(\.type), [.processFallbackUsed])
        XCTAssertEqual(findings.map(\.severity), [.info])
    }

    func testCommandHistoryExportCanIncludeFindingsAndSummaryCounts() throws {
        let eventID = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
        let event = AgentCommandEvent(
            id: eventID,
            recordedAt: Date(timeIntervalSince1970: 100),
            agentPlatform: "codex",
            captureSource: .process,
            executable: "swift",
            arguments: ["swift", "test"],
            command: "swift test"
        )
        let finding = AgentCommandFinding(
            severity: .info,
            type: .processFallbackUsed,
            agentJITGrantID: nil,
            evidenceEventIDs: [eventID],
            recordedAt: event.recordedAt,
            title: "Process fallback used",
            detail: "Authsia recorded this command through local process monitoring.",
            recommendedAction: "Review the command if this was unexpected."
        )
        let store = AgentCommandHistoryStore(fileURL: try makeTempURL())

        let exported = try store.exportJSON(events: [event], findings: [finding])
        let decoded = try JSONDecoder.agentCommandHistory.decode(AgentCommandHistoryExport.self, from: exported)

        XCTAssertEqual(decoded.events.map(\.id), [eventID])
        XCTAssertEqual(decoded.findings.map(\.id), [finding.id])
        XCTAssertEqual(decoded.summary.infoCount, 1)
        XCTAssertEqual(decoded.summary.reviewCount, 0)
        XCTAssertEqual(decoded.summary.warningCount, 0)
    }

    func testAgentSessionActivityExportIncludesCommandsFilesAndFindings() throws {
        let commandID = UUID(uuidString: "11111111-2222-3333-4444-555555555555")!
        let fileID = UUID(uuidString: "22222222-3333-4444-5555-666666666666")!
        let command = AgentCommandEvent(
            id: commandID,
            recordedAt: Date(timeIntervalSince1970: 100),
            agentPlatform: "codex",
            captureSource: .hook,
            executable: "swift",
            arguments: ["swift", "test"],
            command: "swift test"
        )
        let file = AgentFileActivityEvent(
            id: fileID,
            recordedAt: Date(timeIntervalSince1970: 101),
            agentPlatform: "codex",
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project/Package.swift",
            kind: .file,
            action: .read,
            status: .succeeded,
            confidence: .direct
        )
        let finding = AgentCommandFinding(
            severity: .review,
            type: .sensitiveFileActivity,
            agentJITGrantID: nil,
            evidenceEventIDs: [commandID],
            recordedAt: file.recordedAt,
            title: "Sensitive file activity",
            detail: "Authsia observed file activity that may need review.",
            recommendedAction: "Review the file access."
        )

        let export = AgentSessionActivityExport(commands: [command], files: [file], findings: [finding])
        let encoded = try JSONEncoder.agentCommandHistory.encode(export)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        let files = try XCTUnwrap(json["files"] as? [[String: Any]])

        XCTAssertEqual(export.commands.count, 1)
        XCTAssertEqual(export.files.count, 1)
        XCTAssertEqual(export.findings.count, 1)
        XCTAssertEqual(export.summary.totalCount, 1)
        XCTAssertEqual(files.first?["workspaceRelativePath"] as? String, "Package.swift")
        XCTAssertNil(files.first?["path"])
        XCTAssertNil(files.first?["workingDirectory"])
        XCTAssertNil(files.first?["workspaceRoot"])
    }

    func testCommandFindingDecodesMissingFileEvidenceAsEmpty() throws {
        let data = """
        {
          "agentJITGrantID": null,
          "detail": "Authsia recorded this command through local process monitoring.",
          "evidenceEventIDs": ["11111111-2222-3333-4444-555555555555"],
          "id": "legacy-finding",
          "recommendedAction": "Review the command if this was unexpected.",
          "recordedAt": "1970-01-01T00:01:40Z",
          "severity": "info",
          "title": "Process fallback used",
          "type": "processFallbackUsed"
        }
        """.data(using: .utf8)!

        let decoded = try JSONDecoder.agentCommandHistory.decode(AgentCommandFinding.self, from: data)

        XCTAssertEqual(decoded.evidenceEventIDs, [UUID(uuidString: "11111111-2222-3333-4444-555555555555")!])
        XCTAssertEqual(decoded.fileEvidenceEventIDs, [])
    }

    func testCommandEventsRejectConflictingRuntimeContextIdentifiers() {
        let grant = makeGrant()
        let conflictingContext = AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 100),
            agentPlatform: "claude-code",
            sessionID: "other-session",
            turnID: "turn-1",
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            terminalSessionScope: nil,
            executable: "swift",
            arguments: ["swift", "test"],
            command: "swift test"
        )
        let matched = AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 110),
            agentPlatform: "claude-code",
            sessionID: "session-1",
            turnID: "turn-1",
            captureSource: .hook,
            workingDirectory: "/tmp/project",
            terminalSessionScope: nil,
            executable: "npm",
            arguments: ["npm", "test"],
            command: "npm test"
        )

        let events = AgentCommandHistoryQuery.events(for: grant, from: [conflictingContext, matched])
        let findings = AgentCommandFindingDetector.findings(
            for: grant,
            events: [conflictingContext],
            auditRecords: []
        )

        XCTAssertEqual(events.map(\.command), ["npm test"])
        XCTAssertTrue(findings.isEmpty)
    }

    func testProcessMonitorCapturesOnlyActiveManagedAgentScope() {
        let grantID = UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!
        let grant = AgentJITGrant(
            id: grantID,
            agentName: "Codex",
            callerFingerprint: AgentJITCallerFingerprint(
                processName: "authsia",
                bundleIdentifier: nil,
                signingTeamId: nil,
                signingIdentity: nil,
                parentProcessName: "codex",
                parentBundleIdentifier: nil,
                sessionScope: "tty:/dev/ttys002:sid:84",
                workingDirectory: "/tmp/project"
            ),
            folderScope: .folder("Team/API"),
            capabilities: [.exec, .list],
            createdAt: Date(timeIntervalSince1970: 50),
            expiresAt: Date(timeIntervalSince1970: 500),
            revokedAt: nil,
            lastUsedAt: nil,
            requestedItems: [],
            agentRuntimeContext: nil,
            approvedBy: "biometric"
        )
        let monitor = AgentCommandProcessMonitor(snapshotProvider: {
            [
                AgentCommandProcessSnapshot(
                    pid: 10,
                    processName: "swift",
                    arguments: ["swift", "test"],
                    workingDirectory: "/tmp/project",
                    terminalSessionScope: "tty:/dev/ttys002:sid:84",
                    ancestry: [
                        AgenticProcessReference(processName: "swift", bundleIdentifier: nil),
                        AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
                        AgenticProcessReference(processName: "codex", bundleIdentifier: nil),
                    ]
                ),
                AgentCommandProcessSnapshot(
                    pid: 11,
                    processName: "npm",
                    arguments: ["npm", "test"],
                    workingDirectory: "/tmp/other",
                    terminalSessionScope: "tty:/dev/ttys003:sid:85",
                    ancestry: [
                        AgenticProcessReference(processName: "npm", bundleIdentifier: nil),
                        AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
                        AgenticProcessReference(processName: "codex", bundleIdentifier: nil),
                    ]
                ),
                AgentCommandProcessSnapshot(
                    pid: 12,
                    processName: "make",
                    arguments: ["make", "test"],
                    workingDirectory: "/tmp/project",
                    terminalSessionScope: "tty:/dev/ttys002:sid:84",
                    ancestry: [
                        AgenticProcessReference(processName: "make", bundleIdentifier: nil),
                        AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
                        AgenticProcessReference(processName: "Terminal", bundleIdentifier: "com.apple.Terminal"),
                    ]
                ),
            ]
        })

        let events = monitor.events(for: [grant], now: Date(timeIntervalSince1970: 100))

        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(events[0].agentJITGrantID, grantID)
        XCTAssertEqual(events[0].agentPlatform, "codex")
        XCTAssertEqual(events[0].captureSource, .process)
        XCTAssertEqual(events[0].command, "swift test")
    }

    func testProcessMonitorDoesNotRecordAgentProcessItselfAsCommand() {
        let grant = AgentJITGrant(
            id: UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!,
            agentName: "Claude Code",
            callerFingerprint: AgentJITCallerFingerprint(
                processName: "authsia",
                bundleIdentifier: nil,
                signingTeamId: nil,
                signingIdentity: nil,
                parentProcessName: "claude",
                parentBundleIdentifier: nil,
                sessionScope: "tty:/dev/ttys002:sid:84",
                workingDirectory: "/tmp/project"
            ),
            folderScope: .folder("Team/API"),
            capabilities: [.exec, .list],
            createdAt: Date(timeIntervalSince1970: 50),
            expiresAt: Date(timeIntervalSince1970: 500),
            revokedAt: nil,
            lastUsedAt: nil,
            requestedItems: [],
            agentRuntimeContext: nil,
            approvedBy: "biometric"
        )
        let monitor = AgentCommandProcessMonitor(snapshotProvider: {
            [
                AgentCommandProcessSnapshot(
                    pid: 10,
                    processName: "claude",
                    arguments: ["claude"],
                    workingDirectory: "/tmp/project",
                    terminalSessionScope: "tty:/dev/ttys002:sid:84",
                    ancestry: [
                        AgenticProcessReference(processName: "claude", bundleIdentifier: nil),
                        AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
                    ]
                ),
            ]
        })

        XCTAssertTrue(monitor.events(for: [grant], now: Date(timeIntervalSince1970: 100)).isEmpty)
    }

    func testProcessMonitorLabelsVSCodeCopilotExtensionAncestryAsCopilot() {
        let grantID = UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!
        let grant = AgentJITGrant(
            id: grantID,
            agentName: "GitHub Copilot",
            callerFingerprint: AgentJITCallerFingerprint(
                processName: "authsia",
                bundleIdentifier: nil,
                signingTeamId: nil,
                signingIdentity: nil,
                parentProcessName: "Code Helper",
                parentBundleIdentifier: "com.microsoft.VSCode",
                sessionScope: "tty:/dev/ttys004:sid:88",
                workingDirectory: "/tmp/project"
            ),
            folderScope: .folder("Team/API"),
            capabilities: [.exec, .list],
            createdAt: Date(timeIntervalSince1970: 50),
            expiresAt: Date(timeIntervalSince1970: 500),
            revokedAt: nil,
            lastUsedAt: nil,
            requestedItems: [],
            agentRuntimeContext: nil,
            approvedBy: "biometric"
        )
        let monitor = AgentCommandProcessMonitor(snapshotProvider: {
            [
                AgentCommandProcessSnapshot(
                    pid: 10,
                    processName: "npm",
                    arguments: ["npm", "test"],
                    workingDirectory: "/tmp/project",
                    terminalSessionScope: "tty:/dev/ttys004:sid:88",
                    ancestry: [
                        AgenticProcessReference(processName: "npm", bundleIdentifier: nil),
                        AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
                        AgenticProcessReference(
                            processName: "Code Helper",
                            bundleIdentifier: "com.microsoft.VSCode",
                            arguments: [
                                "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper",
                                "--type=extensionHost",
                                "--extensionDevelopmentPath=/Users/example/.vscode/extensions/github.copilot-chat-1.2.3",
                            ]
                        ),
                    ]
                ),
            ]
        })

        let events = monitor.events(for: [grant], now: Date(timeIntervalSince1970: 100))

        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(events[0].agentJITGrantID, grantID)
        XCTAssertEqual(events[0].agentPlatform, "copilot")
        XCTAssertEqual(events[0].captureSource, .process)
        XCTAssertEqual(events[0].command, "npm test")
    }

    private func makeTempURL() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-command-history-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("events.jsonl")
    }

    private func makeGrant(
        agentName: String = "Claude Code",
        expiresAt: Date = Date(timeIntervalSince1970: 500),
        revokedAt: Date? = nil
    ) -> AgentJITGrant {
        AgentJITGrant(
            id: UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!,
            agentName: agentName,
            callerFingerprint: AgentJITCallerFingerprint(
                processName: "authsia",
                bundleIdentifier: nil,
                signingTeamId: nil,
                signingIdentity: nil,
                parentProcessName: agentName == "Codex" ? "codex" : "claude",
                parentBundleIdentifier: nil,
                sessionScope: "tty:/dev/ttys002:sid:84",
                workingDirectory: "/tmp/project"
            ),
            folderScope: .folder("Team/API"),
            capabilities: [.exec, .list],
            createdAt: Date(timeIntervalSince1970: 50),
            expiresAt: expiresAt,
            revokedAt: revokedAt,
            lastUsedAt: nil,
            requestedItems: [],
            agentRuntimeContext: AgentRuntimeContext(
                platform: agentName == "Codex" ? "codex" : "claude-code",
                sessionID: "session-1",
                turnID: "turn-1",
                agentID: nil,
                agentType: nil,
                toolUseID: nil
            ),
            approvedBy: "biometric"
        )
    }
}
