import XCTest
@testable import AuthenticatorBridge

final class AgentSecretPathPolicyTests: XCTestCase {
    func testHighSignalSecretPaths() {
        XCTAssertTrue(AgentSecretPathPolicy.isHighSignalSecretPath("/tmp/project/.env"))
        XCTAssertTrue(AgentSecretPathPolicy.isHighSignalSecretPath("/tmp/project/.env.production"))
        XCTAssertTrue(AgentSecretPathPolicy.isHighSignalSecretPath("/tmp/id_ed25519"))
        XCTAssertTrue(AgentSecretPathPolicy.isHighSignalSecretPath("/tmp/cert.pem"))
        XCTAssertFalse(AgentSecretPathPolicy.isHighSignalSecretPath("/tmp/project/.env.example"))
        XCTAssertFalse(AgentSecretPathPolicy.isHighSignalSecretPath("/tmp/project/notes.txt"))
    }

    func testInjectedExecFindings() {
        let grant = AgentJITGrant(
            id: UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!,
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
            capabilities: [.exec],
            createdAt: Date(timeIntervalSince1970: 50),
            expiresAt: Date(timeIntervalSince1970: 500),
            revokedAt: nil,
            lastUsedAt: nil,
            requestedItems: [],
            approvedBy: "biometric"
        )

        let scrubbed = AgentFileActivityEvent(
            recordedAt: Date(timeIntervalSince1970: 10),
            agentPlatform: "codex",
            agentJITGrantID: grant.id,
            captureSource: .injectedExec,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project/.env",
            kind: .file,
            action: .modify,
            status: .succeeded,
            confidence: .direct,
            detail: InjectedSecretFileActivityDetail.scrubbed
        )
        let detected = AgentFileActivityEvent(
            recordedAt: Date(timeIntervalSince1970: 11),
            agentPlatform: "codex",
            agentJITGrantID: grant.id,
            captureSource: .injectedExec,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project/notes.txt",
            kind: .file,
            action: .modify,
            status: .inferred,
            confidence: .direct,
            detail: InjectedSecretFileActivityDetail.secretDetected
        )
        let verificationFailed = AgentFileActivityEvent(
            recordedAt: Date(timeIntervalSince1970: 12),
            agentPlatform: "codex",
            agentJITGrantID: grant.id,
            captureSource: .injectedExec,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project/.env",
            kind: .file,
            action: .modify,
            status: .failed,
            confidence: .direct,
            detail: InjectedSecretFileActivityDetail.verificationFailed
        )
        let inspectionFailed = AgentFileActivityEvent(
            recordedAt: Date(timeIntervalSince1970: 13),
            agentPlatform: "codex",
            agentJITGrantID: grant.id,
            captureSource: .injectedExec,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project/unreadable.txt",
            kind: .file,
            action: .modify,
            status: .failed,
            confidence: .direct,
            detail: "inspection-failed"
        )
        let remediationFailed = AgentFileActivityEvent(
            recordedAt: Date(timeIntervalSince1970: 14),
            agentPlatform: "codex",
            agentJITGrantID: grant.id,
            captureSource: .injectedExec,
            workingDirectory: "/tmp/project",
            terminalSessionScope: "tty:/dev/ttys002:sid:84",
            workspaceRoot: "/tmp/project",
            path: "/tmp/project/.env",
            kind: .file,
            action: .modify,
            status: .failed,
            confidence: .direct,
            detail: InjectedSecretFileActivityDetail.remediationFailed
        )

        let findings = AgentCommandFindingDetector.findings(
            for: grant,
            events: [],
            fileEvents: [
                scrubbed,
                detected,
                verificationFailed,
                inspectionFailed,
                remediationFailed,
            ],
            auditRecords: []
        )

        XCTAssertEqual(
            Set(findings.map { $0.type.rawValue }),
            [
                "secretDetectedInFile",
                "secretFileScrubbed",
                "secretFileInspectionIncomplete",
                "secretFileCleanupIncomplete",
            ]
        )
        XCTAssertEqual(findings.count, 5)
        let scrubbedFinding = findings.first { $0.type == .secretFileScrubbed }
        XCTAssertEqual(scrubbedFinding?.severity, .info)
        XCTAssertEqual(
            scrubbedFinding?.detail,
            "A known injected secret was replaced with a concealment placeholder in an "
                + "observed candidate file after the mediated child exited."
        )
        let detectedFinding = findings.first { $0.type == .secretDetectedInFile }
        XCTAssertEqual(detectedFinding?.severity, .review)
        XCTAssertEqual(
            detectedFinding?.detail,
            "A known injected secret was confirmed in an observed candidate file and "
                + "intentionally left unchanged because secret-file cleanup was not enabled "
                + "for this run."
        )
        let inspectionFinding = findings.first {
            $0.type.rawValue == "secretFileInspectionIncomplete"
        }
        XCTAssertEqual(inspectionFinding?.fileEvidenceEventIDs, [inspectionFailed.id])
        XCTAssertEqual(inspectionFinding?.severity, .review)
        XCTAssertEqual(inspectionFinding?.title, "Secret-file inspection incomplete")
        XCTAssertEqual(
            inspectionFinding?.detail,
            "Bounded post-exit inspection could not complete, so secret presence in the "
                + "touched file was not confirmed."
        )
        let cleanupFindings = findings.filter { $0.type == .secretFileCleanupIncomplete }
        XCTAssertEqual(cleanupFindings.count, 2)
        XCTAssertEqual(
            Set(cleanupFindings.map(\.fileEvidenceEventIDs)),
            Set([[verificationFailed.id], [remediationFailed.id]])
        )
        XCTAssertEqual(Set(cleanupFindings.map(\.severity)), [.review])
        XCTAssertEqual(Set(cleanupFindings.map(\.title)), ["Secret-file cleanup incomplete"])
        XCTAssertEqual(
            Set(cleanupFindings.map(\.detail)),
            ["Authsia could not verify that a known injected secret was removed from a touched file."]
        )
        XCTAssertEqual(
            Set(cleanupFindings.map(\.recommendedAction)),
            ["Review the affected file activity and remove or rotate any exposed secret if needed."]
        )
    }
}
