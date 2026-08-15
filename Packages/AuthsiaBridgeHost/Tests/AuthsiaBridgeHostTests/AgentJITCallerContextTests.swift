#if os(macOS)
import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge

final class AgentJITCallerContextTests: XCTestCase {
    func testExtractIncludesSigningMetadataAcrossGhosttyLoginBoundaryWhenRequested() throws {
        guard let rawPID = ProcessInfo.processInfo.environment["AUTHSIA_DIAGNOSTIC_PID"],
              let pid = Int32(rawPID) else {
            throw XCTSkip("Set AUTHSIA_DIAGNOSTIC_PID to inspect a live process.")
        }
        let caller = try XCTUnwrap(CallerIdentityExtractor.extract(fromPID: pid))
        let host = try XCTUnwrap(caller.parentProcess)
        XCTAssertEqual(host.bundleIdentifier, "com.mitchellh.ghostty")
        XCTAssertFalse((host.signingTeamId ?? "").isEmpty)
        XCTAssertFalse((host.signingIdentity ?? "").isEmpty)

        let hostIdentity = try XCTUnwrap(CallerIdentityExtractor.extract(fromPID: host.pid))
        XCTAssertFalse((hostIdentity.signingTeamId ?? "").isEmpty)
        XCTAssertFalse((hostIdentity.signingIdentity ?? "").isEmpty)
    }

    func testExtractFromNonexistentPIDReturnsNil() {
        XCTAssertNil(CallerIdentityExtractor.extract(fromPID: pid_t.max))
    }

    func testDoesNotFlagHumanTerminalCaller() {
        XCTAssertFalse(AgentJITCallerContext.hasAgenticCaller(humanTerminalCaller()))
    }

    /// The host built detector references without argv, so every argument-based rule was
    /// dead on this side — GitHub Copilot is detected only through its extension path, so
    /// an agent running inside the IDE looked like the human and never took the JIT path.
    func testDetectsCopilotExtensionHostFromCallerArguments() {
        let caller = CallerIdentity(
            pid: 501,
            processName: "authsia",
            bundleIdentifier: "com.authsia.cli",
            signingTeamId: "33M8QU65SP",
            signingIdentity: "Developer ID Application: CHEN LIANG (33M8QU65SP)",
            parentProcess: ParentProcessInfo(
                pid: 500,
                processName: "Code Helper (Plugin)",
                bundleIdentifier: "com.microsoft.VSCode.helper",
                arguments: [
                    "/Applications/Visual Studio Code.app/Contents/Frameworks/"
                        + "Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)",
                    "--type=extensionHost",
                    "--extensionDevelopmentPath=/Users/example/.vscode/extensions/github.copilot-chat-1.2.3",
                ]
            )
        )

        XCTAssertTrue(AgentJITCallerContext.hasAgenticCaller(caller))
    }

    /// argv is unavailable for some processes; the executable path must still identify the host.
    func testFallsBackToExecutablePathWhenArgumentsAreUnavailable() {
        let caller = CallerIdentity(
            pid: 601,
            processName: "authsia",
            bundleIdentifier: "com.authsia.cli",
            signingTeamId: nil,
            signingIdentity: nil,
            parentProcess: ParentProcessInfo(
                pid: 600,
                processName: "unknown",
                bundleIdentifier: nil,
                executablePath: "/Applications/Cursor.app/Contents/MacOS/Cursor"
            )
        )

        XCTAssertTrue(AgentJITCallerContext.hasAutomationSuspectCaller(caller))
    }

    func testTrustsSignedTerminalAndShellAncestry() {
        XCTAssertTrue(AgentJITCallerContext.isTrustedHumanTerminal(humanTerminalCaller()))
    }

    func testTrustsBundledCLIIdentifierForSignedTerminalAncestry() {
        XCTAssertTrue(
            AgentJITCallerContext.isTrustedHumanTerminal(
                humanTerminalCaller(cliBundleIdentifier: "authsia")
            )
        )
    }

    func testDoesNotTrustIDEHostedShellAsHumanTerminal() {
        XCTAssertFalse(AgentJITCallerContext.isTrustedHumanTerminal(vscodeHostedCaller()))
    }

    func testTrustsSupportedSignedTerminalHostsWithShellAncestry() {
        for bundleIdentifier in [
            "com.googlecode.iterm2",
            "com.mitchellh.ghostty",
            "dev.warp.Warp",
            "dev.warp.Warp-Stable",
        ] {
            XCTAssertTrue(
                AgentJITCallerContext.isTrustedHumanTerminal(
                    terminalHostedCaller(bundleIdentifier: bundleIdentifier)
                ),
                bundleIdentifier
            )
        }
    }

    func testDoesNotPromoteImitatedITermServerAndHostSignedByAnotherTeam() {
        let context = CallerIdentityExtractor.parentProcessContext(from: [
            ParentProcessInfo(pid: 41, processName: "zsh", bundleIdentifier: nil),
            ParentProcessInfo(pid: 40, processName: "login", bundleIdentifier: nil),
            ParentProcessInfo(
                pid: 39,
                processName: "iTermServer-3.6.11",
                bundleIdentifier: "iTermServer",
                signingTeamId: "ATTACKER",
                signingIdentity: "Developer ID Application"
            ),
            ParentProcessInfo(
                pid: 38,
                processName: "iTerm2",
                bundleIdentifier: "com.googlecode.iterm2",
                signingTeamId: "ATTACKER",
                signingIdentity: "Developer ID Application"
            ),
        ])

        XCTAssertEqual(context.parent?.bundleIdentifier, "iTermServer")
        XCTAssertNil(context.host)
    }

    func testIDEHostsDefaultToAutomationSuspect() {
        for (name, bundleIdentifier) in [
            ("Code Helper", "com.microsoft.VSCode"),
            ("Cursor Helper", "com.todesktop.230313mzl4w4u92"),
            ("IntelliJ IDEA", "com.jetbrains.intellij"),
            ("Zed Helper", "dev.zed.Zed"),
        ] {
            XCTAssertTrue(
                AgentJITCallerContext.hasAutomationSuspectCaller(
                    terminalHostedCaller(
                        hostProcessName: name,
                        bundleIdentifier: bundleIdentifier
                    )
                ),
                bundleIdentifier
            )
        }
    }

    func testWrapperRuntimeBetweenCLIAndTerminalIsNotTrustedHumanAncestry() {
        XCTAssertFalse(
            AgentJITCallerContext.isTrustedHumanTerminal(
                terminalHostedCaller(parentProcessName: "node")
            )
        )
    }

    func testDoesNotTrustRenamedOrUnsignedTerminalHosts() {
        let renamedCLI = CallerIdentity(
            pid: 42,
            processName: "authsia",
            bundleIdentifier: "authsia.fake",
            signingTeamId: "TEAM",
            signingIdentity: "Developer ID Application",
            parentProcess: ParentProcessInfo(
                pid: 41,
                processName: "Terminal",
                bundleIdentifier: "com.apple.Terminal",
                isPlatformBinary: true
            )
        )
        let renamed = CallerIdentity(
            pid: 42,
            processName: "authsia",
            bundleIdentifier: "com.authsia.cli",
            signingTeamId: "TEAM",
            signingIdentity: "Developer ID Application",
            parentProcess: ParentProcessInfo(
                pid: 41,
                processName: "Terminal",
                bundleIdentifier: "example.fake-terminal"
            )
        )
        let unsignedCLI = CallerIdentity(
            pid: 42,
            processName: "authsia",
            bundleIdentifier: "com.authsia.cli",
            signingTeamId: nil,
            signingIdentity: nil,
            parentProcess: ParentProcessInfo(
                pid: 41,
                processName: "Terminal",
                bundleIdentifier: "com.apple.Terminal",
                isPlatformBinary: true
            )
        )
        let imitatedAppleTerminal = CallerIdentity(
            pid: 42,
            processName: "authsia",
            bundleIdentifier: "com.authsia.cli",
            signingTeamId: "TEAM",
            signingIdentity: "Developer ID Application",
            parentProcess: ParentProcessInfo(
                pid: 41,
                processName: "Terminal",
                bundleIdentifier: "com.apple.Terminal",
                signingTeamId: "ATTACKER",
                signingIdentity: "Ad Hoc",
                isPlatformBinary: false
            )
        )

        XCTAssertFalse(AgentJITCallerContext.isTrustedHumanTerminal(renamedCLI))
        XCTAssertFalse(AgentJITCallerContext.isTrustedHumanTerminal(renamed))
        XCTAssertFalse(AgentJITCallerContext.isTrustedHumanTerminal(unsignedCLI))
        XCTAssertFalse(AgentJITCallerContext.isTrustedHumanTerminal(imitatedAppleTerminal))
    }

    func testDetectsAgenticParentProcess() {
        XCTAssertTrue(AgentJITCallerContext.hasAgenticCaller(claudeCaller()))
    }

    func testDoesNotDetectIDEHostedShellAsAgenticCaller() {
        XCTAssertFalse(AgentJITCallerContext.hasAgenticCaller(vscodeHostedCaller()))
    }

    func testFingerprintIncludesCallerAncestryAndRequestScope() {
        let request = makeRequest(sessionScope: "tty:/dev/ttys001:sid:10", workingDirectory: "/tmp/project")

        let fingerprint = AgentJITCallerContext.fingerprint(for: request, caller: vscodeHostedCaller())

        XCTAssertEqual(fingerprint?.processName, "authsia")
        XCTAssertEqual(fingerprint?.bundleIdentifier, "com.authsia.cli")
        XCTAssertEqual(fingerprint?.signingTeamId, "TEAM")
        XCTAssertEqual(fingerprint?.signingIdentity, "Developer ID Application")
        XCTAssertEqual(fingerprint?.parentProcessName, "zsh")
        XCTAssertEqual(fingerprint?.parentBundleIdentifier, nil)
        XCTAssertEqual(fingerprint?.hostProcessName, "Code Helper")
        XCTAssertEqual(fingerprint?.hostBundleIdentifier, "com.microsoft.VSCode")
        XCTAssertEqual(fingerprint?.sessionScope, "tty:/dev/ttys001:sid:10")
        XCTAssertEqual(fingerprint?.workingDirectory, "/tmp/project")
    }

    func testFingerprintUsesValidatedWorkspaceRootAcrossDescendantDirectories() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-jit-workspace-\(UUID().uuidString)", isDirectory: true)
        let firstDirectory = root.appendingPathComponent("Am-I-Impacted", isDirectory: true)
        let secondDirectory = root.appendingPathComponent("Am-I-Impacted-IaC/envs/prod", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: firstDirectory, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: secondDirectory, withIntermediateDirectories: true)

        let first = AgentJITCallerContext.fingerprint(
            for: makeRequest(
                sessionScope: "agent:claude-code:sid:1001",
                workingDirectory: firstDirectory.path,
                workspaceAuthorityPath: root.path
            ),
            caller: claudeCaller()
        )
        let second = AgentJITCallerContext.fingerprint(
            for: makeRequest(
                sessionScope: "agent:claude-code:sid:1001",
                workingDirectory: secondDirectory.path,
                workspaceAuthorityPath: root.path
            ),
            caller: claudeCaller()
        )

        XCTAssertEqual(first?.workingDirectory, root.resolvingSymlinksInPath().standardizedFileURL.path)
        XCTAssertEqual(second?.workingDirectory, first?.workingDirectory)
        XCTAssertTrue(try XCTUnwrap(first).matches(XCTUnwrap(second)))
    }

    func testFingerprintRejectsWorkspaceRootAfterSymlinkEscape() throws {
        let container = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-jit-escape-\(UUID().uuidString)", isDirectory: true)
        let root = container.appendingPathComponent("workspace", isDirectory: true)
        let outside = container.appendingPathComponent("outside", isDirectory: true)
        let escape = root.appendingPathComponent("escape", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: container) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: escape, withDestinationURL: outside)

        let fingerprint = AgentJITCallerContext.fingerprint(
            for: makeRequest(
                sessionScope: "agent:claude-code:sid:1001",
                workingDirectory: escape.path,
                workspaceAuthorityPath: root.path
            ),
            caller: claudeCaller()
        )

        XCTAssertEqual(fingerprint?.workingDirectory, escape.path)
    }

    func testCursorExtensionHostFingerprintReusesParentProcessScopeAcrossChildSessions() {
        let caller = cursorHostedCaller()
        let first = AgentJITCallerContext.fingerprint(
            for: makeRequest(sessionScope: "agent:cursor:sid:1001", workingDirectory: "/tmp/project"),
            caller: caller
        )
        let second = AgentJITCallerContext.fingerprint(
            for: makeRequest(sessionScope: "agent:cursor:sid:1002", workingDirectory: "/tmp/project"),
            caller: caller
        )

        XCTAssertEqual(first?.sessionScope, "agent:cursor:pid:41")
        XCTAssertEqual(second?.sessionScope, first?.sessionScope)
    }

    func testAgentProcessFingerprintRewritesCodexSidToParentPIDUnderChatGPT() {
        let caller = CallerIdentity(
            pid: 42,
            processName: "authsia",
            bundleIdentifier: "authsia",
            signingTeamId: "TEAM",
            signingIdentity: "Apple Development",
            parentProcess: ParentProcessInfo(
                pid: 55,
                processName: "codex",
                bundleIdentifier: "codex",
                signingTeamId: "TEAM",
                signingIdentity: "Developer ID",
                isPlatformBinary: false
            ),
            hostProcess: ParentProcessInfo(
                pid: 50,
                processName: "ChatGPT",
                bundleIdentifier: "com.openai.codex",
                signingTeamId: "TEAM",
                signingIdentity: "Developer ID",
                isPlatformBinary: false
            )
        )

        let first = AgentJITCallerContext.fingerprint(
            for: makeRequest(sessionScope: "agent:codex:sid:29549", workingDirectory: "/tmp/demo"),
            caller: caller
        )
        let second = AgentJITCallerContext.fingerprint(
            for: makeRequest(sessionScope: "agent:codex:sid:81474", workingDirectory: "/tmp/demo"),
            caller: caller
        )

        XCTAssertEqual(first?.sessionScope, "agent:codex:pid:55")
        XCTAssertEqual(second?.sessionScope, "agent:codex:pid:55")
    }

    func testAgentProcessFingerprintRewritesCodexSidToCursorHelperPID() {
        let caller = cursorHostedCaller(parentPID: 7909)
        let first = AgentJITCallerContext.fingerprint(
            for: makeRequest(sessionScope: "agent:codex:sid:1001", workingDirectory: "/tmp/demo"),
            caller: caller
        )
        let second = AgentJITCallerContext.fingerprint(
            for: makeRequest(sessionScope: "agent:codex:sid:1002", workingDirectory: "/tmp/demo"),
            caller: caller
        )

        XCTAssertEqual(first?.sessionScope, "agent:codex:pid:7909")
        XCTAssertEqual(second?.sessionScope, first?.sessionScope)
    }

    func testCursorExtensionHostFingerprintIsolatesDifferentParentProcesses() {
        let request = makeRequest(sessionScope: "agent:cursor:sid:1001", workingDirectory: "/tmp/project")

        let first = AgentJITCallerContext.fingerprint(for: request, caller: cursorHostedCaller(parentPID: 41))
        let second = AgentJITCallerContext.fingerprint(for: request, caller: cursorHostedCaller(parentPID: 43))

        XCTAssertEqual(first?.sessionScope, "agent:cursor:pid:41")
        XCTAssertEqual(second?.sessionScope, "agent:cursor:pid:43")
    }

    func testCursorExtensionHostFingerprintPreservesScopeWhenIdentityIsAmbiguous() {
        let cases: [(scope: String, caller: CallerIdentity)] = [
            ("agent:cursor:sid:not-a-pid", cursorHostedCaller()),
            (
                "agent:cursor:sid:1001",
                cursorHostedCaller(parentProcessName: "evil Cursor Helper (Plugin)")
            ),
            (
                "agent:cursor:sid:1001",
                cursorHostedCaller(hostBundleIdentifier: "evil.com.cursor.fake")
            ),
            ("agent:cursor:sid:1001", cursorHostedCaller(includeHost: false)),
            ("agent:cursor:sid:1001", cursorHostedCaller(parentPID: 1)),
        ]

        for testCase in cases {
            let fingerprint = AgentJITCallerContext.fingerprint(
                for: makeRequest(sessionScope: testCase.scope, workingDirectory: "/tmp/project"),
                caller: testCase.caller
            )

            XCTAssertEqual(fingerprint?.sessionScope, testCase.scope)
        }
    }

    func testParentContextPromotesKnownAgentAncestorAsHost() {
        let context = CallerIdentityExtractor.parentProcessContext(from: [
            ParentProcessInfo(pid: 41, processName: "authsia", bundleIdentifier: "com.authsia.cli"),
            ParentProcessInfo(pid: 40, processName: "claude.exe", bundleIdentifier: nil),
        ])

        XCTAssertEqual(context.parent?.processName, "authsia")
        XCTAssertEqual(context.host?.processName, "claude.exe")
        XCTAssertTrue(AgentJITCallerContext.hasAgenticCaller(nestedAuthsiaCaller(context: context)))
    }

    func testHomeDirectoryPairingDoesNotAuthorizeADescendantDirectory() {
        let home = FileManager.default.homeDirectoryForCurrentUser
            .resolvingSymlinksInPath()
            .standardizedFileURL
        let nested = home.appendingPathComponent("Library", isDirectory: true)
            .resolvingSymlinksInPath()
            .standardizedFileURL
            .path
        let now = Date(timeIntervalSince1970: 10_000)
        let pairing = terminalPairing(workspace: home.path, expiresAt: now.addingTimeInterval(60))
        let homeRequest = makeRequest(
            sessionScope: nil,
            workingDirectory: home.path,
            workspaceAuthorityPath: nil
        )
        let nestedRequest = makeRequest(
            sessionScope: nil,
            workingDirectory: nested,
            workspaceAuthorityPath: home.path
        )

        XCTAssertEqual(
            AgentJITCallerContext.terminalPairingWorkspaceRoot(request: homeRequest),
            home.path
        )
        // Pins the nested root: a nil root would fail the pairing match below
        // for the wrong reason.
        XCTAssertEqual(
            AgentJITCallerContext.terminalPairingWorkspaceRoot(request: nestedRequest),
            nested
        )
        XCTAssertTrue(hasPairing(homeRequest, caller: pairedIDECaller(), pairing, now))
        XCTAssertFalse(hasPairing(nestedRequest, caller: pairedIDECaller(), pairing, now))
    }

    func testPairedIDECallerUsesHumanPathOnlyForMatchingTTYAnchorAndWorkspace() throws {
        let workspace = try makeWorkspace()
        defer { try? FileManager.default.removeItem(at: workspace) }
        let now = Date(timeIntervalSince1970: 10_000)
        let pairing = terminalPairing(workspace: workspace.path, expiresAt: now.addingTimeInterval(60))
        let request = makeRequest(
            sessionScope: "caller-controlled-value",
            workingDirectory: workspace.path,
            workspaceAuthorityPath: workspace.path
        )
        let caller = pairedIDECaller()

        XCTAssertTrue(AgentJITCallerContext.hasPairedHumanSession(
            request: request,
            callerIdentity: caller,
            pairings: [pairing],
            now: now,
            processStartTime: { _ in 100 }
        ))
        XCTAssertFalse(XPCRequestHandler.isAgentJITCaller(
            request: request,
            callerIdentity: caller,
            pairings: [pairing],
            now: now,
            processStartTime: { _ in 100 }
        ))
    }

    func testPairingDeniesMissingTTYWrongWorkspaceAndExpiredRecord() throws {
        let workspace = try makeWorkspace()
        let otherWorkspace = try makeWorkspace()
        defer {
            try? FileManager.default.removeItem(at: workspace)
            try? FileManager.default.removeItem(at: otherWorkspace)
        }
        let now = Date(timeIntervalSince1970: 10_000)
        let pairing = terminalPairing(workspace: workspace.path, expiresAt: now.addingTimeInterval(60))
        let matchingRequest = makeRequest(
            sessionScope: "tty:/dev/ttys999:sid:1",
            workingDirectory: workspace.path,
            workspaceAuthorityPath: workspace.path
        )
        let wrongWorkspaceRequest = makeRequest(
            sessionScope: nil,
            workingDirectory: otherWorkspace.path,
            workspaceAuthorityPath: otherWorkspace.path
        )

        XCTAssertFalse(hasPairing(matchingRequest, caller: pairedIDECaller(controllingTerminal: nil), pairing, now))
        XCTAssertFalse(hasPairing(wrongWorkspaceRequest, caller: pairedIDECaller(), pairing, now))
        XCTAssertFalse(hasPairing(
            matchingRequest,
            caller: pairedIDECaller(),
            terminalPairing(workspace: workspace.path, expiresAt: now),
            now
        ))
    }

    func testPairingDeniesAgentInChainExitedOrReusedAnchorAndRuntimeEvidence() throws {
        let workspace = try makeWorkspace()
        defer { try? FileManager.default.removeItem(at: workspace) }
        let now = Date(timeIntervalSince1970: 10_000)
        let pairing = terminalPairing(workspace: workspace.path, expiresAt: now.addingTimeInterval(60))
        let request = makeRequest(
            sessionScope: nil,
            workingDirectory: workspace.path,
            workspaceAuthorityPath: workspace.path
        )
        let agentBetweenCallerAndAnchor = pairedIDECaller(
            shellPrefix: [ParentProcessInfo(
                pid: 42,
                processName: "zsh",
                bundleIdentifier: nil,
                startTimeSeconds: 200
            )]
        )

        XCTAssertFalse(hasPairing(request, caller: agentBetweenCallerAndAnchor, pairing, now))
        XCTAssertFalse(AgentJITCallerContext.hasPairedHumanSession(
            request: request,
            callerIdentity: pairedIDECaller(),
            pairings: [pairing],
            now: now,
            processStartTime: { _ in nil }
        ))
        XCTAssertFalse(AgentJITCallerContext.hasPairedHumanSession(
            request: request,
            callerIdentity: pairedIDECaller(),
            pairings: [pairing],
            now: now,
            processStartTime: { _ in 101 }
        ))

        let runtimeRequest = BridgeRequest(
            id: request.id,
            type: request.type,
            query: request.query,
            options: request.options,
            context: BridgeContext(
                isTTY: true,
                isPiped: false,
                isSSH: false,
                isCI: false,
                timestamp: now,
                requestedCommand: "get",
                workingDirectory: workspace.path,
                workspaceAuthorityPath: workspace.path,
                agentRuntimeContext: AgentRuntimeContext(
                    platform: "codex",
                    sessionID: "session-99"
                )
            )
        )
        XCTAssertFalse(hasPairing(runtimeRequest, caller: pairedIDECaller(), pairing, now))
    }

    func testPairingDoesNotAuthorizeAccessOrExport() throws {
        let workspace = try makeWorkspace()
        defer { try? FileManager.default.removeItem(at: workspace) }
        let now = Date(timeIntervalSince1970: 10_000)
        let pairing = terminalPairing(workspace: workspace.path, expiresAt: now.addingTimeInterval(60))
        let base = makeRequest(
            sessionScope: nil,
            workingDirectory: workspace.path,
            workspaceAuthorityPath: workspace.path
        )

        for type in [BridgeRequestType.createAccess, .exportAccounts] {
            let request = BridgeRequest(
                id: base.id,
                type: type,
                query: base.query,
                options: base.options,
                context: base.context
            )
            XCTAssertTrue(XPCRequestHandler.isAgentJITCaller(
                request: request,
                callerIdentity: pairedIDECaller(),
                pairings: [pairing],
                now: now,
                processStartTime: { _ in 100 }
            ))
        }
    }

    private func makeRequest(
        sessionScope: String?,
        workingDirectory: String?,
        workspaceAuthorityPath: String? = nil
    ) -> BridgeRequest {
        BridgeRequest(
            id: UUID(),
            type: .getPassword,
            query: "prod",
            options: .init(field: nil, copy: false),
            context: .init(
                isTTY: true,
                isPiped: false,
                isSSH: false,
                isCI: false,
                timestamp: Date(),
                requestedCommand: "exec",
                sessionScope: sessionScope,
                workingDirectory: workingDirectory,
                workspaceAuthorityPath: workspaceAuthorityPath
            )
        )
    }

    private func makeWorkspace() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-pairing-workspace-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url.resolvingSymlinksInPath().standardizedFileURL
    }

    private func terminalPairing(workspace: String, expiresAt: Date) -> TerminalPairing {
        TerminalPairing(
            id: UUID(),
            controllingTerminal: "ttys004",
            anchorShellPID: 41,
            anchorShellStartTime: 100,
            workspaceRoot: workspace,
            createdAt: Date(timeIntervalSince1970: 9_000),
            expiresAt: expiresAt
        )
    }

    private func hasPairing(
        _ request: BridgeRequest,
        caller: CallerIdentity,
        _ pairing: TerminalPairing,
        _ now: Date
    ) -> Bool {
        AgentJITCallerContext.hasPairedHumanSession(
            request: request,
            callerIdentity: caller,
            pairings: [pairing],
            now: now,
            processStartTime: { _ in 100 }
        )
    }

    private func pairedIDECaller(
        controllingTerminal: String? = "ttys004",
        shellPrefix: [ParentProcessInfo]? = nil
    ) -> CallerIdentity {
        let anchor = ParentProcessInfo(
            pid: 41,
            processName: "zsh",
            bundleIdentifier: nil,
            startTimeSeconds: 100
        )
        return CallerIdentity(
            pid: 42,
            processName: "authsia",
            bundleIdentifier: "com.authsia.cli",
            signingTeamId: "TEAM",
            signingIdentity: "Developer ID Application",
            parentProcess: anchor,
            hostProcess: ParentProcessInfo(
                pid: 40,
                processName: "Code Helper",
                bundleIdentifier: "com.microsoft.VSCode"
            ),
            controllingTerminal: controllingTerminal,
            shellAncestryPrefix: shellPrefix ?? [anchor]
        )
    }

    private func nestedAuthsiaCaller(context: CallerIdentityExtractor.ParentProcessContext) -> CallerIdentity {
        CallerIdentity(
            pid: 42,
            processName: "authsia",
            bundleIdentifier: "com.authsia.cli",
            signingTeamId: "TEAM",
            signingIdentity: "Developer ID Application",
            parentProcess: context.parent,
            hostProcess: context.host
        )
    }

    private func humanTerminalCaller(
        cliBundleIdentifier: String = "com.authsia.cli"
    ) -> CallerIdentity {
        CallerIdentity(
            pid: 42,
            processName: "authsia",
            bundleIdentifier: cliBundleIdentifier,
            signingTeamId: "TEAM",
            signingIdentity: "Developer ID Application",
            parentProcess: ParentProcessInfo(
                pid: 41,
                processName: "Terminal",
                bundleIdentifier: "com.apple.Terminal",
                isPlatformBinary: true
            )
        )
    }

    private func claudeCaller() -> CallerIdentity {
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

    private func vscodeHostedCaller() -> CallerIdentity {
        CallerIdentity(
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
    }

    private func terminalHostedCaller(
        parentProcessName: String = "zsh",
        hostProcessName: String = "Terminal",
        bundleIdentifier: String = "com.apple.Terminal"
    ) -> CallerIdentity {
        CallerIdentity(
            pid: 42,
            processName: "authsia",
            bundleIdentifier: "com.authsia.cli",
            signingTeamId: "TEAM",
            signingIdentity: "Developer ID Application",
            parentProcess: ParentProcessInfo(
                pid: 41,
                processName: parentProcessName,
                bundleIdentifier: nil
            ),
            hostProcess: ParentProcessInfo(
                pid: 40,
                processName: hostProcessName,
                bundleIdentifier: bundleIdentifier,
                signingTeamId: bundleIdentifier == "com.apple.Terminal" ? nil : "TERMINAL_TEAM",
                signingIdentity: bundleIdentifier == "com.apple.Terminal" ? nil : "Developer ID Application",
                isPlatformBinary: bundleIdentifier == "com.apple.Terminal"
            )
        )
    }

    private func cursorHostedCaller(
        parentPID: Int32 = 41,
        parentProcessName: String = "Cursor Helper (Plugin)",
        hostProcessName: String = "Cursor",
        hostBundleIdentifier: String? = "com.todesktop.230313mzl4w4u92",
        includeHost: Bool = true
    ) -> CallerIdentity {
        CallerIdentity(
            pid: 42,
            processName: "authsia",
            bundleIdentifier: "com.authsia.cli",
            signingTeamId: "TEAM",
            signingIdentity: "Developer ID Application",
            parentProcess: ParentProcessInfo(
                pid: parentPID,
                processName: parentProcessName,
                bundleIdentifier: "com.github.Electron.helper"
            ),
            hostProcess: includeHost ? ParentProcessInfo(
                pid: 40,
                processName: hostProcessName,
                bundleIdentifier: hostBundleIdentifier
            ) : nil
        )
    }
}
#endif
