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
