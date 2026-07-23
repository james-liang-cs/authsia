#if os(macOS)
import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge

final class AgentJITCallerContextTests: XCTestCase {
    func testExtractFromNonexistentPIDReturnsNil() {
        XCTAssertNil(CallerIdentityExtractor.extract(fromPID: pid_t.max))
    }

    func testDoesNotFlagHumanTerminalCaller() {
        XCTAssertFalse(AgentJITCallerContext.hasAgenticCaller(humanTerminalCaller()))
    }

    func testTrustsSignedTerminalAndShellAncestry() {
        XCTAssertTrue(AgentJITCallerContext.isTrustedHumanTerminal(humanTerminalCaller()))
    }

    func testDoesNotTrustIDEHostedShellAsHumanTerminal() {
        XCTAssertFalse(AgentJITCallerContext.isTrustedHumanTerminal(vscodeHostedCaller()))
    }

    func testTrustsSupportedSignedTerminalHostsWithShellAncestry() {
        for bundleIdentifier in [
            "com.googlecode.iterm2",
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

    private func makeRequest(sessionScope: String?, workingDirectory: String?) -> BridgeRequest {
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
                workingDirectory: workingDirectory
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

    private func humanTerminalCaller() -> CallerIdentity {
        CallerIdentity(
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
