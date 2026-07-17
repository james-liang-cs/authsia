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
                bundleIdentifier: "com.apple.Terminal"
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
}
#endif
