#if os(macOS)
import XCTest
@testable import AuthsiaBridgeHost
import AuthenticatorBridge

final class CallerIdentityExtractorTests: XCTestCase {
    func testShellPrefixStopsAtFirstNonShellProcess() {
        XCTAssertEqual(prefixNames([process("zsh")]), ["zsh"])
        XCTAssertEqual(prefixNames([process("claude.exe"), process("zsh")]), [])
        XCTAssertEqual(prefixNames([process("zsh"), process("claude.exe"), process("zsh")]), ["zsh"])
        XCTAssertEqual(prefixNames([process("login"), process("zsh")]), [])
    }

    func testShellPrefixIsNotEncodedInAuditIdentity() throws {
        let identity = CallerIdentity(
            pid: 42,
            processName: "authsia",
            bundleIdentifier: "authsia",
            signingTeamId: "TEAM",
            signingIdentity: "Developer ID",
            controllingTerminal: "ttys004",
            shellAncestryPrefix: [process("zsh")],
            hostCommand: "/usr/local/bin/authsia get password deploy"
        )

        let data = try JSONEncoder().encode(identity)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(object["controllingTerminal"] as? String, "ttys004")
        XCTAssertNil(object["shellAncestryPrefix"])
        XCTAssertNil(object["hostCommand"])
        let decoded = try JSONDecoder().decode(CallerIdentity.self, from: data)
        XCTAssertNil(decoded.shellAncestryPrefix)
        XCTAssertNil(decoded.hostCommand)
    }

    private func prefixNames(_ ancestry: [ParentProcessInfo]) -> [String] {
        CallerIdentityExtractor.parentProcessContext(from: ancestry)
            .shellAncestryPrefix
            .map(\.processName)
    }

    private func process(_ name: String) -> ParentProcessInfo {
        ParentProcessInfo(pid: Int32.random(in: 10...10_000), processName: name, bundleIdentifier: nil)
    }
}
#endif
