import XCTest
@testable import AuthsiaBridgeHost

final class XPCListenerManagerTests: XCTestCase {
    func testIsTrustedCLIExecutablePath_AllowsBundledHelperPath() {
        let bundled = "/Applications/Authsia.app/Contents/Helpers/authsia"

        XCTAssertTrue(
            XPCListenerManager.isTrustedCLIExecutablePath(
                bundled,
                bundledCLIPath: bundled
            )
        )
    }

    func testIsTrustedCLIExecutablePath_AllowsCurrentDevelopmentCLIPath() {
        let bundled = "/Applications/Authsia.app/Contents/Helpers/authsia"
        let developmentCLI = "/Users/demo/Projects/Authsia/Packages/AuthsiaCLI/.build/debug/authsia"

        XCTAssertTrue(
            XPCListenerManager.isTrustedCLIExecutablePath(
                developmentCLI,
                bundledCLIPath: bundled
            )
        )
    }

    func testIsTrustedCLIExecutablePath_AllowsPublicDependencyDevelopmentCLIPath() {
        let bundled = "/Applications/Authsia.app/Contents/Helpers/authsia"
        let developmentCLI = "/Users/demo/Projects/Authsia/Dependencies/Authsia/.build/debug/authsia"

        XCTAssertTrue(
            XPCListenerManager.isTrustedCLIExecutablePath(
                developmentCLI,
                bundledCLIPath: bundled
            )
        )
    }

    func testIsTrustedCLIExecutablePath_RejectsLookalikeDevelopmentCLIPath() {
        let bundled = "/Applications/Authsia.app/Contents/Helpers/authsia"
        let lookalike = "/Users/demo/Dependencies/Authsia/.build-malicious/debug/authsia"

        XCTAssertFalse(
            XPCListenerManager.isTrustedCLIExecutablePath(
                lookalike,
                bundledCLIPath: bundled
            )
        )
    }

    func testIsTrustedCLIExecutablePath_RejectsUnknownExecutablePath() {
        let bundled = "/Applications/Authsia.app/Contents/Helpers/authsia"
        let unknown = "/usr/bin/ssh"

        XCTAssertFalse(
            XPCListenerManager.isTrustedCLIExecutablePath(
                unknown,
                bundledCLIPath: bundled
            )
        )
    }
}
