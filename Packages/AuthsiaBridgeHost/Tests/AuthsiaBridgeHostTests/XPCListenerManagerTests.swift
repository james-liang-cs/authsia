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

    func testIsTrustedCLIExecutablePath_RejectsUnconfiguredLegacyDevelopmentCLIPath() {
        let bundled = "/Applications/Authsia.app/Contents/Helpers/authsia"
        let developmentCLI = "/Users/demo/Projects/Authsia/Packages/AuthsiaCLI/.build/debug/authsia"

        XCTAssertFalse(
            XPCListenerManager.isTrustedCLIExecutablePath(
                developmentCLI,
                bundledCLIPath: bundled
            )
        )
    }

    func testIsTrustedCLIExecutablePath_RejectsUnconfiguredPublicDependencyDevelopmentCLIPath() {
        let bundled = "/Applications/Authsia.app/Contents/Helpers/authsia"
        let developmentCLI = "/Users/demo/Projects/Authsia/Dependencies/Authsia/.build/debug/authsia"

        XCTAssertFalse(
            XPCListenerManager.isTrustedCLIExecutablePath(
                developmentCLI,
                bundledCLIPath: bundled
            )
        )
    }

    func testIsTrustedCLIExecutablePath_AllowsConfiguredPublicDependencyDevelopmentCLIPath() {
        let bundled = "/Applications/Authsia.app/Contents/Helpers/authsia"
        let developmentRoot = "/Users/demo/Projects/Authsia/Dependencies/Authsia/.build"
        let developmentCLI = "\(developmentRoot)/arm64-apple-macosx/debug/authsia"

        XCTAssertTrue(
            XPCListenerManager.isTrustedCLIExecutablePath(
                developmentCLI,
                bundledCLIPath: bundled,
                trustedDevelopmentBuildRoots: [developmentRoot]
            )
        )
    }

    func testIsTrustedCLIExecutablePath_RejectsCLIOutsideConfiguredDevelopmentRoot() {
        let bundled = "/Applications/Authsia.app/Contents/Helpers/authsia"

        XCTAssertFalse(
            XPCListenerManager.isTrustedCLIExecutablePath(
                "/Users/demo/Other/Authsia/.build/debug/authsia",
                bundledCLIPath: bundled,
                trustedDevelopmentBuildRoots: [
                    "/Users/demo/Projects/Authsia/Dependencies/Authsia/.build"
                ]
            )
        )
    }

    func testIsTrustedCLIExecutablePath_RejectsLookalikeConfiguredDevelopmentRoot() {
        let bundled = "/Applications/Authsia.app/Contents/Helpers/authsia"
        let developmentRoot = "/Users/demo/Projects/Authsia/Dependencies/Authsia/.build"

        XCTAssertFalse(
            XPCListenerManager.isTrustedCLIExecutablePath(
                "\(developmentRoot)-malicious/debug/authsia",
                bundledCLIPath: bundled,
                trustedDevelopmentBuildRoots: [developmentRoot]
            )
        )
    }

    func testIsTrustedCLIExecutablePath_RejectsDifferentExecutableNameWithinConfiguredDevelopmentRoot() {
        let bundled = "/Applications/Authsia.app/Contents/Helpers/authsia"
        let developmentRoot = "/Users/demo/Projects/Authsia/Dependencies/Authsia/.build"

        XCTAssertFalse(
            XPCListenerManager.isTrustedCLIExecutablePath(
                "\(developmentRoot)/debug/authsia-helper",
                bundledCLIPath: bundled,
                trustedDevelopmentBuildRoots: [developmentRoot]
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
