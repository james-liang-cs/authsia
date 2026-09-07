import XCTest
@testable import AuthenticatorBridge

final class MCPClientInstallationTests: XCTestCase {
    func testProtectableSourcesHideVSCodeAndDevinWithoutApps() {
        let probe = MCPClientInstallation.Probe(
            bundleInstalled: { _ in false },
            appExists: { _ in false }
        )
        XCTAssertEqual(
            MCPClientInstallation.protectableSources(probe: probe),
            [.codex, .claude, .cursor, .claudeDesktop]
        )
        XCTAssertFalse(MCPClientInstallation.isInstalled(.vscode, probe: probe))
        XCTAssertFalse(MCPClientInstallation.isInstalled(.devin, probe: probe))
        XCTAssertTrue(MCPClientInstallation.isInstalled(.cursor, probe: probe))
    }

    func testProtectableSourcesIncludeVSCodeWhenBundleOrAppExists() {
        let bundle = MCPClientInstallation.Probe(
            bundleInstalled: { $0 == "com.microsoft.VSCode" },
            appExists: { _ in false }
        )
        XCTAssertTrue(MCPClientInstallation.protectableSources(probe: bundle).contains(.vscode))
        XCTAssertFalse(MCPClientInstallation.protectableSources(probe: bundle).contains(.devin))

        let insiders = MCPClientInstallation.Probe(
            bundleInstalled: { _ in false },
            appExists: { $0 == "Visual Studio Code - Insiders.app" }
        )
        XCTAssertTrue(MCPClientInstallation.isInstalled(.vscode, probe: insiders))
    }

    func testProtectableSourcesIncludeDevinWhenAppExists() {
        let probe = MCPClientInstallation.Probe(
            bundleInstalled: { _ in false },
            appExists: { $0 == "Devin.app" }
        )
        XCTAssertTrue(MCPClientInstallation.protectableSources(probe: probe).contains(.devin))
        XCTAssertFalse(MCPClientInstallation.protectableSources(probe: probe).contains(.vscode))
    }

    func testWindsurfDoesNotCountAsVSCodeOrDevin() {
        let probe = MCPClientInstallation.Probe(
            bundleInstalled: { $0 == "com.exafunction.windsurf" },
            appExists: { $0 == "Windsurf.app" }
        )
        XCTAssertFalse(MCPClientInstallation.isInstalled(.vscode, probe: probe))
        XCTAssertFalse(MCPClientInstallation.isInstalled(.devin, probe: probe))
        XCTAssertEqual(
            MCPClientInstallation.protectableSources(probe: probe),
            [.codex, .claude, .cursor, .claudeDesktop]
        )
    }
}
