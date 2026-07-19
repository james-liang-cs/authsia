import XCTest
@testable import AuthsiaBridgeHost

#if os(macOS)
final class BridgeSettingsTests: XCTestCase {
    func testBridgeSettingsUseAppDefaultsDomain() {
        XCTAssertEqual(BridgeSettings.appDefaultsSuiteName, "app.authsia")
    }

    func testDefaultsUseStandardInsideAppBundle() {
        XCTAssertTrue(BridgeSettings.usesStandardDefaults(bundleIdentifier: "app.authsia"))
        XCTAssertTrue(BridgeSettings.defaults(bundleIdentifier: "app.authsia") === UserDefaults.standard)
    }

    func testDefaultsUseExplicitAppDomainOutsideAppBundleIdentifier() {
        XCTAssertFalse(BridgeSettings.usesStandardDefaults(bundleIdentifier: nil))
        XCTAssertFalse(BridgeSettings.usesStandardDefaults(bundleIdentifier: "authsia-bridge"))
    }

    func testSessionTTLReadsConfiguredValue() {
        withDefaults { defaults in
            defaults.set(60.0, forKey: BridgeSettings.cliSessionTTLKey)

            XCTAssertEqual(BridgeSettings.sessionTTL(defaults: defaults), 60.0)
        }
    }

    func testSessionTTLFallsBackWhenUnsetOrZero() {
        withDefaults { defaults in
            XCTAssertEqual(BridgeSettings.sessionTTL(defaults: defaults), BridgeSettings.defaultSessionTTL)

            defaults.set(0.0, forKey: BridgeSettings.cliSessionTTLKey)

            XCTAssertEqual(BridgeSettings.sessionTTL(defaults: defaults), BridgeSettings.defaultSessionTTL)
        }
    }

    func testSessionTTLMapsLegacyNeverTo24Hours() {
        withDefaults { defaults in
            defaults.set(-1.0, forKey: BridgeSettings.cliSessionTTLKey)

            XCTAssertEqual(BridgeSettings.sessionTTL(defaults: defaults), BridgeSettings.maximumSessionTTL)
        }
    }

    func testSessionTTLCapsValuesAt24Hours() {
        withDefaults { defaults in
            defaults.set(BridgeSettings.maximumSessionTTL * 2, forKey: BridgeSettings.cliSessionTTLKey)

            XCTAssertEqual(BridgeSettings.sessionTTL(defaults: defaults), BridgeSettings.maximumSessionTTL)
        }
    }

    func testSSHSessionTTLUsesIndependentKey() {
        withDefaults { defaults in
            defaults.set(30.0, forKey: BridgeSettings.cliSessionTTLKey)
            defaults.set(45.0, forKey: BridgeSettings.sshSessionTTLKey)

            XCTAssertEqual(BridgeSettings.sessionTTL(defaults: defaults), 30.0)
            XCTAssertEqual(BridgeSettings.sshSessionTTL(defaults: defaults), 45.0)
        }
    }

    func testSSHSessionTTLFallsBackToIndependentDefault() {
        withDefaults { defaults in
            defaults.set(15.0, forKey: BridgeSettings.cliSessionTTLKey)

            XCTAssertEqual(BridgeSettings.sessionTTL(defaults: defaults), 15.0)
            XCTAssertEqual(BridgeSettings.sshSessionTTL(defaults: defaults), 1800.0)
        }
    }

    func testSSHSessionTTLMapsLegacyNeverTo24Hours() {
        withDefaults { defaults in
            defaults.set(-1.0, forKey: BridgeSettings.sshSessionTTLKey)

            XCTAssertEqual(BridgeSettings.sshSessionTTL(defaults: defaults), BridgeSettings.maximumSessionTTL)
        }
    }

    func testCLIAccessDefaultsTrueAndCanBeDisabled() {
        withDefaults { defaults in
            XCTAssertTrue(BridgeSettings.isCliAccessEnabled(defaults: defaults))

            defaults.set(false, forKey: BridgeSettings.cliAccessEnabledKey)

            XCTAssertFalse(BridgeSettings.isCliAccessEnabled(defaults: defaults))
        }
    }

    func testRemoteApprovalDefaultsDisabledAndTracksICloudSyncPreference() {
        withDefaults { defaults in
            XCTAssertFalse(BridgeSettings.isRemoteApprovalEnabled(defaults: defaults))

            defaults.set(true, forKey: BridgeSettings.iCloudKeychainSyncEnabledKey)

            XCTAssertTrue(BridgeSettings.isRemoteApprovalEnabled(defaults: defaults))
        }
    }

    private func withDefaults(_ body: (UserDefaults) throws -> Void) rethrows {
        let suiteName = "BridgeSettingsTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        defer { defaults.removePersistentDomain(forName: suiteName) }
        try body(defaults)
    }
}
#endif
