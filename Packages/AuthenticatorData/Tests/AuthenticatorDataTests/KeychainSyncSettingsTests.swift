import XCTest
import Security
@testable import AuthenticatorData

final class KeychainSyncSettingsTests: XCTestCase {
    private enum TestError: Error {
        case copyFailed
    }

    private final class DefaultsBox: @unchecked Sendable {
        let defaults: UserDefaults

        init(_ defaults: UserDefaults) {
            self.defaults = defaults
        }
    }

    func testDefaultIsDisabledWhenPreferenceIsAbsent() {
        let defaults = UserDefaults(suiteName: "KeychainSyncSettingsTests.default")!
        defaults.removePersistentDomain(forName: "KeychainSyncSettingsTests.default")

        XCTAssertFalse(KeychainSyncSettings.isICloudKeychainSyncEnabled(defaults: defaults))
    }

    func testEnabledReflectsStoredPreference() {
        let defaults = UserDefaults(suiteName: "KeychainSyncSettingsTests.enabled")!
        defaults.removePersistentDomain(forName: "KeychainSyncSettingsTests.enabled")
        defaults.set(true, forKey: KeychainSyncSettings.iCloudKeychainSyncEnabledKey)

        XCTAssertTrue(KeychainSyncSettings.isICloudKeychainSyncEnabled(defaults: defaults))
    }

    func testSetEnabledWritesPreference() {
        let defaults = UserDefaults(suiteName: "KeychainSyncSettingsTests.set")!
        defaults.removePersistentDomain(forName: "KeychainSyncSettingsTests.set")

        KeychainSyncSettings.setICloudKeychainSyncEnabled(true, defaults: defaults)

        XCTAssertTrue(defaults.bool(forKey: KeychainSyncSettings.iCloudKeychainSyncEnabledKey))
    }

    func testTemporaryEnableOverrideDoesNotPersistWhenOperationThrows() {
        let defaults = UserDefaults(suiteName: "KeychainSyncSettingsTests.override")!
        defaults.removePersistentDomain(forName: "KeychainSyncSettingsTests.override")
        let defaultsBox = DefaultsBox(defaults)
        let keychain = KeychainStore(syncPolicy: KeychainSyncPolicy {
            KeychainSyncSettings.isICloudKeychainSyncEnabled(defaults: defaultsBox.defaults)
        })

        XCTAssertEqual(keychain.writeSynchronizableValuesForTesting(), [false])

        XCTAssertThrowsError(
            try KeychainSyncSettings.withICloudKeychainSyncEnabled(true) {
                XCTAssertTrue(KeychainSyncSettings.isICloudKeychainSyncEnabled(defaults: defaults))
                XCTAssertEqual(keychain.writeSynchronizableValuesForTesting(), [true, false])
                throw TestError.copyFailed
            }
        )

        XCTAssertFalse(KeychainSyncSettings.isICloudKeychainSyncEnabled(defaults: defaults))
        XCTAssertFalse(defaults.bool(forKey: KeychainSyncSettings.iCloudKeychainSyncEnabledKey))
        XCTAssertEqual(keychain.writeSynchronizableValuesForTesting(), [false])
    }

    func testICloudSyncAvailabilityFailsClosedWithoutICloudAccount() {
        var didProbe = false

        let availability = KeychainSyncSettings.iCloudKeychainSyncAvailability(
            ubiquityIdentityToken: nil,
            synchronizableProbe: {
                didProbe = true
                return errSecSuccess
            }
        )

        XCTAssertEqual(availability, .iCloudAccountUnavailable)
        XCTAssertFalse(didProbe)
    }

    func testICloudSyncAvailabilityUsesSynchronizableProbeWhenICloudAccountExists() {
        let availability = KeychainSyncSettings.iCloudKeychainSyncAvailability(
            ubiquityIdentityToken: NSObject(),
            synchronizableProbe: { errSecSuccess }
        )

        XCTAssertEqual(availability, .available)
    }

    func testICloudSyncAvailabilityReportsSynchronizableProbeFailure() {
        let availability = KeychainSyncSettings.iCloudKeychainSyncAvailability(
            ubiquityIdentityToken: NSObject(),
            synchronizableProbe: { errSecNotAvailable }
        )

        XCTAssertEqual(availability, .keychainUnavailable(errSecNotAvailable))
    }

    func testRequireICloudSyncAvailableThrowsActionableMessageWhenICloudAccountMissing() {
        XCTAssertThrowsError(
            try KeychainSyncSettings.requireICloudKeychainSyncAvailable(
                ubiquityIdentityToken: nil,
                synchronizableProbe: { errSecSuccess }
            )
        ) { error in
            XCTAssertEqual(
                error.localizedDescription,
                "Sign in to iCloud and enable iCloud Keychain in System Settings, then try again."
            )
        }
    }

    func testNormalWriteValidationAllowsLocalFallbackWhenSynchronizableWriteFails() {
        let failure = KeychainSyncSettings.writeFailureStatus(
            statuses: [
                (synchronizable: true, status: errSecNotAvailable),
                (synchronizable: false, status: errSecSuccess),
            ],
            requiresSynchronizableSuccess: false
        )

        XCTAssertNil(failure)
    }

    func testNormalWriteValidationStillRequiresTrailingLocalWriteWhenSynchronizableWriteSucceeds() {
        let failure = KeychainSyncSettings.writeFailureStatus(
            statuses: [
                (synchronizable: true, status: errSecSuccess),
                (synchronizable: false, status: errSecNotAvailable),
            ],
            requiresSynchronizableSuccess: false
        )

        XCTAssertEqual(failure, errSecNotAvailable)
    }

    func testStrictWriteValidationRequiresSynchronizableWriteSuccess() {
        let failure = KeychainSyncSettings.writeFailureStatus(
            statuses: [
                (synchronizable: true, status: errSecNotAvailable),
                (synchronizable: false, status: errSecSuccess),
            ],
            requiresSynchronizableSuccess: true
        )

        XCTAssertEqual(failure, errSecNotAvailable)
    }

    func testStrictWriteRequirementDoesNotPersistWhenOperationThrows() {
        XCTAssertFalse(KeychainSyncSettings.requiresICloudKeychainWriteSuccess)

        XCTAssertThrowsError(
            try KeychainSyncSettings.withRequiredICloudKeychainWriteSuccess {
                XCTAssertTrue(KeychainSyncSettings.requiresICloudKeychainWriteSuccess)
                throw TestError.copyFailed
            }
        )

        XCTAssertFalse(KeychainSyncSettings.requiresICloudKeychainWriteSuccess)
    }
}
