import XCTest
@testable import AuthenticatorData

@MainActor
final class CloudIdentityMonitorTests: XCTestCase {

    private func makeSuite() -> UserDefaults {
        let suite = UserDefaults(suiteName: "CloudIdentityMonitorTests")!
        suite.removePersistentDomain(forName: "CloudIdentityMonitorTests")
        return suite
    }

    func testFirstLaunchStoresTokenNoChange() {
        let defaults = makeSuite()
        let monitor = CloudIdentityMonitor(defaults: defaults)
        var changeFired = false
        monitor.onIdentityChange = { changeFired = true }
        let changed = monitor.checkNow()
        XCTAssertFalse(changed, "Should return false on first launch")
        XCTAssertFalse(changeFired, "Should not fire on first launch")
        XCTAssertTrue(defaults.bool(forKey: CloudIdentityMonitor.hasStoredTokenKey))
    }

    func testTokenChangeFiresCallback() {
        let defaults = makeSuite()
        // Simulate a previously stored token that differs from the real one
        let fakeOldToken = Data([0x01, 0x02, 0x03])
        defaults.set(fakeOldToken, forKey: CloudIdentityMonitor.tokenKey)
        defaults.set(true, forKey: CloudIdentityMonitor.hasStoredTokenKey)

        let monitor = CloudIdentityMonitor(defaults: defaults)
        var changeFired = false
        monitor.onIdentityChange = { changeFired = true }
        let changed = monitor.checkNow()
        XCTAssertTrue(changed, "Should return true when stored token differs from current")
        XCTAssertTrue(changeFired, "Should fire when stored token differs from current")
    }

    func testMatchingTokenDoesNotFire() {
        let defaults = makeSuite()
        // Store the *current* token so they match
        let currentToken = FileManager.default.ubiquityIdentityToken
        if let token = currentToken as? NSCoding {
            let data = try! NSKeyedArchiver.archivedData(withRootObject: token, requiringSecureCoding: false)
            defaults.set(data, forKey: CloudIdentityMonitor.tokenKey)
        } else {
            defaults.removeObject(forKey: CloudIdentityMonitor.tokenKey)
        }
        defaults.set(true, forKey: CloudIdentityMonitor.hasStoredTokenKey)

        let monitor = CloudIdentityMonitor(defaults: defaults)
        var changeFired = false
        monitor.onIdentityChange = { changeFired = true }
        let changed = monitor.checkNow()
        XCTAssertFalse(changed, "Should return false when token matches")
        XCTAssertFalse(changeFired, "Should not fire when token matches")
    }
}
