#if os(macOS)
import Foundation

public enum BridgeSettings {
    public static let appDefaultsSuiteName = "app.authsia"
    public static let cliSessionTTLKey = "cliSessionTTL"
    public static let sshSessionTTLKey = "sshSessionTTL"
    public static let cliAccessEnabledKey = "cliAccessEnabled"
    public static let iCloudKeychainSyncEnabledKey = "iCloudKeychainSyncEnabled"
    public static let defaultSessionTTL: TimeInterval = 15.0
    public static let defaultSSHSessionTTL: TimeInterval = 1800.0
    public static let maximumSessionTTL: TimeInterval = 24 * 60 * 60

    public static var appDefaults: UserDefaults {
        defaults()
    }

    public static func defaults(bundleIdentifier: String? = Bundle.main.bundleIdentifier) -> UserDefaults {
        if usesStandardDefaults(bundleIdentifier: bundleIdentifier) {
            return .standard
        }
        return UserDefaults(suiteName: appDefaultsSuiteName) ?? .standard
    }

    public static func usesStandardDefaults(bundleIdentifier: String?) -> Bool {
        bundleIdentifier == appDefaultsSuiteName
    }

    public static func sessionTTL(defaults: UserDefaults = appDefaults) -> TimeInterval {
        sessionTTL(forKey: cliSessionTTLKey, defaultValue: defaultSessionTTL, defaults: defaults)
    }

    public static func sshSessionTTL(defaults: UserDefaults = appDefaults) -> TimeInterval {
        sessionTTL(forKey: sshSessionTTLKey, defaultValue: defaultSSHSessionTTL, defaults: defaults)
    }

    private static func sessionTTL(
        forKey key: String,
        defaultValue: TimeInterval,
        defaults: UserDefaults
    ) -> TimeInterval {
        guard defaults.object(forKey: key) != nil else {
            return defaultValue
        }
        let value = defaults.double(forKey: key)
        if value < 0 {
            return maximumSessionTTL
        }
        return value > 0 ? min(value, maximumSessionTTL) : defaultValue
    }

    public static func isCliAccessEnabled(defaults: UserDefaults = appDefaults) -> Bool {
        guard defaults.object(forKey: cliAccessEnabledKey) != nil else {
            return true
        }
        return defaults.bool(forKey: cliAccessEnabledKey)
    }

    public static func isRemoteApprovalEnabled(defaults: UserDefaults = appDefaults) -> Bool {
        defaults.bool(forKey: iCloudKeychainSyncEnabledKey)
    }
}
#endif
