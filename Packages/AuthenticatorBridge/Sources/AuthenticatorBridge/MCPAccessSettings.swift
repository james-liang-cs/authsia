#if os(macOS)
import Foundation

public enum MCPAccessSettings {
    public static let appDefaultsSuiteName = "app.authsia"
    public static let enabledKey = "mcpAccessEnabled"

    public static var appDefaults: UserDefaults {
        UserDefaults(suiteName: appDefaultsSuiteName) ?? .standard
    }

    public static func isEnabled(defaults: UserDefaults = appDefaults) -> Bool {
        guard defaults.object(forKey: enabledKey) != nil else {
            return false
        }
        return defaults.bool(forKey: enabledKey)
    }
}
#endif
