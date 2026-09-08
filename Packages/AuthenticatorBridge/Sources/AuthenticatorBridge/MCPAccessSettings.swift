#if os(macOS)
import Foundation

public enum MCPAccessSettings {
    public static let appDefaultsSuiteName = "app.authsia"
    public static let enabledKey = "mcpAccessEnabled"
    public static let disabledMessage = "MCP Integrations are disabled. Enable MCP Integrations in Authsia Settings > Developer Access, then retry."

    public static func requireEnabled(_ enabled: Bool = isEnabled()) throws {
        guard enabled else { throw MCPManagementError.mcpAccessDisabled }
    }
    public static let openCoverageNotification = Notification.Name("app.authsia.openMCPProxyCoverage")

    public static var appDefaults: UserDefaults {
        UserDefaults(suiteName: appDefaultsSuiteName) ?? .standard
    }

    public static func isEnabled(defaults: UserDefaults = appDefaults) -> Bool {
        guard defaults.object(forKey: enabledKey) != nil else {
            return false
        }
        return defaults.bool(forKey: enabledKey)
    }

    public static func setEnabled(_ enabled: Bool, defaults: UserDefaults = appDefaults) {
        defaults.set(enabled, forKey: enabledKey)
    }
}
#endif
