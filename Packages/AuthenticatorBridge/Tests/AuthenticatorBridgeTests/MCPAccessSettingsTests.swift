#if os(macOS)
import Foundation
import Testing
@testable import AuthenticatorBridge

@Suite("MCP access settings")
struct MCPAccessSettingsTests {
    @Test("MCP access is opt-in and honors an explicit setting")
    func optInDefault() throws {
        let suiteName = "app.authsia.tests.mcp-access.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }

        #expect(!MCPAccessSettings.isEnabled(defaults: defaults))

        defaults.set(true, forKey: MCPAccessSettings.enabledKey)
        #expect(MCPAccessSettings.isEnabled(defaults: defaults))

        defaults.set(false, forKey: MCPAccessSettings.enabledKey)
        #expect(!MCPAccessSettings.isEnabled(defaults: defaults))
    }
}
#endif
