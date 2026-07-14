import Foundation
import Security

enum SharedKeychainAccessGroup {
    private static let authsiaAppSuffix = ".app.authsia"

    static func current() -> String? {
        accessGroup(from: entitlementAccessGroups())
    }

    static func accessGroup(from groups: [String]) -> String? {
        groups.first { $0.hasSuffix(authsiaAppSuffix) }
    }

    private static func entitlementAccessGroups() -> [String] {
        #if os(macOS)
        guard let task = SecTaskCreateFromSelf(nil),
              let value = SecTaskCopyValueForEntitlement(
                task,
                "keychain-access-groups" as CFString,
                nil
              ) else {
            return []
        }
        return value as? [String] ?? []
        #else
        return []
        #endif
    }
}
