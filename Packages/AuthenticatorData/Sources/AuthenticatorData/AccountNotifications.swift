import Foundation

/// Notifications for account data changes
public extension Notification.Name {
    /// Posted when accounts are added, updated, or deleted
    static let accountsDidChange = Notification.Name("com.authsia.accountsDidChange")
}
