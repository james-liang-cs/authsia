import Foundation

#if os(macOS)
public extension Notification.Name {
    static let accessCenterActivityDidChange = Notification.Name(
        "com.authsia.accessCenter.activityDidChange"
    )
}

public enum AccessCenterActivityNotifier {
    public static let objectName = "app.authsia.access-center"

    public static func post() {
        postImmediately(
            name: .accessCenterActivityDidChange,
            object: objectName,
            userInfo: ["pid": ProcessInfo.processInfo.processIdentifier]
        )
    }

    /// Grant save/merge/revoke lives in the Bridge host, which stays busy on the
    /// follow-up `exec` XPC. Immediate delivery lets Access Center refresh before
    /// that request returns, instead of waiting for an idle run loop or the 30s poll.
    public static func postGrantDidChange() {
        postImmediately(name: .agentJITGrantDidChange, object: nil, userInfo: nil)
    }

    private static func postImmediately(
        name: Notification.Name,
        object: String?,
        userInfo: [AnyHashable: Any]?
    ) {
        DistributedNotificationCenter.default().postNotificationName(
            name,
            object: object,
            userInfo: userInfo,
            deliverImmediately: true
        )
    }

    public static func isFromCurrentProcess(_ notification: Notification) -> Bool {
        guard let rawPID = notification.userInfo?["pid"] else { return false }
        let sourcePID: Int?
        if let intPID = rawPID as? Int {
            sourcePID = intPID
        } else if let numberPID = rawPID as? NSNumber {
            sourcePID = numberPID.intValue
        } else {
            sourcePID = nil
        }
        guard let sourcePID else { return false }
        return sourcePID == ProcessInfo.processInfo.processIdentifier
    }
}
#endif
