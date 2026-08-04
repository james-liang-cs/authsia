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
        DistributedNotificationCenter.default().post(
            name: .accessCenterActivityDidChange,
            object: objectName,
            userInfo: ["pid": ProcessInfo.processInfo.processIdentifier]
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
