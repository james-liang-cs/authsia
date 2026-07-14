import Foundation

public extension Notification.Name {
    static let vaultPasswordsDidChange = Notification.Name("com.authsia.vault.passwordsDidChange")
    static let vaultAPIKeysDidChange = Notification.Name("com.authsia.vault.apiKeysDidChange")
    static let vaultCertificatesDidChange = Notification.Name("com.authsia.vault.certificatesDidChange")
    static let vaultNotesDidChange = Notification.Name("com.authsia.vault.notesDidChange")
    static let vaultSSHKeysDidChange = Notification.Name("com.authsia.vault.sshKeysDidChange")
    static let vaultFoldersDidChange = Notification.Name("com.authsia.vault.foldersDidChange")

    #if os(macOS)
    static let vaultExternalDidChange = Notification.Name("com.authsia.vault.externalDidChange")
    #endif
}

#if os(macOS)
public enum VaultExternalChangeNotifier {
    public static let objectName = "app.authsia.vault"

    public static func post() {
        DistributedNotificationCenter.default().post(
            name: .vaultExternalDidChange,
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
