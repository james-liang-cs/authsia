import Foundation
import Security

public enum ICloudKeychainSyncAvailability: Equatable {
    case available
    case iCloudAccountUnavailable
    case keychainUnavailable(OSStatus)
}

public enum ICloudKeychainSyncEnableError: LocalizedError, Equatable {
    case iCloudAccountUnavailable
    case keychainUnavailable(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .iCloudAccountUnavailable:
            return "Sign in to iCloud and enable iCloud Keychain in System Settings, then try again."
        case .keychainUnavailable(let status):
            return "iCloud Keychain is not available (Keychain error \(status)). " +
                "Sign in to iCloud and enable iCloud Keychain in System Settings, then try again."
        }
    }
}

public enum KeychainSyncSettings {
    public static let iCloudKeychainSyncEnabledKey = "iCloudKeychainSyncEnabled"
    @TaskLocal static var iCloudKeychainSyncEnabledOverride: Bool?
    @TaskLocal static var requiresICloudKeychainWriteSuccessOverride: Bool?

    public static var isICloudKeychainSyncEnabled: Bool {
        isICloudKeychainSyncEnabled(defaults: .standard)
    }

    static var requiresICloudKeychainWriteSuccess: Bool {
        requiresICloudKeychainWriteSuccessOverride ?? false
    }

    public static func isICloudKeychainSyncEnabled(defaults: UserDefaults) -> Bool {
        if let iCloudKeychainSyncEnabledOverride {
            return iCloudKeychainSyncEnabledOverride
        }
        return defaults.bool(forKey: iCloudKeychainSyncEnabledKey)
    }

    public static func setICloudKeychainSyncEnabled(_ enabled: Bool, defaults: UserDefaults = .standard) {
        defaults.set(enabled, forKey: iCloudKeychainSyncEnabledKey)
    }

    public static func withICloudKeychainSyncEnabled<T>(_ enabled: Bool, operation: () throws -> T) rethrows -> T {
        try $iCloudKeychainSyncEnabledOverride.withValue(enabled) {
            try operation()
        }
    }

    public static func withRequiredICloudKeychainWriteSuccess<T>(operation: () throws -> T) rethrows -> T {
        try $requiresICloudKeychainWriteSuccessOverride.withValue(true) {
            try operation()
        }
    }

    public static func iCloudKeychainSyncAvailability() -> ICloudKeychainSyncAvailability {
        iCloudKeychainSyncAvailability(
            ubiquityIdentityToken: FileManager.default.ubiquityIdentityToken,
            synchronizableProbe: SynchronizableKeychainProbe.run
        )
    }

    static func iCloudKeychainSyncAvailability(
        ubiquityIdentityToken: Any?,
        synchronizableProbe: () -> OSStatus
    ) -> ICloudKeychainSyncAvailability {
        guard ubiquityIdentityToken != nil else {
            return .iCloudAccountUnavailable
        }

        let status = synchronizableProbe()
        guard status == errSecSuccess else {
            return .keychainUnavailable(status)
        }
        return .available
    }

    public static func requireICloudKeychainSyncAvailable() throws {
        try requireICloudKeychainSyncAvailable(
            ubiquityIdentityToken: FileManager.default.ubiquityIdentityToken,
            synchronizableProbe: SynchronizableKeychainProbe.run
        )
    }

    static func requireICloudKeychainSyncAvailable(
        ubiquityIdentityToken: Any?,
        synchronizableProbe: () -> OSStatus
    ) throws {
        switch iCloudKeychainSyncAvailability(
            ubiquityIdentityToken: ubiquityIdentityToken,
            synchronizableProbe: synchronizableProbe
        ) {
        case .available:
            return
        case .iCloudAccountUnavailable:
            throw ICloudKeychainSyncEnableError.iCloudAccountUnavailable
        case .keychainUnavailable(let status):
            throw ICloudKeychainSyncEnableError.keychainUnavailable(status)
        }
    }

    static func writeFailureStatus(
        statuses: [(synchronizable: Bool, status: OSStatus)],
        requiresSynchronizableSuccess: Bool = requiresICloudKeychainWriteSuccess
    ) -> OSStatus? {
        var pendingFailure: OSStatus?
        var attemptedSynchronizable = false
        var didSynchronizableSucceed = false
        var firstSynchronizableFailure: OSStatus?

        for result in statuses {
            if result.synchronizable {
                attemptedSynchronizable = true
                if result.status == errSecSuccess {
                    didSynchronizableSucceed = true
                } else if firstSynchronizableFailure == nil {
                    firstSynchronizableFailure = result.status
                }
            }

            if result.status == errSecSuccess {
                pendingFailure = nil
            } else if pendingFailure == nil {
                pendingFailure = result.status
            }
        }

        if requiresSynchronizableSuccess,
           attemptedSynchronizable,
           !didSynchronizableSucceed {
            return firstSynchronizableFailure ?? pendingFailure
        }

        return pendingFailure
    }
}

private enum SynchronizableKeychainProbe {
    private static let service = "com.authsia.icloud-sync-probe"

    static func run() -> OSStatus {
        let account = UUID().uuidString
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: true,
            kSecValueData as String: Data("probe".utf8),
        ]
        let status = SecItemAdd(query as CFDictionary, nil)

        if status == errSecSuccess {
            let deleteQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecAttrSynchronizable as String: true,
            ]
            SecItemDelete(deleteQuery as CFDictionary)
        }

        return status
    }
}

struct KeychainSyncPolicy: Sendable {
    var isICloudKeychainSyncEnabled: @Sendable () -> Bool

    static let live = KeychainSyncPolicy {
        KeychainSyncSettings.isICloudKeychainSyncEnabled
    }

    static func fixed(_ enabled: Bool) -> KeychainSyncPolicy {
        KeychainSyncPolicy { enabled }
    }
}
