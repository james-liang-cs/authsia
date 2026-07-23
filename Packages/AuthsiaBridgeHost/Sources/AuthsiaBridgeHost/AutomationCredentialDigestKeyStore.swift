#if os(macOS)
import Foundation
import Security

public enum AutomationCredentialDigestKeyStoreError: Error, Equatable, Sendable {
    case invalidKey
    case keychainFailure(Int32)
}

public struct AutomationCredentialDigestKeyStore: Sendable {
    private let service: String
    private let account: String

    public init(
        service: String = "app.authsia.bridge.automation-credential-digest",
        account: String = "v1"
    ) {
        self.service = service
        self.account = account
    }

    public func loadOrCreate() throws -> Data {
        let loaded = load()
        if let key = loaded.key {
            return key
        }
        switch loaded.status {
        case errSecItemNotFound:
            let key = try AutomationCredentialAuthority.secureRandomBytes(count: 32)
            let status = SecItemAdd(
                [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: service,
                    kSecAttrAccount as String: account,
                    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                    kSecValueData as String: key,
                ] as CFDictionary,
                nil
            )
            if status == errSecSuccess {
                return key
            }
            if status == errSecDuplicateItem, let existing = load().key {
                return existing
            }
            throw AutomationCredentialDigestKeyStoreError.keychainFailure(status)
        default:
            let status = loaded.status
            throw AutomationCredentialDigestKeyStoreError.keychainFailure(status)
        }
    }

    private func load() -> (key: Data?, status: OSStatus) {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(
            [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecReturnData as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
            ] as CFDictionary,
            &result
        )
        guard status == errSecSuccess else { return (nil, status) }
        guard let key = result as? Data, key.count == 32 else {
            return (nil, errSecDecode)
        }
        return (key, errSecSuccess)
    }
}
#endif
