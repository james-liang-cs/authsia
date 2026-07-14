import Foundation
import Security
import AuthenticatorCore


public enum KeychainError: Error, LocalizedError {
    case duplicateEntry
    case unknown(OSStatus)
    case itemNotFound
    case unexpectedData

    public var errorDescription: String? {
        switch self {
        case .duplicateEntry:
            return "Keychain item already exists"
        case .unknown(let status):
            return "Keychain error \(status)"
        case .itemNotFound:
            return "Keychain item not found"
        case .unexpectedData:
            return "Keychain item contains unexpected data"
        }
    }
}

public final class KeychainStore: @unchecked Sendable {
    public static let shared = KeychainStore()
    static let preferredSynchronizableValues: [Bool] = [true, false]

    private static let service = "com.authsia.service"
    private static let unavailableStoreStatuses: Set<OSStatus> = [errSecMissingEntitlement]
    private let syncPolicy: KeychainSyncPolicy

    private var syncEnabled: Bool {
        syncPolicy.isICloudKeychainSyncEnabled()
    }

    private var writeSynchronizableValues: [Bool] {
        syncEnabled ? Self.preferredSynchronizableValues : [false]
    }

    private var readSynchronizableValues: [Bool] {
        syncEnabled ? Self.preferredSynchronizableValues : [false, true]
    }

    private var deleteSynchronizableValues: [Bool] {
        Self.preferredSynchronizableValues
    }

    init(syncPolicy: KeychainSyncPolicy = .live) {
        self.syncPolicy = syncPolicy
    }

    /// Saves a secret to the Keychain.
    public func save(secret: Data, for accountID: UUID) throws {
        try save(data: secret, account: accountID.uuidString)
    }

    /// Retrieves a secret from the Keychain.
    public func retrieve(for accountID: UUID) throws -> Data {
        try retrieve(account: accountID.uuidString)
    }

    /// Deletes a secret from the Keychain.
    public func delete(for accountID: UUID) throws {
        try delete(account: accountID.uuidString)
    }

    /// Updates an existing secret.
    public func update(secret: Data, for accountID: UUID) throws {
        try save(secret: secret, for: accountID)
    }

    /// Retrieves a secret using only the legacy (local, non-synced) Keychain.
    /// Used during Apple ID switch recovery when the synced Keychain is inaccessible.
    public func retrieveFromLegacyOnly(for accountID: UUID) throws -> Data? {
        try retrieve(account: accountID.uuidString, synchronizable: false)
    }

    // MARK: - Generic String Key Support

    public func save(data: Data, for key: String) throws {
        try save(data: data, account: key)
    }

    public func retrieve(for key: String) throws -> Data {
        try retrieve(account: key)
    }

    // MARK: - Internal Helpers

    private func save(data: Data, account: String) throws {
        var statuses: [(synchronizable: Bool, status: OSStatus)] = []
        for synchronizable in writeSynchronizableValues {
            let status = upsert(data: data, account: account, synchronizable: synchronizable)
            statuses.append((synchronizable: synchronizable, status: status))
        }

        if let status = KeychainSyncSettings.writeFailureStatus(statuses: statuses) {
            throw KeychainError.unknown(status)
        }
    }

    private func retrieve(account: String) throws -> Data {
        var unavailableStatus: OSStatus?
        for synchronizable in readSynchronizableValues {
            do {
                if let data = try retrieve(account: account, synchronizable: synchronizable) {
                    if synchronizable {
                        _ = upsert(data: data, account: account, synchronizable: false)
                    } else if syncEnabled, unavailableStatus == nil {
                        _ = upsert(data: data, account: account, synchronizable: true)
                    }
                    return data
                }
            } catch KeychainError.unknown(let status) where Self.isStoreUnavailable(status) {
                unavailableStatus = unavailableStatus ?? status
            }
        }

        if let unavailableStatus {
            throw KeychainError.unknown(unavailableStatus)
        }
        throw KeychainError.itemNotFound
    }

    private func retrieve(account: String, synchronizable: Bool) throws -> Data? {
        var firstError: OSStatus?
        let queries = readQueries(account: account, synchronizable: synchronizable)
        for var query in queries {
            query[kSecReturnData as String] = true

            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            if status == errSecItemNotFound {
                continue
            }
            guard status == errSecSuccess else {
                if !Self.isStoreUnavailable(status) || queries.count == 1 {
                    firstError = firstError ?? status
                }
                continue
            }
            guard let data = result as? Data else {
                throw KeychainError.unexpectedData
            }
            return data
        }
        if let firstError {
            throw KeychainError.unknown(firstError)
        }
        return nil
    }

    private func delete(account: String) throws {
        var firstError: OSStatus?
        for synchronizable in deleteSynchronizableValues {
            for query in deleteQueries(account: account, synchronizable: synchronizable) {
                let status = SecItemDelete(query as CFDictionary)
                if status != errSecSuccess,
                   status != errSecItemNotFound,
                   !Self.isStoreUnavailable(status),
                   firstError == nil {
                    firstError = status
                }
            }
        }
        if let firstError {
            throw KeychainError.unknown(firstError)
        }
    }

    private func makeBaseQuery(account: String, synchronizable: Bool) -> [String: Any] {
        Self.makeBaseQuery(account: account, synchronizable: synchronizable, useDataProtectionFallback: true)
    }

    private func readQueries(account: String, synchronizable: Bool) -> [[String: Any]] {
        var queries = [makeBaseQuery(account: account, synchronizable: synchronizable)]
        #if os(macOS)
        if !synchronizable {
            queries.append(Self.makeBaseQuery(
                account: account,
                synchronizable: synchronizable,
                useDataProtectionFallback: false
            ))
        }
        #endif
        return queries
    }

    private func deleteQueries(account: String, synchronizable: Bool) -> [[String: Any]] {
        readQueries(account: account, synchronizable: synchronizable)
    }

    static func baseQueryForTesting(account: String, synchronizable: Bool) -> [String: Any] {
        makeBaseQuery(account: account, synchronizable: synchronizable, useDataProtectionFallback: true)
    }

    func writeSynchronizableValuesForTesting() -> [Bool] {
        writeSynchronizableValues
    }

    func readSynchronizableValuesForTesting() -> [Bool] {
        readSynchronizableValues
    }

    func deleteSynchronizableValuesForTesting() -> [Bool] {
        deleteSynchronizableValues
    }

    private static func isStoreUnavailable(_ status: OSStatus) -> Bool {
        unavailableStoreStatuses.contains(status)
    }

    private static func makeBaseQuery(
        account: String,
        synchronizable: Bool,
        useDataProtectionFallback: Bool
    ) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: synchronizable,
        ]
        #if os(macOS)
        if !synchronizable && useDataProtectionFallback {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        #endif
        return query
    }

    @discardableResult
    private func upsert(data: Data, account: String, synchronizable: Bool) -> OSStatus {
        let status = upsert(
            data: data,
            account: account,
            synchronizable: synchronizable,
            useDataProtectionFallback: true
        )
        #if os(macOS)
        if !synchronizable, Self.isStoreUnavailable(status) {
            return upsert(
                data: data,
                account: account,
                synchronizable: synchronizable,
                useDataProtectionFallback: false
            )
        }
        #endif
        return status
    }

    @discardableResult
    private func upsert(
        data: Data,
        account: String,
        synchronizable: Bool,
        useDataProtectionFallback: Bool
    ) -> OSStatus {
        let baseQuery = Self.makeBaseQuery(
            account: account,
            synchronizable: synchronizable,
            useDataProtectionFallback: useDataProtectionFallback
        )

        var addQuery = baseQuery
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus == errSecSuccess {
            return errSecSuccess
        }

        if addStatus == errSecDuplicateItem {
            let update: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
            ]
            let updateStatus = SecItemUpdate(baseQuery as CFDictionary, update as CFDictionary)
            
            #if os(macOS)
            // macOS file-based keychain doesn't support dual-store for the same account/service.
            // If we got duplicate on Add but NotFound on Update, the duplicate is the *other* synchronizable flag.
            if updateStatus == errSecItemNotFound {
                if synchronizable {
                    // Trying to save SYNCED record, but only LOCAL exists. Delete LOCAL to upgrade it.
                    let conflictingLocalQuery = Self.makeBaseQuery(
                        account: account,
                        synchronizable: false,
                        useDataProtectionFallback: false
                    )
                    SecItemDelete(conflictingLocalQuery as CFDictionary)
                    return SecItemAdd(addQuery as CFDictionary, nil)
                } else {
                    // Prefer the data-protection local fallback. If the duplicate is the
                    // old file-based local item, replace it; if it is the synced item,
                    // the retry still reports duplicate and the synced record is enough.
                    let conflictingLocalQuery = Self.makeBaseQuery(
                        account: account,
                        synchronizable: false,
                        useDataProtectionFallback: false
                    )
                    SecItemDelete(conflictingLocalQuery as CFDictionary)
                    let retryStatus = SecItemAdd(addQuery as CFDictionary, nil)
                    return retryStatus == errSecDuplicateItem ? errSecSuccess : retryStatus
                }
            }
            #endif
            
            return updateStatus
        }

        return addStatus
    }
}
