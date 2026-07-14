import Foundation
import Security

public final class VaultKeychainStore: @unchecked Sendable {
    public static let shared = VaultKeychainStore()
    static let preferredSynchronizableValues: [Bool] = [true, false]

    private static let service = "com.authsia.vault"
    private static let legacyServices = ["com.authenticator.vault"]
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

    // MARK: - Password Secrets

    public func savePassword(_ password: Data, for itemID: UUID) throws {
        try save(password, account: "password-\(itemID.uuidString)")
    }

    public func containsPassword(for itemID: UUID) throws -> Bool {
        try contains(account: "password-\(itemID.uuidString)")
    }

    func passwordExistence(for itemID: UUID) -> SecretExistence {
        existence(account: "password-\(itemID.uuidString)")
    }

    public func retrievePassword(for itemID: UUID) throws -> Data {
        try retrieve(account: "password-\(itemID.uuidString)")
    }

    public func deletePassword(for itemID: UUID) throws {
        try delete(account: "password-\(itemID.uuidString)")
    }

    // MARK: - API Key Secrets

    public func saveAPIKey(_ key: Data, for itemID: UUID) throws {
        try save(key, account: "apikey-\(itemID.uuidString)")
    }

    public func containsAPIKey(for itemID: UUID) throws -> Bool {
        try contains(account: "apikey-\(itemID.uuidString)")
    }

    func apiKeyExistence(for itemID: UUID) -> SecretExistence {
        existence(account: "apikey-\(itemID.uuidString)")
    }

    public func retrieveAPIKey(for itemID: UUID) throws -> Data {
        try retrieve(account: "apikey-\(itemID.uuidString)")
    }

    public func deleteAPIKey(for itemID: UUID) throws {
        try delete(account: "apikey-\(itemID.uuidString)")
    }

    // MARK: - Certificate Data

    public func saveCertificate(_ certData: Data, privateKey: Data?, for itemID: UUID) throws {
        try save(certData, account: "cert-\(itemID.uuidString)")
        if let key = privateKey {
            try save(key, account: "certkey-\(itemID.uuidString)")
        }
    }

    public func containsCertificate(for itemID: UUID) throws -> Bool {
        try contains(account: "cert-\(itemID.uuidString)")
    }

    func certificateExistence(for itemID: UUID) -> SecretExistence {
        existence(account: "cert-\(itemID.uuidString)")
    }

    public func retrieveCertificate(for itemID: UUID) throws -> (cert: Data, key: Data?) {
        let cert = try retrieve(account: "cert-\(itemID.uuidString)")
        let key = try? retrieve(account: "certkey-\(itemID.uuidString)")
        return (cert, key)
    }

    public func deleteCertificate(for itemID: UUID) throws {
        try delete(account: "cert-\(itemID.uuidString)")
        try? delete(account: "certkey-\(itemID.uuidString)")
    }

    public func deleteCertificatePrivateKey(for itemID: UUID) {
        try? delete(account: "certkey-\(itemID.uuidString)")
    }

    // MARK: - SSH Key Data

    public func saveSSHKey(publicKey: Data, privateKey: Data, for itemID: UUID) throws {
        try save(publicKey, account: "sshpub-\(itemID.uuidString)")
        try save(privateKey, account: "sshpriv-\(itemID.uuidString)")
    }

    public func containsSSHKey(for itemID: UUID) throws -> Bool {
        try contains(account: "sshpub-\(itemID.uuidString)") &&
            contains(account: "sshpriv-\(itemID.uuidString)")
    }

    func sshKeyExistence(for itemID: UUID) -> SecretExistence {
        let publicKey = existence(account: "sshpub-\(itemID.uuidString)")
        let privateKey = existence(account: "sshpriv-\(itemID.uuidString)")
        switch (publicKey, privateKey) {
        case (.unavailable, _), (_, .unavailable):
            return .unavailable
        case (.missing, _), (_, .missing):
            return .missing
        case (.present, .present):
            return .present
        }
    }

    public func saveSSHKeyPassphrase(_ passphrase: Data, for itemID: UUID) throws {
        try save(passphrase, account: "sshpass-\(itemID.uuidString)")
    }

    public func retrieveSSHKey(for itemID: UUID) throws -> (publicKey: Data, privateKey: Data) {
        let pub = try retrieve(account: "sshpub-\(itemID.uuidString)")
        let priv = try retrieve(account: "sshpriv-\(itemID.uuidString)")
        return (pub, priv)
    }

    public func retrieveSSHKeyPassphrase(for itemID: UUID) throws -> Data {
        try retrieve(account: "sshpass-\(itemID.uuidString)")
    }

    public func deleteSSHKey(for itemID: UUID) throws {
        try delete(account: "sshpub-\(itemID.uuidString)")
        try delete(account: "sshpriv-\(itemID.uuidString)")
        try? delete(account: "sshpass-\(itemID.uuidString)")
    }

    // MARK: - Secure Note Content

    public func saveNoteContent(_ content: Data, for itemID: UUID) throws {
        try save(content, account: "note-\(itemID.uuidString)")
    }

    public func containsNoteContent(for itemID: UUID) throws -> Bool {
        try contains(account: "note-\(itemID.uuidString)")
    }

    func noteExistence(for itemID: UUID) -> SecretExistence {
        existence(account: "note-\(itemID.uuidString)")
    }

    public func retrieveNoteContent(for itemID: UUID) throws -> Data {
        try retrieve(account: "note-\(itemID.uuidString)")
    }

    public func deleteNoteContent(for itemID: UUID) throws {
        try delete(account: "note-\(itemID.uuidString)")
    }

    // MARK: - Private Helpers

    private func save(_ data: Data, account: String) throws {
        var statuses: [(synchronizable: Bool, status: OSStatus)] = []
        for synchronizable in writeSynchronizableValues {
            let status = upsert(data, account: account, synchronizable: synchronizable)
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
                if let result = try retrieve(account: account, synchronizable: synchronizable) {
                    if result.service != Self.service {
                        _ = upsert(result.data, account: account, synchronizable: synchronizable)
                    }
                    if synchronizable {
                        _ = upsert(result.data, account: account, synchronizable: false)
                    } else if syncEnabled, unavailableStatus == nil {
                        _ = upsert(result.data, account: account, synchronizable: true)
                    }
                    return result.data
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

    private func contains(account: String) throws -> Bool {
        var firstError: OSStatus?
        for synchronizable in readSynchronizableValues {
            let queries = readQueries(account: account, synchronizable: synchronizable)
            for var query in queries {
                query[kSecMatchLimit as String] = kSecMatchLimitOne

                let status = SecItemCopyMatching(query as CFDictionary, nil)
                if status == errSecSuccess {
                    return true
                }
                if status != errSecItemNotFound,
                   (!Self.isStoreUnavailable(status) || queries.count == 1),
                   firstError == nil {
                    firstError = status
                }
            }
        }
        if let firstError {
            throw KeychainError.unknown(firstError)
        }
        return false
    }

    private func existence(account: String) -> SecretExistence {
        for synchronizable in readSynchronizableValues {
            let queries = readQueries(account: account, synchronizable: synchronizable)
            for var query in queries {
                query[kSecMatchLimit as String] = kSecMatchLimitOne

                let status = SecItemCopyMatching(query as CFDictionary, nil)
                switch status {
                case errSecSuccess:
                    return .present
                case errSecItemNotFound:
                    continue
                case errSecMissingEntitlement,
                     errSecInteractionNotAllowed,
                     errSecAuthFailed,
                     errSecUserCanceled:
                    return .unavailable
                default:
                    if Self.isStoreUnavailable(status) {
                        continue
                    }
                    return .unavailable
                }
            }
        }
        return .missing
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

    private func retrieve(account: String, synchronizable: Bool) throws -> KeychainReadResult? {
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
            let service = query[kSecAttrService as String] as? String ?? Self.service
            return KeychainReadResult(data: data, service: service)
        }
        if let firstError {
            throw KeychainError.unknown(firstError)
        }
        return nil
    }

    private func makeBaseQuery(account: String, synchronizable: Bool) -> [String: Any] {
        Self.makeBaseQuery(account: account, synchronizable: synchronizable, useDataProtectionFallback: true)
    }

    private func readQueries(account: String, synchronizable: Bool) -> [[String: Any]] {
        var queries: [[String: Any]] = []
        for service in Self.readServices {
            queries.append(Self.makeBaseQuery(
                account: account,
                synchronizable: synchronizable,
                useDataProtectionFallback: true,
                service: service
            ))
        }
        #if os(macOS)
        if !synchronizable {
            for service in Self.readServices {
                queries.append(Self.makeBaseQuery(
                    account: account,
                    synchronizable: synchronizable,
                    useDataProtectionFallback: false,
                    service: service
                ))
            }
        }
        #endif
        return queries
    }

    private func deleteQueries(account: String, synchronizable: Bool) -> [[String: Any]] {
        readQueries(account: account, synchronizable: synchronizable)
    }

    static func baseQueryForTesting(
        account: String,
        synchronizable: Bool,
        accessGroup: String? = SharedKeychainAccessGroup.current()
    ) -> [String: Any] {
        makeBaseQuery(
            account: account,
            synchronizable: synchronizable,
            useDataProtectionFallback: true,
            accessGroup: accessGroup
        )
    }

    static func readQueriesForTesting(account: String, synchronizable: Bool) -> [[String: Any]] {
        let store = VaultKeychainStore()
        return store.readQueries(account: account, synchronizable: synchronizable)
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

    private static var readServices: [String] {
        [service] + legacyServices
    }

    private static func makeBaseQuery(
        account: String,
        synchronizable: Bool,
        useDataProtectionFallback: Bool,
        service: String? = nil,
        accessGroup: String? = SharedKeychainAccessGroup.current()
    ) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: service ?? Self.service,
            kSecAttrSynchronizable as String: synchronizable,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        #if os(macOS)
        if !synchronizable && useDataProtectionFallback {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        #endif
        return query
    }

    @discardableResult
    private func upsert(_ data: Data, account: String, synchronizable: Bool) -> OSStatus {
        let status = upsert(
            data,
            account: account,
            synchronizable: synchronizable,
            useDataProtectionFallback: true
        )
        #if os(macOS)
        if !synchronizable, Self.isStoreUnavailable(status) {
            return upsert(
                data,
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
        _ data: Data,
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

    private struct KeychainReadResult {
        let data: Data
        let service: String
    }
}
