import Foundation
import Darwin
import Security
import AuthenticatorBridge

protocol SessionSecureStore {
    func save(data: Data, service: String, account: String) -> Bool
    func loadData(service: String, account: String) -> Data?
    func loadAllMetadata(service: String) -> [SessionSecureStoreMetadata]?
    func loadMetadata(service: String, account: String) -> SessionSecureStoreMetadata?
    func delete(service: String, account: String)
}

struct SessionSecureStoreMetadata {
    let account: String
    let modificationDate: Date
}

extension SessionSecureStore {
    func loadAllMetadata(service: String) -> [SessionSecureStoreMetadata]? { nil }
    func loadMetadata(service: String, account: String) -> SessionSecureStoreMetadata? { nil }
}

struct KeychainSessionSecureStore: SessionSecureStore {
    func save(data: Data, service: String, account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false,
        ]

        SecItemDelete(query as CFDictionary)

        var addQuery = query
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        return SecItemAdd(addQuery as CFDictionary, nil) == errSecSuccess
    }

    func loadData(service: String, account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }

    func loadAllMetadata(service: String) -> [SessionSecureStoreMetadata]? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrSynchronizable as String: false,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess,
              let items = result as? [[String: Any]] else {
            return nil
        }

        return items.compactMap(Self.metadata)
    }

    func loadMetadata(service: String, account: String) -> SessionSecureStoreMetadata? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let item = result as? [String: Any] else {
            return nil
        }
        return Self.metadata(item)
    }

    func delete(service: String, account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false,
        ]
        SecItemDelete(query as CFDictionary)
    }

    private static func metadata(_ item: [String: Any]) -> SessionSecureStoreMetadata? {
        guard let account = item[kSecAttrAccount as String] as? String,
              let modificationDate = item[kSecAttrModificationDate as String] as? Date else {
            return nil
        }
        return SessionSecureStoreMetadata(account: account, modificationDate: modificationDate)
    }
}

/// Persists the interactive CLI session token in a terminal-scoped Keychain item.
/// A legacy plaintext file (`~/.authsia/session.json`) is read only for one-time migration.
struct SessionCache {
    private static let keychainService = "com.authsia.cli.session"
    private static let keychainAccountPrefix = "terminal:"
    private static let legacySharedKeychainAccount = "default"
    private static let maximumSessionLifetime: TimeInterval = 24 * 60 * 60
    private static let legacyDirectoryName = ".authsia"
    private static let legacyFileName = "session.json"

    private struct CachedSession: Codable {
        let sessionToken: String
        let expiresAt: Date
    }

    static var legacySessionFilePath: URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home.appendingPathComponent(legacyDirectoryName).appendingPathComponent(legacyFileName)
    }

    /// Saves a session token and expiry to Keychain.
    static func save(token: String, expiresAt: Date, requestedCommand: String? = nil) {
        let secureStore = KeychainSessionSecureStore()
        save(
            token: token,
            expiresAt: expiresAt,
            secureStore: secureStore,
            legacyFilePath: legacySessionFilePath,
            keychainAccount: scopedKeychainAccount(requestedCommand: requestedCommand)
        )
    }

    /// Loads a valid (non-expired) session token.
    /// Returns nil if no cached session exists or it has expired.
    static func load(requestedCommand: String? = nil) -> String? {
        let secureStore = KeychainSessionSecureStore()
        return load(
            secureStore: secureStore,
            legacyFilePath: legacySessionFilePath,
            keychainAccount: scopedKeychainAccount(requestedCommand: requestedCommand)
        )
    }

    /// Returns the cached session's expiry date if it exists and hasn't expired.
    static func loadExpiresAt(requestedCommand: String? = nil) -> Date? {
        let secureStore = KeychainSessionSecureStore()
        return loadExpiresAt(
            secureStore: secureStore,
            legacyFilePath: legacySessionFilePath,
            keychainAccount: scopedKeychainAccount(requestedCommand: requestedCommand)
        )
    }

    static func loadExpiresAt(keychainAccount: String?) -> Date? {
        let secureStore = KeychainSessionSecureStore()
        return loadExpiresAt(
            secureStore: secureStore,
            legacyFilePath: legacySessionFilePath,
            keychainAccount: keychainAccount
        )
    }

    /// Removes any cached session token from Keychain and legacy disk cache.
    static func clear(requestedCommand: String? = nil) {
        let secureStore = KeychainSessionSecureStore()
        clear(
            secureStore: secureStore,
            legacyFilePath: legacySessionFilePath,
            keychainAccount: scopedKeychainAccount(requestedCommand: requestedCommand)
        )
    }

    // MARK: - Internal Test Seams

    static func scopedKeychainAccount(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        terminalIdentifier: String? = TerminalSessionScope.currentTerminalIdentifier(),
        processSessionIdentifier: Int32? = TerminalSessionScope.currentProcessSessionIdentifier(),
        ancestralScope: () -> String? = TerminalSessionScope.currentAncestralScope,
        processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry(),
        requestedCommand: String? = nil
    ) -> String? {
        guard let identity = sessionScope(
            environment: environment,
            terminalIdentifier: terminalIdentifier,
            processSessionIdentifier: processSessionIdentifier,
            ancestralScope: ancestralScope,
            processAncestry: processAncestry,
            requestedCommand: requestedCommand
        ) else {
            return nil
        }
        return "\(keychainAccountPrefix)\(identity)"
    }

    static func humanScopedKeychainAccount(
        terminalIdentifier: String? = TerminalSessionScope.currentTerminalIdentifier(),
        processSessionIdentifier: Int32? = TerminalSessionScope.currentProcessSessionIdentifier(),
        ancestralScope: () -> String? = TerminalSessionScope.currentAncestralScope
    ) -> String? {
        guard let identity = humanSessionScope(
            terminalIdentifier: terminalIdentifier,
            processSessionIdentifier: processSessionIdentifier,
            ancestralScope: ancestralScope
        ) else {
            return nil
        }
        return "\(keychainAccountPrefix)\(identity)"
    }

    static func sessionScope(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        terminalIdentifier: String? = TerminalSessionScope.currentTerminalIdentifier(),
        processSessionIdentifier: Int32? = TerminalSessionScope.currentProcessSessionIdentifier(),
        ancestralScope: () -> String? = TerminalSessionScope.currentAncestralScope,
        processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry(),
        requestedCommand: String? = nil
    ) -> String? {
        guard !hasAutomationCredential(in: environment) else {
            return nil
        }
        if requestedCommand == BridgeContext.chromeNativeHostRequestedCommand
            || BridgeContext.isChromeNativeHostAncestry(processAncestry) {
            return BridgeContext.chromeNativeHostSessionScope
        }
        if let identity = sessionIdentity(
            terminalIdentifier: terminalIdentifier,
            processSessionIdentifier: processSessionIdentifier
        ) {
            return identity
        }
        return ancestralScope()
    }

    /// Terminal scope for status display and lock targeting. Unlike `sessionScope`,
    /// this falls back to the controlling terminal of the nearest tty-bearing
    /// ancestor so it matches the scope the SSH agent records for approvals made
    /// from the same terminal, even when the CLI itself runs with piped stdio.
    static func humanSessionScope(
        terminalIdentifier: String? = TerminalSessionScope.currentTerminalIdentifier(),
        processSessionIdentifier: Int32? = TerminalSessionScope.currentProcessSessionIdentifier(),
        ancestralScope: () -> String? = TerminalSessionScope.currentAncestralScope
    ) -> String? {
        if let identity = sessionIdentity(
            terminalIdentifier: terminalIdentifier,
            processSessionIdentifier: processSessionIdentifier
        ) {
            return identity
        }
        return ancestralScope()
    }

    static func save(
        token: String,
        expiresAt: Date,
        secureStore: any SessionSecureStore,
        legacyFilePath: URL,
        keychainAccount: String?
    ) {
        pruneExpiredSessions(secureStore: secureStore)
        clearLegacySharedSession(secureStore: secureStore, legacyFilePath: legacyFilePath)
        guard let keychainAccount else { return }

        let cached = CachedSession(sessionToken: token, expiresAt: expiresAt)
        guard let data = try? JSONEncoder().encode(cached) else { return }

        _ = secureStore.save(
            data: data,
            service: keychainService,
            account: keychainAccount
        )
    }

    static func load(
        secureStore: any SessionSecureStore,
        legacyFilePath: URL,
        keychainAccount: String?
    ) -> String? {
        pruneExpiredSessions(secureStore: secureStore)
        secureStore.delete(service: keychainService, account: legacySharedKeychainAccount)
        guard let keychainAccount else {
            removeLegacySessionFile(at: legacyFilePath)
            return nil
        }
        return loadCachedSession(
            secureStore: secureStore,
            legacyFilePath: legacyFilePath,
            keychainAccount: keychainAccount
        )?.sessionToken
    }

    static func loadExpiresAt(
        secureStore: any SessionSecureStore,
        legacyFilePath: URL,
        keychainAccount: String?
    ) -> Date? {
        pruneExpiredSessions(secureStore: secureStore)
        secureStore.delete(service: keychainService, account: legacySharedKeychainAccount)
        guard let keychainAccount else {
            removeLegacySessionFile(at: legacyFilePath)
            return nil
        }
        return loadCachedSession(
            secureStore: secureStore,
            legacyFilePath: legacyFilePath,
            keychainAccount: keychainAccount
        )?.expiresAt
    }

    static func clear(
        secureStore: any SessionSecureStore,
        legacyFilePath: URL,
        keychainAccount: String?
    ) {
        pruneExpiredSessions(secureStore: secureStore)
        if let keychainAccount {
            secureStore.delete(service: keychainService, account: keychainAccount)
        }
        clearLegacySharedSession(secureStore: secureStore, legacyFilePath: legacyFilePath)
    }

    // MARK: - Private Helpers

    private static func loadCachedSession(
        secureStore: any SessionSecureStore,
        legacyFilePath: URL,
        keychainAccount: String
    ) -> CachedSession? {
        if let keychainData = secureStore.loadData(service: keychainService, account: keychainAccount) {
            guard let cached = decodeCachedSession(from: keychainData) else {
                secureStore.delete(service: keychainService, account: keychainAccount)
                removeLegacySessionFile(at: legacyFilePath)
                return nil
            }

            guard cached.expiresAt > Date() else {
                clear(
                    secureStore: secureStore,
                    legacyFilePath: legacyFilePath,
                    keychainAccount: keychainAccount
                )
                return nil
            }

            return cached
        }

        return migrateLegacySessionIfNeeded(
            secureStore: secureStore,
            legacyFilePath: legacyFilePath,
            keychainAccount: keychainAccount
        )
    }

    private static func migrateLegacySessionIfNeeded(
        secureStore: any SessionSecureStore,
        legacyFilePath: URL,
        keychainAccount: String
    ) -> CachedSession? {
        guard let data = try? Data(contentsOf: legacyFilePath) else { return nil }
        guard let cached = decodeCachedSession(from: data) else {
            removeLegacySessionFile(at: legacyFilePath)
            return nil
        }
        guard cached.expiresAt > Date() else {
            removeLegacySessionFile(at: legacyFilePath)
            return nil
        }

        if let encoded = try? JSONEncoder().encode(cached) {
            _ = secureStore.save(
                data: encoded,
                service: keychainService,
                account: keychainAccount
            )
        }

        removeLegacySessionFile(at: legacyFilePath)
        return cached
    }

    private static func decodeCachedSession(from data: Data) -> CachedSession? {
        try? JSONDecoder().decode(CachedSession.self, from: data)
    }

    private static func pruneExpiredSessions(
        secureStore: any SessionSecureStore,
        now: Date = Date()
    ) {
        guard let metadata = secureStore.loadAllMetadata(service: keychainService) else { return }
        let staleBefore = now.addingTimeInterval(-maximumSessionLifetime)
        for item in metadata where item.account.hasPrefix(keychainAccountPrefix) {
            let account = item.account
            guard item.modificationDate <= staleBefore,
                  let latest = secureStore.loadMetadata(service: keychainService, account: account),
                  latest.modificationDate <= staleBefore else {
                continue
            }
            secureStore.delete(service: keychainService, account: account)
        }
    }

    private static func removeLegacySessionFile(at legacyFilePath: URL) {
        try? FileManager.default.removeItem(at: legacyFilePath)
    }

    private static func clearLegacySharedSession(
        secureStore: any SessionSecureStore,
        legacyFilePath: URL
    ) {
        secureStore.delete(service: keychainService, account: legacySharedKeychainAccount)
        removeLegacySessionFile(at: legacyFilePath)
    }

    static func hasAutomationCredential(in environment: [String: String]) -> Bool {
        nonEmpty(environment[AutomationCredentialEnvironment.generalCredentialKey]) != nil
            || nonEmpty(environment[AutomationCredentialEnvironment.sshCredentialKey]) != nil
    }

    private static func sessionIdentity(
        terminalIdentifier: String?,
        processSessionIdentifier: Int32?
    ) -> String? {
        TerminalSessionScope.identity(
            terminalIdentifier: terminalIdentifier,
            processSessionIdentifier: processSessionIdentifier
        )
    }

    static func currentTerminalIdentifier() -> String? {
        TerminalSessionScope.currentTerminalIdentifier()
    }

    static func currentProcessSessionIdentifier() -> Int32? {
        TerminalSessionScope.currentProcessSessionIdentifier()
    }

    private static func nonEmpty(_ value: String?) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
