import Testing
import Foundation
import AuthenticatorBridge
@testable import authsia

@Suite("Session cache")
struct SessionCacheTests {
    @Test("saving a session prunes expired terminal sessions")
    func savingSessionPrunesExpiredTerminalSessions() throws {
        let secureStore = ScopedInMemorySessionSecureStore()
        let legacyFile = temporaryLegacyFile()
        defer { try? FileManager.default.removeItem(at: legacyFile.deletingLastPathComponent()) }
        let service = "com.authsia.cli.session"

        _ = secureStore.save(
            data: try encodedSession(token: "expired-token", expiresAt: Date().addingTimeInterval(-60)),
            service: service,
            account: "terminal:expired"
        )
        _ = secureStore.save(
            data: try encodedSession(token: "active-token", expiresAt: Date().addingTimeInterval(60)),
            service: service,
            account: "terminal:active"
        )
        secureStore.modificationDateByAccount["terminal:expired"] = Date().addingTimeInterval(-25 * 60 * 60)

        SessionCache.save(
            token: "current-token",
            expiresAt: Date().addingTimeInterval(60),
            secureStore: secureStore,
            legacyFilePath: legacyFile,
            keychainAccount: "terminal:current"
        )

        #expect(secureStore.loadData(service: service, account: "terminal:expired") == nil)
        #expect(secureStore.loadData(service: service, account: "terminal:active") != nil)
        #expect(secureStore.loadData(service: service, account: "terminal:current") != nil)
    }

    @Test("loading a session prunes corrupt terminal sessions only")
    func loadingSessionPrunesCorruptTerminalSessionsOnly() throws {
        let secureStore = ScopedInMemorySessionSecureStore()
        let legacyFile = temporaryLegacyFile()
        defer { try? FileManager.default.removeItem(at: legacyFile.deletingLastPathComponent()) }
        let service = "com.authsia.cli.session"

        _ = secureStore.save(
            data: Data("not-a-session".utf8),
            service: service,
            account: "terminal:corrupt"
        )
        _ = secureStore.save(
            data: Data("unrelated-data".utf8),
            service: service,
            account: "unrelated-account"
        )
        secureStore.modificationDateByAccount["terminal:corrupt"] = Date().addingTimeInterval(-25 * 60 * 60)
        _ = secureStore.save(
            data: try encodedSession(token: "current-token", expiresAt: Date().addingTimeInterval(60)),
            service: service,
            account: "terminal:current"
        )

        let token = SessionCache.load(
            secureStore: secureStore,
            legacyFilePath: legacyFile,
            keychainAccount: "terminal:current"
        )

        #expect(token == "current-token")
        #expect(secureStore.loadData(service: service, account: "terminal:corrupt") == nil)
        #expect(secureStore.loadData(service: service, account: "unrelated-account") != nil)
    }

    @Test("loading session expiry prunes expired terminal sessions")
    func loadingSessionExpiryPrunesExpiredTerminalSessions() throws {
        let secureStore = ScopedInMemorySessionSecureStore()
        let legacyFile = temporaryLegacyFile()
        defer { try? FileManager.default.removeItem(at: legacyFile.deletingLastPathComponent()) }
        let service = "com.authsia.cli.session"
        let currentExpiry = Date().addingTimeInterval(60)

        _ = secureStore.save(
            data: try encodedSession(token: "expired-token", expiresAt: Date().addingTimeInterval(-60)),
            service: service,
            account: "terminal:expired"
        )
        _ = secureStore.save(
            data: try encodedSession(token: "current-token", expiresAt: currentExpiry),
            service: service,
            account: "terminal:current"
        )
        secureStore.modificationDateByAccount["terminal:expired"] = Date().addingTimeInterval(-25 * 60 * 60)

        let expiresAt = SessionCache.loadExpiresAt(
            secureStore: secureStore,
            legacyFilePath: legacyFile,
            keychainAccount: "terminal:current"
        )

        #expect(expiresAt == currentExpiry)
        #expect(secureStore.loadData(service: service, account: "terminal:expired") == nil)
    }

    @Test("clearing a session prunes expired terminal sessions")
    func clearingSessionPrunesExpiredTerminalSessions() throws {
        let secureStore = ScopedInMemorySessionSecureStore()
        let legacyFile = temporaryLegacyFile()
        defer { try? FileManager.default.removeItem(at: legacyFile.deletingLastPathComponent()) }
        let service = "com.authsia.cli.session"

        _ = secureStore.save(
            data: try encodedSession(token: "expired-token", expiresAt: Date().addingTimeInterval(-60)),
            service: service,
            account: "terminal:expired"
        )
        _ = secureStore.save(
            data: try encodedSession(token: "active-token", expiresAt: Date().addingTimeInterval(60)),
            service: service,
            account: "terminal:active"
        )
        _ = secureStore.save(
            data: try encodedSession(token: "current-token", expiresAt: Date().addingTimeInterval(60)),
            service: service,
            account: "terminal:current"
        )
        secureStore.modificationDateByAccount["terminal:expired"] = Date().addingTimeInterval(-25 * 60 * 60)

        SessionCache.clear(
            secureStore: secureStore,
            legacyFilePath: legacyFile,
            keychainAccount: "terminal:current"
        )

        #expect(secureStore.loadData(service: service, account: "terminal:expired") == nil)
        #expect(secureStore.loadData(service: service, account: "terminal:active") != nil)
        #expect(secureStore.loadData(service: service, account: "terminal:current") == nil)
    }

    @Test("enumeration failure does not delete terminal sessions")
    func enumerationFailureDoesNotDeleteTerminalSessions() throws {
        let secureStore = ScopedInMemorySessionSecureStore()
        let legacyFile = temporaryLegacyFile()
        defer { try? FileManager.default.removeItem(at: legacyFile.deletingLastPathComponent()) }
        let service = "com.authsia.cli.session"

        _ = secureStore.save(
            data: try encodedSession(token: "expired-token", expiresAt: Date().addingTimeInterval(-60)),
            service: service,
            account: "terminal:expired"
        )
        secureStore.enumerationFails = true

        SessionCache.save(
            token: "current-token",
            expiresAt: Date().addingTimeInterval(60),
            secureStore: secureStore,
            legacyFilePath: legacyFile,
            keychainAccount: "terminal:current"
        )

        #expect(secureStore.loadData(service: service, account: "terminal:expired") != nil)
    }

    @Test("stale enumeration does not delete a renewed terminal session")
    func staleEnumerationDoesNotDeleteRenewedTerminalSession() throws {
        let secureStore = ScopedInMemorySessionSecureStore()
        let legacyFile = temporaryLegacyFile()
        defer { try? FileManager.default.removeItem(at: legacyFile.deletingLastPathComponent()) }
        let service = "com.authsia.cli.session"
        let renewedData = try encodedSession(
            token: "renewed-token",
            expiresAt: Date().addingTimeInterval(60)
        )

        _ = secureStore.save(
            data: renewedData,
            service: service,
            account: "terminal:renewed"
        )
        secureStore.enumeratedMetadataByAccount = [
            "terminal:renewed": Date().addingTimeInterval(-25 * 60 * 60)
        ]

        SessionCache.save(
            token: "current-token",
            expiresAt: Date().addingTimeInterval(60),
            secureStore: secureStore,
            legacyFilePath: legacyFile,
            keychainAccount: "terminal:current"
        )

        #expect(secureStore.loadData(service: service, account: "terminal:renewed") == renewedData)
    }

    @Test("old terminal sessions are pruned without reading secret data")
    func oldTerminalSessionsArePrunedWithoutReadingSecretData() throws {
        let secureStore = ScopedInMemorySessionSecureStore()
        let legacyFile = temporaryLegacyFile()
        defer { try? FileManager.default.removeItem(at: legacyFile.deletingLastPathComponent()) }
        let service = "com.authsia.cli.session"

        _ = secureStore.save(
            data: try encodedSession(token: "stale-token", expiresAt: Date().addingTimeInterval(3600)),
            service: service,
            account: "terminal:stale"
        )
        secureStore.modificationDateByAccount["terminal:stale"] = Date().addingTimeInterval(-25 * 60 * 60)

        SessionCache.save(
            token: "current-token",
            expiresAt: Date().addingTimeInterval(60),
            secureStore: secureStore,
            legacyFilePath: legacyFile,
            keychainAccount: "terminal:current"
        )

        #expect(secureStore.dataByAccount["terminal:stale"] == nil)
        #expect(!secureStore.loadedDataAccounts.contains("terminal:stale"))
    }

    @Test("recent terminal sessions are not read during global pruning")
    func recentTerminalSessionsAreNotReadDuringGlobalPruning() throws {
        let secureStore = ScopedInMemorySessionSecureStore()
        let legacyFile = temporaryLegacyFile()
        defer { try? FileManager.default.removeItem(at: legacyFile.deletingLastPathComponent()) }
        let service = "com.authsia.cli.session"

        _ = secureStore.save(
            data: try encodedSession(token: "other-token", expiresAt: Date().addingTimeInterval(-60)),
            service: service,
            account: "terminal:other"
        )

        SessionCache.save(
            token: "current-token",
            expiresAt: Date().addingTimeInterval(60),
            secureStore: secureStore,
            legacyFilePath: legacyFile,
            keychainAccount: "terminal:current"
        )

        #expect(secureStore.dataByAccount["terminal:other"] != nil)
        #expect(!secureStore.loadedDataAccounts.contains("terminal:other"))
    }

    @Test("cached sessions are isolated by terminal scope")
    func cachedSessionsAreIsolatedByTerminalScope() {
        let secureStore = ScopedInMemorySessionSecureStore()
        let legacyFile = temporaryLegacyFile()
        defer { try? FileManager.default.removeItem(at: legacyFile.deletingLastPathComponent()) }

        SessionCache.save(
            token: "human-token",
            expiresAt: Date().addingTimeInterval(60),
            secureStore: secureStore,
            legacyFilePath: legacyFile,
            keychainAccount: "terminal-a"
        )

        #expect(
            SessionCache.load(
                secureStore: secureStore,
                legacyFilePath: legacyFile,
                keychainAccount: "terminal-a"
            ) == "human-token"
        )
        #expect(
            SessionCache.load(
                secureStore: secureStore,
                legacyFilePath: legacyFile,
                keychainAccount: "terminal-b"
            ) == nil
        )
    }

    @Test("automation credentials disable interactive session cache")
    func automationCredentialsDisableInteractiveSessionCache() {
        let account = SessionCache.scopedKeychainAccount(
            environment: [
                AutomationCredentialEnvironment.generalCredentialKey: UUID().uuidString,
                "TERM_SESSION_ID": "human-terminal",
            ],
            terminalIdentifier: "/dev/ttys001"
        )

        #expect(account == nil)
    }

    @Test("chrome native host ancestry uses a stable session scope")
    func chromeNativeHostAncestryUsesStableSessionScope() {
        let ancestry = [
            AgenticProcessReference(processName: "authsia", bundleIdentifier: nil),
            AgenticProcessReference(
                processName: BridgeContext.chromeNativeHostProcessName,
                bundleIdentifier: nil
            ),
            AgenticProcessReference(processName: "Google Chrome", bundleIdentifier: "com.google.Chrome"),
        ]

        let scope = SessionCache.sessionScope(
            environment: [:],
            terminalIdentifier: nil,
            processSessionIdentifier: nil,
            ancestralScope: { nil },
            processAncestry: ancestry
        )
        let account = SessionCache.scopedKeychainAccount(
            environment: [:],
            terminalIdentifier: nil,
            processSessionIdentifier: nil,
            processAncestry: ancestry
        )

        #expect(scope == BridgeContext.chromeNativeHostSessionScope)
        #expect(account == "terminal:\(BridgeContext.chromeNativeHostSessionScope)")
    }

    @Test("chrome native host requested command uses a stable session scope")
    func chromeNativeHostRequestedCommandUsesStableSessionScope() {
        let scope = SessionCache.sessionScope(
            environment: [:],
            terminalIdentifier: nil,
            processSessionIdentifier: nil,
            ancestralScope: { nil },
            processAncestry: [],
            requestedCommand: BridgeContext.chromeNativeHostRequestedCommand
        )

        #expect(scope == BridgeContext.chromeNativeHostSessionScope)
    }

    @Test("automation credentials disable bridge session scope")
    func automationCredentialsDisableBridgeSessionScope() {
        let scope = SessionCache.sessionScope(
            environment: [
                AutomationCredentialEnvironment.generalCredentialKey: UUID().uuidString,
                "TERM_SESSION_ID": "human-terminal",
            ],
            terminalIdentifier: "/dev/ttys001"
        )

        #expect(scope == nil)
    }

    @Test("human terminal scope ignores automation credentials for diagnostics")
    func humanTerminalScopeIgnoresAutomationCredentialsForDiagnostics() {
        let scope = SessionCache.humanSessionScope(
            terminalIdentifier: "/dev/ttys001",
            processSessionIdentifier: 1001
        )
        let account = SessionCache.humanScopedKeychainAccount(
            terminalIdentifier: "/dev/ttys001",
            processSessionIdentifier: 1001
        )

        #expect(scope == "tty:/dev/ttys001:sid:1001")
        #expect(account == "terminal:tty:/dev/ttys001:sid:1001")
    }

    @Test("non-terminal contexts do not reuse interactive sessions")
    func nonTerminalContextsDoNotReuseInteractiveSessions() {
        let account = SessionCache.scopedKeychainAccount(
            environment: [:],
            terminalIdentifier: nil
        )

        #expect(account == nil)
    }

    @Test("inherited terminal session env without live tty does not create scope")
    func inheritedTerminalSessionEnvWithoutLiveTTYDoesNotCreateScope() {
        let account = SessionCache.scopedKeychainAccount(
            environment: ["TERM_SESSION_ID": "shared-by-app"],
            terminalIdentifier: nil,
            processSessionIdentifier: nil
        )

        #expect(account == nil)
    }

    @Test("same tty path is separated by process session id")
    func sameTTYPathIsSeparatedByProcessSessionID() {
        let first = SessionCache.scopedKeychainAccount(
            environment: [:],
            terminalIdentifier: "/dev/ttys001",
            processSessionIdentifier: 1001
        )
        let second = SessionCache.scopedKeychainAccount(
            environment: [:],
            terminalIdentifier: "/dev/ttys001",
            processSessionIdentifier: 1002
        )

        #expect(first == "terminal:tty:/dev/ttys001:sid:1001")
        #expect(second == "terminal:tty:/dev/ttys001:sid:1002")
    }

    @Test("direct CLI session scope falls back to controlling-terminal ancestry without a tty")
    func humanSessionScopeFallsBackToAncestryWithoutTTY() {
        let scope = SessionCache.humanSessionScope(
            terminalIdentifier: nil,
            processSessionIdentifier: nil,
            ancestralScope: { "tty:/dev/ttys004:sid:94228" }
        )
        let account = SessionCache.humanScopedKeychainAccount(
            terminalIdentifier: nil,
            processSessionIdentifier: nil,
            ancestralScope: { "tty:/dev/ttys004:sid:94228" }
        )

        #expect(scope == "tty:/dev/ttys004:sid:94228")
        #expect(account == "terminal:tty:/dev/ttys004:sid:94228")
    }

    @Test("direct CLI session scope prefers own tty over ancestry")
    func humanSessionScopePrefersOwnTTYOverAncestry() {
        let scope = SessionCache.humanSessionScope(
            terminalIdentifier: "/dev/ttys001",
            processSessionIdentifier: 1001,
            ancestralScope: { "tty:/dev/ttys004:sid:94228" }
        )

        #expect(scope == "tty:/dev/ttys001:sid:1001")
    }

    @Test("terminal identity prefers live tty over inherited session env")
    func terminalIdentityPrefersLiveTTYOverInheritedSessionEnv() {
        let account = SessionCache.scopedKeychainAccount(
            environment: ["TERM_SESSION_ID": "A1B2"],
            terminalIdentifier: "/dev/ttys001",
            processSessionIdentifier: 1001
        )

        #expect(account == "terminal:tty:/dev/ttys001:sid:1001")
    }

    private func temporaryLegacyFile() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-session-cache-\(UUID().uuidString)")
            .appendingPathComponent("session.json")
    }

    private func encodedSession(token: String, expiresAt: Date) throws -> Data {
        try JSONEncoder().encode(TestCachedSession(sessionToken: token, expiresAt: expiresAt))
    }
}

private struct TestCachedSession: Codable {
    let sessionToken: String
    let expiresAt: Date
}

private final class ScopedInMemorySessionSecureStore: SessionSecureStore {
    var dataByAccount: [String: Data] = [:]
    var modificationDateByAccount: [String: Date] = [:]
    var loadedDataAccounts: [String] = []
    var enumeratedMetadataByAccount: [String: Date]?
    var enumerationFails = false

    func save(data: Data, service: String, account: String) -> Bool {
        dataByAccount[account] = data
        modificationDateByAccount[account] = Date()
        return true
    }

    func loadData(service: String, account: String) -> Data? {
        loadedDataAccounts.append(account)
        return dataByAccount[account]
    }

    func loadAllMetadata(service: String) -> [SessionSecureStoreMetadata]? {
        guard !enumerationFails else { return nil }
        return (enumeratedMetadataByAccount ?? modificationDateByAccount).map {
            SessionSecureStoreMetadata(account: $0.key, modificationDate: $0.value)
        }
    }

    func loadMetadata(service: String, account: String) -> SessionSecureStoreMetadata? {
        guard let modificationDate = modificationDateByAccount[account] else { return nil }
        return SessionSecureStoreMetadata(account: account, modificationDate: modificationDate)
    }

    func delete(service: String, account: String) {
        dataByAccount.removeValue(forKey: account)
        modificationDateByAccount.removeValue(forKey: account)
    }
}
