#if os(macOS)
import Foundation
import Darwin
import AuthenticatorBridge

public nonisolated struct BridgeActiveSession: Equatable, Identifiable, Sendable {
    public let scope: String?
    public let expiresAt: Date
    public let workingDirectory: String?
    public let origin: BridgeSessionOrigin?

    public init(
        scope: String?,
        expiresAt: Date,
        workingDirectory: String?,
        origin: BridgeSessionOrigin? = nil
    ) {
        self.scope = scope
        self.expiresAt = expiresAt
        self.workingDirectory = workingDirectory
        self.origin = origin
    }

    public var id: String {
        scope ?? "__unscoped__"
    }
}

/// Manages authenticated CLI sessions with anti-replay protection (macOS only)
public final class BridgeSessionManager: @unchecked Sendable {
    public static let shared = BridgeSessionManager()

    private struct StoredSession {
        let session: BridgeSession
        let createdAt: Date
        let origin: BridgeSessionOrigin?
        var usedRequestIds: Set<UUID> = []
    }

    private var sessionsByScope: [String: StoredSession] = [:]
    private let lock = NSLock()
    private let sessionStatusFileURL: URL
    private let processIdentifier: Int32
    private let terminalScopeIsUsable: (String) -> Bool
    private static let maxUsedRequestIds = 1000

    /// The UserDefaults key for CLI session TTL setting
    public static let cliSessionTTLKey = BridgeSettings.cliSessionTTLKey

    /// Default TTL in seconds (15 seconds)
    public static let defaultTTL: TimeInterval = BridgeSettings.defaultSessionTTL

    /// Returns the configured CLI session TTL from UserDefaults, or the default if not set
    public static var configuredTTL: TimeInterval {
        BridgeSettings.sessionTTL()
    }

    public static func configuredTTL(defaults: UserDefaults) -> TimeInterval {
        BridgeSettings.sessionTTL(defaults: defaults)
    }

    public init(
        sessionStatusFileURL: URL = BridgeSessionStatusStore.defaultFileURL,
        processIdentifier: Int32 = getpid(),
        terminalScopeIsUsable: @escaping (String) -> Bool = BridgeSessionManager.defaultTerminalScopeIsUsable
    ) {
        self.sessionStatusFileURL = sessionStatusFileURL
        self.processIdentifier = processIdentifier
        self.terminalScopeIsUsable = terminalScopeIsUsable
    }

    /// Returns the current session if valid under the current TTL setting
    public var currentSession: BridgeSession? {
        lock.lock()
        defer { lock.unlock() }
        pruneExpiredSessions()
        return sessionsByScope.values.first?.session
    }

    public func currentSession(scope: String?) -> BridgeSession? {
        lock.lock()
        defer { lock.unlock() }
        pruneExpiredSessions()
        let key = sessionKey(for: scope)
        guard let stored = sessionsByScope[key],
              isEffectivelyValid(session: stored.session, createdAt: stored.createdAt) else {
            sessionsByScope[key] = nil
            return nil
        }
        return stored.session
    }

    public func activeSessions() -> [BridgeActiveSession] {
        lock.lock()
        defer { lock.unlock() }
        pruneExpiredSessions()
        return Self.loadActiveSessions(
            fileURL: sessionStatusFileURL,
            terminalScopeIsUsable: terminalScopeIsUsable
        )
    }

    public nonisolated static func loadActiveSessionsForAccessCenter() -> [BridgeActiveSession] {
        loadActiveSessions(
            fileURL: BridgeSessionStatusStore.defaultFileURL,
            terminalScopeIsUsable: defaultTerminalScopeIsUsable
        )
    }

    private nonisolated static func loadActiveSessions(
        fileURL: URL,
        terminalScopeIsUsable: (String) -> Bool
    ) -> [BridgeActiveSession] {
        return BridgeSessionStatusStore.activeSessions(fileURL: fileURL)
            .filter { terminalScopeIsUsable($0.scope) }
            .map { record in
                BridgeActiveSession(
                    scope: sessionScope(forStatusScope: record.scope),
                    expiresAt: record.expiresAt,
                    workingDirectory: record.workingDirectory,
                    origin: record.origin
                )
            }
            .sorted {
                switch ($0.scope, $1.scope) {
                case let (lhs?, rhs?):
                    return lhs < rhs
                case (nil, _?):
                    return false
                case (_?, nil):
                    return true
                case (nil, nil):
                    return $0.expiresAt < $1.expiresAt
                }
            }
    }

    /// Creates a new session with a unique token
    public func createSession(
        ttlSeconds: TimeInterval = BridgeSessionManager.configuredTTL,
        scope: String? = nil,
        workingDirectory: String? = nil,
        origin: BridgeSessionOrigin? = nil
    ) throws -> BridgeSession {
        lock.lock()
        defer { lock.unlock() }
        let now = Date()
        let newSession = try BridgeSession(expiresAt: now.addingTimeInterval(ttlSeconds))
        let key = sessionKey(for: scope)
        try BridgeSessionStatusStore.upsertSession(
            scope: key,
            expiresAt: newSession.expiresAt,
            bridgePID: processIdentifier,
            fileURL: sessionStatusFileURL,
            now: now,
            workingDirectory: workingDirectory,
            origin: origin
        )
        sessionsByScope[key] = StoredSession(session: newSession, createdAt: now, origin: origin)
        return newSession
    }

    /// Convenience that maps session-creation failure to a BridgeResponse error.
    /// Use this in XPC reply handlers where throwing is not practical.
    public func createSessionOrNil(
        ttlSeconds: TimeInterval = BridgeSessionManager.configuredTTL,
        scope: String? = nil,
        workingDirectory: String? = nil,
        origin: BridgeSessionOrigin? = nil
    ) -> BridgeSession? {
        try? createSession(
            ttlSeconds: ttlSeconds,
            scope: scope,
            workingDirectory: workingDirectory,
            origin: origin
        )
    }

    /// Invalidates the current session and clears used request IDs
    public func invalidate() {
        lock.lock()
        defer { lock.unlock() }
        sessionsByScope.removeAll()
        BridgeSessionStatusStore.clear(fileURL: sessionStatusFileURL)
    }

    public func invalidate(sessionToken token: String, scope: String? = nil) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let key = sessionKey(for: scope)
        guard let stored = sessionsByScope[key],
              isEffectivelyValid(session: stored.session, createdAt: stored.createdAt),
              stored.session.sessionToken == token else {
            sessionsByScope[key] = nil
            return false
        }
        sessionsByScope[key] = nil
        BridgeSessionStatusStore.clearSessionScope(key, fileURL: sessionStatusFileURL)
        return true
    }

    public func invalidate(scope: String?) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let key = sessionKey(for: scope)
        let didClearStatus = BridgeSessionStatusStore.clearSessionScope(key, fileURL: sessionStatusFileURL)
        guard let stored = sessionsByScope[key],
              isEffectivelyValid(session: stored.session, createdAt: stored.createdAt) else {
            sessionsByScope[key] = nil
            return didClearStatus
        }
        sessionsByScope[key] = nil
        return true
    }

    /// Validates a session token for the current session
    public func validateSessionToken(_ token: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        pruneExpiredSessions()
        return sessionsByScope.values.contains { $0.session.sessionToken == token }
    }

    /// Validates a request ID to prevent replay attacks
    /// Returns true if the request ID is new and valid, false if it's been used or there's no valid session
    public func validateRequestId(
        _ requestId: UUID,
        sessionToken: String,
        scope: String?,
        origin: BridgeSessionOrigin? = nil
    ) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        // Check session validity and token match
        let key = sessionKey(for: scope)
        guard var stored = sessionsByScope[key],
              isEffectivelyValid(session: stored.session, createdAt: stored.createdAt),
              statusStoreContainsSession(scope: key) else {
            sessionsByScope[key] = nil
            return false
        }

        guard stored.session.sessionToken == sessionToken else {
            return false
        }
        guard stored.origin == origin else {
            return false
        }

        // Check if request ID has already been used (replay detection)
        guard !stored.usedRequestIds.contains(requestId) else {
            return false
        }

        // Mark request ID as used
        stored.usedRequestIds.insert(requestId)

        // Prevent memory growth by capping the set size
        if stored.usedRequestIds.count > Self.maxUsedRequestIds {
            let toRemove = stored.usedRequestIds.prefix(stored.usedRequestIds.count - Self.maxUsedRequestIds)
            stored.usedRequestIds.subtract(toRemove)
        }

        sessionsByScope[key] = stored
        return true
    }

    public func hasOrigin(_ origin: BridgeSessionOrigin, scope: String?) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let key = sessionKey(for: scope)
        guard let stored = sessionsByScope[key],
              isEffectivelyValid(session: stored.session, createdAt: stored.createdAt),
              statusStoreContainsSession(scope: key) else {
            return false
        }
        return stored.origin == origin
    }

    // MARK: - Effective Validity

    /// Checks whether a session is still valid under the *current* TTL setting.
    /// Uses `min(session.expiresAt, createdAt + configuredTTL)` so that lowering the TTL
    /// retroactively shortens an existing session.
    private func isEffectivelyValid(session: BridgeSession, createdAt: Date?) -> Bool {
        let now = Date()
        guard session.expiresAt > now else { return false }
        guard let createdAt else { return true }
        let effectiveExpiry = createdAt.addingTimeInterval(Self.configuredTTL)
        return effectiveExpiry > now
    }

    private func pruneExpiredSessions() {
        sessionsByScope = sessionsByScope.filter {
            isEffectivelyValid(session: $0.value.session, createdAt: $0.value.createdAt)
                && statusStoreContainsSession(scope: $0.key)
                && terminalScopeIsUsable($0.key)
        }
    }

    private func sessionKey(for scope: String?) -> String {
        guard let scope = scope?.trimmingCharacters(in: .whitespacesAndNewlines),
              !scope.isEmpty else {
            return BridgeSessionStatusStore.unscopedScope
        }
        return scope
    }

    private nonisolated static func sessionScope(forStatusScope scope: String) -> String? {
        scope == BridgeSessionStatusStore.unscopedScope ? nil : scope
    }

    private func statusStoreContainsSession(scope: String) -> Bool {
        BridgeSessionStatusStore.containsSession(
            scope: scope,
            bridgePID: processIdentifier,
            fileURL: sessionStatusFileURL
        )
    }

    @usableFromInline
    nonisolated static func defaultTerminalScopeIsUsable(_ scope: String) -> Bool {
        guard scope != BridgeSessionStatusStore.unscopedScope,
              TerminalSessionScope.components(from: scope) != nil else {
            return true
        }
        return TerminalSessionScope.liveness(for: scope) != .closed
    }
}
#endif
