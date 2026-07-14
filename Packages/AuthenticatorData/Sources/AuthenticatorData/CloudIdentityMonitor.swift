import Foundation

/// Detects Apple ID changes by tracking the ubiquityIdentityToken across launches.
@MainActor
public final class CloudIdentityMonitor {
    public static let tokenKey = "lastKnownUbiquityIdentityToken"
    public static let hasStoredTokenKey = "hasStoredUbiquityIdentityToken"

    public var onIdentityChange: (@MainActor () -> Void)?

    private let defaults: UserDefaults
    private nonisolated(unsafe) var notificationObserver: NSObjectProtocol?

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    deinit {
        if let observer = notificationObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    /// Start observing `NSUbiquityIdentityDidChange` at runtime.
    public func startObserving() {
        notificationObserver = NotificationCenter.default.addObserver(
            forName: .NSUbiquityIdentityDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                _ = self?.checkNow()
            }
        }
    }

    /// Perform an immediate identity check. Returns true if identity changed, false otherwise.
    /// Called on launch and on notification.
    @discardableResult
    public func checkNow() -> Bool {
        let currentToken = FileManager.default.ubiquityIdentityToken
        let currentData = archiveToken(currentToken)
        let hadPrevious = defaults.bool(forKey: Self.hasStoredTokenKey)

        var changed = false

        if hadPrevious {
            let storedData = defaults.data(forKey: Self.tokenKey)
            if currentData != storedData {
                changed = true
                onIdentityChange?()
            }
        }

        // Persist current state
        if let data = currentData {
            defaults.set(data, forKey: Self.tokenKey)
        } else {
            defaults.removeObject(forKey: Self.tokenKey)
        }
        defaults.set(true, forKey: Self.hasStoredTokenKey)

        return changed
    }

    private func archiveToken(_ token: (any NSCoding & NSObjectProtocol)?) -> Data? {
        guard let token else { return nil }
        return try? NSKeyedArchiver.archivedData(withRootObject: token, requiringSecureCoding: false)
    }
}
