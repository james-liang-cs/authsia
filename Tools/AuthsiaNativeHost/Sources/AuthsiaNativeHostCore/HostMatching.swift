import Foundation

// Host matching itself lives in the app (`ChromeAutofillMatcher` in
// `AuthenticatorBridge`) so the native host never needs the whole vault to
// decide whether a site has anything stored. What remains here is input
// validation and the single-match selection applied to the matches the app
// already returned.

public struct HostMatchCandidate: Equatable {
    public let id: UUID
    public let storedHost: String
    public let isExact: Bool

    public init(id: UUID, storedHost: String, isExact: Bool) {
        self.id = id
        self.storedHost = storedHost
        self.isExact = isExact
    }
}

public enum HostMatchReason: Equatable {
    case singleExact
    case singleSubdomain
    case fuzzyMatch
}

public struct HostMatchSelection: Equatable {
    public let candidate: HostMatchCandidate
    public let reason: HostMatchReason

    public init(candidate: HostMatchCandidate, reason: HostMatchReason) {
        self.candidate = candidate
        self.reason = reason
    }
}

public func sanitizeHost(_ host: String?) -> String? {
    guard let host else { return nil }
    let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    guard !trimmed.isEmpty else { return nil }
    // Conservative host validation: letters, digits, dots, and hyphens only
    let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789.-")
    guard trimmed.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
        return nil
    }
    return trimmed
}

public func selectBestMatch(from candidates: [HostMatchCandidate]) -> HostMatchSelection? {
    guard !candidates.isEmpty else {
        return nil
    }

    let exactMatches = candidates.filter { $0.isExact }
    if exactMatches.count == 1 {
        return HostMatchSelection(candidate: exactMatches[0], reason: .singleExact)
    }

    // Prefer exact (domain) matches over fuzzy name matches. Multiple exact
    // matches stay ambiguous rather than picking arbitrarily.
    if !exactMatches.isEmpty {
        return nil
    }

    if candidates.count == 1 {
        return HostMatchSelection(candidate: candidates[0], reason: .singleSubdomain)
    }

    // Multiple non-exact candidates (e.g. "GitHub" and "GitHub Enterprise").
    // This function returns a SINGLE best match, so ambiguity resolves to none;
    // listing shows them all instead.
    return nil
}
