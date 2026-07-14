import Foundation

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

public func parseStoredHost(from website: String?) -> String? {
    guard let url = parseWebsiteURL(website) else {
        return nil
    }
    return sanitizeHost(url.host)
}

private func parseWebsiteURL(_ website: String?) -> URL? {
    guard let website else { return nil }
    let trimmed = website.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return nil }

    guard !trimmed.contains(" ") else {
        return nil
    }

    let withScheme: String
    if trimmed.range(of: "^[a-zA-Z][a-zA-Z\\d+.-]*:", options: .regularExpression) != nil {
        withScheme = trimmed
    } else {
        withScheme = "https://\(trimmed)"
    }

    guard let url = URL(string: withScheme), url.host != nil else {
        return nil
    }
    return url
}

private func hasMeaningfulPath(_ url: URL) -> Bool {
    let path = url.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    return !path.isEmpty
}

private func normalizedPath(_ path: String) -> String {
    guard !path.isEmpty else { return "/" }
    var normalized = path
    while normalized.count > 1, normalized.hasSuffix("/") {
        normalized.removeLast()
    }
    return normalized
}

private func pathHasSegmentPrefix(currentPath: String, storedPath: String) -> Bool {
    let current = normalizedPath(currentPath)
    let stored = normalizedPath(storedPath)

    if stored == "/" { return true }
    if current == stored { return true }
    return current.hasPrefix("\(stored)/")
}

private func defaultPort(for scheme: String?) -> Int? {
    switch scheme?.lowercased() {
    case "http":
        return 80
    case "https":
        return 443
    default:
        return nil
    }
}

private func normalizedPort(_ url: URL) -> Int? {
    url.port ?? defaultPort(for: url.scheme)
}

private func isAWSSignInHost(_ host: String) -> Bool {
    host == "signin.aws.amazon.com" || host.hasSuffix(".signin.aws.amazon.com")
}

private func canonicalHostForComparison(_ host: String) -> String {
    host.hasPrefix("www.") ? String(host.dropFirst("www.".count)) : host
}

private func hostsAreEquivalent(_ lhs: String, _ rhs: String) -> Bool {
    canonicalHostForComparison(lhs) == canonicalHostForComparison(rhs)
}

private func isObviousPublicSuffix(_ host: String) -> Bool {
    let normalized = canonicalHostForComparison(host)
    if !normalized.contains(".") {
        return true
    }

    let blockedSuffixes: Set<String> = [
        "co.uk",
        "com.au",
        "com.br",
        "com.cn",
        "com.sg",
        "com.tr",
        "co.jp",
        "co.nz",
    ]
    return blockedSuffixes.contains(normalized)
}

private func isAWSSignInRedirectMatch(current: URL, stored: URL, currentHost: String, storedHost: String) -> Bool {
    guard current.scheme?.lowercased() == "https",
          stored.scheme?.lowercased() == "https",
          normalizedPort(current) == normalizedPort(stored),
          isAWSSignInHost(currentHost),
          isAWSSignInHost(storedHost) else {
        return false
    }

    let storedPath = normalizedPath(stored.path)
    let currentPath = normalizedPath(current.path)

    return (storedPath == "/" || storedPath == "/console") &&
        (currentPath == "/console" || currentPath == "/oauth")
}

public func storedURLMatches(currentURL: String?, storedWebsite: String?) -> Bool {
    guard let current = parseWebsiteURL(currentURL),
          let stored = parseWebsiteURL(storedWebsite),
          let currentHost = sanitizeHost(current.host),
          let storedHost = sanitizeHost(stored.host) else {
        return false
    }

    if isAWSSignInRedirectMatch(current: current, stored: stored, currentHost: currentHost, storedHost: storedHost) {
        return true
    }

    guard hostsAreEquivalent(currentHost, storedHost),
          current.scheme?.lowercased() == stored.scheme?.lowercased(),
          normalizedPort(current) == normalizedPort(stored) else {
        return false
    }

    guard hasMeaningfulPath(stored) else {
        return true
    }

    return pathHasSegmentPrefix(currentPath: current.path, storedPath: stored.path)
}

public func storedAWSSignInWebsiteMatchesHost(currentHost: String, storedWebsite: String?) -> Bool {
    guard let currentHost = sanitizeHost(currentHost),
          let stored = parseWebsiteURL(storedWebsite),
          let storedHost = sanitizeHost(stored.host),
          stored.scheme?.lowercased() == "https",
          isAWSSignInHost(currentHost),
          isAWSSignInHost(storedHost) else {
        return false
    }

    let storedPath = normalizedPath(stored.path)
    return storedPath == "/" || storedPath == "/console"
}

public func storedWebsiteHasPath(_ website: String?) -> Bool {
    guard let url = parseWebsiteURL(website) else {
        return false
    }
    return hasMeaningfulPath(url)
}

public func hostMatches(currentHost: String, storedHost: String) -> Bool {
    guard let current = sanitizeHost(currentHost), let stored = sanitizeHost(storedHost) else {
        return false
    }
    // 1. Exact match
    if hostsAreEquivalent(current, stored) { return true }
    let canonicalStored = canonicalHostForComparison(stored)
    guard !isObviousPublicSuffix(canonicalStored) else {
        return false
    }
    // 2. Subdomain match (stored "github.com" matches current "api.github.com")
    if canonicalHostForComparison(current).hasSuffix(".\(canonicalStored)") { return true }
    return false
}

public func selectBestMatch(from candidates: [HostMatchCandidate]) -> HostMatchSelection? {
    guard !candidates.isEmpty else {
        return nil
    }

    let exactMatches = candidates.filter { $0.isExact }
    if exactMatches.count == 1 {
        return HostMatchSelection(candidate: exactMatches[0], reason: .singleExact)
    }
    
    // If we have exact matches (domain matches), prefer them over fuzzy name matches
    if !exactMatches.isEmpty {
        // If multiple exact matches, maybe return the first? Or fail?
        // Let's fail for now to avoid ambiguity, or we could sort by last used if we had that data.
        return nil
    }

    if candidates.count == 1 {
        return HostMatchSelection(candidate: candidates[0], reason: .singleSubdomain)
    }
    
    // Multiple candidates (e.g. "GitHub" and "GitHub Enterprise")
    // Return none (Ambiguous) or return all?
    // This function returns a SINGLE best match.
    // For LISTING credentials, `CredentialResolver` collects ALL matches, so this function is only used for `getCredential` auto-selection.
    // For `getCredential` with ID, this logic is bypassed.
    
    return nil
}
