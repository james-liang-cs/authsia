import Foundation

/// Host matching for Chrome autofill.
///
/// This runs in the app, not in the Chrome native host, so the native host can
/// ask "what matches this host?" without first pulling the whole vault. Pulling
/// the whole vault is what used to raise an approval prompt on every credential
/// field, including on sites with nothing stored.
public enum ChromeAutofillCredentialKind: String, Codable, Equatable, Sendable {
    case password
    case otp
}

/// Non-secret password metadata the matcher needs.
public struct ChromeAutofillPasswordMetadata: Codable, Equatable, Sendable {
    public let id: UUID
    public let name: String
    public let username: String
    public let website: String?

    public init(id: UUID, name: String, username: String, website: String?) {
        self.id = id
        self.name = name
        self.username = username
        self.website = website
    }
}

/// Non-secret OTP account metadata the matcher needs.
public struct ChromeAutofillAccountMetadata: Codable, Equatable, Sendable {
    public let id: UUID
    public let issuer: String
    public let label: String
    public let hosts: [String]?

    public init(id: UUID, issuer: String, label: String, hosts: [String]?) {
        self.id = id
        self.issuer = issuer
        self.label = label
        self.hosts = hosts
    }
}

/// Request body for `BridgeRequestType.chromeAutofillMatches`.
public struct ChromeAutofillMatchQuery: Codable, Equatable, Sendable {
    public let host: String
    public let currentURL: String?
    public let kind: ChromeAutofillCredentialKind?

    public init(host: String, currentURL: String? = nil, kind: ChromeAutofillCredentialKind? = nil) {
        self.host = host
        self.currentURL = currentURL
        self.kind = kind
    }
}

/// A single host match. `storedHost` and `isExact` are carried so the native
/// host can run `selectBestMatch` without re-parsing websites itself.
public struct ChromeAutofillMatch: Codable, Equatable, Sendable {
    public let kind: ChromeAutofillCredentialKind
    public let id: UUID
    public let name: String
    public let username: String?
    public let website: String?
    public let storedHost: String?
    public let isExact: Bool

    public init(
        kind: ChromeAutofillCredentialKind,
        id: UUID,
        name: String,
        username: String?,
        website: String?,
        storedHost: String? = nil,
        isExact: Bool = false
    ) {
        self.kind = kind
        self.id = id
        self.name = name
        self.username = username
        self.website = website
        self.storedHost = storedHost
        self.isExact = isExact
    }
}

public struct ChromeAutofillMatchesPayload: Codable, Equatable, Sendable {
    public let matches: [ChromeAutofillMatch]

    public init(matches: [ChromeAutofillMatch]) {
        self.matches = matches
    }
}

public enum ChromeAutofillMatcher {
    /// Password matches first, then OTP matches ordered by descending score.
    /// A `kind` narrows the result to that kind only.
    public static func matches(
        query: ChromeAutofillMatchQuery,
        passwords: [ChromeAutofillPasswordMetadata],
        accounts: [ChromeAutofillAccountMetadata]
    ) -> [ChromeAutofillMatch] {
        guard let host = sanitizeHost(query.host) else {
            return []
        }
        let currentURL = query.currentURL

        let matchedPasswords = passwords.filter {
            passwordMatchesHost($0, host: host, currentURL: currentURL)
        }
        let passwordMatches = matchedPasswords.map { password -> ChromeAutofillMatch in
            let storedHost = parseStoredHost(from: password.website)
            return ChromeAutofillMatch(
                kind: .password,
                id: password.id,
                name: password.name,
                username: password.username,
                website: password.website,
                storedHost: storedHost,
                isExact: storedHost == host
            )
        }

        if query.kind == .password {
            return passwordMatches
        }

        let related = relatedTokens(from: matchedPasswords)
        let otpMatches = accounts.enumerated().compactMap { index, account -> ScoredMatch? in
            guard let score = accountMatchScore(
                account,
                host: host,
                currentURL: currentURL,
                relatedTokens: related
            ) else {
                return nil
            }
            return ScoredMatch(
                match: ChromeAutofillMatch(
                    kind: .otp,
                    id: account.id,
                    name: account.issuer,
                    username: account.label,
                    website: nil
                ),
                score: score,
                originalIndex: index
            )
        }.sorted {
            if $0.score == $1.score {
                return $0.originalIndex < $1.originalIndex
            }
            return $0.score > $1.score
        }.map(\.match)

        return (query.kind == .otp ? [] : passwordMatches) + otpMatches
    }

    private struct ScoredMatch {
        let match: ChromeAutofillMatch
        let score: Int
        let originalIndex: Int
    }

    // MARK: - Host parsing

    public static func sanitizeHost(_ host: String?) -> String? {
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

    public static func parseStoredHost(from website: String?) -> String? {
        guard let url = parseWebsiteURL(website) else {
            return nil
        }
        return sanitizeHost(url.host)
    }

    private static func parseWebsiteURL(_ website: String?) -> URL? {
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

    private static func hasMeaningfulPath(_ url: URL) -> Bool {
        let path = url.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return !path.isEmpty
    }

    private static func normalizedPath(_ path: String) -> String {
        guard !path.isEmpty else { return "/" }
        var normalized = path
        while normalized.count > 1, normalized.hasSuffix("/") {
            normalized.removeLast()
        }
        return normalized
    }

    private static func pathHasSegmentPrefix(currentPath: String, storedPath: String) -> Bool {
        let current = normalizedPath(currentPath)
        let stored = normalizedPath(storedPath)

        if stored == "/" { return true }
        if current == stored { return true }
        return current.hasPrefix("\(stored)/")
    }

    private static func defaultPort(for scheme: String?) -> Int? {
        switch scheme?.lowercased() {
        case "http":
            return 80
        case "https":
            return 443
        default:
            return nil
        }
    }

    private static func normalizedPort(_ url: URL) -> Int? {
        url.port ?? defaultPort(for: url.scheme)
    }

    private static func isAWSSignInHost(_ host: String) -> Bool {
        host == "signin.aws.amazon.com" || host.hasSuffix(".signin.aws.amazon.com")
    }

    private static func canonicalHostForComparison(_ host: String) -> String {
        host.hasPrefix("www.") ? String(host.dropFirst("www.".count)) : host
    }

    private static func hostsAreEquivalent(_ lhs: String, _ rhs: String) -> Bool {
        canonicalHostForComparison(lhs) == canonicalHostForComparison(rhs)
    }

    private static func isObviousPublicSuffix(_ host: String) -> Bool {
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

    private static func isAWSSignInRedirectMatch(
        current: URL,
        stored: URL,
        currentHost: String,
        storedHost: String
    ) -> Bool {
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

    public static func storedURLMatches(currentURL: String?, storedWebsite: String?) -> Bool {
        guard let current = parseWebsiteURL(currentURL),
              let stored = parseWebsiteURL(storedWebsite),
              let currentHost = sanitizeHost(current.host),
              let storedHost = sanitizeHost(stored.host) else {
            return false
        }

        if isAWSSignInRedirectMatch(
            current: current,
            stored: stored,
            currentHost: currentHost,
            storedHost: storedHost
        ) {
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

    public static func storedAWSSignInWebsiteMatchesHost(currentHost: String, storedWebsite: String?) -> Bool {
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

    public static func storedWebsiteHasPath(_ website: String?) -> Bool {
        guard let url = parseWebsiteURL(website) else {
            return false
        }
        return hasMeaningfulPath(url)
    }

    public static func hostMatches(currentHost: String, storedHost: String) -> Bool {
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

    // MARK: - Item matching

    static func passwordMatchesHost(
        _ password: ChromeAutofillPasswordMetadata,
        host: String,
        currentURL: String?
    ) -> Bool {
        if storedWebsiteHasPath(password.website), currentURL != nil {
            return storedURLMatches(currentURL: currentURL, storedWebsite: password.website) ||
                storedAWSSignInWebsiteMatchesHost(currentHost: host, storedWebsite: password.website)
        }

        if storedAWSSignInWebsiteMatchesHost(currentHost: host, storedWebsite: password.website) {
            return true
        }

        guard let storedHost = parseStoredHost(from: password.website) else {
            return false
        }
        return hostMatches(currentHost: host, storedHost: storedHost)
    }

    static func accountMatchScore(
        _ account: ChromeAutofillAccountMetadata,
        host: String,
        currentURL: String?,
        relatedTokens: RelatedTokens = RelatedTokens()
    ) -> Int? {
        var score: Int?

        if account.hosts?.contains(where: { accountHostMatches($0, host: host, currentURL: currentURL) }) == true {
            score = account.hosts?
                .compactMap { accountHostMatchScore($0, host: host, currentURL: currentURL) }
                .max()
        }

        let issuer = normalizeForHostMatch(account.issuer)
        let label = normalizeForHostMatch(account.label)

        // Issuer names the service, so a matched password's item name may identify it.
        // Labels name the *person* (usually an email reused across services), so only
        // account-scoping aliases may match there — never the password's username.
        if relatedTokens.service.contains(where: { issuer.contains($0) })
            || relatedTokens.alias.contains(where: { label.contains($0) }) {
            score = max(score ?? 0, 0) + 50
        }

        return score
    }

    private static func accountHostMatches(_ accountHost: String, host: String, currentURL: String?) -> Bool {
        accountHostMatchScore(accountHost, host: host, currentURL: currentURL) != nil
    }

    private static func accountHostMatchScore(_ accountHost: String, host: String, currentURL: String?) -> Int? {
        if storedWebsiteHasPath(accountHost), currentURL != nil {
            if storedURLMatches(currentURL: currentURL, storedWebsite: accountHost) {
                return 100
            }
            if storedAWSSignInWebsiteMatchesHost(currentHost: host, storedWebsite: accountHost) {
                return 120
            }
        }

        if storedAWSSignInWebsiteMatchesHost(currentHost: host, storedWebsite: accountHost) {
            return 120
        }

        guard let storedHost = parseStoredHost(from: accountHost) else {
            return nil
        }
        guard hostMatches(currentHost: host, storedHost: storedHost) else {
            return nil
        }
        if storedHost == host {
            return 90
        }
        return 30 + min(storedHost.count, 40)
    }

    /// Tokens derived from host-matched passwords, split by what they may identify.
    /// `service` may match an OTP issuer; `alias` may additionally match an OTP label.
    struct RelatedTokens {
        var service = Set<String>()
        var alias = Set<String>()
    }

    static func relatedTokens(from passwords: [ChromeAutofillPasswordMetadata]) -> RelatedTokens {
        var tokens = RelatedTokens()

        for password in passwords {
            addToken(password.name, to: &tokens.service)

            if let host = parseStoredHost(from: password.website) {
                let awsSuffix = ".signin.aws.amazon.com"
                if host.hasSuffix(awsSuffix) {
                    let alias = String(host.dropLast(awsSuffix.count))
                    addToken(alias, to: &tokens.service)
                    addToken(alias, to: &tokens.alias)
                }
            }
        }

        return tokens
    }

    private static func addToken(_ value: String, to tokens: inout Set<String>) {
        let token = normalizeForHostMatch(value)
        if token.count >= 3 {
            tokens.insert(token)
        }
    }

    private static func normalizeForHostMatch(_ value: String) -> String {
        value
            .lowercased()
            .filter { $0.isLetter || $0.isNumber }
    }
}
