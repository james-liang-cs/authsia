import Foundation

public struct NativeHostRequest: Codable, Equatable {
    public let type: String
    public let host: String?
    public let currentURL: String?
    public let credentialId: UUID?

    public init(type: String, host: String? = nil, currentURL: String? = nil, credentialId: UUID? = nil) {
        self.type = type
        self.host = host
        self.currentURL = currentURL
        self.credentialId = credentialId
    }
}

public enum NativeHostError: String, Codable, Equatable {
    case invalidRequest
    case invalidHost
    case noMatch
    case multipleMatches
    case cliFailure
    case decodeFailure
    case accessDenied
}

public struct NativeHostCredential: Codable, Equatable {
    public let username: String?
    public let password: String?
    public let otpCode: String?
    public let remaining: Int?

    public init(username: String, password: String) {
        self.username = username
        self.password = password
        self.otpCode = nil
        self.remaining = nil
    }

    public init(otpCode: String, remaining: Int) {
        self.username = nil
        self.password = nil
        self.otpCode = otpCode
        self.remaining = remaining
    }
}

public struct NativeHostMatch: Codable, Equatable {
    public let kind: String
    public let id: UUID
    public let name: String
    public let username: String?
    public let website: String?

    public init(kind: String = "password", id: UUID, name: String, username: String?, website: String?) {
        self.kind = kind
        self.id = id
        self.name = name
        self.username = username
        self.website = website
    }
}

public struct NativeHostResponse: Codable, Equatable {
    public let ok: Bool
    public let credential: NativeHostCredential?
    public let match: NativeHostMatch?
    public let credentials: [NativeHostMatch]?
    public let error: NativeHostError?
    public let detail: String?

    public init(
        ok: Bool, 
        credential: NativeHostCredential? = nil, 
        match: NativeHostMatch? = nil, 
        credentials: [NativeHostMatch]? = nil,
        error: NativeHostError? = nil, 
        detail: String? = nil
    ) {
        self.ok = ok
        self.credential = credential
        self.match = match
        self.credentials = credentials
        self.error = error
        self.detail = detail
    }

    public static func success(credential: NativeHostCredential, match: NativeHostMatch) -> NativeHostResponse {
        NativeHostResponse(ok: true, credential: credential, match: match)
    }

    public static func success(credentials: [NativeHostMatch]) -> NativeHostResponse {
        NativeHostResponse(ok: true, credentials: credentials)
    }

    public static func failure(_ error: NativeHostError, detail: String? = nil) -> NativeHostResponse {
        NativeHostResponse(ok: false, error: error, detail: detail)
    }
}

public struct CredentialResolver {
    private let cliClient: CLIClient

    private struct OTPMatchCandidate {
        let match: NativeHostMatch
        let score: Int
        let originalIndex: Int
    }

    public init(cliClient: CLIClient = CLIClient()) {
        self.cliClient = cliClient
    }

    public func listCredentials(forHost host: String, currentURL: String? = nil) throws -> NativeHostResponse {
        guard let sanitizedHost = sanitizeHost(host) else {
            return .failure(.invalidHost)
        }

        let passwords: [CLIListPassword]
        do {
            passwords = try cliClient.listPasswords()
        } catch {
            return .failure(.cliFailure, detail: String(describing: error))
        }

        let accounts: [CLIListAccount]
        do {
            accounts = try cliClient.listAccounts()
        } catch {
            return .failure(.cliFailure, detail: String(describing: error))
        }

        let passwordMatches = passwords.compactMap { password -> NativeHostMatch? in
            guard Self.passwordMatchesHost(password, host: sanitizedHost, currentURL: currentURL) else {
                return nil
            }
            return NativeHostMatch(
                id: password.id, 
                name: password.name, 
                username: password.username, 
                website: password.website
            )
        }
        let matchedPasswords = passwords.filter {
            Self.passwordMatchesHost($0, host: sanitizedHost, currentURL: currentURL)
        }
        let relatedTokens = Self.relatedTokens(from: matchedPasswords)

        let otpMatches = accounts.enumerated().compactMap { index, account -> OTPMatchCandidate? in
            guard let score = Self.accountMatchScore(
                    account,
                    host: sanitizedHost,
                    currentURL: currentURL,
                    relatedTokens: relatedTokens
                  ) else {
                return nil
            }
            return OTPMatchCandidate(
                match: NativeHostMatch(
                    kind: "otp",
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
        
        return .success(credentials: passwordMatches + otpMatches)
    }

    public func getCredential(forHost host: String, currentURL: String? = nil, credentialId: UUID?) throws -> NativeHostResponse {
        guard let sanitizedHost = sanitizeHost(host) else {
            return .failure(.invalidHost)
        }

        let passwords: [CLIListPassword]
        do {
            passwords = try cliClient.listPasswords()
        } catch {
            return .failure(.cliFailure, detail: String(describing: error))
        }

        let accounts: [CLIListAccount]
        do {
            accounts = try cliClient.listAccounts()
        } catch {
            return .failure(.cliFailure, detail: String(describing: error))
        }
        
        // Find matching password metadata
        if let targetId = credentialId {
            // Case 1: Specific ID requested (from menu click)
            if let found = passwords.first(where: { $0.id == targetId }) {
                guard Self.passwordMatchesHost(found, host: sanitizedHost, currentURL: currentURL) else {
                    return .failure(.accessDenied, detail: "Host mismatch for requested ID")
                }

                return fetchPassword(found)
            }

            if let found = accounts.first(where: { $0.id == targetId }) {
                let matchedPasswords = passwords.filter {
                    Self.passwordMatchesHost($0, host: sanitizedHost, currentURL: currentURL)
                }
                let relatedTokens = Self.relatedTokens(from: matchedPasswords)

                guard Self.accountMatchesHost(
                        found,
                        host: sanitizedHost,
                        currentURL: currentURL,
                        relatedTokens: relatedTokens
                      ) else {
                    return .failure(.accessDenied)
                }

                return fetchOTP(found)
            }

            return .failure(.noMatch)
        } else {
            // Case 2: Auto-selection (legacy single-match behavior)
            var candidates: [HostMatchCandidate] = []
            var byId: [UUID: CLIListPassword] = [:]

            for password in passwords {
                guard Self.passwordMatchesHost(password, host: sanitizedHost, currentURL: currentURL),
                      let storedHost = parseStoredHost(from: password.website) else {
                    continue
                }

                let isExact = sanitizedHost == storedHost
                candidates.append(HostMatchCandidate(id: password.id, storedHost: storedHost, isExact: isExact))
                byId[password.id] = password
            }

            guard let selection = selectBestMatch(from: candidates) else {
                return candidates.isEmpty ? .failure(.noMatch) : .failure(.multipleMatches)
            }
            
            guard let found = byId[selection.candidate.id] else {
                return .failure(.decodeFailure)
            }
            return fetchPassword(found)
        }
    }

    private func fetchPassword(_ selectedPassword: CLIListPassword) -> NativeHostResponse {
        // Fetch full secret
        let result: CLIGetPasswordResult
        do {
            result = try cliClient.getPassword(id: selectedPassword.id)
        } catch {
            return .failure(.cliFailure, detail: String(describing: error))
        }

        let credential = NativeHostCredential(username: result.username, password: result.password)
        let match = NativeHostMatch(
            id: selectedPassword.id, 
            name: selectedPassword.name, 
            username: selectedPassword.username,
            website: selectedPassword.website
        )
        return .success(credential: credential, match: match)
    }

    private func fetchOTP(_ account: CLIListAccount) -> NativeHostResponse {
        let result: CLIGetOTPResult
        do {
            result = try cliClient.getOTP(id: account.id)
        } catch {
            return .failure(.cliFailure, detail: String(describing: error))
        }

        let credential = NativeHostCredential(otpCode: result.code, remaining: result.remaining)
        let match = NativeHostMatch(
            kind: "otp",
            id: account.id,
            name: account.issuer,
            username: account.label,
            website: nil
        )
        return .success(credential: credential, match: match)
    }

    private static func passwordMatchesHost(_ password: CLIListPassword, host: String, currentURL: String?) -> Bool {
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

    private static func accountMatchesHost(
        _ account: CLIListAccount,
        host: String,
        currentURL: String?,
        relatedTokens: Set<String> = []
    ) -> Bool {
        accountMatchScore(account, host: host, currentURL: currentURL, relatedTokens: relatedTokens) != nil
    }

    private static func accountMatchScore(
        _ account: CLIListAccount,
        host: String,
        currentURL: String?,
        relatedTokens: Set<String> = []
    ) -> Int? {
        var score: Int?

        if account.hosts?.contains(where: { accountHostMatches($0, host: host, currentURL: currentURL) }) == true {
            score = account.hosts?
                .compactMap { accountHostMatchScore($0, host: host, currentURL: currentURL) }
                .max()
        }

        let issuer = normalizeForHostMatch(account.issuer)
        let label = normalizeForHostMatch(account.label)

        if relatedTokens.contains(where: { token in
            label.contains(token) || issuer.contains(token)
        }) {
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

    private static func relatedTokens(from passwords: [CLIListPassword]) -> Set<String> {
        var tokens = Set<String>()

        for password in passwords {
            addToken(password.name, to: &tokens)
            addToken(password.username, to: &tokens)

            if let host = parseStoredHost(from: password.website) {
                let awsSuffix = ".signin.aws.amazon.com"
                if host.hasSuffix(awsSuffix) {
                    addToken(String(host.dropLast(awsSuffix.count)), to: &tokens)
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
