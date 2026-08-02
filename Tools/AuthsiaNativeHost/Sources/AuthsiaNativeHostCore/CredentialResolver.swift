import Foundation

public enum NativeHostCredentialKind: String, Codable, Equatable {
    case password
    case otp
}

public struct NativeHostRequest: Codable, Equatable {
    public let type: String
    public let host: String?
    public let currentURL: String?
    public let credentialId: UUID?
    public let kind: NativeHostCredentialKind?

    public init(
        type: String,
        host: String? = nil,
        currentURL: String? = nil,
        credentialId: UUID? = nil,
        kind: NativeHostCredentialKind? = nil
    ) {
        self.type = type
        self.host = host
        self.currentURL = currentURL
        self.credentialId = credentialId
        self.kind = kind
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

/// Resolves browser autofill requests.
///
/// Host matching runs in the app, not here: this asks the CLI for the items
/// that already match the requested host. Pulling the whole vault to match
/// locally is what used to raise an approval prompt on every credential field,
/// including on sites the vault has nothing for.
public struct CredentialResolver {
    private let cliClient: CLIClient

    public init(cliClient: CLIClient = CLIClient()) {
        self.cliClient = cliClient
    }

    public func listCredentials(
        forHost host: String,
        currentURL: String? = nil,
        kind: NativeHostCredentialKind? = nil
    ) throws -> NativeHostResponse {
        guard let sanitizedHost = sanitizeHost(host) else {
            return .failure(.invalidHost)
        }

        let matches: [CLIAutofillMatch]
        do {
            matches = try cliClient.autofillMatches(
                host: sanitizedHost,
                currentURL: currentURL,
                kind: kind
            )
        } catch {
            return .failure(.cliFailure, detail: String(describing: error))
        }

        return .success(credentials: matches.map(Self.nativeHostMatch(from:)))
    }

    public func getCredential(
        forHost host: String,
        currentURL: String? = nil,
        credentialId: UUID?,
        kind: NativeHostCredentialKind? = nil
    ) throws -> NativeHostResponse {
        guard let sanitizedHost = sanitizeHost(host) else {
            return .failure(.invalidHost)
        }

        // Auto-selection only ever fills a password, so an OTP-only request
        // without an explicit ID has nothing to select before any lookup.
        if credentialId == nil, kind == .otp {
            return .failure(.noMatch)
        }
        let requestedKind = credentialId == nil ? NativeHostCredentialKind.password : kind

        let matches: [CLIAutofillMatch]
        do {
            matches = try cliClient.autofillMatches(
                host: sanitizedHost,
                currentURL: currentURL,
                kind: requestedKind
            )
        } catch {
            return .failure(.cliFailure, detail: String(describing: error))
        }

        if let targetId = credentialId {
            // Case 1: Specific ID requested (from menu click). An ID outside the
            // host's match set is refused without revealing whether it exists.
            guard let found = matches.first(where: { $0.id == targetId }) else {
                return .failure(.accessDenied, detail: "Requested ID does not match this host")
            }
            return found.kind == .otp ? fetchOTP(found) : fetchPassword(found)
        }

        // Case 2: Auto-selection (legacy single-match behavior)
        var byId: [UUID: CLIAutofillMatch] = [:]
        let candidates = matches.compactMap { match -> HostMatchCandidate? in
            guard match.kind == .password, let storedHost = match.storedHost else {
                return nil
            }
            byId[match.id] = match
            return HostMatchCandidate(id: match.id, storedHost: storedHost, isExact: match.isExact)
        }

        guard let selection = selectBestMatch(from: candidates) else {
            return candidates.isEmpty ? .failure(.noMatch) : .failure(.multipleMatches)
        }

        guard let found = byId[selection.candidate.id] else {
            return .failure(.decodeFailure)
        }
        return fetchPassword(found)
    }

    private static func nativeHostMatch(from match: CLIAutofillMatch) -> NativeHostMatch {
        NativeHostMatch(
            kind: match.kind.rawValue,
            id: match.id,
            name: match.name,
            username: match.username,
            website: match.website
        )
    }

    private func fetchPassword(_ selected: CLIAutofillMatch) -> NativeHostResponse {
        // Fetch full secret
        let result: CLIGetPasswordResult
        do {
            result = try cliClient.getPassword(id: selected.id)
        } catch {
            return .failure(.cliFailure, detail: String(describing: error))
        }

        let credential = NativeHostCredential(username: result.username, password: result.password)
        return .success(credential: credential, match: Self.nativeHostMatch(from: selected))
    }

    private func fetchOTP(_ selected: CLIAutofillMatch) -> NativeHostResponse {
        let result: CLIGetOTPResult
        do {
            result = try cliClient.getOTP(id: selected.id)
        } catch {
            return .failure(.cliFailure, detail: String(describing: error))
        }

        let credential = NativeHostCredential(otpCode: result.code, remaining: result.remaining)
        return .success(credential: credential, match: Self.nativeHostMatch(from: selected))
    }
}
