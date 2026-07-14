import Foundation

public enum OTPAuthError: Error, LocalizedError, Equatable {
    case invalidScheme(String?)
    case invalidHost // Must be 'totp' or 'hotp'
    case missingSecret
    case malformedURL
    case migrationNotSupported
    
    public var errorDescription: String? {
        switch self {
        case .invalidScheme(let scheme):
            if let scheme = scheme {
                return "Invalid URL scheme: '\(scheme)'. Must be 'otpauth'."
            } else {
                return "URL scheme missing. Must be 'otpauth'."
            }
        case .invalidHost: return "URL host must be 'totp' or 'hotp'."
        case .missingSecret: return "The 'secret' parameter is missing."
        case .malformedURL: return "The URL is malformed."
        case .migrationNotSupported: return "Google Authenticator export codes (otpauth-migration) are not yet supported."
        }
    }
}

public struct OTPAuthParser {
    
    public static func parse(_ urlString: String) throws -> Account {
        guard let url = URL(string: urlString) else {
            throw OTPAuthError.malformedURL
        }
        return try parse(url)
    }
    
    public static func parse(_ url: URL) throws -> Account {
        // 1. Validate Scheme
        let scheme = url.scheme?.lowercased()
        guard scheme == "otpauth" else {
            if scheme == "otpauth-migration" {
                throw OTPAuthError.migrationNotSupported
            }
            throw OTPAuthError.invalidScheme(scheme)
        }
        
        // 2. Validate Type (Host)
        guard let host = url.host?.lowercased(), let type = OTPType(rawValue: host) else {
            throw OTPAuthError.invalidHost
        }
        
        // 3. Parse Label (Path)
        // Path is usually "/Issuer:Account" or "/Account"
        // We need to drop the leading "/"
        let path = url.path.dropFirst()
        var pathIssuer: String?
        var accountName: String = String(path)
        
        if let colonIndex = accountName.firstIndex(of: ":") {
            pathIssuer = String(accountName[..<colonIndex]).trimmingCharacters(in: .whitespaces)
            accountName = String(accountName[accountName.index(after: colonIndex)...]).trimmingCharacters(in: .whitespaces)
        }
        
        // 4. Parse Query Items
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems else {
            throw OTPAuthError.missingSecret
        }
        
        // Helper to find query param case-insensitively
        func value(for key: String) -> String? {
            queryItems.first { $0.name.lowercased() == key.lowercased() }?.value
        }
        
        // 5. Secret (Required)
        guard let secretString = value(for: "secret"),
              let secretData = try? Base32.decode(secretString) else {
            throw OTPAuthError.missingSecret
        }
        
        // 6. Issuer (Param vs Path)
        // Param takes precedence over path prefix usually, commonly they match.
        let paramIssuer = value(for: "issuer")
        let finalIssuer = paramIssuer ?? pathIssuer ?? ""
        
        // 7. Algorithm
        let algoString = value(for: "algorithm")?.lowercased()
        let algorithm: OTPAlgorithm
        switch algoString {
        case "sha256": algorithm = .sha256
        case "sha512": algorithm = .sha512
        default: algorithm = .sha1 // Default to SHA1
        }
        
        // 8. Digits
        let digitsString = value(for: "digits")
        let digits = Int(digitsString ?? "6") ?? 6
        
        // 9. Period (TOTP)
        let periodString = value(for: "period")
        let period = TimeInterval(periodString ?? "30") ?? 30
        
        // 10. Counter (HOTP)
        let counterString = value(for: "counter")
        let counter = UInt64(counterString ?? "0") ?? 0
        
        return Account(
            issuer: finalIssuer,
            label: accountName,
            secret: secretData,
            algorithm: algorithm,
            digits: digits,
            type: type,
            period: period,
            counter: counter
        )
    }
}
