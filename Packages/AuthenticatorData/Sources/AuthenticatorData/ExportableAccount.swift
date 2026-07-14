import Foundation
import AuthenticatorCore

// MARK: - Export Container

/// Root container for the JSON export format.
public struct ExportContainer: Codable {
    public var items: [ExportableAccount]
    
    public init(items: [ExportableAccount]) {
        self.items = items
    }
}

// MARK: - Exportable Account

/// Represents an account in the import/export JSON format.
/// This model maps directly to the JSON structure used by the app's backup format.
public struct ExportableAccount: Codable {
    /// Unique identifier (UUID string)
    public let primary: String

    /// Icon identifier (e.g., "google.com")
    public var icon: String?

    /// Account name/label
    public var account: String

    /// Issuer name
    public var issuer: String

    /// Optional folder path
    public var folderPath: String?

    /// Base64 encoded secret
    public var secret: String

    /// TOTP period in seconds (default 30)
    public var period: Int

    /// ISO8601 date string when account was added
    public var added: String

    /// Whether account is excluded from Apple Watch
    public var isExcludedFromWatch: Bool?

    /// Associated host domains
    public var hosts: [String]?

    /// Whether account is marked as favorite
    public var favorite: Bool?

    /// Hash algorithm (sha1, sha256, sha512). Defaults to sha1 if not present.
    public var algorithm: String?

    /// Number of digits in OTP code (6 or 8). Defaults to 6 if not present.
    public var digits: Int?

    /// OTP type (totp or hotp). Defaults to totp if not present.
    public var type: String?

    /// HOTP counter value. Only used when type is hotp.
    public var counter: UInt64?

    public init(
        primary: String,
        icon: String? = nil,
        account: String,
        issuer: String,
        folderPath: String? = nil,
        secret: String,
        period: Int = 30,
        added: String,
        isExcludedFromWatch: Bool? = nil,
        hosts: [String]? = nil,
        favorite: Bool? = nil,
        algorithm: String? = nil,
        digits: Int? = nil,
        type: String? = nil,
        counter: UInt64? = nil
    ) {
        self.primary = primary
        self.icon = icon
        self.account = account
        self.issuer = issuer
        self.folderPath = folderPath
        self.secret = secret
        self.period = period
        self.added = added
        self.isExcludedFromWatch = isExcludedFromWatch
        self.hosts = hosts
        self.favorite = favorite
        self.algorithm = algorithm
        self.digits = digits
        self.type = type
        self.counter = counter
    }
}

// MARK: - Conversion Extensions

extension ExportableAccount {
    /// ISO8601 date formatter for import/export
    private nonisolated(unsafe) static let iso8601Formatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
    
    /// Fallback ISO8601 formatter without fractional seconds
    private nonisolated(unsafe) static let iso8601FallbackFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()
    
    /// Creates an ExportableAccount from AccountMetadata and secret Data
    public init(from metadata: AccountMetadata, secret: Data) {
        self.primary = metadata.id.uuidString
        self.icon = metadata.icon
        self.account = metadata.label
        self.issuer = metadata.issuer
        self.folderPath = metadata.folderPath
        self.secret = secret.base64EncodedString()
        self.period = Int(metadata.period)
        self.added = Self.iso8601Formatter.string(from: metadata.createdAt)
        self.isExcludedFromWatch = metadata.isExcludedFromWatch ? true : nil
        self.hosts = metadata.hosts?.isEmpty == false ? metadata.hosts : nil
        self.favorite = metadata.isFavorite ? true : nil
        self.algorithm = metadata.algorithm.rawValue
        self.digits = metadata.digits
        self.type = metadata.type.rawValue
        self.counter = metadata.type == .hotp ? metadata.counter : nil
    }
    
    /// Converts to an Account object
    public func toAccount() throws -> Account {
        guard let uuid = UUID(uuidString: primary) else {
            throw ImportExportError.invalidUUID(primary)
        }

        guard let secretData = Data(base64Encoded: secret) else {
            throw ImportExportError.invalidSecret
        }

        // Parse date with fallback
        let createdAt: Date
        if let date = Self.iso8601Formatter.date(from: added) {
            createdAt = date
        } else if let date = Self.iso8601FallbackFormatter.date(from: added) {
            createdAt = date
        } else {
            createdAt = Date()
        }

        // Parse algorithm with fallback to sha1
        let parsedAlgorithm: OTPAlgorithm
        if let algoStr = algorithm, let algo = OTPAlgorithm(rawValue: algoStr) {
            parsedAlgorithm = algo
        } else {
            parsedAlgorithm = .sha1
        }

        // Parse type with fallback to totp
        let parsedType: OTPType
        if let typeStr = type, let t = OTPType(rawValue: typeStr) {
            parsedType = t
        } else {
            parsedType = .totp
        }

        return Account(
            id: uuid,
            issuer: issuer,
            label: account,
            folderPath: folderPath,
            secret: secretData,
            algorithm: parsedAlgorithm,
            digits: digits ?? 6,
            type: parsedType,
            period: TimeInterval(period),
            counter: counter ?? 0,
            createdAt: createdAt,
            lastUsed: Date(),
            isFavorite: favorite ?? false,
            icon: icon,
            hosts: hosts,
            isExcludedFromWatch: isExcludedFromWatch ?? false
        )
    }
}

// MARK: - Errors

public enum ImportExportError: Error, LocalizedError {
    case invalidUUID(String)
    case invalidSecret
    case invalidJSON
    case fileReadError(Error)
    case fileWriteError(Error)
    
    public var errorDescription: String? {
        switch self {
        case .invalidUUID(let uuid):
            return "Invalid UUID format: \(uuid)"
        case .invalidSecret:
            return "Invalid Base64 encoded secret"
        case .invalidJSON:
            return "Invalid JSON format"
        case .fileReadError(let error):
            return "Failed to read file: \(error.localizedDescription)"
        case .fileWriteError(let error):
            return "Failed to write file: \(error.localizedDescription)"
        }
    }
}
