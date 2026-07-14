import Foundation

public enum OTPType: String, Codable {
    case totp
    case hotp
}

public struct Account: Identifiable, Codable, Equatable {
    public let id: UUID
    public var issuer: String
    public var label: String
    public var folderPath: String?
    public var secret: Data // In M2, this might be removed/detached for Keychain storage
    public var algorithm: OTPAlgorithm
    public var digits: Int
    public var type: OTPType
    
    // TOTP specific
    public var period: TimeInterval
    
    // HOTP specific
    public var counter: UInt64
    
    public var createdAt: Date
    public var lastUsed: Date
    
    // UI Metadata
    public var isFavorite: Bool
    public var isCliEnabled: Bool
    public var isScraped: Bool
    
    // Import/Export Metadata
    public var icon: String?
    public var hosts: [String]?
    public var isExcludedFromWatch: Bool
    
    public init(
        id: UUID = UUID(),
        issuer: String = "",
        label: String = "",
        folderPath: String? = nil,
        secret: Data,
        algorithm: OTPAlgorithm = .sha1,
        digits: Int = 6,
        type: OTPType = .totp,
        period: TimeInterval = 30,
        counter: UInt64 = 0,
        createdAt: Date = Date(),
        lastUsed: Date = Date(),
        isFavorite: Bool = false,
        isCliEnabled: Bool = true,
        isScraped: Bool = false,
        icon: String? = nil,
        hosts: [String]? = nil,
        isExcludedFromWatch: Bool = false
    ) {
        self.id = id
        self.issuer = issuer
        self.label = label
        self.folderPath = folderPath
        self.secret = secret
        self.algorithm = algorithm
        self.digits = digits
        self.type = type
        self.period = period
        self.counter = counter
        self.createdAt = createdAt
        self.lastUsed = lastUsed
        self.isFavorite = isFavorite
        self.isCliEnabled = isCliEnabled
        self.isScraped = isScraped
        self.icon = icon
        self.hosts = hosts
        self.isExcludedFromWatch = isExcludedFromWatch
    }
}

extension Account {
    enum CodingKeys: String, CodingKey {
        case id, issuer, label, folderPath, secret, algorithm, digits, type
        case period, counter, createdAt, lastUsed
        case isFavorite, isCliEnabled, isScraped, icon, hosts, isExcludedFromWatch
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        issuer = try container.decode(String.self, forKey: .issuer)
        label = try container.decode(String.self, forKey: .label)
        folderPath = try container.decodeIfPresent(String.self, forKey: .folderPath)
        secret = try container.decode(Data.self, forKey: .secret)
        algorithm = try container.decode(OTPAlgorithm.self, forKey: .algorithm)
        digits = try container.decode(Int.self, forKey: .digits)
        type = try container.decode(OTPType.self, forKey: .type)
        period = try container.decode(TimeInterval.self, forKey: .period)
        counter = try container.decode(UInt64.self, forKey: .counter)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        lastUsed = try container.decode(Date.self, forKey: .lastUsed)
        isFavorite = try container.decodeIfPresent(Bool.self, forKey: .isFavorite) ?? false
        isCliEnabled = try container.decodeIfPresent(Bool.self, forKey: .isCliEnabled) ?? true
        isScraped = try container.decodeIfPresent(Bool.self, forKey: .isScraped) ?? false
        icon = try container.decodeIfPresent(String.self, forKey: .icon)
        hosts = try container.decodeIfPresent([String].self, forKey: .hosts)
        isExcludedFromWatch = try container.decodeIfPresent(Bool.self, forKey: .isExcludedFromWatch) ?? false
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(issuer, forKey: .issuer)
        try container.encode(label, forKey: .label)
        try container.encodeIfPresent(folderPath, forKey: .folderPath)
        try container.encode(secret, forKey: .secret)
        try container.encode(algorithm, forKey: .algorithm)
        try container.encode(digits, forKey: .digits)
        try container.encode(type, forKey: .type)
        try container.encode(period, forKey: .period)
        try container.encode(counter, forKey: .counter)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(lastUsed, forKey: .lastUsed)
        try container.encode(isFavorite, forKey: .isFavorite)
        try container.encode(isCliEnabled, forKey: .isCliEnabled)
        try container.encode(isScraped, forKey: .isScraped)
        try container.encodeIfPresent(icon, forKey: .icon)
        try container.encodeIfPresent(hosts, forKey: .hosts)
        try container.encode(isExcludedFromWatch, forKey: .isExcludedFromWatch)
    }
}
