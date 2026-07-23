import Foundation

public enum AutomationCredentialToken {
    public static let prefix = "authsia_ac1_"
    public static let randomByteCount = 32

    public struct Parsed: Equatable, Sendable {
        public let id: UUID
        public let randomBytes: Data
    }

    public static func issue(id: UUID, randomBytes: Data) throws -> String {
        guard randomBytes.count == randomByteCount else {
            throw AutomationCredentialTokenError.invalidRandomLength
        }
        return prefix + id.uuidString.lowercased() + "_" + base64URLEncoded(randomBytes)
    }

    public static func parse(_ token: String) throws -> Parsed {
        guard token.hasPrefix(prefix) else {
            throw AutomationCredentialTokenError.invalidFormat
        }
        let body = token.dropFirst(prefix.count)
        let pieces = body.split(separator: "_", omittingEmptySubsequences: false)
        guard pieces.count == 2,
              let id = UUID(uuidString: String(pieces[0])),
              let randomBytes = base64URLDecoded(String(pieces[1])),
              randomBytes.count == randomByteCount else {
            throw AutomationCredentialTokenError.invalidFormat
        }
        return Parsed(id: id, randomBytes: randomBytes)
    }

    private static func base64URLEncoded(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func base64URLDecoded(_ value: String) -> Data? {
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = (4 - base64.count % 4) % 4
        base64.append(String(repeating: "=", count: padding))
        return Data(base64Encoded: base64)
    }
}

public enum AutomationCredentialTokenError: Error, Equatable, Sendable {
    case invalidFormat
    case invalidRandomLength
}

public struct AutomationCredentialMetadata: Codable, Equatable, Identifiable, Sendable {
    public enum Status: String, Codable, Equatable, Sendable {
        case active
        case expired
        case revoked
        case consumed
        case legacyDisabled
    }

    public let id: UUID
    public let name: String
    public let scope: String?
    public let createdAt: Date
    public let expiresAt: Date
    public let revokedAt: Date?
    public let machineId: String
    public let machineName: String
    public let allowedCommands: Set<CapabilityCommand>
    public let environmentScope: EnvironmentAccessScope?
    public let maximumUses: Int
    public let consumedUses: Int

    public init(
        id: UUID,
        name: String,
        scope: String?,
        createdAt: Date,
        expiresAt: Date,
        revokedAt: Date?,
        machineId: String,
        machineName: String,
        allowedCommands: Set<CapabilityCommand>,
        environmentScope: EnvironmentAccessScope?,
        maximumUses: Int = .max,
        consumedUses: Int = 0
    ) {
        self.id = id
        self.name = name
        self.scope = scope
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.revokedAt = revokedAt
        self.machineId = machineId
        self.machineName = machineName
        self.allowedCommands = allowedCommands
        self.environmentScope = environmentScope
        self.maximumUses = maximumUses
        self.consumedUses = consumedUses
    }

    public func status(asOf date: Date) -> Status {
        if revokedAt != nil { return .revoked }
        if expiresAt <= date { return .expired }
        if consumedUses >= maximumUses { return .consumed }
        return .active
    }
}

public struct AutomationCredentialIssuedPayload: Codable, Equatable, Sendable {
    public let credential: AutomationCredentialMetadata
    public let token: String

    public init(credential: AutomationCredentialMetadata, token: String) {
        self.credential = credential
        self.token = token
    }
}

public struct AutomationCredentialListRequestPayload: Codable, Equatable, Sendable {
    public let includeAll: Bool

    public init(includeAll: Bool) {
        self.includeAll = includeAll
    }
}

public struct AutomationCredentialListPayload: Codable, Equatable, Sendable {
    public let credentials: [AutomationCredentialMetadata]

    public init(credentials: [AutomationCredentialMetadata]) {
        self.credentials = credentials
    }
}

public struct AutomationCredentialRevokePayload: Codable, Equatable, Sendable {
    public let id: UUID

    public init(id: UUID) {
        self.id = id
    }
}

public struct AutomationCredentialValidatePayload: Codable, Equatable, Sendable {
    public let token: String
    public let requestedCommand: CapabilityCommand

    public init(token: String, requestedCommand: CapabilityCommand) {
        self.token = token
        self.requestedCommand = requestedCommand
    }
}

public struct AutomationCredentialValidationPayload: Codable, Equatable, Sendable {
    public let credential: AutomationCredentialMetadata

    public init(credential: AutomationCredentialMetadata) {
        self.credential = credential
    }
}
