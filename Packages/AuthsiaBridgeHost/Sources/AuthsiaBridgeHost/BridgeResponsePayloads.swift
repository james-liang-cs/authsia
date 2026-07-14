#if os(macOS)
import Foundation
import AuthenticatorCore

public struct OTPPayload: Codable, Equatable {
    public let accountId: String
    public let issuer: String
    public let label: String
    public let code: String
    public let remaining: Int
    public let expiresAt: Date
    public let isFavorite: Bool

    public init(
        accountId: String,
        issuer: String,
        label: String,
        code: String,
        remaining: Int,
        expiresAt: Date,
        isFavorite: Bool
    ) {
        self.accountId = accountId
        self.issuer = issuer
        self.label = label
        self.code = code
        self.remaining = remaining
        self.expiresAt = expiresAt
        self.isFavorite = isFavorite
    }
}

public struct PasswordPayload: Codable, Equatable {
    public let id: String
    public let name: String
    public let username: String
    public let password: String
    public let website: String?
    public let notes: String?
    public let createdAt: Date
    public let modifiedAt: Date
    public let isFavorite: Bool

    public init(
        id: String,
        name: String,
        username: String,
        password: String,
        website: String?,
        notes: String?,
        createdAt: Date,
        modifiedAt: Date,
        isFavorite: Bool
    ) {
        self.id = id
        self.name = name
        self.username = username
        self.password = password
        self.website = website
        self.notes = notes
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.isFavorite = isFavorite
    }
}

public struct APIKeyPayload: Codable, Equatable {
    public let id: String
    public let name: String
    public let key: String
    public let website: String?
    public let notes: String?
    public let createdAt: Date
    public let modifiedAt: Date
    public let isFavorite: Bool

    public init(
        id: String,
        name: String,
        key: String,
        website: String?,
        notes: String?,
        createdAt: Date,
        modifiedAt: Date,
        isFavorite: Bool
    ) {
        self.id = id
        self.name = name
        self.key = key
        self.website = website
        self.notes = notes
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.isFavorite = isFavorite
    }
}

public struct CertificatePayload: Codable, Equatable {
    public let id: String
    public let name: String
    public let certificate: String
    public let privateKey: String?
    public let issuer: String?
    public let subject: String?
    public let expirationDate: Date?
    public let notes: String?
    public let createdAt: Date
    public let modifiedAt: Date
    public let isFavorite: Bool

    public init(
        id: String,
        name: String,
        certificate: String,
        privateKey: String?,
        issuer: String?,
        subject: String?,
        expirationDate: Date?,
        notes: String?,
        createdAt: Date,
        modifiedAt: Date,
        isFavorite: Bool
    ) {
        self.id = id
        self.name = name
        self.certificate = certificate
        self.privateKey = privateKey
        self.issuer = issuer
        self.subject = subject
        self.expirationDate = expirationDate
        self.notes = notes
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.isFavorite = isFavorite
    }
}

public struct NotePayload: Codable, Equatable {
    public let id: String
    public let title: String
    public let content: String
    public let createdAt: Date
    public let modifiedAt: Date
    public let isFavorite: Bool

    public init(
        id: String,
        title: String,
        content: String,
        createdAt: Date,
        modifiedAt: Date,
        isFavorite: Bool
    ) {
        self.id = id
        self.title = title
        self.content = content
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.isFavorite = isFavorite
    }
}

public struct SSHPayload: Codable, Equatable {
    public let id: String
    public let name: String
    public let publicKey: String
    public let privateKey: String
    public let comment: String
    public let fingerprint: String
    public let keyType: SSHKeyType
    public let approvalPolicy: SSHKeyApprovalPolicy
    public let boundHosts: [String]
    public let createdAt: Date
    public let modifiedAt: Date
    public let isFavorite: Bool
    public let passphrase: String?

    public init(
        id: String,
        name: String,
        publicKey: String,
        privateKey: String,
        comment: String,
        fingerprint: String,
        keyType: SSHKeyType,
        approvalPolicy: SSHKeyApprovalPolicy,
        boundHosts: [String],
        createdAt: Date,
        modifiedAt: Date,
        isFavorite: Bool,
        passphrase: String?
    ) {
        self.id = id
        self.name = name
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.comment = comment
        self.fingerprint = fingerprint
        self.keyType = keyType
        self.approvalPolicy = approvalPolicy
        self.boundHosts = boundHosts
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.isFavorite = isFavorite
        self.passphrase = passphrase
    }
}

public struct UnlockPayload: Codable, Equatable {
    public let expiresAt: Date
    public let ttlSeconds: Int
    public let sessionToken: String

    public init(expiresAt: Date, ttlSeconds: Int, sessionToken: String) {
        self.expiresAt = expiresAt
        self.ttlSeconds = ttlSeconds
        self.sessionToken = sessionToken
    }
}
#endif
