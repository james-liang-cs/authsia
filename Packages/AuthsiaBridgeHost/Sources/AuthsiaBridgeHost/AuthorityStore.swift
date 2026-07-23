#if os(macOS)
import Foundation

public enum AuthorityRecordType: String, Codable, Sendable {
    case agentJITGrant
    case automationCredential
    case executionLease
}

public struct AuthorityRecord: Codable, Equatable, Identifiable, Sendable {
    public let type: AuthorityRecordType
    public let id: UUID
    public let createdAt: Date
    public let expiresAt: Date
    public let revokedAt: Date?
    public let maximumUses: Int
    public let consumedUses: Int
    public let bindingDigest: Data
    /// Non-secret labels for approval and audit display. Never store credentials here.
    public let displayMetadata: [String: String]
    /// Authenticated, non-secret policy state owned by the Bridge.
    public let payload: Data?

    public init(
        type: AuthorityRecordType,
        id: UUID,
        createdAt: Date,
        expiresAt: Date,
        revokedAt: Date?,
        maximumUses: Int,
        consumedUses: Int,
        bindingDigest: Data,
        displayMetadata: [String: String],
        payload: Data? = nil
    ) {
        self.type = type
        self.id = id
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.revokedAt = revokedAt
        self.maximumUses = maximumUses
        self.consumedUses = consumedUses
        self.bindingDigest = bindingDigest
        self.displayMetadata = displayMetadata
        self.payload = payload
    }

    func consumingOneUse() -> AuthorityRecord {
        AuthorityRecord(
            type: type,
            id: id,
            createdAt: createdAt,
            expiresAt: expiresAt,
            revokedAt: revokedAt,
            maximumUses: maximumUses,
            consumedUses: consumedUses + 1,
            bindingDigest: bindingDigest,
            displayMetadata: displayMetadata,
            payload: payload
        )
    }

    func revoking(at date: Date) -> AuthorityRecord {
        AuthorityRecord(
            type: type,
            id: id,
            createdAt: createdAt,
            expiresAt: expiresAt,
            revokedAt: revokedAt ?? date,
            maximumUses: maximumUses,
            consumedUses: consumedUses,
            bindingDigest: bindingDigest,
            displayMetadata: displayMetadata,
            payload: payload
        )
    }
}

public enum AuthorityStoreError: Error, Equatable, Sendable {
    case missing
    case duplicate
    case incompatibleVersion(Int)
    case corruptRecord
    case expired
    case revoked
    case consumed
    case bindingMismatch
    case storageFailure(Int32)
}

public protocol AuthorityStoring: Sendable {
    func insert(_ record: AuthorityRecord) throws
    func upsert(_ record: AuthorityRecord) throws
    func upsert(_ records: [AuthorityRecord]) throws
    func record(id: UUID, asOf date: Date) throws -> AuthorityRecord?
    func consume(id: UUID, bindingDigest: Data, asOf date: Date) throws -> AuthorityRecord
    func revoke(id: UUID, at date: Date) throws
    func activeRecords(asOf date: Date) throws -> [AuthorityRecord]
    func allRecords() throws -> [AuthorityRecord]
}

struct AuthorityEnvelope: Codable, Equatable, Sendable {
    static let currentVersion = 1

    let version: Int
    var records: [AuthorityRecord]

    init(version: Int = currentVersion, records: [AuthorityRecord]) {
        self.version = version
        self.records = records
    }
}
#endif
