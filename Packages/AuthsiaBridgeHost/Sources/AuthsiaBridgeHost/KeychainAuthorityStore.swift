#if os(macOS)
import Foundation
import Security

protocol AuthorityBlobStoring: Sendable {
    func load() throws -> Data?
    func save(_ data: Data) throws
}

final class SecurityAuthorityBlobStore: AuthorityBlobStoring, @unchecked Sendable {
    private static let service = "app.authsia.bridge.authority"
    private static let account = "authority-store-v1"

    func load() throws -> Data? {
        var query = Self.baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw AuthorityStoreError.storageFailure(status)
        }
        guard let data = result as? Data else {
            throw AuthorityStoreError.corruptRecord
        }
        return data
    }

    func save(_ data: Data) throws {
        var addQuery = Self.baseQuery()
        addQuery[kSecValueData as String] = data
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus == errSecSuccess {
            return
        }
        guard addStatus == errSecDuplicateItem else {
            throw AuthorityStoreError.storageFailure(addStatus)
        }

        let update = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(Self.baseQuery() as CFDictionary, update as CFDictionary)
        guard updateStatus == errSecSuccess else {
            throw AuthorityStoreError.storageFailure(updateStatus)
        }
    }

    static func baseQueryForTesting() -> [String: Any] {
        baseQuery()
    }

    private static func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }
}

public final class KeychainAuthorityStore: AuthorityStoring, @unchecked Sendable {
    private static let mutationLock = NSLock()
    private let blobStore: AuthorityBlobStoring

    public convenience init() {
        self.init(blobStore: SecurityAuthorityBlobStore())
    }

    init(blobStore: AuthorityBlobStoring) {
        self.blobStore = blobStore
    }

    public func insert(_ record: AuthorityRecord) throws {
        try Self.mutationLock.withLock {
            var envelope = try loadEnvelope()
            try validate(record)
            guard !envelope.records.contains(where: { $0.id == record.id }) else {
                throw AuthorityStoreError.duplicate
            }
            envelope.records.append(record)
            try save(envelope)
        }
    }

    public func record(id: UUID, asOf date: Date) throws -> AuthorityRecord? {
        try Self.mutationLock.withLock {
            let envelope = try loadEnvelope()
            guard let record = envelope.records.first(where: { $0.id == id }) else {
                return nil
            }
            try validateActive(record, asOf: date)
            return record
        }
    }

    public func consume(
        id: UUID,
        bindingDigest: Data,
        asOf date: Date
    ) throws -> AuthorityRecord {
        try Self.mutationLock.withLock {
            var envelope = try loadEnvelope()
            guard let index = envelope.records.firstIndex(where: { $0.id == id }) else {
                throw AuthorityStoreError.missing
            }
            let record = envelope.records[index]
            try validateActive(record, asOf: date)
            guard record.bindingDigest == bindingDigest else {
                throw AuthorityStoreError.bindingMismatch
            }
            let consumed = record.consumingOneUse()
            envelope.records[index] = consumed
            try save(envelope)
            return consumed
        }
    }

    public func revoke(id: UUID, at date: Date) throws {
        try Self.mutationLock.withLock {
            var envelope = try loadEnvelope()
            guard let index = envelope.records.firstIndex(where: { $0.id == id }) else {
                throw AuthorityStoreError.missing
            }
            envelope.records[index] = envelope.records[index].revoking(at: date)
            try save(envelope)
        }
    }

    public func activeRecords(asOf date: Date) throws -> [AuthorityRecord] {
        try Self.mutationLock.withLock {
            let records = try loadEnvelope().records
            return try records.filter { record in
                try validate(record)
                return record.revokedAt == nil
                    && record.expiresAt > date
                    && record.consumedUses < record.maximumUses
            }
        }
    }

    private func loadEnvelope() throws -> AuthorityEnvelope {
        guard let data = try blobStore.load() else {
            return AuthorityEnvelope(records: [])
        }
        let envelope: AuthorityEnvelope
        do {
            envelope = try Self.decoder.decode(AuthorityEnvelope.self, from: data)
        } catch {
            throw AuthorityStoreError.corruptRecord
        }
        guard envelope.version == AuthorityEnvelope.currentVersion else {
            throw AuthorityStoreError.incompatibleVersion(envelope.version)
        }
        for record in envelope.records {
            try validate(record)
        }
        return envelope
    }

    private func save(_ envelope: AuthorityEnvelope) throws {
        do {
            try blobStore.save(Self.encoder.encode(envelope))
        } catch let error as AuthorityStoreError {
            throw error
        } catch {
            throw AuthorityStoreError.corruptRecord
        }
    }

    private func validateActive(_ record: AuthorityRecord, asOf date: Date) throws {
        try validate(record)
        if record.revokedAt != nil {
            throw AuthorityStoreError.revoked
        }
        if record.expiresAt <= date {
            throw AuthorityStoreError.expired
        }
        if record.consumedUses >= record.maximumUses {
            throw AuthorityStoreError.consumed
        }
    }

    private func validate(_ record: AuthorityRecord) throws {
        guard record.expiresAt > record.createdAt,
              record.maximumUses > 0,
              record.consumedUses >= 0,
              record.consumedUses <= record.maximumUses,
              !record.bindingDigest.isEmpty else {
            throw AuthorityStoreError.corruptRecord
        }
    }

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()
}
#endif
