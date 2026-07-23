#if os(macOS)
import Foundation
@testable import AuthsiaBridgeHost

final class TestAuthorityStore: AuthorityStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var records: [AuthorityRecord] = []

    func insert(_ record: AuthorityRecord) throws {
        try lock.withLock {
            guard !records.contains(where: { $0.id == record.id }) else {
                throw AuthorityStoreError.duplicate
            }
            records.append(record)
        }
    }

    func upsert(_ record: AuthorityRecord) {
        upsert([record])
    }

    func upsert(_ newRecords: [AuthorityRecord]) {
        lock.withLock {
            for record in newRecords {
                if let index = records.firstIndex(where: { $0.id == record.id }) {
                    records[index] = record
                } else {
                    records.append(record)
                }
            }
        }
    }

    func record(id: UUID, asOf date: Date) throws -> AuthorityRecord? {
        try lock.withLock {
            guard let record = records.first(where: { $0.id == id }) else { return nil }
            try validateActive(record, asOf: date)
            return record
        }
    }

    func consume(id: UUID, bindingDigest: Data, asOf date: Date) throws -> AuthorityRecord {
        try lock.withLock {
            guard let index = records.firstIndex(where: { $0.id == id }) else {
                throw AuthorityStoreError.missing
            }
            let record = records[index]
            try validateActive(record, asOf: date)
            guard record.bindingDigest == bindingDigest else {
                throw AuthorityStoreError.bindingMismatch
            }
            let consumed = record.consumingOneUse()
            records[index] = consumed
            return consumed
        }
    }

    func revoke(id: UUID, at date: Date) throws {
        try lock.withLock {
            guard let index = records.firstIndex(where: { $0.id == id }) else {
                throw AuthorityStoreError.missing
            }
            records[index] = records[index].revoking(at: date)
        }
    }

    func activeRecords(asOf date: Date) throws -> [AuthorityRecord] {
        try lock.withLock {
            try records.filter {
                try validateActive($0, asOf: date)
                return true
            }
        }
    }

    func allRecords() -> [AuthorityRecord] {
        lock.withLock { records }
    }

    private func validateActive(_ record: AuthorityRecord, asOf date: Date) throws {
        if record.revokedAt != nil { throw AuthorityStoreError.revoked }
        if record.expiresAt <= date { throw AuthorityStoreError.expired }
        if record.consumedUses >= record.maximumUses { throw AuthorityStoreError.consumed }
    }
}
#endif
