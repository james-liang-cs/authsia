import Foundation
import Security
import XCTest
@testable import AuthsiaBridgeHost

#if os(macOS)
final class AuthorityStoreTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    func testInsertAndLoadRoundTrip() throws {
        let store = makeStore()
        let record = makeRecord()

        try store.insert(record)

        XCTAssertEqual(try store.record(id: record.id, asOf: now), record)
        XCTAssertEqual(try store.activeRecords(asOf: now), [record])
    }

    func testConsumeAtomicallyIncrementsUseCount() throws {
        let store = makeStore()
        let record = makeRecord(maximumUses: 2)
        try store.insert(record)

        let consumed = try store.consume(
            id: record.id,
            bindingDigest: record.bindingDigest,
            asOf: now
        )

        XCTAssertEqual(consumed.consumedUses, 1)
        XCTAssertEqual(try store.record(id: record.id, asOf: now)?.consumedUses, 1)
    }

    func testRevokeMakesRecordUnavailable() throws {
        let store = makeStore()
        let record = makeRecord()
        try store.insert(record)

        try store.revoke(id: record.id, at: now)

        XCTAssertThrowsError(try store.record(id: record.id, asOf: now)) {
            XCTAssertEqual($0 as? AuthorityStoreError, .revoked)
        }
        XCTAssertEqual(try store.activeRecords(asOf: now), [])
    }

    func testExpiredRecordIsRejected() throws {
        let store = makeStore()
        let record = makeRecord(expiresAt: now.addingTimeInterval(-1))
        try store.insert(record)

        XCTAssertThrowsError(try store.record(id: record.id, asOf: now)) {
            XCTAssertEqual($0 as? AuthorityStoreError, .expired)
        }
    }

    func testMissingRecordIsDistinguished() {
        let store = makeStore()

        XCTAssertThrowsError(try store.consume(
            id: UUID(),
            bindingDigest: Data(repeating: 0x11, count: 32),
            asOf: now
        )) {
            XCTAssertEqual($0 as? AuthorityStoreError, .missing)
        }
    }

    func testWrongBindingIsRejected() throws {
        let store = makeStore()
        let record = makeRecord()
        try store.insert(record)

        XCTAssertThrowsError(try store.consume(
            id: record.id,
            bindingDigest: Data(repeating: 0x22, count: 32),
            asOf: now
        )) {
            XCTAssertEqual($0 as? AuthorityStoreError, .bindingMismatch)
        }
    }

    func testConsumedRecordIsRejected() throws {
        let store = makeStore()
        let record = makeRecord(maximumUses: 1)
        try store.insert(record)
        _ = try store.consume(id: record.id, bindingDigest: record.bindingDigest, asOf: now)

        XCTAssertThrowsError(try store.consume(
            id: record.id,
            bindingDigest: record.bindingDigest,
            asOf: now
        )) {
            XCTAssertEqual($0 as? AuthorityStoreError, .consumed)
        }
    }

    func testCorruptBlobIsRejected() {
        let blobStore = TestAuthorityBlobStore(Data("not-json".utf8))
        let store = KeychainAuthorityStore(blobStore: blobStore)

        XCTAssertThrowsError(try store.activeRecords(asOf: now)) {
            XCTAssertEqual($0 as? AuthorityStoreError, .corruptRecord)
        }
    }

    func testIncompatibleEnvelopeVersionIsRejected() {
        let data = Data("""
        {"version":999,"records":[]}
        """.utf8)
        let store = KeychainAuthorityStore(blobStore: TestAuthorityBlobStore(data))

        XCTAssertThrowsError(try store.activeRecords(asOf: now)) {
            XCTAssertEqual($0 as? AuthorityStoreError, .incompatibleVersion(999))
        }
    }

    func testConcurrentSingleUseConsumeHasExactlyOneSuccess() throws {
        let store = makeStore()
        let record = makeRecord(maximumUses: 1)
        try store.insert(record)
        let results = LockedResults()
        let consumeDate = now

        DispatchQueue.concurrentPerform(iterations: 2) { _ in
            do {
                _ = try store.consume(
                    id: record.id,
                    bindingDigest: record.bindingDigest,
                    asOf: consumeDate
                )
                results.append(.success(()))
            } catch {
                results.append(.failure(error))
            }
        }

        XCTAssertEqual(results.successCount, 1)
        XCTAssertEqual(results.errors.compactMap { $0 as? AuthorityStoreError }, [.consumed])
    }

    func testNewStoreInstanceLoadsPersistedRecordsAfterRestart() throws {
        let blobStore = TestAuthorityBlobStore()
        let firstStore = KeychainAuthorityStore(blobStore: blobStore)
        let record = makeRecord()
        try firstStore.insert(record)

        let restartedStore = KeychainAuthorityStore(blobStore: blobStore)

        XCTAssertEqual(try restartedStore.record(id: record.id, asOf: now), record)
    }

    func testKeychainQueryUsesDedicatedLocalAfterFirstUnlockService() {
        let query = SecurityAuthorityBlobStore.baseQueryForTesting()

        XCTAssertEqual(query[kSecAttrService as String] as? String, "app.authsia.bridge.authority")
        XCTAssertEqual(query[kSecAttrAccount as String] as? String, "authority-store-v1")
        XCTAssertEqual(
            query[kSecAttrAccessible as String] as? String,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String
        )
        XCTAssertNil(query[kSecAttrAccessGroup as String])
        XCTAssertNil(query[kSecAttrSynchronizable as String])
    }

    private func makeStore() -> KeychainAuthorityStore {
        KeychainAuthorityStore(blobStore: TestAuthorityBlobStore())
    }

    private func makeRecord(
        expiresAt: Date? = nil,
        maximumUses: Int = 1
    ) -> AuthorityRecord {
        AuthorityRecord(
            type: .executionLease,
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
            createdAt: now.addingTimeInterval(-60),
            expiresAt: expiresAt ?? now.addingTimeInterval(300),
            revokedAt: nil,
            maximumUses: maximumUses,
            consumedUses: 0,
            bindingDigest: Data(repeating: 0x11, count: 32),
            displayMetadata: [
                "agent": "Synthetic Agent",
                "scope": "Team/API",
            ]
        )
    }
}

private final class TestAuthorityBlobStore: AuthorityBlobStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?

    init(_ data: Data? = nil) {
        self.data = data
    }

    func load() throws -> Data? {
        lock.withLock { data }
    }

    func save(_ data: Data) throws {
        lock.withLock {
            self.data = data
        }
    }
}

private final class LockedResults: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [Result<Void, Error>] = []

    func append(_ result: Result<Void, Error>) {
        lock.withLock {
            storage.append(result)
        }
    }

    var successCount: Int {
        lock.withLock {
            storage.filter {
                if case .success = $0 { return true }
                return false
            }.count
        }
    }

    var errors: [Error] {
        lock.withLock {
            storage.compactMap {
                if case .failure(let error) = $0 { return error }
                return nil
            }
        }
    }
}
#endif
