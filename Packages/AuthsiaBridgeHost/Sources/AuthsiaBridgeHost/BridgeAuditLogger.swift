#if os(macOS)
import Foundation
import Security
import AuthenticatorBridge
import CryptoKit

public final class BridgeAuditLogger {
    private let fileURL: URL
    private let hmacKeyProvider: () throws -> SymmetricKey
    private let queue = DispatchQueue(label: "com.authsia.bridge.audit")
    /// Current audit entry schema version.
    /// - v1: Plain SHA256, non-deterministic key order (cannot be re-verified).
    /// - v2: HMAC-SHA256 but non-deterministic key order (cannot be re-verified).
    /// - v3: HMAC-SHA256 with sorted keys — fully verifiable.
    /// - v4: Adds `requestedCommand` to `BridgeAuditRecord`. v3 entries must be migrated
    ///   (re-hashed) because adding the field changes the HMAC payload.
    /// - v5: Adds SSH-agent signing requester info. v4 entries must be migrated
    ///   because adding the field changes the HMAC payload.
    /// - v6: Adds `agentJITGrantID` to `BridgeAuditRecord`. v5 entries must be migrated
    ///   because adding the field changes the HMAC payload.
    /// - v7: Adds `agentRuntimeContext` to `BridgeAuditRecord`. v6 entries must be migrated
    ///   because adding the field changes the HMAC payload.
    /// - v8: Adds `fullCommand` to `BridgeAuditRecord`. v7 entries must be migrated
    ///   because adding the field changes the HMAC payload.
    /// - v9: Adds display-only `workspaceContext` to `BridgeAuditRecord`. v8 entries must be
    ///   migrated because adding the field changes the HMAC payload.
    /// - v10: Adds environment scope to agent approval and access records. v9 entries must be
    ///   migrated because adding the field changes the HMAC payload.
    private static let entryVersion = 10
    private static let legacyV1 = 1
    private static let legacyV2 = 2
    private static let legacyV3 = 3
    private static let legacyV4 = 4
    private static let legacyV5 = 5
    private static let legacyV6 = 6
    private static let legacyV7 = 7
    private static let legacyV8 = 8
    private static let legacyV9 = 9
    private static let fileMode: mode_t = 0o600
    private static let directoryMode: NSNumber = 0o700

    // MARK: - HMAC Key Keychain Constants
    private static let hmacKeyService = "com.authsia.audit.hmac-key"
    private static let hmacKeyAccount = "audit-chain"

    public init(fileURL: URL = BridgeAuditLogger.defaultFileURL()) {
        self.fileURL = fileURL
        self.hmacKeyProvider = Self.loadOrCreateHMACKey
    }

    init(fileURL: URL, hmacKeyProvider: @escaping () throws -> SymmetricKey) {
        self.fileURL = fileURL
        self.hmacKeyProvider = hmacKeyProvider
    }

    nonisolated deinit {}

    public func record(_ record: BridgeAuditRecord) throws {
        try queue.sync {
            try ensureDirectory()
            let key = try hmacKeyProvider()
            let previousHash = try lastEntryHash()
            let entryHash = Self.computeHMAC(for: record, previousHash: previousHash, key: key)
            let entry = AuditEntry(
                version: Self.entryVersion,
                record: record,
                previousHash: previousHash,
                entryHash: entryHash
            )

            let data = try JSONEncoder.bridge.encode(entry)
            var lineData = data
            lineData.append(0x0A)
            try appendLineData(lineData)
        }
    }

    public func verifyIntegrity() throws -> Bool {
        try queue.sync {
            guard FileManager.default.fileExists(atPath: fileURL.path) else { return true }
            let key = try hmacKeyProvider()
            let data = try Data(contentsOf: fileURL)
            let lines = data.split(separator: 0x0A)
            guard !lines.isEmpty else { return true }

            var needsMigration = false
            var previousHash: String?
            for rawLine in lines {
                let lineData = Data(rawLine)
                guard let entry = try? JSONDecoder.bridge.decode(AuditEntry.self, from: lineData) else {
                    return false
                }
                guard entry.previousHash == previousHash else {
                    return false
                }
                switch entry.version {
                case Self.legacyV1:
                    // v1 used plain SHA256 with non-deterministic key order — cannot reliably verify after struct changes
                    needsMigration = true
                case Self.legacyV2:
                    // v2 used HMAC but non-deterministic key order — cannot reliably verify after struct changes
                    needsMigration = true
                case Self.legacyV3, Self.legacyV4, Self.legacyV5, Self.legacyV6, Self.legacyV7,
                     Self.legacyV8, Self.legacyV9:
                    // v3+ use sorted-key HMAC over the record payload. Verify before re-signing
                    // so a legacy row cannot be tampered with and then silently migrated.
                    let expectedHash = Self.computeHMAC(for: entry.record, previousHash: entry.previousHash, key: key)
                    guard expectedHash == entry.entryHash else {
                        return false
                    }
                    needsMigration = true
                case Self.entryVersion:
                    // Current entries use HMAC with sorted keys over the current record schema — fully verifiable
                    let expectedHash = Self.computeHMAC(for: entry.record, previousHash: entry.previousHash, key: key)
                    guard expectedHash == entry.entryHash else {
                        return false
                    }
                default:
                    return false
                }
                previousHash = entry.entryHash
            }

            if needsMigration {
                try migrateLog(data: data, key: key)
            }

            return true
        }
    }

    public func loadRecords(limit: Int? = nil, since: Date? = nil) throws -> [BridgeAuditRecord] {
        try queue.sync {
            try Self.loadRecordsForAccessCenter(fileURL: fileURL, limit: limit, since: since)
        }
    }

    public nonisolated static var accessCenterFileURL: URL { defaultFileURL() }

    public nonisolated static func loadRecordsForAccessCenter(
        fileURL: URL,
        limit: Int? = nil,
        since: Date? = nil
    ) throws -> [BridgeAuditRecord] {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return [] }
        if let limit, limit <= 0 {
            return []
        }

        let data = try Data(contentsOf: fileURL)
        let lines = data.split(separator: 0x0A)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let records = try lines
            .map { try decoder.decode(AuditEntry.self, from: Data($0)).record }
            .filter { record in
                guard let since else { return true }
                return record.timestamp >= since
            }
            .sorted { $0.timestamp < $1.timestamp }
        guard let limit, records.count > limit else {
            return records
        }
        return Array(records.suffix(limit))
    }

    // MARK: - HMAC Key Management

    private static func loadOrCreateHMACKey() throws -> SymmetricKey {
        if let existingKey = try loadHMACKey() {
            return existingKey
        }
        let newKey = SymmetricKey(size: .bits256)
        try saveHMACKey(newKey)
        return newKey
    }

    private static func loadHMACKey() throws -> SymmetricKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: hmacKeyService,
            kSecAttrAccount as String: hmacKeyAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseDataProtectionKeychain as String: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw BridgeAuditLoggerError.keychainError(status)
        }
        return SymmetricKey(data: data)
    }

    private static func saveHMACKey(_ key: SymmetricKey) throws {
        let keyData = key.withUnsafeBytes { Data($0) }
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: hmacKeyService,
            kSecAttrAccount as String: hmacKeyAccount,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecUseDataProtectionKeychain as String: true,
        ]
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus == errSecDuplicateItem {
            // Item already exists — update its value
            let searchQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: hmacKeyService,
                kSecAttrAccount as String: hmacKeyAccount,
                kSecUseDataProtectionKeychain as String: true,
            ]
            let updateStatus = SecItemUpdate(searchQuery as CFDictionary, [kSecValueData as String: keyData] as CFDictionary)
            guard updateStatus == errSecSuccess else {
                throw BridgeAuditLoggerError.keychainError(updateStatus)
            }
        } else if addStatus != errSecSuccess {
            throw BridgeAuditLoggerError.keychainError(addStatus)
        }
    }

    // MARK: - Hash Computation

    /// Deterministic encoder for hash computation — `.sortedKeys` ensures
    /// the HMAC is stable across struct layout changes (added optional fields).
    private static var hashEncoder: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = .sortedKeys
        return encoder
    }

    private static func computeHMAC(
        for record: BridgeAuditRecord,
        previousHash: String?,
        key: SymmetricKey
    ) -> String {
        let input = AuditHashInput(record: record, previousHash: previousHash)
        let payload = (try? hashEncoder.encode(input)) ?? Data()
        let mac = HMAC<SHA256>.authenticationCode(for: payload, using: key)
        return Data(mac).map { String(format: "%02x", $0) }.joined()
    }

    /// Legacy plain SHA256 hash for backward compatibility with v1 log entries
    private static func computeLegacyHash(for record: BridgeAuditRecord, previousHash: String?) -> String {
        let input = AuditHashInput(record: record, previousHash: previousHash)
        let payload = (try? hashEncoder.encode(input)) ?? Data()
        let digest = SHA256.hash(data: payload)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Migration

    /// Re-signs all entries under the current `entryVersion` (HMAC over sorted-key JSON
    /// of the current record struct). Preserves all records and chain order; only the
    /// hashes change. Used to migrate legacy entries forward.
    private func migrateLog(data: Data, key: SymmetricKey) throws {
        let lines = data.split(separator: 0x0A)
        var migrated = Data()
        var previousHash: String?

        for rawLine in lines {
            guard let oldEntry = try? JSONDecoder.bridge.decode(AuditEntry.self, from: Data(rawLine)) else {
                continue
            }
            let newHash = Self.computeHMAC(for: oldEntry.record, previousHash: previousHash, key: key)
            let newEntry = AuditEntry(
                version: Self.entryVersion,
                record: oldEntry.record,
                previousHash: previousHash,
                entryHash: newHash
            )
            var lineData = try JSONEncoder.bridge.encode(newEntry)
            lineData.append(0x0A)
            migrated.append(lineData)
            previousHash = newHash
        }

        try migrated.write(to: fileURL, options: .atomic)
    }

    // MARK: - File Helpers

    private func ensureDirectory() throws {
        let directory = fileURL.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: directory.path) {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: Self.directoryMode]
            )
        } else {
            try? FileManager.default.setAttributes([.posixPermissions: Self.directoryMode], ofItemAtPath: directory.path)
        }
    }

    private func lastEntryHash() throws -> String? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return nil }
        let data = try Data(contentsOf: fileURL)
        let lines = data.split(separator: 0x0A)
        guard let lastLine = lines.last else { return nil }
        let entry = try JSONDecoder.bridge.decode(AuditEntry.self, from: Data(lastLine))
        return entry.entryHash
    }

    private func appendLineData(_ data: Data) throws {
        let fd = open(fileURL.path, O_WRONLY | O_CREAT | O_APPEND, Self.fileMode)
        guard fd >= 0 else {
            throw BridgeAuditLoggerError.failedToOpen(errno)
        }
        defer { _ = close(fd) }

        var bytesWritten = 0
        try data.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            while bytesWritten < rawBuffer.count {
                let pointer = baseAddress.advanced(by: bytesWritten)
                let remaining = rawBuffer.count - bytesWritten
                let written = write(fd, pointer, remaining)
                if written < 0 {
                    throw BridgeAuditLoggerError.failedToWrite(errno)
                }
                bytesWritten += written
            }
        }
        if fchmod(fd, Self.fileMode) != 0 {
            throw BridgeAuditLoggerError.failedToSetPermissions(errno)
        }
    }

    @usableFromInline
    nonisolated static func defaultFileURL() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first ?? FileManager.default.temporaryDirectory
        let directory = base.appendingPathComponent("Authsia", isDirectory: true)
        return directory.appendingPathComponent("bridge_audit.log")
    }
}

private struct AuditHashInput: Codable {
    let record: BridgeAuditRecord
    let previousHash: String?
}

private nonisolated struct AuditEntry: Codable {
    let version: Int
    let record: BridgeAuditRecord
    let previousHash: String?
    let entryHash: String
}

private enum BridgeAuditLoggerError: Error {
    case invalidEntryVersion
    case failedToOpen(Int32)
    case failedToWrite(Int32)
    case failedToSetPermissions(Int32)
    case keychainError(OSStatus)
}
#endif
