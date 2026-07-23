#if os(macOS)
import CryptoKit
import Foundation
import Security
import AuthenticatorBridge

public enum AutomationCredentialAuthorityError: Error, Equatable, Sendable {
    case invalidToken
    case notFound
    case expired
    case revoked
    case consumed
    case machineMismatch
    case commandDenied
    case rateLimited
    case corruptedStore
    case randomGenerationFailed
}

public final class AutomationCredentialInvalidAttemptLimiter: @unchecked Sendable {
    public static let shared = AutomationCredentialInvalidAttemptLimiter()

    private let lock = NSLock()
    private let maximumAttempts: Int
    private let window: TimeInterval
    private var attemptsByCredentialID: [UUID: [Date]] = [:]

    public init(maximumAttempts: Int = 8, window: TimeInterval = 60) {
        self.maximumAttempts = maximumAttempts
        self.window = window
    }

    func allowsAttempt(for credentialID: UUID, at date: Date) -> Bool {
        lock.withLock {
            prune(at: date)
            return attemptsByCredentialID[credentialID, default: []].count < maximumAttempts
        }
    }

    func recordInvalidAttempt(for credentialID: UUID, at date: Date) {
        lock.withLock {
            prune(at: date)
            attemptsByCredentialID[credentialID, default: []].append(date)
        }
    }

    private func prune(at date: Date) {
        let cutoff = date.addingTimeInterval(-window)
        attemptsByCredentialID = attemptsByCredentialID.compactMapValues { attempts in
            let active = attempts.filter { $0 > cutoff }
            return active.isEmpty ? nil : active
        }
    }
}

public final class AutomationCredentialAuthority: @unchecked Sendable {
    public typealias RandomBytes = @Sendable (Int) throws -> Data

    private let authorityStore: AuthorityStoring
    private let digestKey: SymmetricKey
    private let randomBytes: RandomBytes
    private let invalidAttemptLimiter: AutomationCredentialInvalidAttemptLimiter

    public init(
        authorityStore: AuthorityStoring,
        digestKey: Data,
        invalidAttemptLimiter: AutomationCredentialInvalidAttemptLimiter = .shared,
        randomBytes: @escaping RandomBytes = AutomationCredentialAuthority.secureRandomBytes
    ) {
        self.authorityStore = authorityStore
        self.digestKey = SymmetricKey(data: digestKey)
        self.invalidAttemptLimiter = invalidAttemptLimiter
        self.randomBytes = randomBytes
    }

    public func create(
        payload: AccessCreateApprovalPayload,
        now: Date = Date(),
        maximumUses: Int? = nil
    ) throws -> AutomationCredentialIssuedPayload {
        let effectiveMaximumUses = maximumUses ?? payload.maximumUses ?? .max
        guard effectiveMaximumUses > 0,
              payload.ttlSeconds > 0,
              payload.expiresAt > now,
              payload.expiresAt.timeIntervalSince(now) <= TimeInterval(payload.ttlSeconds) + 5,
              !payload.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw AutomationCredentialAuthorityError.corruptedStore
        }
        let allowedCommands = Set(payload.allowedCommands.compactMap(CapabilityCommand.init(rawValue:)))
        guard allowedCommands.count == payload.allowedCommands.count,
              !allowedCommands.isEmpty,
              !allowedCommands.contains(.ssh) || allowedCommands == [.ssh] else {
            throw AutomationCredentialAuthorityError.commandDenied
        }

        let id = UUID()
        let token = try AutomationCredentialToken.issue(
            id: id,
            randomBytes: try randomBytes(AutomationCredentialToken.randomByteCount)
        )
        let metadata = AutomationCredentialMetadata(
            id: id,
            name: payload.name,
            scope: payload.scope,
            createdAt: now,
            expiresAt: payload.expiresAt,
            revokedAt: nil,
            machineId: payload.machineId,
            machineName: payload.machineName,
            allowedCommands: allowedCommands,
            environmentScope: payload.environmentScope,
            maximumUses: effectiveMaximumUses
        )
        let encoded = try Self.encoder.encode(metadata)
        try authorityStore.insert(
            AuthorityRecord(
                type: .automationCredential,
                id: id,
                createdAt: metadata.createdAt,
                expiresAt: metadata.expiresAt,
                revokedAt: nil,
                maximumUses: effectiveMaximumUses,
                consumedUses: 0,
                bindingDigest: digest(token),
                displayMetadata: [
                    "name": metadata.name,
                    "scope": AutomationCredentialScope.displayName(metadata.scope),
                ],
                payload: encoded
            )
        )
        return AutomationCredentialIssuedPayload(credential: metadata, token: token)
    }

    public func validate(
        token: String,
        requestedCommand: CapabilityCommand,
        currentMachineId: String,
        now: Date = Date(),
        consumingUse: Bool = true
    ) throws -> AutomationCredentialMetadata {
        let parsed: AutomationCredentialToken.Parsed
        do {
            parsed = try AutomationCredentialToken.parse(token)
        } catch {
            throw AutomationCredentialAuthorityError.invalidToken
        }
        let record: AuthorityRecord
        do {
            guard let found = try authorityStore.record(id: parsed.id, asOf: now),
                  found.type == .automationCredential else {
                guard invalidAttemptLimiter.allowsAttempt(for: parsed.id, at: now) else {
                    throw AutomationCredentialAuthorityError.rateLimited
                }
                invalidAttemptLimiter.recordInvalidAttempt(for: parsed.id, at: now)
                throw AutomationCredentialAuthorityError.notFound
            }
            record = found
        } catch let error as AuthorityStoreError {
            throw map(error)
        }

        guard HMAC<SHA256>.isValidAuthenticationCode(
            record.bindingDigest,
            authenticating: Data(token.utf8),
            using: digestKey
        ) else {
            guard invalidAttemptLimiter.allowsAttempt(for: parsed.id, at: now) else {
                throw AutomationCredentialAuthorityError.rateLimited
            }
            invalidAttemptLimiter.recordInvalidAttempt(for: parsed.id, at: now)
            throw AutomationCredentialAuthorityError.invalidToken
        }
        let metadata = try Self.metadata(from: record)
        guard metadata.machineId == currentMachineId else {
            throw AutomationCredentialAuthorityError.machineMismatch
        }
        guard metadata.allowedCommands.contains(requestedCommand) else {
            throw AutomationCredentialAuthorityError.commandDenied
        }
        guard consumingUse else { return metadata }

        do {
            let consumed = try authorityStore.consume(
                id: record.id,
                bindingDigest: record.bindingDigest,
                asOf: now
            )
            return try Self.metadata(from: consumed)
        } catch let error as AuthorityStoreError {
            throw map(error)
        }
    }

    public func list(
        includeAll: Bool,
        now: Date = Date()
    ) throws -> [AutomationCredentialMetadata] {
        do {
            return try authorityStore.allRecords()
                .filter { $0.type == .automationCredential }
                .map(Self.metadata(from:))
                .filter { includeAll || $0.status(asOf: now) == .active }
                .sorted {
                    if $0.createdAt != $1.createdAt { return $0.createdAt > $1.createdAt }
                    return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
                }
        } catch let error as AutomationCredentialAuthorityError {
            throw error
        } catch {
            throw AutomationCredentialAuthorityError.corruptedStore
        }
    }

    public func revoke(id: UUID, at date: Date = Date()) throws -> AutomationCredentialMetadata {
        do {
            try authorityStore.revoke(id: id, at: date)
            guard let record = try authorityStore.allRecords().first(where: {
                $0.id == id && $0.type == .automationCredential
            }) else {
                throw AutomationCredentialAuthorityError.notFound
            }
            return try Self.metadata(from: record)
        } catch let error as AuthorityStoreError {
            throw map(error)
        }
    }

    private func digest(_ token: String) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data(token.utf8), using: digestKey))
    }

    private func map(_ error: AuthorityStoreError) -> AutomationCredentialAuthorityError {
        switch error {
        case .missing: return .notFound
        case .expired: return .expired
        case .revoked: return .revoked
        case .consumed: return .consumed
        case .bindingMismatch: return .invalidToken
        case .corruptRecord, .incompatibleVersion, .duplicate, .storageFailure:
            return .corruptedStore
        }
    }

    private static func metadata(from record: AuthorityRecord) throws -> AutomationCredentialMetadata {
        guard let payload = record.payload,
              var metadata = try? decoder.decode(AutomationCredentialMetadata.self, from: payload),
              metadata.id == record.id,
              metadata.createdAt == record.createdAt,
              metadata.expiresAt == record.expiresAt else {
            throw AutomationCredentialAuthorityError.corruptedStore
        }
        metadata = AutomationCredentialMetadata(
            id: metadata.id,
            name: metadata.name,
            scope: metadata.scope,
            createdAt: metadata.createdAt,
            expiresAt: metadata.expiresAt,
            revokedAt: record.revokedAt,
            machineId: metadata.machineId,
            machineName: metadata.machineName,
            allowedCommands: metadata.allowedCommands,
            environmentScope: metadata.environmentScope,
            maximumUses: record.maximumUses,
            consumedUses: record.consumedUses
        )
        return metadata
    }

    public static func secureRandomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
            throw AutomationCredentialAuthorityError.randomGenerationFailed
        }
        return Data(bytes)
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
