#if os(macOS)
import CryptoKit
import Foundation
import AuthenticatorBridge

public enum SSHAutomationExecutionLeaseError: Error, Equatable, Sendable {
    case invalidBinding
    case invalidCredential
    case tooManyActiveLeases
    case corruptedStore
}

public final class SSHAutomationExecutionLeaseAuthority: @unchecked Sendable {
    private struct Payload: Codable, Equatable, Sendable {
        let credentialID: UUID
        let sessionScope: String?
        let rootProcessID: Int32?
    }

    private let authorityStore: AuthorityStoring
    private static let mutationLock = NSLock()
    private static let maximumActiveLeasesPerCredential = 64

    public init(authorityStore: AuthorityStoring) {
        self.authorityStore = authorityStore
    }

    public func create(
        credential: AutomationCredentialMetadata,
        binding: SSHAutomationExecutionLeaseBinding,
        now: Date = Date()
    ) throws -> UUID {
        let sessionScope = Self.normalized(binding.sessionScope)
        let rootProcessID = binding.rootProcessID
        guard (sessionScope != nil) != (rootProcessID != nil) else {
            throw SSHAutomationExecutionLeaseError.invalidBinding
        }
        if let rootProcessID, rootProcessID <= 1 {
            throw SSHAutomationExecutionLeaseError.invalidBinding
        }
        guard credential.status(asOf: now) == .active,
              credential.allowedCommands == [.ssh] else {
            throw SSHAutomationExecutionLeaseError.invalidCredential
        }

        let payload = Payload(
            credentialID: credential.id,
            sessionScope: sessionScope,
            rootProcessID: rootProcessID
        )
        let encoded = try Self.encoder.encode(payload)
        let bindingDigest = Data(SHA256.hash(data: encoded))
        do {
            return try Self.mutationLock.withLock {
                let records = try authorityStore.allRecords()
                if let existing = records.first(where: {
                    $0.type == .executionLease
                        && $0.revokedAt == nil
                        && $0.expiresAt > now
                        && $0.consumedUses < $0.maximumUses
                        && $0.bindingDigest == bindingDigest
                        && $0.payload == encoded
                }) {
                    return existing.id
                }

                try authorityStore.pruneExpiredRecords(
                    ofType: .executionLease,
                    asOf: now
                )
                let activeLeaseCount = records.filter {
                    guard $0.type == .executionLease,
                          $0.revokedAt == nil,
                          $0.expiresAt > now,
                          $0.consumedUses < $0.maximumUses,
                          let payload = try? Self.payload(from: $0) else {
                        return false
                    }
                    return payload.credentialID == credential.id
                }.count
                guard activeLeaseCount < Self.maximumActiveLeasesPerCredential else {
                    throw SSHAutomationExecutionLeaseError.tooManyActiveLeases
                }
                let leaseID = UUID()
                let record = AuthorityRecord(
                    type: .executionLease,
                    id: leaseID,
                    createdAt: now,
                    expiresAt: credential.expiresAt,
                    revokedAt: nil,
                    maximumUses: .max,
                    consumedUses: 0,
                    bindingDigest: bindingDigest,
                    displayMetadata: [:],
                    payload: encoded
                )
                try authorityStore.insert(record)
                return leaseID
            }
        } catch let error as SSHAutomationExecutionLeaseError {
            throw error
        } catch {
            throw SSHAutomationExecutionLeaseError.corruptedStore
        }
    }

    public func retire(
        leaseID: UUID,
        credentialID: UUID
    ) throws {
        do {
            try Self.mutationLock.withLock {
                guard let lease = try authorityStore.allRecords().first(where: {
                    $0.id == leaseID
                }) else {
                    return
                }
                guard lease.type == .executionLease,
                      try Self.payload(from: lease).credentialID == credentialID else {
                    throw SSHAutomationExecutionLeaseError.invalidCredential
                }
                try authorityStore.removeRecord(
                    id: leaseID,
                    ofType: .executionLease
                )
            }
        } catch let error as SSHAutomationExecutionLeaseError {
            throw error
        } catch {
            throw SSHAutomationExecutionLeaseError.corruptedStore
        }
    }

    public func lookup(
        leaseID: UUID,
        sessionScope: String?,
        ancestryPIDs: [Int32],
        now: Date = Date()
    ) -> AutomationCredentialLookup.Result {
        do {
            guard let lease = try authorityStore.record(id: leaseID, asOf: now),
                  lease.type == .executionLease,
                  let payload = try? Self.payload(from: lease),
                  Self.bindingMatches(
                    payload,
                    sessionScope: sessionScope,
                    ancestryPIDs: ancestryPIDs
                  ),
                  let credential = try authorityStore.record(id: payload.credentialID, asOf: now),
                  credential.type == .automationCredential else {
                return .credentialNotFound
            }
            return .found(
                AutomationCredentialLookup.CredentialRecord(
                    metadata: try AutomationCredentialAuthority.metadata(from: credential)
                )
            )
        } catch AuthorityStoreError.corruptRecord,
                AuthorityStoreError.incompatibleVersion {
            return .corruptedStore
        } catch AutomationCredentialAuthorityError.corruptedStore {
            return .corruptedStore
        } catch {
            return .credentialNotFound
        }
    }

    public func consume(leaseID: UUID, now: Date = Date()) -> Bool {
        do {
            guard let lease = try authorityStore.record(id: leaseID, asOf: now),
                  lease.type == .executionLease,
                  let payload = try? Self.payload(from: lease),
                  let credential = try authorityStore.record(id: payload.credentialID, asOf: now),
                  credential.type == .automationCredential else {
                return false
            }
            _ = try authorityStore.consume(
                id: credential.id,
                bindingDigest: credential.bindingDigest,
                asOf: now
            )
            return true
        } catch {
            return false
        }
    }

    private static func payload(from record: AuthorityRecord) throws -> Payload {
        guard let data = record.payload,
              let payload = try? decoder.decode(Payload.self, from: data) else {
            throw SSHAutomationExecutionLeaseError.corruptedStore
        }
        return payload
    }

    private static func bindingMatches(
        _ payload: Payload,
        sessionScope: String?,
        ancestryPIDs: [Int32]
    ) -> Bool {
        if let requiredScope = payload.sessionScope {
            return normalized(sessionScope) == requiredScope
        }
        if let rootProcessID = payload.rootProcessID {
            return ancestryPIDs.contains(rootProcessID)
        }
        return false
    }

    private static func normalized(_ value: String?) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
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
