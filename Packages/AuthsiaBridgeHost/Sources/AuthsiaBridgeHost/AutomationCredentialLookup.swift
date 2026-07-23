#if os(macOS)
import Foundation
import AuthenticatorBridge

/// Legacy file lookup retained for compatibility tests and decoding disabled
/// display records. Production Bridge and SSH authorization use
/// `AutomationCredentialAuthority`; this file never grants authority.
public enum AutomationCredentialLookup {
    /// Legacy display-only path. Override via parameter for tests.
    public static var defaultFileURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".authsia", isDirectory: true)
            .appendingPathComponent("access-credentials.json")
    }

    public struct CredentialRecord: Decodable, Equatable {
        public enum Status: String, Equatable {
            case active
            case expired
            case revoked
        }

        public let id: UUID
        public let scope: String?
        public let expiresAt: Date
        public let revokedAt: Date?
        public let machineId: String
        public let allowedCommands: Set<CapabilityCommand>
        public let environmentScope: EnvironmentAccessScope?

        enum CodingKeys: String, CodingKey {
            case id, scope, expiresAt, revokedAt, machineId, allowedCommands, environmentScope
        }

        public init(
            id: UUID,
            scope: String?,
            expiresAt: Date,
            revokedAt: Date?,
            machineId: String,
            allowedCommands: Set<CapabilityCommand>,
            environmentScope: EnvironmentAccessScope? = nil
        ) {
            self.id = id
            self.scope = scope
            self.expiresAt = expiresAt
            self.revokedAt = revokedAt
            self.machineId = machineId
            self.allowedCommands = allowedCommands
            self.environmentScope = environmentScope
        }

        public init(metadata: AutomationCredentialMetadata) {
            self.init(
                id: metadata.id,
                scope: metadata.scope,
                expiresAt: metadata.expiresAt,
                revokedAt: metadata.revokedAt,
                machineId: metadata.machineId,
                allowedCommands: metadata.allowedCommands,
                environmentScope: metadata.environmentScope
            )
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            id = try container.decode(UUID.self, forKey: .id)
            scope = try container.decodeIfPresent(String.self, forKey: .scope)
            expiresAt = try container.decode(Date.self, forKey: .expiresAt)
            revokedAt = try container.decodeIfPresent(Date.self, forKey: .revokedAt)
            machineId = try container.decode(String.self, forKey: .machineId)
            allowedCommands = try container.decodeIfPresent(Set<CapabilityCommand>.self, forKey: .allowedCommands)
                ?? [.exec]
            environmentScope = try container.decodeIfPresent(EnvironmentAccessScope.self, forKey: .environmentScope)
        }

        public func status(asOf date: Date) -> Status {
            if revokedAt != nil { return .revoked }
            return expiresAt > date ? .active : .expired
        }
    }

    /// Distinguishes missing, corrupt, and unknown records so authorization can
    /// fail closed with useful errors.
    public enum Result: Equatable {
        case fileMissing
        case credentialNotFound
        case corruptedStore
        case found(CredentialRecord)
    }

    public static func lookup(
        credentialID: UUID,
        fileURL: URL = defaultFileURL,
        fileManager: FileManager = .default
    ) -> Result {
        guard fileManager.fileExists(atPath: fileURL.path) else {
            return .fileMissing
        }
        guard let data = try? Data(contentsOf: fileURL), !data.isEmpty else {
            return .fileMissing
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        guard let records = try? decoder.decode([CredentialRecord].self, from: data) else {
            return .corruptedStore
        }

        guard let match = records.first(where: { $0.id == credentialID }) else {
            return .credentialNotFound
        }

        return .found(match)
    }

    public static func currentMachineId(
        fileURL: URL = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".authsia", isDirectory: true)
            .appendingPathComponent("machine.json")
    ) -> String? {
        struct MachineRecord: Decodable {
            let machineId: String
        }

        guard let data = try? Data(contentsOf: fileURL),
              let record = try? JSONDecoder().decode(MachineRecord.self, from: data) else {
            return nil
        }
        return record.machineId
    }
}
#endif
