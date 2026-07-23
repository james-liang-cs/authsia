import Foundation
import AuthenticatorBridge

struct AccessCredential: Codable, Equatable, Identifiable {
    enum Status: String, Codable, CaseIterable {
        case active
        case expired
        case revoked
    }

    let id: UUID
    let name: String
    let scope: String?
    let createdAt: Date
    let expiresAt: Date
    let revokedAt: Date?
    let machineId: String
    let machineName: String
    let allowedCommands: Set<CapabilityCommand>
    let environmentScope: EnvironmentAccessScope?
    let bearerToken: String?

    init(
        id: UUID,
        name: String,
        scope: String?,
        createdAt: Date,
        expiresAt: Date,
        revokedAt: Date?,
        machineId: String,
        machineName: String,
        allowedCommands: Set<CapabilityCommand> = [.exec],
        environmentScope: EnvironmentAccessScope? = nil,
        bearerToken: String? = nil
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
        self.bearerToken = bearerToken
    }

    var isRevoked: Bool { revokedAt != nil }

    func status(asOf date: Date) -> Status {
        if isRevoked { return .revoked }
        return expiresAt > date ? .active : .expired
    }

    // Legacy records on disk predate `allowedCommands`. Decode missing field as
    // `[.exec]` so existing CI/agent credentials become exec-only automatically —
    // fails closed rather than silently granting full access.
    enum CodingKeys: String, CodingKey {
        case id, name, scope, createdAt, expiresAt, revokedAt
        case machineId, machineName, allowedCommands, environmentScope
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decode(UUID.self, forKey: .id)
        self.name = try c.decode(String.self, forKey: .name)
        self.scope = try c.decodeIfPresent(String.self, forKey: .scope)
        self.createdAt = try c.decode(Date.self, forKey: .createdAt)
        self.expiresAt = try c.decode(Date.self, forKey: .expiresAt)
        self.revokedAt = try c.decodeIfPresent(Date.self, forKey: .revokedAt)
        self.machineId = try c.decode(String.self, forKey: .machineId)
        self.machineName = try c.decode(String.self, forKey: .machineName)
        self.allowedCommands = try c.decodeIfPresent(Set<CapabilityCommand>.self, forKey: .allowedCommands)
            ?? [.exec]
        self.environmentScope = try c.decodeIfPresent(EnvironmentAccessScope.self, forKey: .environmentScope)
        self.bearerToken = nil
    }

    func withBearerToken(_ token: String) -> AccessCredential {
        AccessCredential(
            id: id,
            name: name,
            scope: scope,
            createdAt: createdAt,
            expiresAt: expiresAt,
            revokedAt: revokedAt,
            machineId: machineId,
            machineName: machineName,
            allowedCommands: allowedCommands,
            environmentScope: environmentScope,
            bearerToken: token
        )
    }

    init(metadata: AutomationCredentialMetadata, bearerToken: String? = nil) {
        self.init(
            id: metadata.id,
            name: metadata.name,
            scope: metadata.scope,
            createdAt: metadata.createdAt,
            expiresAt: metadata.expiresAt,
            revokedAt: metadata.revokedAt,
            machineId: metadata.machineId,
            machineName: metadata.machineName,
            allowedCommands: metadata.allowedCommands,
            environmentScope: metadata.environmentScope,
            bearerToken: bearerToken
        )
    }
}
