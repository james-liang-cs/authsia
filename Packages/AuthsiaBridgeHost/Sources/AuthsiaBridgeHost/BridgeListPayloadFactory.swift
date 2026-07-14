#if os(macOS)
import Foundation
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData

public enum BridgeListPayloadFactory {
    public nonisolated static func defaultAccounts() throws -> [BridgeAccount] {
        try MetadataStore.shared.loadAll().map {
            BridgeAccount(
                id: $0.id,
                issuer: $0.issuer,
                label: $0.label,
                hosts: $0.hosts,
                isFavorite: $0.isFavorite,
                isCliEnabled: $0.isCliEnabled,
                isScraped: $0.isScraped,
                createdAt: $0.createdAt,
                updatedAt: $0.lastUsed
            )
        }
    }

    public static func defaultPayload() throws -> BridgeListPayload {
        let snapshot = try? VaultCLIMetadataSnapshotStore.shared.load()
        let accounts = try defaultAccounts()
        let passwordMetadata = try VaultMetadataStore.shared.loadPasswords()
        let apiKeyMetadata = try VaultMetadataStore.shared.loadAPIKeys()
        let certificateMetadata = try VaultMetadataStore.shared.loadCertificates()
        let noteMetadata = try VaultMetadataStore.shared.loadNotes()
        let sshKeyMetadata = try VaultMetadataStore.shared.loadSSHKeys()
        let passwords = metadataWithSnapshotFallback(
            loaded: passwordMetadata,
            snapshot: snapshot?.passwords,
            mapLoaded: { bridgePassword(from: $0, hasSecret: passwordHasSecret(id: $0.id)) },
            mapSnapshot: { bridgePassword(from: $0) }
        )
        let apiKeys = metadataWithSnapshotFallback(
            loaded: apiKeyMetadata,
            snapshot: snapshot?.apiKeys,
            mapLoaded: { bridgeAPIKey(from: $0, hasSecret: apiKeyHasSecret(id: $0.id)) },
            mapSnapshot: { bridgeAPIKey(from: $0) }
        )
        let certificates = metadataWithSnapshotFallback(
            loaded: certificateMetadata,
            snapshot: snapshot?.certificates,
            mapLoaded: { bridgeCertificate(from: $0) },
            mapSnapshot: { bridgeCertificate(from: $0) }
        )
        let notes = metadataWithSnapshotFallback(
            loaded: noteMetadata,
            snapshot: snapshot?.notes,
            mapLoaded: { bridgeNote(from: $0) },
            mapSnapshot: { bridgeNote(from: $0) }
        )
        let sshKeys = metadataWithSnapshotFallback(
            loaded: sshKeyMetadata,
            snapshot: snapshot?.sshKeys,
            mapLoaded: { bridgeSSHKey(from: $0) },
            mapSnapshot: { bridgeSSHKey(from: $0) }
        )
        return BridgeListPayload(
            accounts: accounts,
            passwords: passwords,
            apiKeys: apiKeys,
            certificates: certificates,
            notes: notes,
            sshKeys: sshKeys
        )
    }

    /// Loads only the non-secret metadata needed by workspace status, validation, and sync previews.
    /// This is safe to call off the main actor and intentionally skips OTP accounts and
    /// per-item secret-existence probes.
    public nonisolated static func workspaceMetadataPayload() throws -> BridgeListPayload {
        let passwords = try VaultMetadataStore.shared.loadPasswords()
        let apiKeys = try VaultMetadataStore.shared.loadAPIKeys()
        let certificates = try VaultMetadataStore.shared.loadCertificates()
        let notes = try VaultMetadataStore.shared.loadNotes()
        let sshKeys = try VaultMetadataStore.shared.loadSSHKeys()
        return BridgeListPayload(
            accounts: [],
            passwords: passwords.map { bridgePassword(from: $0, hasSecret: nil) },
            apiKeys: apiKeys.map { bridgeAPIKey(from: $0, hasSecret: nil) },
            certificates: certificates.map { bridgeCertificate(from: $0) },
            notes: notes.map { bridgeNote(from: $0) },
            sshKeys: sshKeys.map { bridgeSSHKey(from: $0) }
        )
    }

    @MainActor
    public static func repositoryPayload(
        accounts: [BridgeAccount],
        repository: VaultRepositoryProviding
    ) -> BridgeListPayload {
        BridgeListPayload(
            accounts: accounts,
            passwords: repository.passwords.map { bridgePassword(from: $0, hasSecret: passwordHasSecret(id: $0.id)) },
            apiKeys: repository.apiKeys.map { bridgeAPIKey(from: $0, hasSecret: apiKeyHasSecret(id: $0.id)) },
            certificates: repository.certificates.map { bridgeCertificate(from: $0) },
            notes: repository.notes.map { bridgeNote(from: $0) },
            sshKeys: repository.sshKeys.map { bridgeSSHKey(from: $0) }
        )
    }

    /// Builds a payload from the repository's already-loaded, in-memory metadata **without**
    /// per-item keychain probes. Used for workspace metadata previews, where a full-vault
    /// `hasSecret` sweep on the app's main thread would freeze the UI. `hasSecret` is left
    /// `nil`; `WorkspaceVaultIndex` treats a referenced item present in metadata as verified.
    @MainActor
    public static func repositoryMetadataPayload(
        repository: VaultRepositoryProviding
    ) -> BridgeListPayload {
        BridgeListPayload(
            accounts: [],
            passwords: repository.passwords.map { bridgePassword(from: $0, hasSecret: nil) },
            apiKeys: repository.apiKeys.map { bridgeAPIKey(from: $0, hasSecret: nil) },
            certificates: repository.certificates.map { bridgeCertificate(from: $0) },
            notes: repository.notes.map { bridgeNote(from: $0) },
            sshKeys: repository.sshKeys.map { bridgeSSHKey(from: $0) }
        )
    }

    /// Adds secret-existence state only after workspace metadata has been reduced to
    /// the exact requested references. No secret values are read or returned.
    public static func validationPayload(
        _ payload: BridgeListPayload,
        passwordHasSecret: (UUID) -> Bool?,
        apiKeyHasSecret: (UUID) -> Bool?
    ) -> BridgeListPayload {
        BridgeListPayload(
            accounts: [],
            passwords: payload.passwords.map { password in
                BridgePassword(
                    id: password.id,
                    name: password.name,
                    username: password.username,
                    website: password.website,
                    folderPath: password.folderPath,
                    isFavorite: password.isFavorite,
                    isCliEnabled: password.isCliEnabled,
                    isScraped: password.isScraped,
                    createdAt: password.createdAt,
                    updatedAt: password.updatedAt,
                    expiresAt: password.expiresAt,
                    scrapeMachineName: password.scrapeMachineName,
                    scrapeMachineId: password.scrapeMachineId,
                    hasSecret: passwordHasSecret(password.id),
                    environments: password.environments
                )
            },
            apiKeys: payload.apiKeys.map { apiKey in
                BridgeAPIKey(
                    id: apiKey.id,
                    name: apiKey.name,
                    website: apiKey.website,
                    folderPath: apiKey.folderPath,
                    isFavorite: apiKey.isFavorite,
                    isCliEnabled: apiKey.isCliEnabled,
                    isScraped: apiKey.isScraped,
                    createdAt: apiKey.createdAt,
                    updatedAt: apiKey.updatedAt,
                    expiresAt: apiKey.expiresAt,
                    scrapeMachineName: apiKey.scrapeMachineName,
                    scrapeMachineId: apiKey.scrapeMachineId,
                    hasSecret: apiKeyHasSecret(apiKey.id),
                    environments: apiKey.environments
                )
            },
            certificates: payload.certificates,
            notes: payload.notes,
            sshKeys: payload.sshKeys
        )
    }

    public static func passwordMetadataForLookup(
        loaded: [PasswordMetadata],
        snapshot: [VaultCLIMetadataSnapshot.Password]?
    ) -> [PasswordMetadata] {
        var merged = loaded
        var seenIDs = Set(loaded.map(\.id))
        for snapshotPassword in snapshot ?? [] where !seenIDs.contains(snapshotPassword.id) {
            merged.append(passwordMetadata(from: snapshotPassword))
            seenIDs.insert(snapshotPassword.id)
        }
        return merged
    }

    public static func apiKeyMetadataForLookup(
        loaded: [APIKeyMetadata],
        snapshot: [VaultCLIMetadataSnapshot.APIKey]?
    ) -> [APIKeyMetadata] {
        var merged = loaded
        var seenIDs = Set(loaded.map(\.id))
        for snapshotAPIKey in snapshot ?? [] where !seenIDs.contains(snapshotAPIKey.id) {
            merged.append(apiKeyMetadata(from: snapshotAPIKey))
            seenIDs.insert(snapshotAPIKey.id)
        }
        return merged
    }

    public static func metadataWithSnapshotFallback<Loaded, Snapshot, Output>(
        loaded: [Loaded],
        snapshot: [Snapshot]?,
        mapLoaded: (Loaded) -> Output,
        mapSnapshot: (Snapshot) -> Output
    ) -> [Output] {
        if loaded.isEmpty {
            return (snapshot ?? []).map(mapSnapshot)
        }
        return loaded.map(mapLoaded)
    }

    private nonisolated static func bridgePassword(
        from metadata: PasswordMetadata,
        hasSecret: Bool?
    ) -> BridgePassword {
        BridgePassword(
            id: metadata.id,
            name: metadata.name,
            username: metadata.username,
            website: metadata.website,
            folderPath: metadata.folderPath,
            isFavorite: metadata.isFavorite,
            isCliEnabled: metadata.isCliEnabled,
            isScraped: metadata.isScraped,
            createdAt: metadata.createdAt,
            updatedAt: metadata.modifiedAt,
            expiresAt: metadata.expiresAt,
            scrapeMachineName: metadata.scrapeMachineName,
            scrapeMachineId: metadata.scrapeMachineId,
            hasSecret: hasSecret,
            environments: metadata.environments
        )
    }

    private static func bridgePassword(from metadata: VaultCLIMetadataSnapshot.Password) -> BridgePassword {
        BridgePassword(
            id: metadata.id,
            name: metadata.name,
            username: metadata.username,
            website: metadata.website,
            folderPath: metadata.folderPath,
            isFavorite: metadata.isFavorite,
            isCliEnabled: metadata.isCliEnabled,
            isScraped: metadata.isScraped,
            createdAt: metadata.createdAt,
            updatedAt: metadata.modifiedAt,
            expiresAt: metadata.expiresAt,
            scrapeMachineName: metadata.scrapeMachineName,
            scrapeMachineId: metadata.scrapeMachineId,
            environments: metadata.environments
        )
    }

    private static func passwordMetadata(from snapshot: VaultCLIMetadataSnapshot.Password) -> PasswordMetadata {
        PasswordMetadata(
            id: snapshot.id,
            name: snapshot.name,
            username: snapshot.username,
            website: snapshot.website,
            notes: nil,
            folderPath: snapshot.folderPath,
            createdAt: snapshot.createdAt,
            modifiedAt: snapshot.modifiedAt,
            isFavorite: snapshot.isFavorite,
            isCliEnabled: snapshot.isCliEnabled,
            isScraped: snapshot.isScraped,
            scrapeMachineName: snapshot.scrapeMachineName,
            scrapeMachineId: snapshot.scrapeMachineId,
            expiresAt: snapshot.expiresAt,
            environments: snapshot.environments
        )
    }

    public static func passwordHasSecret(id: UUID) -> Bool? {
        do {
            return try VaultKeychainStore.shared.containsPassword(for: id)
        } catch {
            return nil
        }
    }

    private nonisolated static func bridgeAPIKey(from metadata: APIKeyMetadata, hasSecret: Bool?) -> BridgeAPIKey {
        BridgeAPIKey(
            id: metadata.id,
            name: metadata.name,
            website: metadata.website,
            folderPath: metadata.folderPath,
            isFavorite: metadata.isFavorite,
            isCliEnabled: metadata.isCliEnabled,
            isScraped: metadata.isScraped,
            createdAt: metadata.createdAt,
            updatedAt: metadata.modifiedAt,
            expiresAt: metadata.expiresAt,
            scrapeMachineName: metadata.scrapeMachineName,
            scrapeMachineId: metadata.scrapeMachineId,
            hasSecret: hasSecret,
            environments: metadata.environments
        )
    }

    private static func bridgeAPIKey(from metadata: VaultCLIMetadataSnapshot.APIKey) -> BridgeAPIKey {
        BridgeAPIKey(
            id: metadata.id,
            name: metadata.name,
            website: metadata.website,
            folderPath: metadata.folderPath,
            isFavorite: metadata.isFavorite,
            isCliEnabled: metadata.isCliEnabled,
            isScraped: metadata.isScraped,
            createdAt: metadata.createdAt,
            updatedAt: metadata.modifiedAt,
            expiresAt: metadata.expiresAt,
            scrapeMachineName: metadata.scrapeMachineName,
            scrapeMachineId: metadata.scrapeMachineId,
            environments: metadata.environments
        )
    }

    private static func apiKeyMetadata(from snapshot: VaultCLIMetadataSnapshot.APIKey) -> APIKeyMetadata {
        APIKeyMetadata(
            id: snapshot.id,
            name: snapshot.name,
            website: snapshot.website,
            notes: nil,
            folderPath: snapshot.folderPath,
            createdAt: snapshot.createdAt,
            modifiedAt: snapshot.modifiedAt,
            isFavorite: snapshot.isFavorite,
            isCliEnabled: snapshot.isCliEnabled,
            isScraped: snapshot.isScraped,
            scrapeMachineName: snapshot.scrapeMachineName,
            scrapeMachineId: snapshot.scrapeMachineId,
            expiresAt: snapshot.expiresAt,
            environments: snapshot.environments
        )
    }

    public static func apiKeyHasSecret(id: UUID) -> Bool? {
        do {
            return try VaultKeychainStore.shared.containsAPIKey(for: id)
        } catch {
            return nil
        }
    }

    private nonisolated static func bridgeCertificate(from metadata: CertificateMetadata) -> BridgeCertificate {
        BridgeCertificate(
            id: metadata.id,
            name: metadata.name,
            issuer: metadata.issuer,
            subject: metadata.subject,
            expirationDate: metadata.expirationDate,
            folderPath: metadata.folderPath,
            isFavorite: metadata.isFavorite,
            isCliEnabled: metadata.isCliEnabled,
            isScraped: metadata.isScraped,
            createdAt: metadata.createdAt,
            updatedAt: metadata.modifiedAt,
            scrapeMachineName: metadata.scrapeMachineName,
            scrapeMachineId: metadata.scrapeMachineId,
            environments: metadata.environments
        )
    }

    private static func bridgeCertificate(from metadata: VaultCLIMetadataSnapshot.Certificate) -> BridgeCertificate {
        BridgeCertificate(
            id: metadata.id,
            name: metadata.name,
            issuer: metadata.issuer,
            subject: metadata.subject,
            expirationDate: metadata.expirationDate,
            folderPath: metadata.folderPath,
            isFavorite: metadata.isFavorite,
            isCliEnabled: metadata.isCliEnabled,
            isScraped: metadata.isScraped,
            createdAt: metadata.createdAt,
            updatedAt: metadata.modifiedAt,
            scrapeMachineName: metadata.scrapeMachineName,
            scrapeMachineId: metadata.scrapeMachineId,
            environments: metadata.environments
        )
    }

    private nonisolated static func bridgeNote(from metadata: SecureNoteMetadata) -> BridgeNote {
        BridgeNote(
            id: metadata.id,
            title: metadata.title,
            folderPath: metadata.folderPath,
            isFavorite: metadata.isFavorite,
            isCliEnabled: metadata.isCliEnabled,
            isScraped: metadata.isScraped,
            createdAt: metadata.createdAt,
            updatedAt: metadata.modifiedAt,
            scrapeMachineName: metadata.scrapeMachineName,
            scrapeMachineId: metadata.scrapeMachineId,
            environments: metadata.environments
        )
    }

    private static func bridgeNote(from metadata: VaultCLIMetadataSnapshot.Note) -> BridgeNote {
        BridgeNote(
            id: metadata.id,
            title: metadata.title,
            folderPath: metadata.folderPath,
            isFavorite: metadata.isFavorite,
            isCliEnabled: metadata.isCliEnabled,
            isScraped: metadata.isScraped,
            createdAt: metadata.createdAt,
            updatedAt: metadata.modifiedAt,
            scrapeMachineName: metadata.scrapeMachineName,
            scrapeMachineId: metadata.scrapeMachineId,
            environments: metadata.environments
        )
    }

    private nonisolated static func bridgeSSHKey(from metadata: SSHKeyMetadata) -> BridgeSSHKey {
        BridgeSSHKey(
            id: metadata.id,
            name: metadata.name,
            comment: metadata.comment,
            fingerprint: metadata.fingerprint,
            publicKey: metadata.publicKey,
            folderPath: metadata.folderPath,
            isFavorite: metadata.isFavorite,
            isCliEnabled: metadata.isCliEnabled,
            isScraped: metadata.isScraped,
            createdAt: metadata.createdAt,
            updatedAt: metadata.modifiedAt,
            scrapeMachineName: metadata.scrapeMachineName,
            scrapeMachineId: metadata.scrapeMachineId,
            keyType: metadata.keyType,
            approvalPolicy: metadata.approvalPolicy,
            boundHosts: metadata.boundHosts,
            environments: metadata.environments
        )
    }

    private static func bridgeSSHKey(from metadata: VaultCLIMetadataSnapshot.SSHKey) -> BridgeSSHKey {
        BridgeSSHKey(
            id: metadata.id,
            name: metadata.name,
            comment: metadata.comment,
            fingerprint: metadata.fingerprint,
            publicKey: metadata.publicKey,
            folderPath: metadata.folderPath,
            isFavorite: metadata.isFavorite,
            isCliEnabled: metadata.isCliEnabled,
            isScraped: metadata.isScraped,
            createdAt: metadata.createdAt,
            updatedAt: metadata.modifiedAt,
            scrapeMachineName: metadata.scrapeMachineName,
            scrapeMachineId: metadata.scrapeMachineId,
            keyType: metadata.keyType,
            approvalPolicy: metadata.approvalPolicy,
            boundHosts: metadata.boundHosts,
            environments: metadata.environments
        )
    }
}
#endif
