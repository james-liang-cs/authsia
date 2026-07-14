#if os(macOS)
import Foundation
import AuthenticatorCore
import AuthenticatorData

@MainActor
public protocol VaultRepositoryProviding {
    var passwords: [PasswordMetadata] { get }
    var apiKeys: [APIKeyMetadata] { get }
    var certificates: [CertificateMetadata] { get }
    var notes: [SecureNoteMetadata] { get }
    var sshKeys: [SSHKeyMetadata] { get }
    var hasLoadedVaultState: Bool { get }

    func load() throws

    func addPassword(_ item: PasswordItem) throws
    func updatePassword(_ item: PasswordItem) throws
    func deletePassword(id: UUID) throws
    func convertPasswordToAPIKey(id: UUID, modifiedAt: Date) throws -> APIKeyItem?
    func getFullPassword(metadata: PasswordMetadata) throws -> PasswordItem

    func addAPIKey(_ item: APIKeyItem) throws
    func updateAPIKey(_ item: APIKeyItem) throws
    func deleteAPIKey(id: UUID) throws
    func getFullAPIKey(metadata: APIKeyMetadata) throws -> APIKeyItem

    func addCertificate(_ item: CertificateItem) throws
    func updateCertificate(_ item: CertificateItem) throws
    func deleteCertificatePrivateKey(id: UUID)
    func deleteCertificate(id: UUID) throws
    func getFullCertificate(metadata: CertificateMetadata) throws -> CertificateItem

    func addNote(_ item: SecureNoteItem) throws
    func updateNote(_ item: SecureNoteItem) throws
    func deleteNote(id: UUID) throws
    func getFullNote(metadata: SecureNoteMetadata) throws -> SecureNoteItem

    func addSSHKey(_ item: SSHKeyItem) throws
    func updateSSHKey(_ item: SSHKeyItem) throws
    func deleteSSHKey(id: UUID) throws
    func getFullSSHKey(metadata: SSHKeyMetadata) throws -> SSHKeyItem

    func addFolder(_ path: String, type: VaultItemType) throws
    func deleteFolder(path: String, type: VaultItemType) async throws
}

public extension VaultRepositoryProviding {
    func deleteFolder(path: String, type: VaultItemType) async throws {
        throw NSError(
            domain: "VaultRepositoryProviding",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Folder deletion is not supported by this repository."]
        )
    }
}

extension VaultRepository: VaultRepositoryProviding {}
#endif
