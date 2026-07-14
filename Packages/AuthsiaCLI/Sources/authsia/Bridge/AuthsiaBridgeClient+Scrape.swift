import Foundation

extension AuthsiaBridgeClient: ScrapeVaultClient {
    func existingPasswordID(named name: String, folderPath: String?) throws -> String? {
        try list().passwords.first {
            Self.isSameScrapeItemName($0.name, name) && Self.isSameScrapeFolder($0.folderPath, folderPath)
        }?.id.uuidString
    }

    func existingAPIKeyID(named name: String, folderPath: String?) throws -> String? {
        try list().apiKeys.first {
            Self.isSameScrapeItemName($0.name, name) && Self.isSameScrapeFolder($0.folderPath, folderPath)
        }?.id.uuidString
    }

    func existingCertificateID(named name: String, folderPath: String?) throws -> String? {
        try list().certificates.first {
            Self.isSameScrapeItemName($0.name, name) && Self.isSameScrapeFolder($0.folderPath, folderPath)
        }?.id.uuidString
    }

    func existingNoteID(title: String, folderPath: String?) throws -> String? {
        try list().notes.first {
            Self.isSameScrapeItemName($0.title, title) && Self.isSameScrapeFolder($0.folderPath, folderPath)
        }?.id.uuidString
    }

    func existingPasswordID(named name: String, folderPath: String?, environments: [String]) throws -> String? {
        try list().passwords.first {
            Self.isSameScrapeItemName($0.name, name) &&
                Self.isSameScrapeFolder($0.folderPath, folderPath) &&
                WorkspaceSetupExchange.environmentTiersOverlap($0.environments, environments)
        }?.id.uuidString
    }

    func existingAPIKeyID(named name: String, folderPath: String?, environments: [String]) throws -> String? {
        try list().apiKeys.first {
            Self.isSameScrapeItemName($0.name, name) &&
                Self.isSameScrapeFolder($0.folderPath, folderPath) &&
                WorkspaceSetupExchange.environmentTiersOverlap($0.environments, environments)
        }?.id.uuidString
    }

    func existingCertificateID(named name: String, folderPath: String?, environments: [String]) throws -> String? {
        try list().certificates.first {
            Self.isSameScrapeItemName($0.name, name) &&
                Self.isSameScrapeFolder($0.folderPath, folderPath) &&
                WorkspaceSetupExchange.environmentTiersOverlap($0.environments, environments)
        }?.id.uuidString
    }

    func existingNoteID(title: String, folderPath: String?, environments: [String]) throws -> String? {
        try list().notes.first {
            Self.isSameScrapeItemName($0.title, title) &&
                Self.isSameScrapeFolder($0.folderPath, folderPath) &&
                WorkspaceSetupExchange.environmentTiersOverlap($0.environments, environments)
        }?.id.uuidString
    }

    func sshKeyExists(named name: String) throws -> Bool {
        do {
            _ = try getSSH(query: name)
            return true
        } catch BridgeClientError.bridgeError(let code, _, _) where code == "notFound" {
            return false
        }
    }

    func existingSSHKey(named name: String, folderPath: String?) throws -> SSHAdoptionService.ExistingVaultKey? {
        guard let key = try list().sshKeys.first(where: {
            Self.isSameScrapeItemName($0.name, name) && Self.isSameScrapeFolder($0.folderPath, folderPath)
        }) else { return nil }

        let privateKey = try? getSSH(query: key.id.uuidString, field: "privateKey").privateKey
        return SSHAdoptionService.ExistingVaultKey(
            publicKey: key.publicKey,
            fingerprint: key.fingerprint,
            privateKey: privateKey
        )
    }

    private static func isSameScrapeItemName(_ lhs: String, _ rhs: String) -> Bool {
        lhs.trimmingCharacters(in: .whitespacesAndNewlines)
            .caseInsensitiveCompare(rhs.trimmingCharacters(in: .whitespacesAndNewlines)) == .orderedSame
    }

    private static func isSameScrapeFolder(_ lhs: String?, _ rhs: String?) -> Bool {
        normalizeFolderPath(lhs) == normalizeFolderPath(rhs)
    }
}

extension AuthsiaBridgeClient: WorkspaceSetupVaultClient {}
