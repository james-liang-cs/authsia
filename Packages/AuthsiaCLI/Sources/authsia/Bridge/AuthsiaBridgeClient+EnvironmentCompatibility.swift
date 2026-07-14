import AuthenticatorCore
import Foundation

extension AuthsiaBridgeClient {
    func addPassword(
        name: String,
        username: String,
        password: String,
        website: String?,
        notes: String?,
        isScraped: Bool,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?,
        expiresAt: Date?
    ) throws -> WriteResult {
        try addPassword(
            name: name,
            username: username,
            password: password,
            website: website,
            notes: notes,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            expiresAt: expiresAt,
            environments: []
        )
    }

    func updatePassword(
        query: String,
        name: String?,
        username: String?,
        password: String?,
        website: String?,
        notes: String?,
        isScraped: Bool?,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?,
        expiresAt: Date?,
        clearExpiresAt: Bool
    ) throws -> WriteResult {
        try updatePassword(
            query: query,
            name: name,
            username: username,
            password: password,
            website: website,
            notes: notes,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            expiresAt: expiresAt,
            clearExpiresAt: clearExpiresAt,
            environments: nil
        )
    }

    func addAPIKey(
        name: String,
        key: String,
        website: String?,
        notes: String?,
        isScraped: Bool,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?,
        expiresAt: Date?
    ) throws -> WriteResult {
        try addAPIKey(
            name: name,
            key: key,
            website: website,
            notes: notes,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            expiresAt: expiresAt,
            environments: []
        )
    }

    func updateAPIKey(
        query: String,
        name: String?,
        key: String?,
        website: String?,
        notes: String?,
        isScraped: Bool?,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?,
        expiresAt: Date?,
        clearExpiresAt: Bool
    ) throws -> WriteResult {
        try updateAPIKey(
            query: query,
            name: name,
            key: key,
            website: website,
            notes: notes,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            expiresAt: expiresAt,
            clearExpiresAt: clearExpiresAt,
            environments: nil
        )
    }

    func addCertificate(
        name: String,
        certificate: String,
        privateKey: String?,
        notes: String?,
        folderPath: String?,
        isScraped: Bool,
        scrapeMachineName: String?,
        scrapeMachineId: String?
    ) throws -> WriteResult {
        try addCertificate(
            name: name,
            certificate: certificate,
            privateKey: privateKey,
            notes: notes,
            folderPath: folderPath,
            isScraped: isScraped,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            environments: []
        )
    }

    func updateCertificate(
        query: String,
        name: String?,
        certificate: String?,
        privateKey: String?,
        clearPrivateKey: Bool,
        notes: String?,
        folderPath: String?,
        isScraped: Bool?,
        scrapeMachineName: String?,
        scrapeMachineId: String?
    ) throws -> WriteResult {
        try updateCertificate(
            query: query,
            name: name,
            certificate: certificate,
            privateKey: privateKey,
            clearPrivateKey: clearPrivateKey,
            notes: notes,
            folderPath: folderPath,
            isScraped: isScraped,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            environments: nil
        )
    }

    func addNote(
        title: String,
        content: String,
        isScraped: Bool,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?
    ) throws -> WriteResult {
        try addNote(
            title: title,
            content: content,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            environments: []
        )
    }

    func updateNote(
        query: String,
        title: String?,
        content: String?,
        isScraped: Bool?,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?
    ) throws -> WriteResult {
        try updateNote(
            query: query,
            title: title,
            content: content,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            environments: nil
        )
    }

    func addSSH(
        name: String,
        publicKey: String,
        privateKey: String,
        comment: String,
        fingerprint: String,
        passphrase: String?,
        keyType: SSHKeyType?,
        approvalPolicy: SSHKeyApprovalPolicy?,
        boundHosts: [String]?,
        isScraped: Bool,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?
    ) throws -> WriteResult {
        try addSSH(
            name: name,
            publicKey: publicKey,
            privateKey: privateKey,
            comment: comment,
            fingerprint: fingerprint,
            passphrase: passphrase,
            keyType: keyType,
            approvalPolicy: approvalPolicy,
            boundHosts: boundHosts,
            isScraped: isScraped,
            folderPath: folderPath,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId,
            environments: []
        )
    }
}
