import ArgumentParser
import Foundation
import AuthenticatorBridge

enum OutputFormat: String, ExpressibleByArgument, CaseIterable {
    case json
    case table
}

struct OutputFormatter {
    struct OTPListItem: Codable, Equatable {
        let id: UUID
        let issuer: String
        let label: String
        let hosts: [String]?
        let isFavorite: Bool
        let isCliEnabled: Bool
        let isScraped: Bool
        let createdAt: Date
        let updatedAt: Date
    }

    struct PasswordListItem: Codable {
        let id: String
        let name: String
        let username: String
        let website: String?
        let notes: String?
        let folderPath: String?
        let createdAt: Date
        let updatedAt: Date
        let expiresAt: Date?
        let isFavorite: Bool
        let isCliEnabled: Bool
        let isScraped: Bool
        let scrapeMachineName: String?
        let scrapeMachineId: String?
        let environments: [String]
    }

    struct APIKeyListItem: Codable {
        let id: String
        let name: String
        let website: String?
        let notes: String?
        let folderPath: String?
        let createdAt: Date
        let updatedAt: Date
        let expiresAt: Date?
        let isFavorite: Bool
        let isCliEnabled: Bool
        let isScraped: Bool
        let scrapeMachineName: String?
        let scrapeMachineId: String?
        let environments: [String]
    }

    struct CertificateListItem: Codable {
        let id: String
        let name: String
        let certificate: String
        let privateKey: String?
        let expirationDate: Date?
        let issuer: String?
        let subject: String?
        let notes: String?
        let folderPath: String?
        let createdAt: Date
        let updatedAt: Date
        let isFavorite: Bool
        let isCliEnabled: Bool
        let isScraped: Bool
        let scrapeMachineName: String?
        let scrapeMachineId: String?
        let environments: [String]
    }

    struct NoteListItem: Codable {
        let id: String
        let title: String
        let content: String
        let folderPath: String?
        let createdAt: Date
        let updatedAt: Date
        let isFavorite: Bool
        let isCliEnabled: Bool
        let isScraped: Bool
        let scrapeMachineName: String?
        let scrapeMachineId: String?
        let environments: [String]
    }

    struct SSHKeyListItem: Codable {
        let id: UUID
        let name: String
        let comment: String
        let fingerprint: String
        let publicKey: String
        let keyType: String
        let approvalPolicy: String
        let boundHosts: [String]
        let folderPath: String?
        let isFavorite: Bool
        let isCliEnabled: Bool
        let isScraped: Bool
        let createdAt: Date
        let updatedAt: Date
        let scrapeMachineName: String?
        let scrapeMachineId: String?
        let environments: [String]
    }

    static func formatOTPList(_ otpItems: [BridgeAccount], format: OutputFormat) throws -> String {
        switch format {
        case .table:
            return TableFormatter.formatOTPItems(otpItems)
        case .json:
            let items = otpItems.map { otpItem in
                OTPListItem(
                    id: otpItem.id,
                    issuer: otpItem.issuer,
                    label: otpItem.label,
                    hosts: otpItem.hosts,
                    isFavorite: otpItem.isFavorite,
                    isCliEnabled: otpItem.isCliEnabled,
                    isScraped: otpItem.isScraped,
                    createdAt: otpItem.createdAt,
                    updatedAt: otpItem.updatedAt
                )
            }
            return try encodeJSON(items)
        }
    }
}



// MARK: - Bridge Result Formatting

extension OutputFormatter {

    static func formatPasswords(_ passwords: [BridgePassword], format: OutputFormat) throws -> String {
        switch format {
        case .table:
            return TableFormatter.formatPasswords(passwords)
        case .json:
            let items = passwords.map { password in
                PasswordListItem(
                    id: password.id.uuidString,
                    name: password.name,
                    username: password.username,
                    website: password.website,
                    notes: nil,
                    folderPath: password.folderPath,
                    createdAt: password.createdAt,
                    updatedAt: password.updatedAt,
                    expiresAt: password.expiresAt,
                    isFavorite: password.isFavorite,
                    isCliEnabled: password.isCliEnabled,
                    isScraped: password.isScraped,
                    scrapeMachineName: password.scrapeMachineName,
                    scrapeMachineId: password.scrapeMachineId,
                    environments: password.environments
                )
            }
            return try encodeJSON(items)
        }
    }

    static func formatAPIKeys(_ apiKeys: [BridgeAPIKey], format: OutputFormat) throws -> String {
        switch format {
        case .table:
            return TableFormatter.formatAPIKeys(apiKeys)
        case .json:
            let items = apiKeys.map { apiKey in
                APIKeyListItem(
                    id: apiKey.id.uuidString,
                    name: apiKey.name,
                    website: apiKey.website,
                    notes: nil,
                    folderPath: apiKey.folderPath,
                    createdAt: apiKey.createdAt,
                    updatedAt: apiKey.updatedAt,
                    expiresAt: apiKey.expiresAt,
                    isFavorite: apiKey.isFavorite,
                    isCliEnabled: apiKey.isCliEnabled,
                    isScraped: apiKey.isScraped,
                    scrapeMachineName: apiKey.scrapeMachineName,
                    scrapeMachineId: apiKey.scrapeMachineId,
                    environments: apiKey.environments
                )
            }
            return try encodeJSON(items)
        }
    }

    static func formatCertificates(_ certificates: [BridgeCertificate], format: OutputFormat) throws -> String {
        switch format {
        case .table:
            return TableFormatter.formatCertificates(certificates)
        case .json:
            let items = certificates.map { cert in
                CertificateListItem(
                    id: cert.id.uuidString,
                    name: cert.name,
                    certificate: "",
                    privateKey: nil,
                    expirationDate: cert.expirationDate,
                    issuer: cert.issuer,
                    subject: cert.subject,
                    notes: nil,
                    folderPath: cert.folderPath,
                    createdAt: cert.createdAt,
                    updatedAt: cert.updatedAt,
                    isFavorite: cert.isFavorite,
                    isCliEnabled: cert.isCliEnabled,
                    isScraped: cert.isScraped,
                    scrapeMachineName: cert.scrapeMachineName,
                    scrapeMachineId: cert.scrapeMachineId,
                    environments: cert.environments
                )
            }
            return try encodeJSON(items)
        }
    }
    
    static func formatNotes(_ notes: [BridgeNote], format: OutputFormat) throws -> String {
        switch format {
        case .table:
            return TableFormatter.formatNotes(notes)
        case .json:
            let items = notes.map { note in
                NoteListItem(
                    id: note.id.uuidString,
                    title: note.title,
                    content: "",
                    folderPath: note.folderPath,
                    createdAt: note.createdAt,
                    updatedAt: note.updatedAt,
                    isFavorite: note.isFavorite,
                    isCliEnabled: note.isCliEnabled,
                    isScraped: note.isScraped,
                    scrapeMachineName: note.scrapeMachineName,
                    scrapeMachineId: note.scrapeMachineId,
                    environments: note.environments
                )
            }
            return try encodeJSON(items)
        }
    }

    static func formatSSHKeys(_ keys: [BridgeSSHKey], format: OutputFormat) throws -> String {
        switch format {
        case .table:
            return TableFormatter.formatSSHKeys(keys)
        case .json:
            let items = keys.map { key in
                SSHKeyListItem(
                    id: key.id,
                    name: key.name,
                    comment: key.comment,
                    fingerprint: key.fingerprint,
                    publicKey: key.publicKey,
                    keyType: key.keyType.rawValue,
                    approvalPolicy: key.approvalPolicy.rawValue,
                    boundHosts: key.boundHosts,
                    folderPath: key.folderPath,
                    isFavorite: key.isFavorite,
                    isCliEnabled: key.isCliEnabled,
                    isScraped: key.isScraped,
                    createdAt: key.createdAt,
                    updatedAt: key.updatedAt,
                    scrapeMachineName: key.scrapeMachineName,
                    scrapeMachineId: key.scrapeMachineId,
                    environments: key.environments
                )
            }
            return try encodeJSON(items)
        }
    }
    struct PasswordResultOutput: Codable {
        let id: String
        let name: String
        let username: String
        let password: String
        let website: String?
        let notes: String?
        let createdAt: Date
        let modifiedAt: Date
        let isFavorite: Bool
        let isCliEnabled: Bool
    }

    struct APIKeyResultOutput: Codable {
        let id: String
        let name: String
        let key: String
        let website: String?
        let notes: String?
        let createdAt: Date
        let modifiedAt: Date
        let isFavorite: Bool
        let isCliEnabled: Bool
    }

    struct CertificateResultOutput: Codable {
        let id: String
        let name: String
        let certificate: String
        let privateKey: String?
        let expirationDate: Date?
        let issuer: String?
        let subject: String?
        let notes: String?
        let createdAt: Date
        let modifiedAt: Date
        let isFavorite: Bool
        let isCliEnabled: Bool
    }

    struct NoteResultOutput: Codable {
        let id: String
        let title: String
        let content: String
        let createdAt: Date
        let modifiedAt: Date
        let isFavorite: Bool
        let isCliEnabled: Bool
    }

    struct SSHKeyResultOutput: Codable {
        let id: String
        let name: String
        let publicKey: String
        let privateKey: String
        let comment: String
        let fingerprint: String
        let keyType: String
        let approvalPolicy: String
        let boundHosts: [String]
        let createdAt: Date
        let modifiedAt: Date
        let isFavorite: Bool
        let isCliEnabled: Bool
    }

    struct WriteResultOutput: Codable {
        let id: String
        let message: String
    }
    
    struct OTPResultOutput: Codable {
        let id: String
        let issuer: String
        let label: String
        let code: String
        let remaining: Int
        let expiresAt: Date
        let isFavorite: Bool
    }

    static func formatOTPResult(_ result: OTPResult, format: OutputFormat) throws -> String {
        switch format {
        case .json:
            let payload = OTPResultOutput(
                id: result.accountId,
                issuer: result.issuer,
                label: result.label,
                code: result.code,
                remaining: result.remaining,
                expiresAt: result.expiresAt,
                isFavorite: result.isFavorite
            )
            return try encodeJSON(payload)
        case .table:
            return CodeFormatter.formatBridge(
                issuer: result.issuer,
                label: result.label,
                code: result.code,
                remaining: result.remaining
            )
        }
    }

    static func formatPasswordResult(_ result: PasswordResult, format: OutputFormat) throws -> String {
        switch format {
        case .json:
            let payload = PasswordResultOutput(
                id: result.id,
                name: result.name,
                username: result.username,
                password: result.password,
                website: result.website,
                notes: result.notes,
                createdAt: result.createdAt,
                modifiedAt: result.modifiedAt,
                isFavorite: result.isFavorite,
                isCliEnabled: true
            )
            return try encodeJSON(payload)
        case .table:
            var lines = [
                "Name: \(result.name)",
                "Username: \(result.username)",
                "Password: \(result.password)",
                "Website: \(result.website ?? "-")",
                "Notes: \(result.notes ?? "-")"
            ]
            if result.isFavorite {
                lines.append("Favorite: Yes")
            }
            return lines.joined(separator: "\n")
        }
    }

    static func formatAPIKeyResult(_ result: APIKeyResult, format: OutputFormat) throws -> String {
        switch format {
        case .json:
            let payload = APIKeyResultOutput(
                id: result.id,
                name: result.name,
                key: result.key,
                website: result.website,
                notes: result.notes,
                createdAt: result.createdAt,
                modifiedAt: result.modifiedAt,
                isFavorite: result.isFavorite,
                isCliEnabled: true
            )
            return try encodeJSON(payload)
        case .table:
            var lines = [
                "Name: \(result.name)",
                "API Key: \(result.key)",
                "Website: \(result.website ?? "-")",
                "Notes: \(result.notes ?? "-")"
            ]
            if result.isFavorite {
                lines.append("Favorite: Yes")
            }
            return lines.joined(separator: "\n")
        }
    }

    static func formatCertificateResult(_ result: CertificateResult, includePrivateKey: Bool, format: OutputFormat) throws -> String {
        switch format {
        case .json:
            let payload = CertificateResultOutput(
                id: result.id,
                name: result.name,
                certificate: result.certificate,
                privateKey: includePrivateKey ? result.privateKey : nil,
                expirationDate: result.expirationDate,
                issuer: result.issuer,
                subject: result.subject,
                notes: result.notes,
                createdAt: result.createdAt,
                modifiedAt: result.modifiedAt,
                isFavorite: result.isFavorite,
                isCliEnabled: true
            )
            return try encodeJSON(payload)
        case .table:
            var lines = [
                "Name: \(result.name)",
                "Issuer: \(result.issuer ?? "-")",
                "Subject: \(result.subject ?? "-")",
                "Notes: \(result.notes ?? "-")",
                "Certificate: \(result.certificate)"
            ]
            if result.isFavorite {
                lines.insert("Favorite: Yes", at: 0)
            }
            return lines.joined(separator: "\n")
        }
    }

    static func formatNoteResult(_ result: NoteResult, format: OutputFormat) throws -> String {
        switch format {
        case .json:
            let payload = NoteResultOutput(
                id: result.id,
                title: result.title,
                content: result.content,
                createdAt: result.createdAt,
                modifiedAt: result.modifiedAt,
                isFavorite: result.isFavorite,
                isCliEnabled: true
            )
            return try encodeJSON(payload)
        case .table:
            var lines = [
                "Title: \(result.title)",
                "Content: \(result.content)"
            ]
            if result.isFavorite {
                lines.append("Favorite: Yes")
            }
            return lines.joined(separator: "\n")
        }
    }

    static func formatSSHKeyResult(_ result: SSHKeyResult, format: OutputFormat) throws -> String {
        switch format {
        case .json:
            let payload = SSHKeyResultOutput(
                id: result.id,
                name: result.name,
                publicKey: result.publicKey,
                privateKey: result.privateKey,
                comment: result.comment,
                fingerprint: result.fingerprint,
                keyType: result.keyType.rawValue,
                approvalPolicy: result.approvalPolicy.rawValue,
                boundHosts: result.boundHosts,
                createdAt: result.createdAt,
                modifiedAt: result.modifiedAt,
                isFavorite: result.isFavorite,
                isCliEnabled: true
            )
            return try encodeJSON(payload)
        case .table:
            var lines = [
                "Name: \(result.name)",
                "Comment: \(result.comment)",
                "Fingerprint: \(result.fingerprint)",
                "Key Type: \(result.keyType.rawValue)",
                "Approval: \(result.approvalPolicy.rawValue)",
                "Hosts: \(result.boundHosts.isEmpty ? "any" : result.boundHosts.joined(separator: ","))",
                "Public Key: \(result.publicKey)",
                "Private Key: \(result.privateKey)"
            ]
            if result.isFavorite {
                lines.insert("Favorite: Yes", at: 0)
            }
            return lines.joined(separator: "\n")
        }
    }

    static func formatWriteResult(_ result: WriteResult, format: OutputFormat) throws -> String {
        switch format {
        case .json:
            let payload = WriteResultOutput(id: result.id, message: result.message)
            return try encodeJSON(payload)
        case .table:
            throw CLIError.unsupported(
                message: "Table format is not supported for write commands."
            ).asValidationError
        }
    }
    static func encodeJSON<T: Encodable>(_ value: T) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(value)
        return String(decoding: data, as: UTF8.self)
    }
}
