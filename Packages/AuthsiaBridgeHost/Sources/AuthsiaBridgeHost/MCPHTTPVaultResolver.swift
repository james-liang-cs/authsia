#if os(macOS)
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
import Foundation

@MainActor
protocol MCPHTTPVaultSource {
    var passwords: [PasswordMetadata] { get }
    var apiKeys: [APIKeyMetadata] { get }
    var notes: [SecureNoteMetadata] { get }
    func load() throws
    func getFullPassword(metadata: PasswordMetadata) throws -> PasswordItem
    func getFullAPIKey(metadata: APIKeyMetadata) throws -> APIKeyItem
    func getFullNote(metadata: SecureNoteMetadata) throws -> SecureNoteItem
}

@MainActor
private struct MCPHTTPRepositoryAdapter: MCPHTTPVaultSource {
    let repository: any VaultRepositoryProviding
    var passwords: [PasswordMetadata] { repository.passwords }
    var apiKeys: [APIKeyMetadata] { repository.apiKeys }
    var notes: [SecureNoteMetadata] { repository.notes }
    func load() throws { try repository.load() }
    func getFullPassword(metadata: PasswordMetadata) throws -> PasswordItem { try repository.getFullPassword(metadata: metadata) }
    func getFullAPIKey(metadata: APIKeyMetadata) throws -> APIKeyItem { try repository.getFullAPIKey(metadata: metadata) }
    func getFullNote(metadata: SecureNoteMetadata) throws -> SecureNoteItem { try repository.getFullNote(metadata: metadata) }
}

@MainActor
final class MCPHTTPVaultResolver {
    private let repository: any MCPHTTPVaultSource
    init(repository: any VaultRepositoryProviding) { self.repository = MCPHTTPRepositoryAdapter(repository: repository) }
    init(source: any MCPHTTPVaultSource) { self.repository = source }

    func metadata(_ headers: [MCPUpstreamCredentialHeader]) throws -> [MCPHTTPResolvedItem] {
        if headers.isEmpty { return [] }
        try repository.load()
        return try headers.map { header in
            let reference = try MCPHeaderReference(header.reference)
            switch reference.type {
            case "api-key":
                let candidates = repository.apiKeys.filter {
                    ($0.id.uuidString.caseInsensitiveCompare(reference.item) == .orderedSame || $0.name == reference.item)
                        && (reference.folder == nil || ($0.folderPath ?? "") == reference.folder)
                }
                guard candidates.count == 1, let item = candidates.first,
                      item.isCliEnabled, item.expiresAt.map({ $0 > Date() }) ?? true else { throw MCPManagementError.denied }
                return try resolved(header, reference, id: item.id, label: item.name, metadata: item)
            case "password":
                let candidates = repository.passwords.filter {
                    ($0.id.uuidString.caseInsensitiveCompare(reference.item) == .orderedSame || $0.name == reference.item)
                        && (reference.folder == nil || ($0.folderPath ?? "") == reference.folder)
                }
                guard candidates.count == 1, let item = candidates.first,
                      item.isCliEnabled, item.expiresAt.map({ $0 > Date() }) ?? true else { throw MCPManagementError.denied }
                return try resolved(header, reference, id: item.id, label: item.name, metadata: item)
            case "note":
                let candidates = repository.notes.filter {
                    ($0.id.uuidString.caseInsensitiveCompare(reference.item) == .orderedSame || $0.title == reference.item)
                        && (reference.folder == nil || ($0.folderPath ?? "") == reference.folder)
                }
                guard candidates.count == 1, let item = candidates.first, item.isCliEnabled else { throw MCPManagementError.denied }
                return try resolved(header, reference, id: item.id, label: item.title, metadata: item)
            default: throw MCPManagementError.invalidRequest
            }
        }
    }

    func value(_ item: MCPHTTPResolvedItem) throws -> String {
        guard try metadata([item.header]) == [item] else { throw MCPManagementError.stale }
        let data: Data
        switch item.type {
        case "api-key":
            guard let metadata = repository.apiKeys.first(where: { $0.id == item.id }) else { throw MCPManagementError.denied }
            data = try repository.getFullAPIKey(metadata: metadata).key
        case "password":
            guard let metadata = repository.passwords.first(where: { $0.id == item.id }) else { throw MCPManagementError.denied }
            if item.field == "username" { return metadata.username }
            data = try repository.getFullPassword(metadata: metadata).password
        case "note":
            guard let metadata = repository.notes.first(where: { $0.id == item.id }) else { throw MCPManagementError.denied }
            data = try repository.getFullNote(metadata: metadata).content
        default: throw MCPManagementError.invalidRequest
        }
        guard let string = String(data: data, encoding: .utf8) else { throw MCPManagementError.invalidRequest }
        return string
    }

    private func resolved<T: Encodable>(_ header: MCPUpstreamCredentialHeader, _ reference: MCPHeaderReference,
                                        id: UUID, label: String, metadata: T) throws -> MCPHTTPResolvedItem {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return MCPHTTPResolvedItem(header: header, id: id, type: reference.type, field: reference.field,
                                  label: label, revision: MCPWorkspaceStore.digest(try encoder.encode(metadata)))
    }
}
#endif
