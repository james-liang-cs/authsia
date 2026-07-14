import Foundation
import AuthenticatorCore

public enum VaultImportConflictPolicy: Sendable {
    case keepExisting
    case overwriteExisting
}

public struct VaultImportPreview: Sendable {
    public let totalItems: Int
    public let duplicateCount: Int

    public var newItemsCount: Int {
        max(0, totalItems - duplicateCount)
    }

    public init(totalItems: Int, duplicateCount: Int) {
        self.totalItems = totalItems
        self.duplicateCount = duplicateCount
    }
}

public enum VaultImportPayloadKind: Equatable, Sendable {
    case all
    case item(VaultItemType)
}

@MainActor
public final class VaultImportExportService {
    public static let shared = VaultImportExportService()

    private static let format = "authsia.vault.export"
    private static let allFormat = "authsia.vault.export.all"
    private static let supportedVersion = 1

    private init() {}

    // MARK: - Export

    public func exportItems(
        of itemType: VaultItemType,
        from repository: VaultRepository
    ) async throws -> Data {
        try repository.load()

        switch itemType {
        case .password:
            return try encodeContainer(itemType: itemType, items: passwordItems(from: repository))
        case .apiKey:
            return try encodeContainer(itemType: itemType, items: apiKeyItems(from: repository))

        case .certificate:
            return try encodeContainer(itemType: itemType, items: certificateItems(from: repository))

        case .secureNote:
            return try encodeContainer(itemType: itemType, items: noteItems(from: repository))

        case .sshKey:
            return try encodeContainer(itemType: itemType, items: sshKeyItems(from: repository))
        }
    }

    // MARK: - Export All

    public func exportAllItems(from repository: VaultRepository) async throws -> Data {
        try repository.load()

        return try encodeAllContainer(
            passwords: passwordItems(from: repository),
            apiKeys: apiKeyItems(from: repository),
            certificates: certificateItems(from: repository),
            notes: noteItems(from: repository),
            sshKeys: sshKeyItems(from: repository)
        )
    }

    public func exportItems(
        inFolder folderPath: String,
        itemType: VaultItemType?,
        from repository: VaultRepository
    ) async throws -> Data {
        guard let normalizedPath = normalizedFolderPath(folderPath) else {
            throw VaultImportExportError.invalidFolderPath
        }

        try repository.load()

        switch itemType {
        case .password:
            return try encodeContainer(
                itemType: .password,
                items: passwordItems(from: repository, inFolder: normalizedPath)
            )
        case .apiKey:
            return try encodeContainer(
                itemType: .apiKey,
                items: apiKeyItems(from: repository, inFolder: normalizedPath)
            )
        case .certificate:
            return try encodeContainer(
                itemType: .certificate,
                items: certificateItems(from: repository, inFolder: normalizedPath)
            )
        case .secureNote:
            return try encodeContainer(
                itemType: .secureNote,
                items: noteItems(from: repository, inFolder: normalizedPath)
            )
        case .sshKey:
            return try encodeContainer(
                itemType: .sshKey,
                items: sshKeyItems(from: repository, inFolder: normalizedPath)
            )
        case nil:
            return try encodeAllContainer(
                passwords: passwordItems(from: repository, inFolder: normalizedPath),
                apiKeys: apiKeyItems(from: repository, inFolder: normalizedPath),
                certificates: certificateItems(from: repository, inFolder: normalizedPath),
                notes: noteItems(from: repository, inFolder: normalizedPath),
                sshKeys: sshKeyItems(from: repository, inFolder: normalizedPath)
            )
        }
    }

    // MARK: - Import All

    public func importAllItems(
        from data: Data,
        into repository: VaultRepository,
        conflictPolicy: VaultImportConflictPolicy = .keepExisting
    ) async throws -> Int {
        try repository.load()

        let container = try decodeAllContainer(from: data)
        var total = 0
        total += try importPasswords(container.passwords, conflictPolicy: conflictPolicy, into: repository)
        total += try importAPIKeys(container.apiKeys, conflictPolicy: conflictPolicy, into: repository)
        total += try importCertificates(container.certificates, conflictPolicy: conflictPolicy, into: repository)
        total += try importNotes(container.secureNotes, conflictPolicy: conflictPolicy, into: repository)
        total += try importSSHKeys(container.sshKeys, conflictPolicy: conflictPolicy, into: repository)
        return total
    }

    // MARK: - Import

    public func detectImportPayloadKind(from data: Data) throws -> VaultImportPayloadKind {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let header: VaultExportKindHeader
        do {
            header = try decoder.decode(VaultExportKindHeader.self, from: data)
        } catch {
            throw VaultImportExportError.invalidJSON
        }

        guard header.version == Self.supportedVersion else {
            throw VaultImportExportError.unsupportedVersion(header.version)
        }

        switch header.format {
        case Self.allFormat:
            return .all
        case Self.format:
            guard let itemType = header.itemType else {
                throw VaultImportExportError.invalidJSON
            }
            return .item(itemType)
        default:
            throw VaultImportExportError.unsupportedFormat
        }
    }

    public func importItems(
        from data: Data,
        into repository: VaultRepository,
        conflictPolicy: VaultImportConflictPolicy = .keepExisting
    ) async throws -> Int {
        switch try detectImportPayloadKind(from: data) {
        case .all:
            return try await importAllItems(from: data, into: repository, conflictPolicy: conflictPolicy)
        case .item(let itemType):
            return try await importItems(
                of: itemType,
                from: data,
                into: repository,
                conflictPolicy: conflictPolicy
            )
        }
    }

    public func importItems(
        of itemType: VaultItemType,
        from data: Data,
        into repository: VaultRepository,
        conflictPolicy: VaultImportConflictPolicy = .keepExisting
    ) async throws -> Int {
        try repository.load()

        switch itemType {
        case .password:
            let items: [PasswordItem] = try decodeContainer(itemType: itemType, data: data)
            return try importPasswords(items, conflictPolicy: conflictPolicy, into: repository)
        case .apiKey:
            let items: [APIKeyItem] = try decodeContainer(itemType: itemType, data: data)
            return try importAPIKeys(items, conflictPolicy: conflictPolicy, into: repository)
        case .certificate:
            let items: [CertificateItem] = try decodeContainer(itemType: itemType, data: data)
            return try importCertificates(items, conflictPolicy: conflictPolicy, into: repository)
        case .secureNote:
            let items: [SecureNoteItem] = try decodeContainer(itemType: itemType, data: data)
            return try importNotes(items, conflictPolicy: conflictPolicy, into: repository)
        case .sshKey:
            let items: [SSHKeyItem] = try decodeContainer(itemType: itemType, data: data)
            return try importSSHKeys(items, conflictPolicy: conflictPolicy, into: repository)
        }
    }

    public func previewImportItems(
        from data: Data,
        into repository: VaultRepository
    ) async throws -> VaultImportPreview {
        switch try detectImportPayloadKind(from: data) {
        case .all:
            return try await previewImportAllItems(from: data, into: repository)
        case .item(let itemType):
            return try await previewImportItems(of: itemType, from: data, into: repository)
        }
    }

    public func previewImportItems(
        of itemType: VaultItemType,
        from data: Data,
        into repository: VaultRepository
    ) async throws -> VaultImportPreview {
        try repository.load()

        switch itemType {
        case .password:
            let items: [PasswordItem] = try decodeContainer(itemType: itemType, data: data)
            return makePreview(items: items, existingIDs: livePasswordIDs(in: repository))
        case .apiKey:
            let items: [APIKeyItem] = try decodeContainer(itemType: itemType, data: data)
            return makePreview(items: items, existingIDs: liveAPIKeyIDs(in: repository))
        case .certificate:
            let items: [CertificateItem] = try decodeContainer(itemType: itemType, data: data)
            return makePreview(items: items, existingIDs: liveCertificateIDs(in: repository))
        case .secureNote:
            let items: [SecureNoteItem] = try decodeContainer(itemType: itemType, data: data)
            return makePreview(items: items, existingIDs: liveNoteIDs(in: repository))
        case .sshKey:
            let items: [SSHKeyItem] = try decodeContainer(itemType: itemType, data: data)
            return makePreview(items: items, existingIDs: liveSSHKeyIDs(in: repository))
        }
    }

    private func previewImportAllItems(
        from data: Data,
        into repository: VaultRepository
    ) async throws -> VaultImportPreview {
        try repository.load()

        let container = try decodeAllContainer(from: data)
        let previews = [
            makePreview(items: container.passwords, existingIDs: livePasswordIDs(in: repository)),
            makePreview(items: container.apiKeys, existingIDs: liveAPIKeyIDs(in: repository)),
            makePreview(items: container.certificates, existingIDs: liveCertificateIDs(in: repository)),
            makePreview(items: container.secureNotes, existingIDs: liveNoteIDs(in: repository)),
            makePreview(items: container.sshKeys, existingIDs: liveSSHKeyIDs(in: repository)),
        ]

        return VaultImportPreview(
            totalItems: previews.reduce(0) { $0 + $1.totalItems },
            duplicateCount: previews.reduce(0) { $0 + $1.duplicateCount }
        )
    }

    // MARK: - File I/O

    public func exportToFile(
        url: URL,
        itemType: VaultItemType,
        from repository: VaultRepository
    ) async throws {
        let data = try await exportItems(of: itemType, from: repository)

        let didStartAccessing = url.startAccessingSecurityScopedResource()
        defer {
            if didStartAccessing {
                url.stopAccessingSecurityScopedResource()
            }
        }

        do {
            try data.write(to: url, options: .atomic)
            CoreLogger.shared.info("Exported \(itemType.rawValue) items to \(url.path)")
        } catch {
            throw VaultImportExportError.fileWriteError(error)
        }
    }

    public func importFromFile(
        url: URL,
        itemType: VaultItemType,
        into repository: VaultRepository,
        conflictPolicy: VaultImportConflictPolicy = .keepExisting
    ) async throws -> Int {
        let didStartAccessing = url.startAccessingSecurityScopedResource()
        defer {
            if didStartAccessing {
                url.stopAccessingSecurityScopedResource()
            }
        }

        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw VaultImportExportError.fileReadError(error)
        }

        CoreLogger.shared.info("Importing \(itemType.rawValue) items from \(url.path)")
        return try await importItems(of: itemType, from: data, into: repository, conflictPolicy: conflictPolicy)
    }

    public func previewImportFromFile(
        url: URL,
        itemType: VaultItemType,
        into repository: VaultRepository
    ) async throws -> VaultImportPreview {
        let didStartAccessing = url.startAccessingSecurityScopedResource()
        defer {
            if didStartAccessing {
                url.stopAccessingSecurityScopedResource()
            }
        }

        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw VaultImportExportError.fileReadError(error)
        }

        return try await previewImportItems(of: itemType, from: data, into: repository)
    }

    // MARK: - Helpers

    private func importPasswords(
        _ items: [PasswordItem],
        conflictPolicy: VaultImportConflictPolicy,
        into repository: VaultRepository
    ) throws -> Int {
        var importedCount = 0
        var existingByID = Dictionary(uniqueKeysWithValues: repository.passwords.map { ($0.id, $0) })
        var liveExistingIDs = livePasswordIDs(in: repository)

        for item in items {
            if existingByID[item.id] != nil {
                guard conflictPolicy == .overwriteExisting || !liveExistingIDs.contains(item.id) else {
                    continue
                }

                do {
                    var replacement = item
                    replacement.modifiedAt = overwriteModifiedAt(after: existingByID[item.id]?.modifiedAt)
                    try repository.updatePassword(replacement)
                    existingByID[item.id] = PasswordMetadata(from: replacement)
                    liveExistingIDs.insert(item.id)
                    importedCount += 1
                } catch {
                    CoreLogger.shared.error("Failed to overwrite password item \(item.id): \(error)")
                    throw VaultImportExportError.itemSaveFailed(itemType: .password, underlying: error)
                }
                continue
            }

            do {
                try repository.addPassword(item)
                existingByID[item.id] = PasswordMetadata(from: item)
                liveExistingIDs.insert(item.id)
                importedCount += 1
            } catch {
                CoreLogger.shared.error("Failed to import password item \(item.id): \(error)")
                throw VaultImportExportError.itemSaveFailed(itemType: .password, underlying: error)
            }
        }
        return importedCount
    }

    private func importCertificates(
        _ items: [CertificateItem],
        conflictPolicy: VaultImportConflictPolicy,
        into repository: VaultRepository
    ) throws -> Int {
        var importedCount = 0
        var existingByID = Dictionary(uniqueKeysWithValues: repository.certificates.map { ($0.id, $0) })
        var liveExistingIDs = liveCertificateIDs(in: repository)

        for item in items {
            if existingByID[item.id] != nil {
                guard conflictPolicy == .overwriteExisting || !liveExistingIDs.contains(item.id) else {
                    continue
                }

                do {
                    var replacement = item
                    replacement.modifiedAt = overwriteModifiedAt(after: existingByID[item.id]?.modifiedAt)
                    try repository.updateCertificate(replacement)
                    existingByID[item.id] = CertificateMetadata(from: replacement)
                    liveExistingIDs.insert(item.id)
                    importedCount += 1
                } catch {
                    CoreLogger.shared.error("Failed to overwrite certificate item \(item.id): \(error)")
                    throw VaultImportExportError.itemSaveFailed(itemType: .certificate, underlying: error)
                }
                continue
            }

            do {
                try repository.addCertificate(item)
                existingByID[item.id] = CertificateMetadata(from: item)
                liveExistingIDs.insert(item.id)
                importedCount += 1
            } catch {
                CoreLogger.shared.error("Failed to import certificate item \(item.id): \(error)")
                throw VaultImportExportError.itemSaveFailed(itemType: .certificate, underlying: error)
            }
        }
        return importedCount
    }

    private func importAPIKeys(
        _ items: [APIKeyItem],
        conflictPolicy: VaultImportConflictPolicy,
        into repository: VaultRepository
    ) throws -> Int {
        var importedCount = 0
        var existingByID = Dictionary(uniqueKeysWithValues: repository.apiKeys.map { ($0.id, $0) })
        var liveExistingIDs = liveAPIKeyIDs(in: repository)

        for item in items {
            if existingByID[item.id] != nil {
                guard conflictPolicy == .overwriteExisting || !liveExistingIDs.contains(item.id) else {
                    continue
                }

                do {
                    var replacement = item
                    replacement.modifiedAt = overwriteModifiedAt(after: existingByID[item.id]?.modifiedAt)
                    try repository.updateAPIKey(replacement)
                    existingByID[item.id] = APIKeyMetadata(from: replacement)
                    liveExistingIDs.insert(item.id)
                    importedCount += 1
                } catch {
                    CoreLogger.shared.error("Failed to overwrite API key item \(item.id): \(error)")
                    throw VaultImportExportError.itemSaveFailed(itemType: .apiKey, underlying: error)
                }
                continue
            }

            do {
                try repository.addAPIKey(item)
                existingByID[item.id] = APIKeyMetadata(from: item)
                liveExistingIDs.insert(item.id)
                importedCount += 1
            } catch {
                CoreLogger.shared.error("Failed to import API key item \(item.id): \(error)")
                throw VaultImportExportError.itemSaveFailed(itemType: .apiKey, underlying: error)
            }
        }
        return importedCount
    }

    private func importNotes(
        _ items: [SecureNoteItem],
        conflictPolicy: VaultImportConflictPolicy,
        into repository: VaultRepository
    ) throws -> Int {
        var importedCount = 0
        var existingByID = Dictionary(uniqueKeysWithValues: repository.notes.map { ($0.id, $0) })
        var liveExistingIDs = liveNoteIDs(in: repository)

        for item in items {
            if existingByID[item.id] != nil {
                guard conflictPolicy == .overwriteExisting || !liveExistingIDs.contains(item.id) else {
                    continue
                }

                do {
                    var replacement = item
                    replacement.modifiedAt = overwriteModifiedAt(after: existingByID[item.id]?.modifiedAt)
                    try repository.updateNote(replacement)
                    existingByID[item.id] = SecureNoteMetadata(from: replacement)
                    liveExistingIDs.insert(item.id)
                    importedCount += 1
                } catch {
                    CoreLogger.shared.error("Failed to overwrite secure note item \(item.id): \(error)")
                    throw VaultImportExportError.itemSaveFailed(itemType: .secureNote, underlying: error)
                }
                continue
            }

            do {
                try repository.addNote(item)
                existingByID[item.id] = SecureNoteMetadata(from: item)
                liveExistingIDs.insert(item.id)
                importedCount += 1
            } catch {
                CoreLogger.shared.error("Failed to import secure note item \(item.id): \(error)")
                throw VaultImportExportError.itemSaveFailed(itemType: .secureNote, underlying: error)
            }
        }
        return importedCount
    }

    private func importSSHKeys(
        _ items: [SSHKeyItem],
        conflictPolicy: VaultImportConflictPolicy,
        into repository: VaultRepository
    ) throws -> Int {
        var importedCount = 0
        var existingByID = Dictionary(uniqueKeysWithValues: repository.sshKeys.map { ($0.id, $0) })
        var liveExistingIDs = liveSSHKeyIDs(in: repository)

        for item in items {
            if existingByID[item.id] != nil {
                guard conflictPolicy == .overwriteExisting || !liveExistingIDs.contains(item.id) else {
                    continue
                }

                do {
                    var replacement = item
                    replacement.modifiedAt = overwriteModifiedAt(after: existingByID[item.id]?.modifiedAt)
                    try repository.updateSSHKey(replacement)
                    existingByID[item.id] = SSHKeyMetadata(from: replacement)
                    liveExistingIDs.insert(item.id)
                    importedCount += 1
                } catch {
                    CoreLogger.shared.error("Failed to overwrite SSH key item \(item.id): \(error)")
                    throw VaultImportExportError.itemSaveFailed(itemType: .sshKey, underlying: error)
                }
                continue
            }

            do {
                try repository.addSSHKey(item)
                existingByID[item.id] = SSHKeyMetadata(from: item)
                liveExistingIDs.insert(item.id)
                importedCount += 1
            } catch {
                CoreLogger.shared.error("Failed to import SSH key item \(item.id): \(error)")
                throw VaultImportExportError.itemSaveFailed(itemType: .sshKey, underlying: error)
            }
        }
        return importedCount
    }

    private func overwriteModifiedAt(after existing: Date?) -> Date {
        let now = Date()
        guard let existing, existing >= now else { return now }
        return existing.addingTimeInterval(0.001)
    }

    private func livePasswordIDs(in repository: VaultRepository) -> Set<UUID> {
        Set(repository.passwords.filter { repository.passwordSecretExistence($0) != .missing }.map(\.id))
    }

    private func liveAPIKeyIDs(in repository: VaultRepository) -> Set<UUID> {
        Set(repository.apiKeys.filter { repository.apiKeySecretExistence($0) != .missing }.map(\.id))
    }

    private func liveCertificateIDs(in repository: VaultRepository) -> Set<UUID> {
        Set(repository.certificates.filter { repository.certificateSecretExistence($0) != .missing }.map(\.id))
    }

    private func liveNoteIDs(in repository: VaultRepository) -> Set<UUID> {
        Set(repository.notes.filter { repository.noteSecretExistence($0) != .missing }.map(\.id))
    }

    private func liveSSHKeyIDs(in repository: VaultRepository) -> Set<UUID> {
        Set(repository.sshKeys.filter { repository.sshKeySecretExistence($0) != .missing }.map(\.id))
    }

    private func makePreview<Item: Identifiable>(
        items: [Item],
        existingIDs: Set<UUID>
    ) -> VaultImportPreview where Item.ID == UUID {
        let duplicateCount = items.reduce(into: 0) { count, item in
            if existingIDs.contains(item.id) {
                count += 1
            }
        }
        return VaultImportPreview(totalItems: items.count, duplicateCount: duplicateCount)
    }

    private func passwordItems(from repository: VaultRepository, inFolder folderPath: String? = nil) -> [PasswordItem] {
        var items: [PasswordItem] = []
        for metadata in repository.passwords where isPath(metadata.folderPath, withinFolder: folderPath) {
            do {
                items.append(try repository.getFullPassword(metadata: metadata))
            } catch {
                CoreLogger.shared.error("Failed to export password item \(metadata.id): \(error)")
            }
        }
        return items
    }

    private func apiKeyItems(from repository: VaultRepository, inFolder folderPath: String? = nil) -> [APIKeyItem] {
        var items: [APIKeyItem] = []
        for metadata in repository.apiKeys where isPath(metadata.folderPath, withinFolder: folderPath) {
            do {
                items.append(try repository.getFullAPIKey(metadata: metadata))
            } catch {
                CoreLogger.shared.error("Failed to export API key item \(metadata.id): \(error)")
            }
        }
        return items
    }

    private func certificateItems(from repository: VaultRepository, inFolder folderPath: String? = nil) -> [CertificateItem] {
        var items: [CertificateItem] = []
        for metadata in repository.certificates where isPath(metadata.folderPath, withinFolder: folderPath) {
            do {
                items.append(try repository.getFullCertificate(metadata: metadata))
            } catch {
                CoreLogger.shared.error("Failed to export certificate item \(metadata.id): \(error)")
            }
        }
        return items
    }

    private func noteItems(from repository: VaultRepository, inFolder folderPath: String? = nil) -> [SecureNoteItem] {
        var items: [SecureNoteItem] = []
        for metadata in repository.notes where isPath(metadata.folderPath, withinFolder: folderPath) {
            do {
                items.append(try repository.getFullNote(metadata: metadata))
            } catch {
                CoreLogger.shared.error("Failed to export secure note item \(metadata.id): \(error)")
            }
        }
        return items
    }

    private func sshKeyItems(from repository: VaultRepository, inFolder folderPath: String? = nil) -> [SSHKeyItem] {
        var items: [SSHKeyItem] = []
        for metadata in repository.sshKeys where isPath(metadata.folderPath, withinFolder: folderPath) {
            do {
                items.append(try repository.getFullSSHKey(metadata: metadata))
            } catch {
                CoreLogger.shared.error("Failed to export SSH key item \(metadata.id): \(error)")
            }
        }
        return items
    }

    private func isPath(_ candidate: String?, withinFolder folderPath: String?) -> Bool {
        guard let folderPath else { return true }
        guard let candidate = normalizedFolderPath(candidate) else { return false }
        return candidate == folderPath || candidate.hasPrefix(folderPath + "/")
    }

    private func normalizedFolderPath(_ folderPath: String?) -> String? {
        let segments = (folderPath ?? "")
            .split(separator: "/")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard !segments.isEmpty else { return nil }
        return segments.joined(separator: "/")
    }

    private func encodeAllContainer(
        passwords: [PasswordItem],
        apiKeys: [APIKeyItem],
        certificates: [CertificateItem],
        notes: [SecureNoteItem],
        sshKeys: [SSHKeyItem]
    ) throws -> Data {
        let container = VaultExportAllContainer(
            format: Self.allFormat,
            version: Self.supportedVersion,
            exportedAt: Date(),
            passwords: passwords,
            apiKeys: apiKeys,
            certificates: certificates,
            secureNotes: notes,
            sshKeys: sshKeys
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        do {
            return try encoder.encode(container)
        } catch {
            throw VaultImportExportError.invalidJSON
        }
    }

    private func encodeContainer<Item: Codable>(itemType: VaultItemType, items: [Item]) throws -> Data {
        let container = VaultExportContainer(
            format: Self.format,
            version: Self.supportedVersion,
            itemType: itemType,
            exportedAt: Date(),
            items: items
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        do {
            return try encoder.encode(container)
        } catch {
            throw VaultImportExportError.invalidJSON
        }
    }

    private func decodeContainer<Item: Codable>(itemType: VaultItemType, data: Data) throws -> [Item] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let header: VaultExportHeader
        do {
            header = try decoder.decode(VaultExportHeader.self, from: data)
        } catch {
            throw VaultImportExportError.invalidJSON
        }

        guard header.format == Self.format else {
            throw VaultImportExportError.unsupportedFormat
        }
        guard header.version == Self.supportedVersion else {
            throw VaultImportExportError.unsupportedVersion(header.version)
        }
        guard header.itemType == itemType else {
            throw VaultImportExportError.typeMismatch(expected: itemType, actual: header.itemType)
        }

        do {
            let container = try decoder.decode(VaultExportContainer<Item>.self, from: data)
            return container.items
        } catch {
            throw VaultImportExportError.invalidJSON
        }
    }

    private func decodeAllContainer(from data: Data) throws -> VaultExportAllContainer {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let container: VaultExportAllContainer
        do {
            container = try decoder.decode(VaultExportAllContainer.self, from: data)
        } catch {
            throw VaultImportExportError.invalidJSON
        }

        guard container.format == Self.allFormat else {
            throw VaultImportExportError.unsupportedFormat
        }
        guard container.version == Self.supportedVersion else {
            throw VaultImportExportError.unsupportedVersion(container.version)
        }
        return container
    }
}

private struct VaultExportKindHeader: Codable {
    let format: String
    let version: Int
    let itemType: VaultItemType?
}

private struct VaultExportHeader: Codable {
    let format: String
    let version: Int
    let itemType: VaultItemType
}

private struct VaultExportAllContainer: Codable {
    let format: String
    let version: Int
    let exportedAt: Date
    let passwords: [PasswordItem]
    let apiKeys: [APIKeyItem]
    let certificates: [CertificateItem]
    let secureNotes: [SecureNoteItem]
    let sshKeys: [SSHKeyItem]

    private enum CodingKeys: String, CodingKey {
        case format
        case version
        case exportedAt
        case passwords
        case apiKeys
        case certificates
        case secureNotes
        case sshKeys
    }

    init(
        format: String,
        version: Int,
        exportedAt: Date,
        passwords: [PasswordItem],
        apiKeys: [APIKeyItem],
        certificates: [CertificateItem],
        secureNotes: [SecureNoteItem],
        sshKeys: [SSHKeyItem]
    ) {
        self.format = format
        self.version = version
        self.exportedAt = exportedAt
        self.passwords = passwords
        self.apiKeys = apiKeys
        self.certificates = certificates
        self.secureNotes = secureNotes
        self.sshKeys = sshKeys
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        format = try container.decode(String.self, forKey: .format)
        version = try container.decode(Int.self, forKey: .version)
        exportedAt = try container.decode(Date.self, forKey: .exportedAt)
        passwords = try container.decode([PasswordItem].self, forKey: .passwords)
        apiKeys = try container.decodeIfPresent([APIKeyItem].self, forKey: .apiKeys) ?? []
        certificates = try container.decode([CertificateItem].self, forKey: .certificates)
        secureNotes = try container.decode([SecureNoteItem].self, forKey: .secureNotes)
        sshKeys = try container.decode([SSHKeyItem].self, forKey: .sshKeys)
    }
}

private struct VaultExportContainer<Item: Codable>: Codable {
    let format: String
    let version: Int
    let itemType: VaultItemType
    let exportedAt: Date
    let items: [Item]
}

public enum VaultImportExportError: Error, LocalizedError {
    case invalidJSON
    case invalidFolderPath
    case unsupportedFormat
    case unsupportedVersion(Int)
    case typeMismatch(expected: VaultItemType, actual: VaultItemType)
    case fileReadError(Error)
    case fileWriteError(Error)
    case itemSaveFailed(itemType: VaultItemType, underlying: Error)

    public var errorDescription: String? {
        switch self {
        case .invalidJSON:
            return "Invalid JSON format"
        case .invalidFolderPath:
            return "Invalid folder path"
        case .unsupportedFormat:
            return "Unsupported vault export format"
        case .unsupportedVersion(let version):
            return "Unsupported vault export version: \(version)"
        case .typeMismatch(let expected, let actual):
            return "Selected type \(expected.displayName) does not match file type \(actual.displayName)"
        case .fileReadError(let error):
            return "Failed to read file: \(error.localizedDescription)"
        case .fileWriteError(let error):
            return "Failed to write file: \(error.localizedDescription)"
        case .itemSaveFailed(let itemType, let underlying):
            return "Failed to save imported \(itemType.displayName) item to Keychain: "
                + String(describing: underlying)
        }
    }
}
