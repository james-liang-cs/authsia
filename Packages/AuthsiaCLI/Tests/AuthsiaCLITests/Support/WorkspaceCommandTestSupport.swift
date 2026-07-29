import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
@testable import authsia

func makeResetRootWithManagedEnvFile() throws -> URL {
    let root = try makeWorkspaceRoot()
    let config = WorkspaceConfig(
        workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
        managedEnvFiles: [".env"],
        agents: nil
    )
    try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
    try "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi\n".write(
        to: root.appendingPathComponent(".env"),
        atomically: true,
        encoding: .utf8
    )
    return root
}

final class RecordingWorkspaceSetupVaultClient: WorkspaceSetupVaultClient {
    private let ensureError: Error?
    private let exposeAddedPasswords: Bool
    private(set) var ensuredFolders: [String] = []
    private(set) var addedPasswords: [String] = []
    private(set) var addedPasswordFolders: [String?] = []
    private(set) var addedAPIKeys: [String] = []
    private(set) var addedAPIKeyFolders: [String?] = []
    private(set) var addedCertificates: [String] = []
    private(set) var addedNotes: [String] = []

    init(ensureError: Error? = nil, exposeAddedPasswords: Bool = true) {
        self.ensureError = ensureError
        self.exposeAddedPasswords = exposeAddedPasswords
    }

    func ensureVaultFolder(path: String) throws -> WriteResult {
        ensuredFolders.append(path)
        if let ensureError {
            throw ensureError
        }
        return WriteResult(id: path, message: "folder ensured")
    }

    func existingPasswordID(named name: String, folderPath: String?) throws -> String? {
        guard exposeAddedPasswords else { return nil }
        return zip(addedPasswords, addedPasswordFolders)
            .first { addedName, addedFolder in
                addedName == name && Self.sameFolder(addedFolder, folderPath)
            }?
            .0
    }
    func existingAPIKeyID(named name: String, folderPath: String?) throws -> String? {
        guard exposeAddedPasswords else { return nil }
        return zip(addedAPIKeys, addedAPIKeyFolders)
            .first { addedName, addedFolder in
                addedName == name && Self.sameFolder(addedFolder, folderPath)
            }?
            .0
    }

    func existingCertificateID(named name: String, folderPath: String?) throws -> String? { nil }
    func existingNoteID(title: String, folderPath: String?) throws -> String? { nil }

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
        addedPasswords.append(name)
        addedPasswordFolders.append(folderPath)
        return WriteResult(id: name, message: "password added")
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
        addedAPIKeys.append(name)
        addedAPIKeyFolders.append(folderPath)
        return WriteResult(id: name, message: "api key added")
    }

    private static func sameFolder(_ lhs: String?, _ rhs: String?) -> Bool {
        normalizeFolder(lhs) == normalizeFolder(rhs)
    }

    private static func normalizeFolder(_ folder: String?) -> String? {
        guard let folder else { return nil }
        let segments = folder
            .split(separator: "/")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        return segments.isEmpty ? nil : segments.joined(separator: "/")
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
        WriteResult(id: query, message: "password updated")
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
        WriteResult(id: query, message: "api key updated")
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
        addedCertificates.append(name)
        return WriteResult(id: name, message: "certificate added")
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
        WriteResult(id: query, message: "certificate updated")
    }

    func addNote(
        title: String,
        content: String,
        isScraped: Bool,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?
    ) throws -> WriteResult {
        addedNotes.append(title)
        return WriteResult(id: title, message: "note added")
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
        WriteResult(id: query, message: "note updated")
    }
}

final class WorkspaceResetBackupVaultClient: BackupVaultClient, @unchecked Sendable {
    private var noteContents: [String: String] = [:]
    private var manifestContents: [String: String] = [:]

    func addNote(title: String, content: String, isScraped: Bool, folderPath: String?) throws -> WriteResult {
        if title.hasPrefix("authsia_scrape_backups") {
            manifestContents[title] = content
            return WriteResult(id: title, message: "added")
        }
        let id = "note-\(noteContents.count + 1)"
        noteContents[id] = content
        noteContents[title] = content
        return WriteResult(id: id, message: "added")
    }

    func updateNote(
        query: String,
        title: String?,
        content: String?,
        isScraped: Bool?,
        folderPath: String?
    ) throws -> WriteResult {
        if let content {
            manifestContents[query] = content
        }
        return WriteResult(id: query, message: "updated")
    }

    func getNote(query: String) throws -> NoteResult {
        if let content = manifestContents[query] {
            return noteResult(id: query, title: query, content: content)
        }
        if query.hasPrefix("authsia_scrape_backups") {
            throw BridgeClientError.bridgeError(code: "notFound", message: "not found", query: query)
        }
        if let content = noteContents[query] {
            return noteResult(id: query, title: query, content: content)
        }
        throw BridgeClientError.bridgeError(code: "notFound", message: "not found", query: query)
    }

    func deleteNote(query: String) throws -> WriteResult {
        noteContents.removeValue(forKey: query)
        manifestContents.removeValue(forKey: query)
        return WriteResult(id: query, message: "deleted")
    }

    func list() throws -> BridgeListPayload {
        BridgeListPayload(accounts: [], passwords: [], certificates: [], notes: [], sshKeys: [])
    }

    private func noteResult(id: String, title: String, content: String) -> NoteResult {
        NoteResult(
            id: id,
            title: title,
            content: content,
            createdAt: Date(timeIntervalSince1970: 0),
            modifiedAt: Date(timeIntervalSince1970: 0),
            isFavorite: false
        )
    }
}

final class WorkspaceResetDenyingVaultClient: BackupVaultClient, @unchecked Sendable {
    private let error: BridgeClientError

    init(error: BridgeClientError) {
        self.error = error
    }

    func addNote(title: String, content: String, isScraped: Bool, folderPath: String?) throws -> WriteResult {
        throw error
    }

    func updateNote(
        query: String,
        title: String?,
        content: String?,
        isScraped: Bool?,
        folderPath: String?
    ) throws -> WriteResult {
        throw error
    }

    func getNote(query: String) throws -> NoteResult {
        throw error
    }

    func deleteNote(query: String) throws -> WriteResult {
        throw error
    }

    func list() throws -> BridgeListPayload {
        throw error
    }
}

func makeWorkspaceRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("authsia-workspace-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    return root
}

func read(_ path: String, in root: URL) throws -> String {
    try String(contentsOf: root.appendingPathComponent(path), encoding: .utf8)
}

func writeNestedFile(_ content: String, relativePath: String, in root: URL) throws {
    let url = root.appendingPathComponent(relativePath)
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try content.write(to: url, atomically: true, encoding: .utf8)
}

func workspaceSyncConfig(bindings: [WorkspaceConfig.EnvBinding]) -> WorkspaceConfig {
    WorkspaceConfig(
        workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
        managedEnvFiles: [],
        agents: nil,
        envBindings: bindings
    )
}

func workspaceSyncPayload(passwords: [BridgePassword], apiKeys: [BridgeAPIKey] = []) -> BridgeListPayload {
    BridgeListPayload(
        accounts: [],
        passwords: passwords,
        apiKeys: apiKeys,
        certificates: [],
        notes: [],
        sshKeys: []
    )
}

func apiKey(id: String, name: String, folderPath: String?, hasSecret: Bool? = nil) -> BridgeAPIKey {
    BridgeAPIKey(
        id: UUID(uuidString: id)!,
        name: name,
        website: nil,
        folderPath: folderPath,
        isFavorite: false,
        isCliEnabled: true,
        isScraped: false,
        createdAt: Date(),
        updatedAt: Date(),
        hasSecret: hasSecret
    )
}

func workspaceDetectedSecret(
    key: String,
    confidence: SecretConfidence = .high,
    type: SecretType = .password,
    value: String? = nil,
    filePath: String = "/tmp/project/.env",
    lineNumber: Int = 1
) -> DetectedSecret {
    let value = value ?? "sk_live_\(key.lowercased())abcdefghijklmnopqrstuvwxyz123456"
    return DetectedSecret(
        filePath: filePath,
        lineNumber: lineNumber,
        originalLine: "\(key)=\(value)",
        key: key,
        value: value,
        rawContent: nil,
        confidence: confidence,
        type: type,
        entropy: 5.0,
        description: "test secret",
        sshMetadata: nil
    )
}

func password(
    id: String,
    name: String,
    folderPath: String?,
    hasSecret: Bool? = nil,
    environments: [String] = []
) -> BridgePassword {
    BridgePassword(
        id: UUID(uuidString: id)!,
        name: name,
        username: "u",
        website: nil,
        folderPath: folderPath,
        isFavorite: false,
        isCliEnabled: true,
        isScraped: false,
        createdAt: Date(timeIntervalSince1970: 0),
        updatedAt: Date(timeIntervalSince1970: 0),
        hasSecret: hasSecret,
        environments: environments
    )
}
