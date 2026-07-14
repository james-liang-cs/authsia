import Foundation

public protocol LegacyMetadataMigrationKeychain {
    func load(key: String) throws -> Data?
    func save(data: Data, key: String) throws
}

public enum LegacyMetadataMigrationOutcome: Equatable {
    case migrated
    case alreadyMigrated
    case nothingToDo
}

public struct LegacyMetadataMigrationJob {
    public let fileURL: URL
    public let keychainKey: String
    public let keychain: any LegacyMetadataMigrationKeychain

    public init(
        fileURL: URL,
        keychainKey: String,
        keychain: any LegacyMetadataMigrationKeychain
    ) {
        self.fileURL = fileURL
        self.keychainKey = keychainKey
        self.keychain = keychain
    }
}

public struct LegacyMetadataMigrationReport {
    public let fileURL: URL
    public let keychainKey: String
    public let outcome: LegacyMetadataMigrationOutcome?
    public let errorDescription: String?
}

public struct MetadataKeychainAdapter: LegacyMetadataMigrationKeychain {
    private let store: KeychainStore

    public init(store: KeychainStore = .shared) {
        self.store = store
    }

    public func load(key: String) throws -> Data? {
        do {
            return try store.retrieve(for: key)
        } catch KeychainError.itemNotFound {
            return nil
        }
    }

    public func save(data: Data, key: String) throws {
        try store.save(data: data, for: key)
    }
}

public struct VaultMetadataKeychainAdapter: LegacyMetadataMigrationKeychain {
    private let store: any VaultMetadataKeychainStoring

    public init() {
        self.store = SecurityVaultMetadataKeychainStore()
    }

    init(store: any VaultMetadataKeychainStoring) {
        self.store = store
    }

    public func load(key: String) throws -> Data? {
        try store.load(key: key)
    }

    public func save(data: Data, key: String) throws {
        try store.save(data: data, key: key)
    }
}

public enum LegacyMetadataMigration {
    public static func runDefaultLocations() -> [LegacyMetadataMigrationReport] {
        run(jobs: defaultJobs())
    }

    public static func defaultJobs(
        documentsDirectory: URL? = nil,
        includeLegacySandboxDirectories: Bool = true
    ) -> [LegacyMetadataMigrationJob] {
        let metadataKeychain = MetadataKeychainAdapter()
        let vaultKeychain = VaultMetadataKeychainAdapter()
        let specs: [(fileName: String, keychainKey: String, keychain: any LegacyMetadataMigrationKeychain)] = [
            ("accounts_metadata.json", "account_metadata", metadataKeychain),
            ("accounts_folders.json", "account_folders", metadataKeychain),
            ("vault_passwords_metadata.json", "vault_passwords_metadata", vaultKeychain),
            ("vault_certificates_metadata.json", "vault_certificates_metadata", vaultKeychain),
            ("vault_notes_metadata.json", "vault_notes_metadata", vaultKeychain),
            ("vault_sshkeys_metadata.json", "vault_sshkeys_metadata", vaultKeychain),
            ("vault_folders.json", "vault_folders", vaultKeychain),
        ]
        let primaryDocuments = documentsDirectory ?? defaultDocumentsDirectory()

        return specs.flatMap { spec in
            migrationFileURLs(
                named: spec.fileName,
                documentsDirectory: primaryDocuments,
                includeLegacySandboxDirectories: includeLegacySandboxDirectories
            ).map {
                LegacyMetadataMigrationJob(
                    fileURL: $0,
                    keychainKey: spec.keychainKey,
                    keychain: spec.keychain
                )
            }
        }
    }

    public static func run(jobs: [LegacyMetadataMigrationJob]) -> [LegacyMetadataMigrationReport] {
        jobs.map { job in
            do {
                let outcome = try run(
                    fileURL: job.fileURL,
                    keychainKey: job.keychainKey,
                    keychain: job.keychain
                )
                return LegacyMetadataMigrationReport(
                    fileURL: job.fileURL,
                    keychainKey: job.keychainKey,
                    outcome: outcome,
                    errorDescription: nil
                )
            } catch {
                return LegacyMetadataMigrationReport(
                    fileURL: job.fileURL,
                    keychainKey: job.keychainKey,
                    outcome: nil,
                    errorDescription: error.localizedDescription
                )
            }
        }
    }

    @discardableResult
    public static func run(
        fileURL: URL,
        keychainKey: String,
        keychain: LegacyMetadataMigrationKeychain
    ) throws -> LegacyMetadataMigrationOutcome {
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return .nothingToDo
        }

        let keychainData = try keychain.load(key: keychainKey)
        if isMeaningfulJSONPayload(keychainData) {
            try FileManager.default.removeItem(at: fileURL)
            return .alreadyMigrated
        }

        let fileData = try Data(contentsOf: fileURL)
        guard isMeaningfulJSONPayload(fileData) else {
            try FileManager.default.removeItem(at: fileURL)
            return .nothingToDo
        }

        try keychain.save(data: fileData, key: keychainKey)
        try FileManager.default.removeItem(at: fileURL)
        return .migrated
    }

    private static func defaultDocumentsDirectory() -> URL? {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
    }

    private static func migrationFileURLs(
        named fileName: String,
        documentsDirectory: URL?,
        includeLegacySandboxDirectories: Bool
    ) -> [URL] {
        var urls = documentsDirectory.map { [$0.appendingPathComponent(fileName)] } ?? []
        if includeLegacySandboxDirectories {
            urls.append(contentsOf: legacySandboxFileURLs(named: fileName))
        }
        return urls
    }

    private static func legacySandboxFileURLs(named fileName: String) -> [URL] {
        #if os(macOS)
        let containerIDs = [
            "app.authsia",
            "Authsia",
            "Notesia.Authenticator",
        ]
        let containersURL = FileManager.default
            .homeDirectoryForCurrentUser
            .appendingPathComponent("Library")
            .appendingPathComponent("Containers")

        return containerIDs.map {
            containersURL
                .appendingPathComponent($0)
                .appendingPathComponent("Data")
                .appendingPathComponent("Documents")
                .appendingPathComponent(fileName)
        }
        #else
        return []
        #endif
    }

    private static func isMeaningfulJSONPayload(_ data: Data?) -> Bool {
        guard let data else { return false }
        let trimmedData = data.trimmingASCIIWhitespace()
        guard !trimmedData.isEmpty else { return false }

        guard let value = try? JSONSerialization.jsonObject(with: trimmedData) else {
            return true
        }
        if let array = value as? [Any] {
            return !array.isEmpty
        }
        if let dictionary = value as? [String: Any] {
            return !dictionary.isEmpty
        }
        return true
    }
}

private extension Data {
    func trimmingASCIIWhitespace() -> Data {
        let whitespace = Set<UInt8>([9, 10, 11, 12, 13, 32])
        let bytes = Array(self)
        guard let start = bytes.firstIndex(where: { !whitespace.contains($0) }) else {
            return Data()
        }
        let end = bytes.lastIndex(where: { !whitespace.contains($0) })!
        return Data(bytes[start...end])
    }
}
