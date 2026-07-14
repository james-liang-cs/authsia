import Foundation

protocol ScrapeVaultClient {
    func existingPasswordID(named name: String, folderPath: String?) throws -> String?
    func existingAPIKeyID(named name: String, folderPath: String?) throws -> String?
    func existingCertificateID(named name: String, folderPath: String?) throws -> String?
    func existingNoteID(title: String, folderPath: String?) throws -> String?
    func existingPasswordID(named name: String, folderPath: String?, environments: [String]) throws -> String?
    func existingAPIKeyID(named name: String, folderPath: String?, environments: [String]) throws -> String?
    func existingCertificateID(named name: String, folderPath: String?, environments: [String]) throws -> String?
    func existingNoteID(title: String, folderPath: String?, environments: [String]) throws -> String?

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
    ) throws -> WriteResult
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
    ) throws -> WriteResult

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
    ) throws -> WriteResult
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
    ) throws -> WriteResult

    func addCertificate(
        name: String,
        certificate: String,
        privateKey: String?,
        notes: String?,
        folderPath: String?,
        isScraped: Bool,
        scrapeMachineName: String?,
        scrapeMachineId: String?
    ) throws -> WriteResult
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
    ) throws -> WriteResult

    func addNote(
        title: String,
        content: String,
        isScraped: Bool,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?
    ) throws -> WriteResult
    func updateNote(
        query: String,
        title: String?,
        content: String?,
        isScraped: Bool?,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?
    ) throws -> WriteResult

    func addPassword(name: String, username: String, password: String, website: String?, notes: String?, isScraped: Bool, folderPath: String?, scrapeMachineName: String?, scrapeMachineId: String?, expiresAt: Date?, environments: [String]) throws -> WriteResult
    func updatePassword(query: String, name: String?, username: String?, password: String?, website: String?, notes: String?, isScraped: Bool?, folderPath: String?, scrapeMachineName: String?, scrapeMachineId: String?, expiresAt: Date?, clearExpiresAt: Bool, environments: [String]?) throws -> WriteResult
    func addAPIKey(name: String, key: String, website: String?, notes: String?, isScraped: Bool, folderPath: String?, scrapeMachineName: String?, scrapeMachineId: String?, expiresAt: Date?, environments: [String]) throws -> WriteResult
    func updateAPIKey(query: String, name: String?, key: String?, website: String?, notes: String?, isScraped: Bool?, folderPath: String?, scrapeMachineName: String?, scrapeMachineId: String?, expiresAt: Date?, clearExpiresAt: Bool, environments: [String]?) throws -> WriteResult
    func addCertificate(name: String, certificate: String, privateKey: String?, notes: String?, folderPath: String?, isScraped: Bool, scrapeMachineName: String?, scrapeMachineId: String?, environments: [String]) throws -> WriteResult
    func updateCertificate(query: String, name: String?, certificate: String?, privateKey: String?, clearPrivateKey: Bool, notes: String?, folderPath: String?, isScraped: Bool?, scrapeMachineName: String?, scrapeMachineId: String?, environments: [String]?) throws -> WriteResult
    func addNote(title: String, content: String, isScraped: Bool, folderPath: String?, scrapeMachineName: String?, scrapeMachineId: String?, environments: [String]) throws -> WriteResult
    func updateNote(query: String, title: String?, content: String?, isScraped: Bool?, folderPath: String?, scrapeMachineName: String?, scrapeMachineId: String?, environments: [String]?) throws -> WriteResult
}

extension ScrapeVaultClient {
    func existingPasswordID(named name: String, folderPath: String?, environments: [String]) throws -> String? { try existingPasswordID(named: name, folderPath: folderPath) }
    func existingAPIKeyID(named name: String, folderPath: String?, environments: [String]) throws -> String? { try existingAPIKeyID(named: name, folderPath: folderPath) }
    func existingCertificateID(named name: String, folderPath: String?, environments: [String]) throws -> String? { try existingCertificateID(named: name, folderPath: folderPath) }
    func existingNoteID(title: String, folderPath: String?, environments: [String]) throws -> String? { try existingNoteID(title: title, folderPath: folderPath) }
    func addPassword(name: String, username: String, password: String, website: String?, notes: String?, isScraped: Bool, folderPath: String?, scrapeMachineName: String?, scrapeMachineId: String?, expiresAt: Date?, environments: [String]) throws -> WriteResult { try addPassword(name: name, username: username, password: password, website: website, notes: notes, isScraped: isScraped, folderPath: folderPath, scrapeMachineName: scrapeMachineName, scrapeMachineId: scrapeMachineId, expiresAt: expiresAt) }
    func updatePassword(query: String, name: String?, username: String?, password: String?, website: String?, notes: String?, isScraped: Bool?, folderPath: String?, scrapeMachineName: String?, scrapeMachineId: String?, expiresAt: Date?, clearExpiresAt: Bool, environments: [String]?) throws -> WriteResult { try updatePassword(query: query, name: name, username: username, password: password, website: website, notes: notes, isScraped: isScraped, folderPath: folderPath, scrapeMachineName: scrapeMachineName, scrapeMachineId: scrapeMachineId, expiresAt: expiresAt, clearExpiresAt: clearExpiresAt) }
    func addAPIKey(name: String, key: String, website: String?, notes: String?, isScraped: Bool, folderPath: String?, scrapeMachineName: String?, scrapeMachineId: String?, expiresAt: Date?, environments: [String]) throws -> WriteResult { try addAPIKey(name: name, key: key, website: website, notes: notes, isScraped: isScraped, folderPath: folderPath, scrapeMachineName: scrapeMachineName, scrapeMachineId: scrapeMachineId, expiresAt: expiresAt) }
    func updateAPIKey(query: String, name: String?, key: String?, website: String?, notes: String?, isScraped: Bool?, folderPath: String?, scrapeMachineName: String?, scrapeMachineId: String?, expiresAt: Date?, clearExpiresAt: Bool, environments: [String]?) throws -> WriteResult { try updateAPIKey(query: query, name: name, key: key, website: website, notes: notes, isScraped: isScraped, folderPath: folderPath, scrapeMachineName: scrapeMachineName, scrapeMachineId: scrapeMachineId, expiresAt: expiresAt, clearExpiresAt: clearExpiresAt) }
    func addCertificate(name: String, certificate: String, privateKey: String?, notes: String?, folderPath: String?, isScraped: Bool, scrapeMachineName: String?, scrapeMachineId: String?, environments: [String]) throws -> WriteResult { try addCertificate(name: name, certificate: certificate, privateKey: privateKey, notes: notes, folderPath: folderPath, isScraped: isScraped, scrapeMachineName: scrapeMachineName, scrapeMachineId: scrapeMachineId) }
    func updateCertificate(query: String, name: String?, certificate: String?, privateKey: String?, clearPrivateKey: Bool, notes: String?, folderPath: String?, isScraped: Bool?, scrapeMachineName: String?, scrapeMachineId: String?, environments: [String]?) throws -> WriteResult { try updateCertificate(query: query, name: name, certificate: certificate, privateKey: privateKey, clearPrivateKey: clearPrivateKey, notes: notes, folderPath: folderPath, isScraped: isScraped, scrapeMachineName: scrapeMachineName, scrapeMachineId: scrapeMachineId) }
    func addNote(title: String, content: String, isScraped: Bool, folderPath: String?, scrapeMachineName: String?, scrapeMachineId: String?, environments: [String]) throws -> WriteResult { try addNote(title: title, content: content, isScraped: isScraped, folderPath: folderPath, scrapeMachineName: scrapeMachineName, scrapeMachineId: scrapeMachineId) }
    func updateNote(query: String, title: String?, content: String?, isScraped: Bool?, folderPath: String?, scrapeMachineName: String?, scrapeMachineId: String?, environments: [String]?) throws -> WriteResult { try updateNote(query: query, title: title, content: content, isScraped: isScraped, folderPath: folderPath, scrapeMachineName: scrapeMachineName, scrapeMachineId: scrapeMachineId) }
}

enum ScrapeMigrationError: LocalizedError {
    case missingContent

    var errorDescription: String? {
        switch self {
        case .missingContent:
            return "Missing secret content for migration."
        }
    }
}

struct ScrapeMigrationSummary {
    let addedCount: Int
    let skippedCount: Int
    let failed: [(DetectedSecret, Error)]
    let results: [ScrapeMigrationResult]
    var referenceBySecretID: [UUID: String] = [:]
}

struct ScrapeMigrationResult: Equatable {
    let secret: DetectedSecret
    let outcome: ScrapeMigrationOutcome
}

enum ScrapeMigrationOutcome: Equatable {
    case added
    case updated
    case reused
    case skipped
}

struct ScrapeMigrator {
    private struct CertificateCoalescingKey: Hashable {
        let authsiaKey: String
        let sourceStem: String
    }

    enum ConflictMode {
        case skip
        case overwrite
        case reuse
        case prompt((DetectedSecret) -> Bool)
        case choose((DetectedSecret) -> ConflictDecision)
    }

    enum ConflictDecision {
        case skip
        case overwrite
        case reuse
    }

    let client: ScrapeVaultClient
    let conflictMode: ConflictMode
    let folderPath: String?
    let machineName: String
    let machineId: String
    var environmentTagsBySecretID: [UUID: [String]] = [:]

    nonisolated(unsafe) private static let iso8601Formatter = ISO8601DateFormatter()

    init(
        client: ScrapeVaultClient,
        conflictMode: ConflictMode,
        folderPath: String? = nil,
        machineName: String = MachineIdentity.load().displayName,
        machineId: String = MachineIdentity.load().machineId,
        environmentTagsBySecretID: [UUID: [String]] = [:]
    ) {
        self.client = client
        self.conflictMode = conflictMode
        self.folderPath = folderPath
        self.machineName = machineName
        self.machineId = machineId
        self.environmentTagsBySecretID = environmentTagsBySecretID
    }

    /// Builds a human-readable provenance note to store alongside a scraped secret.
    static func provenanceNote(filePath: String, lineNumber: Int, machineName: String, date: String) -> String {
        "Scraped by authsia\nMachine: \(machineName)  |  File: \(filePath)  |  Line: \(lineNumber)\nDate: \(date)"
    }

    func migrate(_ secrets: [DetectedSecret]) throws -> ScrapeMigrationSummary {
        var addedCount = 0
        var skippedCount = 0
        var failed: [(DetectedSecret, Error)] = []
        var results: [ScrapeMigrationResult] = []
        var referenceBySecretID: [UUID: String] = [:]
        let migrationSecrets = Self.coalescedCertificateSecrets(secrets)

        for secret in migrationSecrets {
            do {
                let (outcome, itemID) = try migrateSecret(secret)
                switch outcome {
                case .added, .updated:
                    addedCount += 1
                case .reused:
                    break
                case .skipped:
                    skippedCount += 1
                }
                results.append(ScrapeMigrationResult(secret: secret, outcome: outcome))
                if let itemID {
                    referenceBySecretID[secret.id] = secret.secretReferenceURI(itemQuery: itemID, folderPath: folderPath)
                }
            } catch {
                failed.append((secret, error))
            }
        }

        return ScrapeMigrationSummary(
            addedCount: addedCount,
            skippedCount: skippedCount,
            failed: failed,
            results: results,
            referenceBySecretID: referenceBySecretID
        )
    }

    private static func coalescedCertificateSecrets(_ secrets: [DetectedSecret]) -> [DetectedSecret] {
        var output: [DetectedSecret] = []
        var coalescedKeys = Set<CertificateCoalescingKey>()

        for secret in secrets {
            guard let groupKey = certificateCoalescingKey(for: secret) else {
                output.append(secret)
                continue
            }

            let matching = secrets.filter {
                certificateCoalescingKey(for: $0) == groupKey
            }
            if shouldCoalesceCertificateSecrets(matching) {
                guard coalescedKeys.insert(groupKey).inserted else {
                    continue
                }
                output.append(combinedCertificateSecret(from: matching))
            } else {
                output.append(secret)
            }
        }

        return output
    }

    private static func certificateCoalescingKey(for secret: DetectedSecret) -> CertificateCoalescingKey? {
        guard secret.type == .certificate,
              secret.resolvedCertificateContent != nil else {
            return nil
        }
        return CertificateCoalescingKey(
            authsiaKey: secret.authsiaKey,
            sourceStem: certificateSourceStem(for: secret)
        )
    }

    private static func certificateSourceStem(for secret: DetectedSecret) -> String {
        let sourcePath = certificateSourcePath(for: secret)
        return ((sourcePath as NSString).standardizingPath as NSString).deletingPathExtension
    }

    private static func certificateSourcePath(for secret: DetectedSecret) -> String {
        let trimmedValue = secret.value.trimmingCharacters(in: .whitespacesAndNewlines)
        if isPEMCertificatePath(trimmedValue) {
            return expandedCredentialPath(trimmedValue, relativeTo: secret.filePath)
        }
        let standardizedFilePath = (secret.filePath as NSString).standardizingPath
        return "\(standardizedFilePath):\(secret.lineNumber):\(secret.authsiaKey)"
    }

    private static func isPEMCertificatePath(_ path: String) -> Bool {
        let ext = ".\((path as NSString).pathExtension.lowercased())"
        return [".pem", ".crt", ".cer", ".key"].contains(ext)
    }

    private static func expandedCredentialPath(_ path: String, relativeTo scannedFilePath: String) -> String {
        if path.hasPrefix("~") {
            return NSString(string: path).expandingTildeInPath
        }
        if path.hasPrefix("/") {
            return path
        }
        let baseDirectory = (scannedFilePath as NSString).deletingLastPathComponent
        return (baseDirectory as NSString).appendingPathComponent(path)
    }

    private static func shouldCoalesceCertificateSecrets(_ secrets: [DetectedSecret]) -> Bool {
        guard secrets.count > 1 else { return false }

        let contents = secrets.compactMap(\.resolvedCertificateContent)
        let hasCertificate = contents.contains { $0.certificate != nil }
        let hasPrivateKeyOnly = contents.contains { $0.certificate == nil && $0.privateKey != nil }
        return hasCertificate && hasPrivateKeyOnly
    }

    private static func combinedCertificateSecret(from secrets: [DetectedSecret]) -> DetectedSecret {
        guard let first = secrets.first else {
            fatalError("combinedCertificateSecret requires at least one secret")
        }

        let certificates = secrets.compactMap { $0.resolvedCertificateContent?.certificate }
        let privateKeys = secrets.compactMap { $0.resolvedCertificateContent?.privateKey }
        let content = PEMCertificateContent(
            certificate: certificates.isEmpty ? nil : certificates.joined(separator: "\n"),
            privateKey: privateKeys.isEmpty ? nil : privateKeys.joined(separator: "\n")
        )
        let rawContent = [content.certificate, content.privateKey]
            .compactMap { $0 }
            .joined(separator: "\n")

        return DetectedSecret(
            filePath: first.filePath,
            lineNumber: first.lineNumber,
            originalLine: first.originalLine,
            key: first.key,
            value: first.value,
            rawContent: rawContent,
            confidence: first.confidence,
            type: first.type,
            entropy: first.entropy,
            description: first.description,
            sshMetadata: first.sshMetadata,
            certificateContent: content
        )
    }

    private func migrateSecret(_ secret: DetectedSecret) throws -> (ScrapeMigrationOutcome, String?) {
        switch secret.type {
        case .apiKey, .token, .secret, .accessKey:
            return try migrateAPIKey(secret)
        case .jsonCredential:
            return try migratePassword(secret)
        case .certificate:
            if secret.resolvedCertificateContent != nil {
                return try migrateCertificate(secret)
            }
            if secret.rawContent != nil {
                return try migrateNote(secret)
            }
            return try migratePassword(secret)
        case .sshKey:
            return (.skipped, nil)
        default:
            return try migratePassword(secret)
        }
    }

    private func migratePassword(_ secret: DetectedSecret) throws -> (ScrapeMigrationOutcome, String?) {
        let passwordValue: String
        if secret.type == .jsonCredential, let rawContent = secret.rawContent {
            passwordValue = rawContent
        } else {
            passwordValue = secret.value
        }

        let environments = environmentTagsBySecretID[secret.id] ?? []
        let existingID = try client.existingPasswordID(
            named: secret.authsiaKey,
            folderPath: folderPath,
            environments: environments
        )
        let dateStr = String(Self.iso8601Formatter.string(from: Date()).prefix(10))
        let notes = ScrapeMigrator.provenanceNote(
            filePath: secret.filePath,
            lineNumber: secret.lineNumber,
            machineName: machineName,
            date: dateStr
        )

        if let existingID {
            switch conflictDecision(for: secret) {
            case .skip:
                return (.skipped, nil)
            case .overwrite:
                let result = try client.updatePassword(
                    query: existingID,
                    name: secret.authsiaKey,
                    username: nil,
                    password: passwordValue,
                    website: nil,
                    notes: notes + " (updated)",
                    isScraped: true,
                    folderPath: folderPath,
                    scrapeMachineName: machineName,
                    scrapeMachineId: machineId,
                    expiresAt: nil,
                    clearExpiresAt: false,
                    environments: environments
                )
                return (.updated, result.id)
            case .reuse:
                return (.reused, existingID)
            }
        }

        let result = try client.addPassword(
            name: secret.authsiaKey,
            username: "",
            password: passwordValue,
            website: nil,
            notes: notes,
            isScraped: true,
            folderPath: folderPath,
            scrapeMachineName: machineName,
            scrapeMachineId: machineId,
            expiresAt: nil,
            environments: environments
        )
        return (.added, result.id)
    }

    private func migrateAPIKey(_ secret: DetectedSecret) throws -> (ScrapeMigrationOutcome, String?) {
        let environments = environmentTagsBySecretID[secret.id] ?? []
        let existingID = try client.existingAPIKeyID(
            named: secret.authsiaKey,
            folderPath: folderPath,
            environments: environments
        )
        let dateStr = String(Self.iso8601Formatter.string(from: Date()).prefix(10))
        let notes = ScrapeMigrator.provenanceNote(
            filePath: secret.filePath,
            lineNumber: secret.lineNumber,
            machineName: machineName,
            date: dateStr
        )

        if let existingID {
            switch conflictDecision(for: secret) {
            case .skip:
                return (.skipped, nil)
            case .overwrite:
                let result = try client.updateAPIKey(
                    query: existingID,
                    name: secret.authsiaKey,
                    key: secret.value,
                    website: nil,
                    notes: notes + " (updated)",
                    isScraped: true,
                    folderPath: folderPath,
                    scrapeMachineName: machineName,
                    scrapeMachineId: machineId,
                    expiresAt: nil,
                    clearExpiresAt: false,
                    environments: environments
                )
                return (.updated, result.id)
            case .reuse:
                return (.reused, existingID)
            }
        }

        let result = try client.addAPIKey(
            name: secret.authsiaKey,
            key: secret.value,
            website: nil,
            notes: notes,
            isScraped: true,
            folderPath: folderPath,
            scrapeMachineName: machineName,
            scrapeMachineId: machineId,
            expiresAt: nil,
            environments: environments
        )
        return (.added, result.id)
    }

    private func migrateCertificate(_ secret: DetectedSecret) throws -> (ScrapeMigrationOutcome, String?) {
        guard let content = secret.resolvedCertificateContent else {
            throw ScrapeMigrationError.missingContent
        }

        let environments = environmentTagsBySecretID[secret.id] ?? []
        let existingID = try client.existingCertificateID(
            named: secret.authsiaKey,
            folderPath: folderPath,
            environments: environments
        )
        let dateStr = String(Self.iso8601Formatter.string(from: Date()).prefix(10))
        let notes = ScrapeMigrator.provenanceNote(
            filePath: secret.filePath,
            lineNumber: secret.lineNumber,
            machineName: machineName,
            date: dateStr
        )

        if let existingID {
            switch conflictDecision(for: secret) {
            case .skip:
                return (.skipped, nil)
            case .overwrite:
                let result = try client.updateCertificate(
                    query: existingID,
                    name: secret.authsiaKey,
                    certificate: content.certificate,
                    privateKey: content.privateKey,
                    clearPrivateKey: false,
                    notes: notes + " (updated)",
                    folderPath: folderPath,
                    isScraped: true,
                    scrapeMachineName: machineName,
                    scrapeMachineId: machineId,
                    environments: environments
                )
                return (.updated, result.id)
            case .reuse:
                return (.reused, existingID)
            }
        }

        let result = try client.addCertificate(
            name: secret.authsiaKey,
            certificate: content.certificate ?? "",
            privateKey: content.privateKey,
            notes: notes,
            folderPath: folderPath,
            isScraped: true,
            scrapeMachineName: machineName,
            scrapeMachineId: machineId,
            environments: environments
        )
        return (.added, result.id)
    }

    private func migrateNote(_ secret: DetectedSecret) throws -> (ScrapeMigrationOutcome, String?) {
        guard let content = secret.rawContent else {
            throw ScrapeMigrationError.missingContent
        }
        let title = secret.authsiaKey
        let environments = environmentTagsBySecretID[secret.id] ?? []
        let existingID = try client.existingNoteID(
            title: title,
            folderPath: folderPath,
            environments: environments
        )

        let dateStr = String(Self.iso8601Formatter.string(from: Date()).prefix(10))
        let provenance = "\n\n# \(ScrapeMigrator.provenanceNote(filePath: secret.filePath, lineNumber: secret.lineNumber, machineName: machineName, date: dateStr))"
        let contentWithProvenance = content + provenance

        if let existingID {
            switch conflictDecision(for: secret) {
            case .skip:
                return (.skipped, nil)
            case .overwrite:
                let result = try client.updateNote(
                    query: existingID,
                    title: title,
                    content: contentWithProvenance,
                    isScraped: true,
                    folderPath: folderPath,
                    scrapeMachineName: machineName,
                    scrapeMachineId: machineId,
                    environments: environments
                )
                return (.updated, result.id)
            case .reuse:
                return (.reused, existingID)
            }
        }

        let result = try client.addNote(
            title: title,
            content: contentWithProvenance,
            isScraped: true,
            folderPath: folderPath,
            scrapeMachineName: machineName,
            scrapeMachineId: machineId,
            environments: environments
        )
        return (.added, result.id)
    }

    private func conflictDecision(for secret: DetectedSecret) -> ConflictDecision {
        switch conflictMode {
        case .skip:
            return .skip
        case .overwrite:
            return .overwrite
        case .reuse:
            return .reuse
        case .prompt(let confirm):
            return confirm(secret) ? .overwrite : .skip
        case .choose(let choose):
            return choose(secret)
        }
    }
}
