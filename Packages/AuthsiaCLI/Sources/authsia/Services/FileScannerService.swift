import Foundation

actor FileScannerService {
    
    static let scanTargets: [ScanTarget] = [
        ScanTarget(pattern: ".env*", type: .envFile, autoReplace: false),
        ScanTarget(pattern: ".zshrc", type: .shellConfig, autoReplace: true),
        ScanTarget(pattern: ".bashrc", type: .shellConfig, autoReplace: true),
        ScanTarget(pattern: ".bash_profile", type: .shellConfig, autoReplace: true),
        ScanTarget(pattern: ".zprofile", type: .shellConfig, autoReplace: true),
        ScanTarget(pattern: ".profile", type: .shellConfig, autoReplace: true),
        ScanTarget(pattern: "id_*", type: .envFile, autoReplace: false),
        ScanTarget(pattern: "*.json", type: .envFile, autoReplace: false),
        ScanTarget(pattern: "*.pem", type: .envFile, autoReplace: false),
        ScanTarget(pattern: "*.crt", type: .envFile, autoReplace: false),
        ScanTarget(pattern: "*.cer", type: .envFile, autoReplace: false),
        ScanTarget(pattern: "*.key", type: .envFile, autoReplace: false),
    ]

    static let skippedRecursiveDirectoryNames: Set<String> = [
        // Source control
        ".git",
        ".hg",
        ".svn",
        ".bzr",
        ".worktrees",

        // Swift / Xcode / Apple
        ".build",
        ".swiftpm",
        "DerivedData",
        "Library",
        "Packages",
        "Carthage",
        "Checkouts",
        "Pods",

        // JavaScript / TypeScript
        "node_modules",
        ".npm",
        ".pnpm-store",
        ".yarn",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".astro",
        ".vite",
        ".turbo",
        ".parcel-cache",

        // Python
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".eggs",

        // Java / Kotlin / JVM
        ".gradle",
        ".m2",
        ".kotlin",
        "target",

        // .NET
        ".vs",
        "bin",
        "obj",
        "TestResults",
        "packages",

        // Ruby / PHP / Go
        ".bundle",
        "vendor",

        // Terraform / cloud / IaC
        ".terraform",
        ".terragrunt-cache",
        ".pulumi",
        ".serverless",
        ".aws-sam",
        "cdk.out",

        // Editors / IDEs / AI tools
        ".idea",
        ".vscode",
        ".zed",
        ".cursor",
        ".qoder",
        ".claude",
        ".codex",
        ".aider",
        ".continue",
        ".windsurf",

        // General build / cache / generated output
        ".cache",
        "build",
        "dist",
        "out",
        "output",
        "coverage",
        "htmlcov",
        "logs",
        "tmp",
        "temp",
        "graphify-out",
    ]

    static let skippedDirectoryFileNames: Set<String> = [
        "package-lock.json",
    ]

    struct ScanProgress: Equatable, Sendable {
        let folderName: String
        let current: Int
        let total: Int

        var displayMessage: String {
            "Scanning \(folderName), \(current)/\(total)"
        }
    }

    typealias ScanProgressHandler = @Sendable (ScanProgress) -> Void

    private enum ReferenceSyntax {
        case all
        case uriOnly
        case shellOnly
    }
    
    struct ScanTarget {
        let pattern: String
        let type: FileType
        let autoReplace: Bool
        
        enum FileType {
            case envFile
            case shellConfig
        }
    }
    
    func scanPaths(
        _ paths: [String],
        detectionService: SecretDetectionService,
        recursive: Bool = false,
        progress: ScanProgressHandler? = nil
    ) async -> [DetectedSecret] {
        var allSecrets: [DetectedSecret] = []
        let fileManager = FileManager.default
        
        for path in paths {
            let expandedPath = FilePathNormalizer.absoluteStandardizedPath(path)
            var isDirectory: ObjCBool = false
            
            guard fileManager.fileExists(atPath: expandedPath, isDirectory: &isDirectory) else {
                continue
            }
            
            let secrets: [DetectedSecret]
            if isDirectory.boolValue {
                secrets = await scanDirectory(
                    expandedPath,
                    detectionService: detectionService,
                    recursive: recursive,
                    progress: progress
                )
            } else {
                secrets = await scanFile(
                    expandedPath,
                    detectionService: detectionService,
                    allowLegacyPrivateKeyOnlyPEM: isPEMCertificateFilePath(expandedPath)
                )
            }
            
            allSecrets.append(contentsOf: secrets)
        }
        
        return allSecrets.sorted { 
            if $0.confidence != $1.confidence {
                return $0.confidence > $1.confidence
            }
            return $0.filePath < $1.filePath
        }
    }

    func findAuthsiaReferences(in paths: [String], recursive: Bool = false) async -> [AuthsiaReference] {
        await findAuthsiaReferences(in: paths, recursive: recursive, syntax: .all)
    }

    func findShellAuthsiaReferences(in paths: [String], recursive: Bool = false) async -> [AuthsiaReference] {
        await findAuthsiaReferences(in: paths, recursive: recursive, syntax: .shellOnly)
    }

    func findURIAuthsiaReferences(in paths: [String], recursive: Bool = false) async -> [AuthsiaReference] {
        await findAuthsiaReferences(in: paths, recursive: recursive, syntax: .uriOnly)
    }

    private func findAuthsiaReferences(
        in paths: [String],
        recursive: Bool,
        syntax: ReferenceSyntax
    ) async -> [AuthsiaReference] {
        var allReferences = Set<AuthsiaReference>()
        let fileManager = FileManager.default

        for path in paths {
            let expandedPath = FilePathNormalizer.absoluteStandardizedPath(path)
            var isDirectory: ObjCBool = false

            guard fileManager.fileExists(atPath: expandedPath, isDirectory: &isDirectory) else {
                continue
            }

            let references: Set<AuthsiaReference>
            if isDirectory.boolValue {
                references = await findAuthsiaReferencesInDirectory(
                    expandedPath,
                    recursive: recursive,
                    syntax: syntax
                )
            } else {
                references = await findAuthsiaReferencesInFile(expandedPath, syntax: syntax)
            }
            allReferences.formUnion(references)
        }

        return allReferences.sorted {
            if $0.itemType != $1.itemType {
                return $0.itemType.rawValue < $1.itemType.rawValue
            }
            if $0.query != $1.query {
                return $0.query < $1.query
            }
            return ($0.folderPath ?? "") < ($1.folderPath ?? "")
        }
    }
    
    func scanFile(_ path: String, detectionService: SecretDetectionService) async -> [DetectedSecret] {
        await scanFile(path, detectionService: detectionService, allowLegacyPrivateKeyOnlyPEM: false)
    }

    private func scanFile(
        _ path: String,
        detectionService: SecretDetectionService,
        allowLegacyPrivateKeyOnlyPEM: Bool
    ) async -> [DetectedSecret] {
        var secrets: [DetectedSecret] = []
        
        guard FileManager.default.isReadableFile(atPath: path),
              !isBinaryFile(path) else {
            return secrets
        }
        
        do {
            let content = try String(contentsOfFile: path, encoding: .utf8)

            if let sshSecret = detectSSHKey(in: content, filePath: path) {
                return [sshSecret]
            }
            if let jsonSecret = detectJsonCredential(in: content, filePath: path) {
                return [jsonSecret]
            }
            if isJSONFilePath(path) {
                return secrets
            }
            if isPEMCertificateFilePath(path),
               let certificateSecret = detectPEMCertificate(
                in: content,
                filePath: path,
                allowLegacyPrivateKeyOnly: allowLegacyPrivateKeyOnlyPEM
               ) {
                return [certificateSecret]
            }

            let lines = content.components(separatedBy: .newlines)
            
            for (index, line) in lines.enumerated() {
                let lineNumber = index + 1
                let trimmedLine = line.trimmingCharacters(in: .whitespaces)
                
                guard !trimmedLine.isEmpty,
                      !trimmedLine.hasPrefix("#"),
                      !trimmedLine.hasPrefix("//") else {
                    continue
                }
                
                if let (key, value) = parseKeyValue(from: line) {
                    // Skip values already migrated to authsia
                    if isAuthsiaReference(value) { continue }

                    if var secret = await detectionService.detectSecret(
                        key: key,
                        value: value,
                        originalLine: line,
                        filePath: path,
                        lineNumber: lineNumber
                    ) {
                        // If it's a path-based credential, try to load the file content
                        if secret.type == .jsonCredential || secret.type == .certificate {
                            if let fileContent = loadCredentialFile(at: secret.value, relativeTo: secret.filePath) {
                                let certificateContent = secret.type == .certificate
                                    ? PEMCertificateParser.parse(fileContent)
                                    : nil
                                secret = DetectedSecret(
                                    filePath: secret.filePath,
                                    lineNumber: secret.lineNumber,
                                    originalLine: secret.originalLine,
                                    key: secret.key,
                                    value: secret.value,
                                    rawContent: fileContent,
                                    confidence: secret.confidence,
                                    type: secret.type,
                                    entropy: secret.entropy,
                                    description: secret.description + " (file loaded)",
                                    sshMetadata: nil,
                                    certificateContent: certificateContent
                                )
                            }
                        }
                        secrets.append(secret)
                    }
                }
            }
        } catch {
            // Skip files that can't be read
        }
        
        return secrets
    }

    private func detectSSHKey(in content: String, filePath: String) -> DetectedSecret? {
        let markers = [
            "BEGIN OPENSSH PRIVATE KEY",
            "BEGIN RSA PRIVATE KEY",
            "BEGIN EC PRIVATE KEY",
            "BEGIN DSA PRIVATE KEY"
        ]
        guard markers.contains(where: { content.contains($0) }) else { return nil }

        let pubPath = filePath + ".pub"
        guard FileManager.default.isReadableFile(atPath: pubPath),
              let pubContent = try? String(contentsOfFile: pubPath, encoding: .utf8) else {
            return nil
        }

        guard let pubLine = pubContent
            .split(separator: "\n", omittingEmptySubsequences: true)
            .map({ $0.trimmingCharacters(in: .whitespaces) })
            .first(where: { !$0.isEmpty }) else {
            return nil
        }

        let derivedKey = (filePath as NSString).lastPathComponent
        guard let metadata = try? SSHKeyMetadataResolver.parsePublicKeyLine(
            pubLine,
            fallbackComment: derivedKey
        ) else {
            return nil
        }

        let sshMetadata = DetectedSecret.SSHMetadata(
            publicKey: metadata.publicKey,
            comment: metadata.comment,
            fingerprint: metadata.fingerprint,
            keyType: metadata.keyType
        )

        return DetectedSecret(
            filePath: filePath,
            lineNumber: 0,
            originalLine: "",
            key: derivedKey,
            value: "",
            rawContent: content,
            confidence: .high,
            type: .sshKey,
            entropy: 0,
            description: "ssh private key",
            sshMetadata: sshMetadata
        )
    }

    private func detectJsonCredential(in content: String, filePath: String) -> DetectedSecret? {
        let fileURL = URL(fileURLWithPath: filePath)
        let isKubeConfig = fileURL.lastPathComponent == "config"
            && fileURL.deletingLastPathComponent().lastPathComponent == ".kube"
        let isJsonFile = fileURL.pathExtension.lowercased() == "json"

        guard isKubeConfig || isJsonFile else { return nil }

        if isJsonFile {
            guard let data = content.data(using: .utf8),
                  let jsonObject = try? JSONSerialization.jsonObject(with: data, options: []),
                  Self.isCredentialJSON(jsonObject) else {
                return nil
            }
        }

        let derivedKey = fileURL.deletingPathExtension().lastPathComponent

        return DetectedSecret(
            filePath: filePath,
            lineNumber: 0,
            originalLine: "",
            key: derivedKey,
            value: "",
            rawContent: content,
            confidence: .high,
            type: .jsonCredential,
            entropy: 0,
            description: isKubeConfig ? "kube config" : "json credential",
            sshMetadata: nil
        )
    }

    private static func isCredentialJSON(_ value: Any) -> Bool {
        var keys = Set<String>()
        collectJSONKeys(from: value, into: &keys)

        let credentialKeys: Set<String> = [
            "access_token",
            "auth",
            "auths",
            "aws_access_key_id",
            "aws_secret_access_key",
            "client_email",
            "client_id",
            "client_secret",
            "identitytoken",
            "private_key",
            "private_key_id",
            "project_id",
            "refresh_token",
            "secret_access_key",
            "token_uri",
        ]
        let sensitiveKeys: Set<String> = [
            "access_token",
            "auth",
            "aws_secret_access_key",
            "client_secret",
            "identitytoken",
            "private_key",
            "refresh_token",
            "secret_access_key",
        ]

        return !keys.isDisjoint(with: sensitiveKeys) &&
            keys.intersection(credentialKeys).count >= 2
    }

    private static func collectJSONKeys(from value: Any, into keys: inout Set<String>) {
        if let dictionary = value as? [String: Any] {
            for (key, value) in dictionary {
                keys.insert(key.lowercased())
                collectJSONKeys(from: value, into: &keys)
            }
        } else if let array = value as? [Any] {
            for value in array {
                collectJSONKeys(from: value, into: &keys)
            }
        }
    }

    private func detectPEMCertificate(
        in content: String,
        filePath: String,
        allowLegacyPrivateKeyOnly: Bool = false
    ) -> DetectedSecret? {
        guard allowLegacyPrivateKeyOnly || !PEMCertificateParser.isLegacySSHPrivateKeyOnly(content) else {
            return nil
        }
        guard let certificateContent = PEMCertificateParser.parse(content) else {
            return nil
        }

        let fileURL = URL(fileURLWithPath: filePath)
        let derivedKey = fileURL.deletingPathExtension().lastPathComponent

        return DetectedSecret(
            filePath: filePath,
            lineNumber: 0,
            originalLine: "",
            key: derivedKey,
            value: filePath,
            rawContent: content,
            confidence: .high,
            type: .certificate,
            entropy: 0,
            description: certificateContent.privateKey == nil ? "pem certificate" : "pem certificate with private key",
            sshMetadata: nil,
            certificateContent: certificateContent
        )
    }

    private func isPEMCertificateFilePath(_ path: String) -> Bool {
        let ext = (path as NSString).pathExtension.lowercased()
        return ["pem", "crt", "cer", "key"].contains(ext)
    }

    private func isJSONFilePath(_ path: String) -> Bool {
        (path as NSString).pathExtension.lowercased() == "json"
    }
    
    func scanDirectory(
        _ path: String,
        detectionService: SecretDetectionService,
        recursive: Bool = false,
        progress: ScanProgressHandler? = nil
    ) async -> [DetectedSecret] {
        var secrets: [DetectedSecret] = []
        let candidateFiles = Self.directoryCandidateFiles(
            in: path,
            recursive: recursive,
            includeSSHKeyCandidates: true
        )

        if candidateFiles.isEmpty {
            progress?(Self.scanProgress(folderPath: path, current: 0, total: 0))
        }

        for (index, filePath) in candidateFiles.enumerated() {
            progress?(Self.scanProgress(folderPath: path, current: index + 1, total: candidateFiles.count))
            let fileSecrets = await scanFile(
                filePath,
                detectionService: detectionService,
                allowLegacyPrivateKeyOnlyPEM: true
            )
            secrets.append(contentsOf: fileSecrets)
        }

        return deduplicated(normalizedDirectoryCertificateSecrets(secrets, rootPath: path))
    }

    private func normalizedDirectoryCertificateSecrets(
        _ secrets: [DetectedSecret],
        rootPath: String
    ) -> [DetectedSecret] {
        let certificateGroups = Dictionary(grouping: secrets.filter(isStandalonePEMCertificateFile)) {
            relativeStem(for: $0.filePath, rootPath: rootPath)
        }
        let importableGroups = certificateGroups.filter { _, group in
            group.contains { $0.resolvedCertificateContent?.certificate != nil }
        }
        guard !importableGroups.isEmpty else {
            return secrets.filter { !isStandalonePEMCertificateFile($0) }
        }

        let keyByStem = directoryCertificateKeyMap(for: importableGroups)
        return secrets.compactMap { secret in
            guard isStandalonePEMCertificateFile(secret) else {
                return secret
            }

            let stem = relativeStem(for: secret.filePath, rootPath: rootPath)
            guard importableGroups[stem] != nil else {
                return nil
            }

            guard let key = keyByStem[stem], key != secret.key else {
                return secret
            }
            return copyCertificateSecret(secret, key: key)
        }
    }

    private func isStandalonePEMCertificateFile(_ secret: DetectedSecret) -> Bool {
        secret.type == .certificate &&
            secret.lineNumber == 0 &&
            secret.originalLine.isEmpty &&
            secret.resolvedCertificateContent != nil
    }

    private func directoryCertificateKeyMap(
        for groups: [String: [DetectedSecret]]
    ) -> [String: String] {
        let baseKeyByStem = groups.mapValues { group in
            group.first?.authsiaKey ?? "certificate"
        }
        let stemsByBaseKey = Dictionary(grouping: groups.keys) {
            baseKeyByStem[$0] ?? "certificate"
        }
        var candidateByStem: [String: String] = [:]

        for stem in groups.keys {
            let baseKey = baseKeyByStem[stem] ?? "certificate"
            if stemsByBaseKey[baseKey, default: []].count > 1 {
                candidateByStem[stem] = slugifiedCertificateKey(from: stem)
            } else {
                candidateByStem[stem] = baseKey
            }
        }

        var used: [String: Int] = [:]
        var keyByStem: [String: String] = [:]
        for stem in groups.keys.sorted() {
            let candidate = candidateByStem[stem] ?? "certificate"
            let nextCount = (used[candidate] ?? 0) + 1
            used[candidate] = nextCount
            keyByStem[stem] = nextCount == 1 ? candidate : "\(candidate)_\(nextCount)"
        }
        return keyByStem
    }

    private func relativeStem(for filePath: String, rootPath: String) -> String {
        let root = (rootPath as NSString).standardizingPath
        let path = (filePath as NSString).standardizingPath
        let relativePath: String
        if path == root {
            relativePath = (path as NSString).lastPathComponent
        } else if path.hasPrefix(root + "/") {
            relativePath = String(path.dropFirst(root.count + 1))
        } else {
            relativePath = (path as NSString).lastPathComponent
        }
        return (relativePath as NSString).deletingPathExtension
    }

    private func slugifiedCertificateKey(from stem: String) -> String {
        let allowed = CharacterSet.alphanumerics
        let mapped = stem.unicodeScalars.map { scalar -> Character in
            allowed.contains(scalar) ? Character(scalar) : "_"
        }
        let collapsed = String(mapped).replacingOccurrences(of: "_+", with: "_", options: .regularExpression)
        let trimmed = collapsed.trimmingCharacters(in: CharacterSet(charactersIn: "_"))
        return trimmed.isEmpty ? "certificate" : trimmed
    }

    private func copyCertificateSecret(_ secret: DetectedSecret, key: String) -> DetectedSecret {
        DetectedSecret(
            filePath: secret.filePath,
            lineNumber: secret.lineNumber,
            originalLine: secret.originalLine,
            key: key,
            value: secret.value,
            rawContent: secret.rawContent,
            confidence: secret.confidence,
            type: secret.type,
            entropy: secret.entropy,
            description: secret.description,
            sshMetadata: secret.sshMetadata,
            certificateContent: secret.certificateContent
        )
    }

    private func deduplicated(_ secrets: [DetectedSecret]) -> [DetectedSecret] {
        var seen = Set<String>()
        return secrets.filter { secret in
            let key = "\(secret.type.rawValue)|\(secret.filePath)|\(secret.lineNumber)|\(secret.key)"
            return seen.insert(key).inserted
        }
    }

    private func findAuthsiaReferencesInDirectory(
        _ path: String,
        recursive: Bool,
        syntax: ReferenceSyntax
    ) async -> Set<AuthsiaReference> {
        var references = Set<AuthsiaReference>()

        for filePath in Self.directoryCandidateFiles(in: path, recursive: recursive, includeSSHKeyCandidates: false) {
            references.formUnion(await findAuthsiaReferencesInFile(filePath, syntax: syntax))
        }

        return references
    }

    private func findAuthsiaReferencesInFile(_ path: String, syntax: ReferenceSyntax) async -> Set<AuthsiaReference> {
        var references = Set<AuthsiaReference>()

        guard FileManager.default.isReadableFile(atPath: path),
              !isBinaryFile(path) else {
            return references
        }

        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            return references
        }

        let lines = content.components(separatedBy: .newlines)
        for line in lines {
            let trimmedLine = line.trimmingCharacters(in: .whitespaces)
            guard !trimmedLine.isEmpty,
                  !trimmedLine.hasPrefix("#"),
                  !trimmedLine.hasPrefix("//"),
                  let (_, value) = parseKeyValue(from: line),
                  let reference = parseAuthsiaReference(from: value, syntax: syntax) else {
                continue
            }
            references.insert(reference)
        }

        return references
    }

    private func loadCredentialFile(at path: String, relativeTo scannedFilePath: String? = nil) -> String? {
        // Expand tilde if present
        let expandedPath: String
        if path.hasPrefix("~") {
            expandedPath = NSString(string: path).expandingTildeInPath
        } else if path.hasPrefix("/") {
            expandedPath = path
        } else if let scannedFilePath {
            let baseDirectory = (scannedFilePath as NSString).deletingLastPathComponent
            expandedPath = (baseDirectory as NSString).appendingPathComponent(path)
        } else {
            expandedPath = path
        }

        guard FileManager.default.isReadableFile(atPath: expandedPath) else {
            return nil
        }

        do {
            let content = try String(contentsOfFile: expandedPath, encoding: .utf8)
            return content
        } catch {
            return nil
        }
    }

    private func parseKeyValue(from line: String) -> (key: String, value: String)? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        
        // export KEY=value or KEY=value
        if let match = trimmed.firstMatch(of: /^(export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/) {
            let key = String(match.2)
            var value = String(match.3).trimmingCharacters(in: .whitespaces)
            value = stripQuotes(value)
            return (key, value)
        }
        
        // JSON: "key": "value"
        if let match = trimmed.firstMatch(of: /"([A-Za-z_][A-Za-z0-9_]*)"\s*:\s*"([^"]+)"/) {
            return (String(match.1), String(match.2))
        }
        
        // YAML: key: value
        if let match = trimmed.firstMatch(of: /^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+)$/) {
            var value = String(match.2).trimmingCharacters(in: .whitespaces)
            value = stripQuotes(value)
            return (String(match.1), value)
        }
        
        return nil
    }
    
    private func isAuthsiaReference(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespaces)
        // Legacy shell-substitution form: KEY=$(authsia get ...)
        if trimmed.hasPrefix("$(authsia ") || trimmed.hasPrefix("$(authsia\t") {
            return true
        }
        // .env URI form written by EnvFileRewriteService: KEY=authsia://type/item/field
        return SecretReference.isSecretReference(trimmed)
    }

    private func parseAuthsiaReference(from value: String, syntax: ReferenceSyntax) -> AuthsiaReference? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if syntax != .shellOnly, SecretReference.isSecretReference(trimmed) {
            return parseAuthsiaURIReference(from: trimmed)
        }

        guard syntax != .uriOnly else { return nil }

        guard trimmed.hasPrefix("$("), trimmed.hasSuffix(")") else { return nil }

        let inner = String(trimmed.dropFirst(2).dropLast()).trimmingCharacters(in: .whitespacesAndNewlines)
        let tokens = splitShellTokens(inner)
        guard tokens.count >= 4 else { return nil }
        guard tokens[0] == "authsia", tokens[1] == "get" else { return nil }
        guard let itemType = AuthsiaReference.ItemType(rawValue: tokens[2]) else { return nil }

        return AuthsiaReference(itemType: itemType, query: tokens[3])
    }

    private func parseAuthsiaURIReference(from value: String) -> AuthsiaReference? {
        guard let reference = try? SecretReference.parse(value) else { return nil }
        let itemType: AuthsiaReference.ItemType
        switch reference.type {
        case .password:
            itemType = .password
        case .apiKey:
            itemType = .apiKey
        case .cert:
            itemType = .certificate
        case .note:
            itemType = .note
        case .ssh:
            itemType = .ssh
        case .otp:
            return nil
        }
        return AuthsiaReference(itemType: itemType, query: reference.item, folderPath: normalizeFolderPath(reference.folder))
    }

    private func splitShellTokens(_ value: String) -> [String] {
        var tokens: [String] = []
        var current = ""
        var quoteCharacter: Character?

        for character in value {
            if let activeQuote = quoteCharacter {
                if character == activeQuote {
                    quoteCharacter = nil
                } else {
                    current.append(character)
                }
                continue
            }

            if character == "\"" || character == "'" {
                quoteCharacter = character
                continue
            }

            if character.isWhitespace {
                if !current.isEmpty {
                    tokens.append(current)
                    current.removeAll(keepingCapacity: true)
                }
                continue
            }

            current.append(character)
        }

        if !current.isEmpty {
            tokens.append(current)
        }

        return tokens
    }

    private func stripQuotes(_ value: String) -> String {
        var result = value
        if (result.hasPrefix("\"") && result.hasSuffix("\"")) ||
           (result.hasPrefix("'") && result.hasSuffix("'")) {
            result = String(result.dropFirst().dropLast())
        }
        return result
    }
    
    private func isBinaryFile(_ path: String) -> Bool {
        guard let data = FileManager.default.contents(atPath: path),
              data.count > 0 else { return false }
        
        let checkLength = min(data.count, 1024)
        for i in 0..<checkLength {
            if data[i] == 0 { return true }
        }
        return false
    }
    
    static func directoryCandidateFiles(
        in path: String,
        recursive: Bool = false,
        includeSSHKeyCandidates: Bool,
        allowedSkippedDirectoryNames: Set<String> = []
    ) -> [String] {
        if !recursive {
            return shallowDirectoryCandidateFiles(in: path, includeSSHKeyCandidates: includeSSHKeyCandidates)
        }

        var files = Set<String>()
        let fileManager = FileManager.default

        guard let enumerator = fileManager.enumerator(atPath: path) else {
            return []
        }

        while let relativePath = enumerator.nextObject() as? String {
            let fullPath = (path as NSString).appendingPathComponent(relativePath)
            let fileName = (relativePath as NSString).lastPathComponent

            var isDirectory: ObjCBool = false
            guard fileManager.fileExists(atPath: fullPath, isDirectory: &isDirectory) else {
                continue
            }

            if isDirectory.boolValue {
                if shouldSkipRecursiveDirectory(named: fileName),
                   !allowedSkippedDirectoryNames.contains(fileName) {
                    enumerator.skipDescendants()
                }
                continue
            }

            if skippedDirectoryFileNames.contains(fileName) {
                continue
            }

            guard fileManager.isReadableFile(atPath: fullPath) else {
                continue
            }

            if shouldScanDirectoryRelativePath(relativePath) ||
                (includeSSHKeyCandidates && shouldScanSSHKeyCandidate(at: fullPath, fileName: fileName)) {
                files.insert(fullPath)
            }
        }

        return files.sorted()
    }

    private static func shallowDirectoryCandidateFiles(in path: String, includeSSHKeyCandidates: Bool) -> [String] {
        let fileManager = FileManager.default
        guard let contents = try? fileManager.contentsOfDirectory(atPath: path) else {
            return []
        }

        var files = Set<String>()
        for fileName in contents {
            let fullPath = (path as NSString).appendingPathComponent(fileName)
            var isDirectory: ObjCBool = false
            guard fileManager.fileExists(atPath: fullPath, isDirectory: &isDirectory),
                  !isDirectory.boolValue,
                  fileManager.isReadableFile(atPath: fullPath) else {
                continue
            }

            if skippedDirectoryFileNames.contains(fileName) {
                continue
            }

            if shouldScanDirectoryRelativePath(fileName) ||
                (includeSSHKeyCandidates && shouldScanSSHKeyCandidate(at: fullPath, fileName: fileName)) {
                files.insert(fullPath)
            }
        }

        return files.sorted()
    }

    private static func scanProgress(folderPath: String, current: Int, total: Int) -> ScanProgress {
        let folderName = (folderPath as NSString).lastPathComponent
        return ScanProgress(
            folderName: folderName.isEmpty ? folderPath : folderName,
            current: current,
            total: total
        )
    }

    private static func shouldScanDirectoryRelativePath(_ relativePath: String) -> Bool {
        let fileName = (relativePath as NSString).lastPathComponent
        return scanTargets.contains { target in
            if target.pattern.contains("*") {
                return matchesGlobPattern(fileName, pattern: target.pattern)
            }
            return relativePath == target.pattern
        }
    }

    private static func shouldSkipRecursiveDirectory(named fileName: String) -> Bool {
        skippedRecursiveDirectoryNames.contains(fileName) || fileName.hasSuffix(".xcassets")
    }

    private static func shouldScanSSHKeyCandidate(at path: String, fileName: String) -> Bool {
        guard !fileName.hasSuffix(".pub") else {
            return false
        }
        return FileManager.default.isReadableFile(atPath: path + ".pub")
    }

    static func matchesGlobPattern(_ fileName: String, pattern: String) -> Bool {
        let regexPattern = pattern
            .replacingOccurrences(of: ".", with: "\\.")
            .replacingOccurrences(of: "*", with: ".*")
            .replacingOccurrences(of: "?", with: ".")
        
        return fileName.range(of: "^\(regexPattern)$", options: .regularExpression) != nil
    }
}
