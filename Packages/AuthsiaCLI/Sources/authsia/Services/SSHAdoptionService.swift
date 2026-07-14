import Foundation
import AuthenticatorCore

protocol SSHAdoptionVaultClient {
    func existingSSHKey(named name: String, folderPath: String?) throws -> SSHAdoptionService.ExistingVaultKey?
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
    ) throws -> WriteResult
}

extension AuthsiaBridgeClient: SSHAdoptionVaultClient {}

protocol SSHAdoptionBackuping {
    func createBackup(
        of filePath: String,
        originalContent: String,
        description: String,
        kind: BackupService.BackupKind
    ) async throws -> BackupService.BackupEntry
}

extension BackupService: SSHAdoptionBackuping {}

enum SSHAdoptionService {
    static let backupDescription = "Before authsia ssh adopt"

    enum AdoptionError: LocalizedError, Equatable {
        case vaultPrivateKeyNotVerified(String)
        case restoredPrivateKeyNotVerified(String)

        var errorDescription: String? {
            switch self {
            case .vaultPrivateKeyNotVerified(let keyName):
                return "Vault storage for SSH key '\(keyName)' could not be verified; local private key was not replaced."
            case .restoredPrivateKeyNotVerified(let keyName):
                return "Restored SSH key '\(keyName)' could not be verified after writing."
            }
        }
    }

    struct ExistingVaultKey: Equatable {
        let publicKey: String
        let fingerprint: String
        let privateKey: String?

        func matches(_ candidate: Candidate, localPrivateKey: String) -> Bool {
            fingerprint == candidate.metadata.fingerprint &&
                normalizedPrivateKey(privateKey) == normalizedPrivateKey(localPrivateKey)
        }

        private func normalizedPrivateKey(_ value: String?) -> String? {
            value?.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    struct HostBinding: Equatable {
        let host: String
        let hostName: String?
        let user: String?

        var effectiveHost: String {
            let candidate = hostName?.trimmingCharacters(in: .whitespacesAndNewlines)
            if let candidate, !candidate.isEmpty {
                return candidate
            }
            return host
        }
    }

    struct Candidate: Equatable {
        let keyName: String
        let privateKeyPath: String
        let publicKeyPath: String
        let metadata: SSHKeyMetadataResolver.Metadata
        let hostBindings: [HostBinding]

        var boundHosts: [String] {
            var seen = Set<String>()
            var hosts: [String] = []
            for binding in hostBindings {
                let host = binding.effectiveHost
                guard !host.isEmpty,
                      host != "*",
                      !host.hasPrefix("!"),
                      !seen.contains(host) else { continue }
                seen.insert(host)
                hosts.append(host)
            }
            return hosts
        }
    }

    struct AdoptionSummary: Equatable {
        let added: Int
        let managedExisting: Int
        let skipped: Int

        var adopted: Int {
            added + managedExisting
        }
    }

    struct DiscoveryResult: Equatable {
        let candidates: [Candidate]
        let managedStubPaths: [String]
    }

    static func discover(
        path: String,
        configPath: String? = nil
    ) throws -> [Candidate] {
        try inspect(path: path, configPath: configPath).candidates
    }

    static func inspect(
        path: String,
        configPath: String? = nil
    ) throws -> DiscoveryResult {
        let expandedPath = NSString(string: path).expandingTildeInPath
        let resolvedConfigPath = configPath ?? defaultConfigPath(for: expandedPath)
        let configBindings = SSHConfigInspector.bindings(configPath: resolvedConfigPath)
        let bindingByIdentity = Dictionary(grouping: configBindings) {
            normalizePath($0.identityFilePath)
        }

        let keyPaths = candidatePrivateKeyPaths(in: expandedPath, configBindings: configBindings)
        var managedStubPaths: [String] = []
        let candidates = keyPaths.compactMap { privateKeyPath -> Candidate? in
            guard let content = try? String(contentsOfFile: privateKeyPath, encoding: .utf8) else {
                return nil
            }
            guard SSHKeyMetadataResolver.looksLikePrivateKey(content) else {
                if SSHKeyStubService.looksLikeManagedStub(content) {
                    managedStubPaths.append(privateKeyPath)
                }
                return nil
            }

            let publicKeyPath = "\(privateKeyPath).pub"
            guard let metadata = try? SSHKeyMetadataResolver.resolveMetadata(
                privateKeyPath: privateKeyPath,
                publicKeyPath: publicKeyPath
            ) else {
                return nil
            }

            return Candidate(
                keyName: (privateKeyPath as NSString).lastPathComponent,
                privateKeyPath: privateKeyPath,
                publicKeyPath: publicKeyPath,
                metadata: metadata,
                hostBindings: bindingByIdentity[normalizePath(privateKeyPath), default: []]
                    .map { HostBinding(host: $0.host, hostName: $0.hostName, user: $0.user) }
            )
        }
        return DiscoveryResult(candidates: candidates, managedStubPaths: managedStubPaths.sorted())
    }

    static func renderDryRun(candidates: [Candidate]) -> String {
        renderDryRun(candidates: candidates, managedStubPaths: [])
    }

    static func renderDryRun(candidates: [Candidate], managedStubPaths: [String]) -> String {
        var lines = [
            "Shell setup: eval \"$(authsia init zsh)\"",
            "",
        ]

        guard !candidates.isEmpty else {
            if managedStubPaths.isEmpty {
                return "No adoptable SSH private keys were found. Use --path <key> or run `authsia ssh generate --name <name>`."
            }

            lines.insert(
                "No adoptable SSH private keys were found. Use --path <key> or run `authsia ssh generate --name <name>`.",
                at: 0
            )
            lines.append("Already managed by Authsia (skipped):")
            lines.append(contentsOf: managedStubPaths.map { "- \($0)" })
            return lines.joined(separator: "\n")
        }

        lines.insert(
            "Would adopt \(candidates.count) SSH key\(candidates.count == 1 ? "" : "s") into Authsia.",
            at: 0
        )

        for candidate in candidates {
            lines.append("- \(candidate.keyName)")
            lines.append("  Private key: \(candidate.privateKeyPath)")
            lines.append("  Public key:  \(candidate.publicKeyPath)")
            lines.append("  Fingerprint: \(candidate.metadata.fingerprint)")
            lines.append("  Key type:    \(candidate.metadata.keyType.rawValue)")
            if candidate.hostBindings.isEmpty {
                lines.append("  Hosts:       any host")
            } else {
                let hosts = candidate.hostBindings.map { binding in
                    let user = binding.user.map { " as \($0)" } ?? ""
                    return "\(binding.host) -> \(binding.effectiveHost)\(user)"
                }
                lines.append("  Hosts:       \(hosts.joined(separator: ", "))")
            }
            lines.append("  Action:      store in vault, replace private key file with Authsia stub")
        }

        if !managedStubPaths.isEmpty {
            lines.append("")
            lines.append("Already managed by Authsia (skipped):")
            lines.append(contentsOf: managedStubPaths.map { "- \($0)" })
        }

        return lines.joined(separator: "\n")
    }

    static func adopt(
        candidates: [Candidate],
        client: SSHAdoptionVaultClient,
        backupService _: (any SSHAdoptionBackuping)?,
        folderPath: String?,
        configPath: String
    ) async throws -> AdoptionSummary {
        var added = 0
        var managedExisting = 0
        var skipped = 0

        for candidate in candidates {
            let privateKey = try String(contentsOfFile: candidate.privateKeyPath, encoding: .utf8)
            if let existingKey = try client.existingSSHKey(named: candidate.keyName, folderPath: folderPath) {
                if existingKey.matches(candidate, localPrivateKey: privateKey) {
                    try SSHKeyStubService.stubPrivateKeyFile(
                        at: candidate.privateKeyPath,
                        keyName: candidate.keyName
                    )
                    SSHKeyStubService.annotateSSHConfig(
                        at: configPath,
                        forKeyPath: candidate.privateKeyPath,
                        keyName: candidate.keyName
                    )
                    managedExisting += 1
                } else {
                    skipped += 1
                }
                continue
            }

            _ = try client.addSSH(
                name: candidate.keyName,
                publicKey: candidate.metadata.publicKey,
                privateKey: privateKey,
                comment: candidate.metadata.comment,
                fingerprint: candidate.metadata.fingerprint,
                passphrase: nil,
                keyType: candidate.metadata.keyType,
                approvalPolicy: .sessionBased,
                boundHosts: candidate.boundHosts,
                isScraped: true,
                folderPath: folderPath,
                scrapeMachineName: MachineIdentity.load().displayName,
                scrapeMachineId: MachineIdentity.load().machineId
            )
            guard let storedKey = try client.existingSSHKey(named: candidate.keyName, folderPath: folderPath),
                  storedKey.matches(candidate, localPrivateKey: privateKey) else {
                throw AdoptionError.vaultPrivateKeyNotVerified(candidate.keyName)
            }
            try SSHKeyStubService.stubPrivateKeyFile(at: candidate.privateKeyPath, keyName: candidate.keyName)
            SSHKeyStubService.annotateSSHConfig(
                at: configPath,
                forKeyPath: candidate.privateKeyPath,
                keyName: candidate.keyName
            )
            added += 1
        }

        return AdoptionSummary(added: added, managedExisting: managedExisting, skipped: skipped)
    }

    static func restoreManagedStub(
        at path: String,
        client: SSHAdoptionVaultClient,
        folderPath: String?
    ) throws -> Bool {
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            return false
        }
        guard SSHKeyStubService.looksLikeManagedStub(content) else {
            return false
        }

        let keyName = (path as NSString).lastPathComponent
        guard let vaultKey = try client.existingSSHKey(named: keyName, folderPath: folderPath),
              let privateKey = vaultKey.privateKey,
              !privateKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return false
        }

        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        let permissions = attrs[.posixPermissions] as? Int ?? 0o600
        try privateKey.write(toFile: path, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: permissions], ofItemAtPath: path)

        let restored = try String(contentsOfFile: path, encoding: .utf8)
        guard restored == privateKey else {
            throw AdoptionError.restoredPrivateKeyNotVerified(keyName)
        }
        return true
    }

    static func latestActiveAdoptionBackup(
        from backups: [BackupService.BackupEntry]
    ) -> BackupService.BackupEntry? {
        backups
            .filter { !$0.isRestored && $0.kind == .sshAdoption }
            .max(by: { $0.timestamp < $1.timestamp })
    }

    static func latestActiveAdoptionBackupsByPath(
        from backups: [BackupService.BackupEntry]
    ) -> [BackupService.BackupEntry] {
        let backupsByPath = Dictionary(grouping: backups.filter {
            !$0.isRestored && $0.kind == .sshAdoption
        }) { $0.originalPath }

        return backupsByPath.values
            .compactMap { backups in backups.max(by: { $0.timestamp < $1.timestamp }) }
            .sorted(by: { $0.originalPath < $1.originalPath })
    }

    private static func candidatePrivateKeyPaths(
        in path: String,
        configBindings: [SSHConfigInspector.Binding]
    ) -> [String] {
        var candidates = Set<String>()
        var isDirectory: ObjCBool = false
        let exists = FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory)
        guard exists else { return [] }

        if isDirectory.boolValue {
            if let enumerator = FileManager.default.enumerator(atPath: path) {
                while let relativePath = enumerator.nextObject() as? String {
                    let fileName = (relativePath as NSString).lastPathComponent
                    guard !fileName.hasSuffix(".pub") else { continue }

                    let candidatePath = (path as NSString).appendingPathComponent(relativePath)
                    let attributes = try? FileManager.default.attributesOfItem(atPath: candidatePath)
                    guard attributes?[.type] as? FileAttributeType == .typeRegular else { continue }
                    candidates.insert(candidatePath)
                }
            }
        } else {
            candidates.insert(path)
        }

        for binding in configBindings {
            if FileManager.default.fileExists(atPath: binding.identityFilePath) {
                candidates.insert(binding.identityFilePath)
            }
        }

        return candidates.sorted()
    }

    private static func normalizePath(_ path: String) -> String {
        (NSString(string: path).expandingTildeInPath as NSString).standardizingPath
    }

    private static func defaultConfigPath(for expandedPath: String) -> String {
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: expandedPath, isDirectory: &isDirectory),
           !isDirectory.boolValue {
            return ((expandedPath as NSString).deletingLastPathComponent as NSString)
                .appendingPathComponent("config")
        }
        return (expandedPath as NSString).appendingPathComponent("config")
    }
}

enum SSHConfigInspector {
    struct Binding: Equatable {
        let host: String
        let hostName: String?
        let user: String?
        let identityFilePath: String
    }

    static func bindings(configPath: String) -> [Binding] {
        guard let content = try? String(contentsOfFile: configPath, encoding: .utf8) else {
            return []
        }

        var result: [Binding] = []
        var hosts: [String] = []
        var hostName: String?
        var user: String?
        var identityFiles: [String] = []

        func flush() {
            guard !hosts.isEmpty else { return }
            for identityFile in identityFiles {
                for host in hosts {
                    result.append(Binding(
                        host: host,
                        hostName: hostName,
                        user: user,
                        identityFilePath: expandSSHPath(identityFile)
                    ))
                }
            }
        }

        for rawLine in content.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            let parts = line.split(
                maxSplits: 1,
                omittingEmptySubsequences: true,
                whereSeparator: { $0.isWhitespace }
            )
            guard parts.count == 2 else { continue }

            let keyword = parts[0].lowercased()
            let value = stripQuotes(String(parts[1]).trimmingCharacters(in: .whitespaces))
            switch keyword {
            case "host":
                flush()
                hosts = value.split(separator: " ").map(String.init)
                hostName = nil
                user = nil
                identityFiles = []
            case "hostname":
                hostName = value
            case "user":
                user = value
            case "identityfile":
                identityFiles.append(value)
            default:
                continue
            }
        }
        flush()

        return result
    }

    private static func expandSSHPath(_ path: String) -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let expanded = path.replacingOccurrences(of: "%d", with: home)
        return (NSString(string: expanded).expandingTildeInPath as NSString).standardizingPath
    }

    private static func stripQuotes(_ value: String) -> String {
        guard value.count >= 2 else { return value }
        if (value.hasPrefix("\"") && value.hasSuffix("\"")) ||
            (value.hasPrefix("'") && value.hasSuffix("'")) {
            return String(value.dropFirst().dropLast())
        }
        return value
    }
}
