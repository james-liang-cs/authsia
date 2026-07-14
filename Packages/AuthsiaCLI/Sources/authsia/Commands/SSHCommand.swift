import ArgumentParser
import Foundation
import AuthenticatorCore

struct SSH: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ssh",
        abstract: "SSH key generation, host configuration, and signing setup",
        subcommands: [Generate.self, Adopt.self, Config.self, GitSigning.self]
    )

    struct Generate: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "generate",
            abstract: "Generate an ed25519 or RSA keypair stored in the Authsia vault",
            discussion: """
                Generates an ed25519 (default) or RSA keypair with no passphrase.
                Use --type rsa --bits 4096 for RSA keys. The private key is stored
                in the Authsia vault and served by the built-in SSH agent — it is
                never written to disk in plaintext. Only the public key and an
                Authsia-managed stub are written at the chosen --path.
                """
        )

        @Option(name: .long, help: "Key name for the Authsia vault entry, leftover filenames at --path, and ssh-keygen comment")
        var name: String

        @Option(name: .long, help: "Directory where the public key and Authsia stub should be written")
        var path: String = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh", isDirectory: true).path

        @Option(name: .shortAndLong, help: "Key type: ed25519 (default) or rsa")
        var type: String = "ed25519"

        @Option(name: .long, help: "RSA key size: 2048, 3072, or 4096 (default when type is rsa)")
        var bits: Int?

        func run() throws {
            try AuthsiaBridgeClient.shared.withRequestedCommand("ssh", includeAutomationCredential: false) {
                let privateKeyPath = try SSHKeyGenerator.generate(
                    name: name,
                    directory: path,
                    type: type,
                    bits: bits,
                    vaultClient: AuthsiaBridgeClient.shared,
                    keyGenInvocation: Self.runSSHKeygen
                )
                print("Generated SSH keypair at \(privateKeyPath) and \(privateKeyPath).pub")
                print("Private key stored in the Authsia vault — served by the built-in SSH agent.")
            }
        }

        private static func runSSHKeygen(
            outputStem: URL,
            type: String,
            bits: Int?,
            comment: String
        ) throws {
            var arguments = ["-q", "-t", type]
            if type == "rsa" {
                let rsaBits = bits ?? 4096
                arguments += ["-b", String(rsaBits)]
            }
            arguments += ["-N", "", "-C", comment, "-f", outputStem.path]

            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
            process.arguments = arguments

            let stderr = Pipe()
            process.standardError = stderr
            try process.run()
            process.waitUntilExit()

            guard process.terminationStatus == 0 else {
                let errorOutput = String(
                    data: stderr.fileHandleForReading.readDataToEndOfFile(),
                    encoding: .utf8
                ) ?? "ssh-keygen failed"
                throw NSError(
                    domain: "SSHKeyGenerator.ssh-keygen",
                    code: Int(process.terminationStatus),
                    userInfo: [NSLocalizedDescriptionKey: errorOutput.trimmingCharacters(in: .whitespacesAndNewlines)]
                )
            }
        }
    }

    struct Adopt: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "adopt",
            abstract: "Adopt existing SSH private keys into Authsia",
            discussion: """
                Discovers SSH private keys, uses matching .pub files when present,
                derives public keys when possible, maps
                existing ~/.ssh/config Host entries, and imports the keys into
                Authsia. The private key is stored in the vault, then the local
                private key file is replaced with an Authsia stub without writing
                a duplicate backup note. Use --dry-run first to preview the plan.
                Use --revert to restore an Authsia-managed stub from the vault,
                or to restore a legacy adoption backup.

                Examples:
                  authsia ssh adopt --path ~/.ssh --dry-run
                  authsia ssh adopt --path ~/.ssh --yes --folder Infra/SSH
                  authsia ssh adopt --revert ~/.ssh/id_ed25519
                  authsia ssh adopt --revert-all
                """
        )

        @Option(name: .long, help: "File or directory to scan for SSH private keys")
        var path: String = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh", isDirectory: true).path

        @Option(name: .long, help: "SSH config file to inspect and annotate")
        var config: String?

        @Option(
            name: .shortAndLong,
            help: "Folder path for adopted SSH keys",
            completion: .custom(ShellCompletionMetadata.completeFolders)
        )
        var folder: String?

        @Option(name: .long, help: "Revert an Authsia-managed SSH private key file")
        var revert: String?

        @Option(name: .long, help: "Revert from a specific machine's backup")
        var machine: String?

        @Flag(name: .long, help: "Revert all legacy SSH adoption backups for the current machine")
        var revertAll = false

        @Flag(name: .long, help: "Preview adoption without modifying files or vault items")
        var dryRun = false

        @Flag(name: .shortAndLong, help: "Apply the adoption plan without an interactive prompt")
        var yes = false

        func run() async throws {
            try await AuthsiaBridgeClient.shared.withRequestedCommand("ssh", includeAutomationCredential: false) {
                let backupService = BackupService()

                try validateRevertOptions()

                if let revertPath = revert {
                    try await handleRevert(backupService: backupService, path: revertPath, machine: machine)
                    return
                }

                if revertAll {
                    try await handleRevertAll(backupService: backupService, machine: machine)
                    return
                }

                let expandedPath = NSString(string: path).expandingTildeInPath
                let configPath = config.map { NSString(string: $0).expandingTildeInPath }
                    ?? Self.defaultConfigPath(for: expandedPath)
                let discovery = try SSHAdoptionService.inspect(path: expandedPath, configPath: configPath)
                let candidates = discovery.candidates
                let plan = SSHAdoptionService.renderDryRun(
                    candidates: candidates,
                    managedStubPaths: discovery.managedStubPaths
                )

                if dryRun {
                    print(plan)
                    return
                }

                guard yes else {
                    print(plan)
                    throw ValidationError("Refusing to modify SSH keys without --yes. Re-run with --dry-run to preview or --yes to apply.")
                }

                let summary = try await SSHAdoptionService.adopt(
                    candidates: candidates,
                    client: AuthsiaBridgeClient.shared,
                    backupService: backupService,
                    folderPath: normalizeFolderPath(folder),
                    configPath: configPath
                )
                let alreadyManaged = discovery.managedStubPaths.count
                print(Self.renderAdoptionSummary(summary, alreadyManaged: alreadyManaged))

                if summary.adopted > 0 {
                    switch await ShellConfigService().ensureShellIntegration() {
                    case .added(let path):
                        print("Enabled Authsia shell integration in \(path).")
                        print("Run 'eval \"$(authsia init zsh)\"' now (or open a new terminal) so git can use adopted keys.")
                    case .alreadyPresent:
                        print("Shell integration already enabled. Open a new terminal so adopted keys load into SSH_AUTH_SOCK.")
                    case .unsupported:
                        print("Add 'eval \"$(authsia init zsh)\"' to your shell startup file so git can use adopted keys.")
                    }
                }
            }
        }

        static func renderAdoptionSummary(
            _ summary: SSHAdoptionService.AdoptionSummary,
            alreadyManaged: Int
        ) -> String {
            var parts = [
                "Adopted \(summary.adopted) SSH key\(summary.adopted == 1 ? "" : "s") for Authsia management.",
            ]
            if summary.added > 0 && summary.managedExisting > 0 {
                parts.append("Added \(summary.added) new vault item\(summary.added == 1 ? "" : "s").")
            }
            if summary.managedExisting > 0 {
                parts.append(
                    "Replaced \(summary.managedExisting) local key" +
                    "\(summary.managedExisting == 1 ? "" : "s") already in the vault."
                )
            }
            parts.append("Skipped \(summary.skipped).")
            if alreadyManaged > 0 {
                parts.append("Already managed \(alreadyManaged).")
            }
            return parts.joined(separator: " ")
        }

        func validateRevertOptions() throws {
            if revert != nil && revertAll {
                throw ValidationError(
                    "--revert and --revert-all cannot be used together. " +
                        "Use --revert <path> for one key or --revert-all for every backup."
                )
            }
            if machine != nil && revert == nil && !revertAll {
                throw ValidationError(
                    "--machine is only valid with --revert or --revert-all. " +
                        "Example: authsia ssh adopt --revert-all --machine <name>"
                )
            }
        }

        static func normalizedRevertPath(
            _ path: String,
            currentDirectoryPath: String = FileManager.default.currentDirectoryPath,
            homeDirectoryPath: String = FileManager.default.homeDirectoryForCurrentUser.path,
            fileExists: (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }
        ) -> String {
            let expandedPath = NSString(string: path).expandingTildeInPath
            if expandedPath.hasPrefix("/") {
                return (expandedPath as NSString).standardizingPath
            }

            let currentDirectoryCandidate = FilePathNormalizer.absoluteStandardizedPath(
                expandedPath,
                currentDirectoryPath: currentDirectoryPath
            )
            guard !expandedPath.contains("/") else {
                return currentDirectoryCandidate
            }
            guard !fileExists(currentDirectoryCandidate) else {
                return currentDirectoryCandidate
            }

            let defaultSSHPath = ((homeDirectoryPath as NSString)
                .appendingPathComponent(".ssh") as NSString)
                .appendingPathComponent(expandedPath)
            return (defaultSSHPath as NSString).standardizingPath
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

        private func handleRevert(backupService: BackupService, path: String, machine: String?) async throws {
            let expandedPath = Self.normalizedRevertPath(path)

            let candidates = await backupService.listBackups(for: expandedPath, machineName: machine)
            guard let target = SSHAdoptionService.latestActiveAdoptionBackup(from: candidates) else {
                if try SSHAdoptionService.restoreManagedStub(
                    at: expandedPath,
                    client: AuthsiaBridgeClient.shared,
                    folderPath: normalizeFolderPath(folder)
                ) {
                    print("Successfully restored \(expandedPath) from Authsia vault item.")
                    return
                }

                if candidates.contains(where: { $0.kind == .sshAdoption }) {
                    print("All SSH adoption backups for \(expandedPath) have already been restored.")
                    if machine == nil {
                        print(
                            "Tip: run 'authsia scrape --list-modified --all-machines' " +
                            "to see backups from other machines,"
                        )
                        print("     then use --machine <name> to revert from a specific machine.")
                    }
                    return
                }

                let error = BackupService.BackupError.noBackupFound(expandedPath)
                print("Failed to revert: \(error.localizedDescription)")
                if machine == nil {
                    print(
                        "Tip: run 'authsia scrape --list-modified --all-machines' " +
                        "to see backups from other machines,"
                    )
                    print("     then use --machine <name> to revert from a specific machine.")
                }
                throw error
            }

            print("Reverting: \(expandedPath)")
            print("  Backup from:  \(target.displayMachine)")
            print("  Created:      \(target.formattedDate)")
            print("  Hash:         \(target.fileHash)")
            print("")

            do {
                try await backupService.restoreBackup(entry: target)
                print("Successfully reverted \(expandedPath)")
            } catch {
                print("Failed to revert: \(error.localizedDescription)")
                if machine == nil {
                    print(
                        "Tip: run 'authsia scrape --list-modified --all-machines' " +
                        "to see backups from other machines,"
                    )
                    print("     then use --machine <name> to revert from a specific machine.")
                }
                throw error
            }
        }

        private func handleRevertAll(backupService: BackupService, machine: String?) async throws {
            let backups = await backupService.listBackups(machineName: machine)
            let activeAdoptionBackups = SSHAdoptionService.latestActiveAdoptionBackupsByPath(from: backups)

            guard !activeAdoptionBackups.isEmpty else {
                print("No active SSH adoption backups found.")
                if machine == nil {
                    print(
                        "Tip: run 'authsia scrape --list-modified --all-machines' " +
                        "to see backups from other machines,"
                    )
                    print("     then use --machine <name> to revert from a specific machine.")
                }
                return
            }

            print("Reverting SSH adoption backups:")
            for backup in activeAdoptionBackups {
                print("  - \(backup.originalPath)")
                print("    Backup from: \(backup.displayMachine), created: \(backup.formattedDate)")
            }

            guard CLIPrompt.confirm("Proceed with revert?", defaultValue: false) else {
                print("Cancelled.")
                return
            }

            var failedPaths: [String] = []
            for backup in activeAdoptionBackups {
                do {
                    try await backupService.restoreBackup(entry: backup)
                    print("Reverted: \(backup.originalPath)")
                } catch {
                    failedPaths.append(backup.originalPath)
                    print("Failed to revert \(backup.originalPath): \(error.localizedDescription)")
                }
            }

            if !failedPaths.isEmpty {
                throw CLIError.unsupported(
                    message: "Failed to revert \(failedPaths.count) SSH adoption backup" +
                        "\(failedPaths.count == 1 ? "" : "s")."
                )
            }
        }
    }

    struct Config: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "config",
            abstract: "Add or update an SSH config host entry with Authsia guidance",
            discussion: """
                Writes or updates a Host block in ~/.ssh/config that uses the
                Authsia-managed key via the SSH agent.

                Examples:
                  authsia ssh config --host github.com --key WorkKey
                  authsia ssh config --host github.com --alias github-work --key WorkKey --user git
                  authsia ssh config --host deploy.internal --key InfraKey --config ~/.ssh/config.d/work
                """
        )

        @Option(name: .long, help: "SSH host to configure, for example github.com")
        var host: String

        @Option(name: .long, help: "Optional SSH alias to use in the Host entry, for example github-work")
        var alias: String?

        @Option(name: .long, help: "Authsia SSH key name to load for this host")
        var key: String

        @Option(name: .long, help: "Optional SSH username to include in the host entry")
        var user: String?

        @Option(name: .long, help: "Path to SSH config file")
        var config: String = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh", isDirectory: true)
            .appendingPathComponent("config").path

        func run() throws {
            let trimmedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
            let trimmedAlias = alias?.trimmingCharacters(in: .whitespacesAndNewlines)
            let trimmedKey = key.trimmingCharacters(in: .whitespacesAndNewlines)
            let trimmedUser = user?.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmedHost.isEmpty else {
                throw ValidationError("SSH host cannot be empty. Example: --host github.com")
            }
            if let trimmedAlias, trimmedAlias.isEmpty {
                throw ValidationError("SSH alias cannot be empty. Omit --alias or provide a value like github-work.")
            }
            guard !trimmedKey.isEmpty else {
                throw ValidationError("SSH key name cannot be empty. Run `authsia list ssh --format table` to see key names.")
            }
            if let trimmedUser, trimmedUser.isEmpty {
                throw ValidationError("SSH user cannot be empty. Omit --user or provide a value like git.")
            }

            let entry = SSHConfigWriter.HostEntry(
                host: trimmedAlias ?? trimmedHost,
                hostname: trimmedHost,
                user: trimmedUser,
                keyName: trimmedKey
            )
            try SSHConfigWriter.upsertHostEntry(entry: entry, configPath: config)
            print("Updated SSH config for \(entry.host) at \(config).")
        }
    }

    struct GitSigning: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "git-signing",
            abstract: "Configure repo-local Git SSH signing with an allowed signers file",
            discussion: """
                Writes a .git/authsia/allowed_signers file and sets repo-local Git
                config for SSH-based commit and tag signing.

                Examples:
                  authsia ssh git-signing --principal dev@example.com --public-key ~/.ssh/work.pub
                  authsia ssh git-signing --principal dev@example.com --public-key ~/.ssh/work.pub --repo /path/to/repo
                """
        )

        @Option(name: .long, help: "Signing principal, usually the email used in Git signatures")
        var principal: String

        @Option(name: .long, help: "Path to the SSH public key file to use for signing")
        var publicKey: String

        @Option(name: .long, help: "Repository path to configure; defaults to the current directory")
        var repo: String = FileManager.default.currentDirectoryPath

        func run() throws {
            let result = try GitSigningConfigWriter.configure(
                repositoryPath: repo,
                principal: principal,
                publicKeyPath: publicKey
            )
            print(
                """
                Configured repo-local Git SSH signing.
                Git config: \(result.configURL.path)
                Allowed signers: \(result.allowedSignersURL.path)
                """
            )
        }
    }
}
