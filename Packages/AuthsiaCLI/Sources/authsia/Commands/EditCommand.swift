import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore

struct Edit: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "edit",
        abstract: "Update an existing item",
        discussion: """
            Updates existing vault items.

            Subcommands:
              api-key    Update API key fields
              password   Update password fields
              cert       Update certificate data/metadata
              note       Update note title/content
              ssh        Update SSH metadata/keys

            Examples:
              authsia edit api-key Stripe --key -
              authsia edit password GitHub --username admin@example.com
              authsia edit cert prod-cert --notes "Rotated 2026-01-01"
              authsia edit note "Runbook" --content-file runbook-v2.md
              authsia edit ssh deploy --comment "deploy@new-cluster"
              authsia edit ssh deploy --approval always --hosts "github.com"
            """,
        subcommands: [EditAPIKey.self, EditPassword.self, EditCertificate.self, EditNote.self, EditSSH.self]
    )
}

struct EditAPIKey: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "api-key",
        abstract: "Update an API key",
        discussion: """
            Updates fields on an existing API key.

            Examples:
              authsia edit api-key Stripe --key -
              authsia edit api-key Stripe --website https://dashboard.stripe.com --folder Team/API
            """
    )

    @Argument var query: String

    @Option(name: .long) var name: String?
    @Option(name: .long) var key: String?
    @Option(name: .long) var token: String?
    @Option(name: .long) var website: String?
    @Option(name: .long) var notes: String?
    @Option(
        name: .shortAndLong,
        help: "Folder path (supports nested paths like Team/API)",
        completion: .custom(ShellCompletionMetadata.completeFolders)
    )
    var folder: String?
    @Option(name: .customLong("expires-at"), help: "Auto-destroy date (YYYY-MM-DD or ISO-8601 timestamp)")
    var expiresAt: String?
    @Flag(name: .customLong("clear-expires-at"), help: "Remove the auto-destroy date") var clearExpiresAt = false
    @Option(name: .long, help: "Environment tag used to disambiguate the item") var environment: String?
    @Option(name: .customLong("add-environment"), help: "Add an environment tag (repeatable)") var addEnvironment: [String] = []
    @Option(name: .customLong("remove-environment"), help: "Remove an environment tag (repeatable)") var removeEnvironment: [String] = []
    @Flag(name: .customLong("clear-environments"), help: "Remove all environment tags and make the item use the Default environment") var clearEnvironments = false
    @Option(name: .long) var format: OutputFormat = .json

    func run() throws {
        if expiresAt != nil && clearExpiresAt {
            throw ValidationError(
                "Use either --expires-at or --clear-expires-at, not both. " +
                    "Example: authsia edit api-key Stripe --clear-expires-at"
            )
        }
        let keyValue = try resolveOptionalAPIKeySecret(key: key, token: token)
        let expiry = try expiresAt.map { try ExpiryDateParser.parse($0) }
        let candidate = try resolveVaultItem(type: .apiKey, query: query, environment: environment)
        let replacement = try environmentReplacement(
            existing: candidate.environments,
            add: addEnvironment,
            remove: removeEnvironment,
            clear: clearEnvironments
        )

        let result = try AuthsiaBridgeClient.shared.updateAPIKey(
            query: candidate.id.uuidString,
            name: name,
            key: keyValue,
            website: website,
            notes: notes,
            folderPath: normalizeFolderPath(folder),
            expiresAt: expiry,
            clearExpiresAt: clearExpiresAt,
            environments: replacement
        )
        let output = try OutputFormatter.formatWriteResult(result, format: format)
        print(output)
    }
}

struct EditPassword: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "password",
        abstract: "Update a password",
        discussion: """
            Updates fields on an existing password.

            Examples:
              authsia edit password GitHub --password -
              authsia edit password Stripe --website https://dashboard.stripe.com --folder Team/API
            """
    )

    @Argument var query: String

    @Option(name: .long) var name: String?
    @Option(name: .long) var username: String?
    @Option(name: .long) var password: String?
    @Option(name: .long) var website: String?
    @Option(name: .long) var notes: String?
    @Option(
        name: .shortAndLong,
        help: "Folder path (supports nested paths like Team/API)",
        completion: .custom(ShellCompletionMetadata.completeFolders)
    )
    var folder: String?
    @Option(name: .customLong("expires-at"), help: "Auto-destroy date (YYYY-MM-DD or ISO-8601 timestamp)")
    var expiresAt: String?
    @Flag(name: .customLong("clear-expires-at"), help: "Remove the auto-destroy date") var clearExpiresAt = false
    @Option(name: .long, help: "Environment tag used to disambiguate the item") var environment: String?
    @Option(name: .customLong("add-environment"), help: "Add an environment tag (repeatable)") var addEnvironment: [String] = []
    @Option(name: .customLong("remove-environment"), help: "Remove an environment tag (repeatable)") var removeEnvironment: [String] = []
    @Flag(name: .customLong("clear-environments"), help: "Remove all environment tags and make the item use the Default environment") var clearEnvironments = false
    @Option(name: .long) var format: OutputFormat = .json

    func run() throws {
        if expiresAt != nil && clearExpiresAt {
            throw ValidationError(
                "Use either --expires-at or --clear-expires-at, not both. " +
                    "Example: authsia edit password GitHub --clear-expires-at"
            )
        }
        let passwordValue = try StdinReader.resolveOptionalSecret(option: password, prompt: "Password")
        let expiry = try expiresAt.map { try ExpiryDateParser.parse($0) }
        let candidate = try resolveVaultItem(type: .password, query: query, environment: environment)
        let replacement = try environmentReplacement(existing: candidate.environments, add: addEnvironment, remove: removeEnvironment, clear: clearEnvironments)

        let result = try AuthsiaBridgeClient.shared.updatePassword(
            query: candidate.id.uuidString,
            name: name,
            username: username,
            password: passwordValue,
            website: website,
            notes: notes,
            folderPath: normalizeFolderPath(folder),
            expiresAt: expiry,
            clearExpiresAt: clearExpiresAt,
            environments: replacement
        )
        let output = try OutputFormatter.formatWriteResult(result, format: format)
        print(output)
    }
}

struct EditCertificate: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "cert",
        abstract: "Update a certificate",
        discussion: """
            Updates certificate content or metadata.

            Examples:
              authsia edit cert prod-cert --cert-file cert-new.pem
              authsia edit cert prod-cert --key-file key-new.pem --notes "Rotated key"
            """
    )

    @Argument var query: String

    @Option(name: .long) var name: String?
    @Option(name: [.customLong("cert-file"), .customLong("certificate")]) var certFile: String?
    @Option(name: .customLong("key-file")) var keyFile: String?
    @Option(name: .long) var notes: String?
    @Option(
        name: .shortAndLong,
        help: "Folder path (supports nested paths like Team/API)",
        completion: .custom(ShellCompletionMetadata.completeFolders)
    )
    var folder: String?
    @Option(name: .long, help: "Environment tag used to disambiguate the item") var environment: String?
    @Option(name: .customLong("add-environment"), help: "Add an environment tag (repeatable)") var addEnvironment: [String] = []
    @Option(name: .customLong("remove-environment"), help: "Remove an environment tag (repeatable)") var removeEnvironment: [String] = []
    @Flag(name: .customLong("clear-environments"), help: "Remove all environment tags and make the item use the Default environment") var clearEnvironments = false
    @Option(name: .long) var format: OutputFormat = .json

    func run() throws {
        let certificate = try certFile.map { try StdinReader.readFileOrStdin($0) }
        let privateKey = try keyFile.map { try StdinReader.readFileOrStdin($0) }
        let candidate = try resolveVaultItem(type: .certificate, query: query, environment: environment)
        let replacement = try environmentReplacement(existing: candidate.environments, add: addEnvironment, remove: removeEnvironment, clear: clearEnvironments)
        let result = try AuthsiaBridgeClient.shared.updateCertificate(
            query: candidate.id.uuidString,
            name: name,
            certificate: certificate,
            privateKey: privateKey,
            notes: notes,
            folderPath: normalizeFolderPath(folder),
            environments: replacement
        )
        let output = try OutputFormatter.formatWriteResult(result, format: format)
        print(output)
    }
}

struct EditNote: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "note",
        abstract: "Update a secure note",
        discussion: """
            Updates title/content for a secure note.

            Examples:
              authsia edit note "Runbook" --content -
              authsia edit note "Runbook" --content-file runbook.md --folder Ops/Runbooks
            """
    )

    @Argument var query: String

    @Option(name: .long) var title: String?
    @Option(name: .long) var content: String?
    @Option(name: .customLong("content-file")) var contentFile: String?
    @Option(
        name: .shortAndLong,
        help: "Folder path (supports nested paths like Team/API)",
        completion: .custom(ShellCompletionMetadata.completeFolders)
    )
    var folder: String?
    @Option(name: .long, help: "Environment tag used to disambiguate the item") var environment: String?
    @Option(name: .customLong("add-environment"), help: "Add an environment tag (repeatable)") var addEnvironment: [String] = []
    @Option(name: .customLong("remove-environment"), help: "Remove an environment tag (repeatable)") var removeEnvironment: [String] = []
    @Flag(name: .customLong("clear-environments"), help: "Remove all environment tags and make the item use the Default environment") var clearEnvironments = false
    @Option(name: .long) var format: OutputFormat = .json

    func run() throws {
        let contentValue = try resolveNoteContent(content: content, contentFile: contentFile)
        let candidate = try resolveVaultItem(type: .note, query: query, environment: environment)
        let replacement = try environmentReplacement(existing: candidate.environments, add: addEnvironment, remove: removeEnvironment, clear: clearEnvironments)
        let result = try AuthsiaBridgeClient.shared.updateNote(
            query: candidate.id.uuidString,
            title: title,
            content: contentValue,
            folderPath: normalizeFolderPath(folder),
            environments: replacement
        )
        let output = try OutputFormatter.formatWriteResult(result, format: format)
        print(output)
    }
}

struct EditSSH: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ssh",
        abstract: "Update an SSH key",
        discussion: """
            Updates SSH key metadata and optional key material.

            Examples:
              authsia edit ssh deploy --comment "deploy@prod-v2"
              authsia edit ssh deploy --public-key deploy.pub --private-key deploy --folder Infra/SSH
              authsia edit ssh deploy --approval always
              authsia edit ssh deploy --hosts "github.com,*.corp.internal"
              authsia edit ssh deploy --hosts ""   # clear host bindings
            """
    )

    @Argument var query: String

    @Option(name: .long, help: "New display name for the key") var name: String?
    @Option(name: .customLong("public-key"), help: "Path to updated public key file") var publicKey: String?
    @Option(name: .customLong("private-key"), help: "Path to updated private key file") var privateKey: String?
    @Option(name: .long, help: "SSH key comment") var comment: String?
    @Option(name: .long, help: "SSH key fingerprint (SHA256:...)") var fingerprint: String?
    @Option(
        name: .shortAndLong,
        help: "Folder path (supports nested paths like Team/API)",
        completion: .custom(ShellCompletionMetadata.completeFolders)
    )
    var folder: String?
    @Option(name: .long, help: "Approval policy: always, session, or auto") var approval: String?
    @Option(name: .long, help: "Comma-separated bound hosts (e.g. github.com,*.corp.internal). Empty string clears.")
    var hosts: String?
    @Option(name: .long, help: "Environment tag used to disambiguate the item") var environment: String?
    @Option(name: .customLong("add-environment"), help: "Add an environment tag (repeatable)") var addEnvironment: [String] = []
    @Option(name: .customLong("remove-environment"), help: "Remove an environment tag (repeatable)") var removeEnvironment: [String] = []
    @Flag(name: .customLong("clear-environments"), help: "Remove all environment tags and make the item use the Default environment") var clearEnvironments = false
    @Option(name: .long, help: "Output format") var format: OutputFormat = .json

    func run() throws {
        if let approval {
            let validValues = ["always", "session", "auto"]
            guard validValues.contains(approval) else {
                throw ValidationError(
                    "Invalid approval policy '\(approval)'. Use: \(validValues.joined(separator: ", ")). " +
                        "Example: authsia edit ssh DeployKey --approval session"
                )
            }
        }

        let publicKeyValue = try publicKey.map { try StdinReader.readFileOrStdin($0) }
        let privateKeyValue = try privateKey.map { try StdinReader.readFileOrStdin($0) }
        let keyType = publicKeyValue.map { SSHKeyTypeDetector.detect(publicKey: $0) }

        // Map CLI approval string to wire enum value
        let approvalWire: String? = approval.map { value in
            switch value {
            case "always": return "alwaysPrompt"
            case "session": return "sessionBased"
            case "auto": return "autoApprove"
            default: return value
            }
        }

        // Parse comma-separated hosts: nil means don't change, empty string means clear
        let parsedHosts: [String]? = hosts.map { value in
            value.isEmpty ? [] : value.split(separator: ",").map { String($0.trimmingCharacters(in: .whitespaces)) }
        }
        let candidate = try resolveVaultItem(type: .ssh, query: query, environment: environment)
        let replacement = try environmentReplacement(existing: candidate.environments, add: addEnvironment, remove: removeEnvironment, clear: clearEnvironments)

        let result = try AuthsiaBridgeClient.shared.updateSSH(
            query: candidate.id.uuidString,
            name: name,
            publicKey: publicKeyValue,
            privateKey: privateKeyValue,
            comment: comment,
            fingerprint: fingerprint,
            folderPath: normalizeFolderPath(folder),
            keyType: keyType,
            approvalPolicy: approvalWire,
            boundHosts: parsedHosts,
            environments: replacement
        )
        let output = try OutputFormatter.formatWriteResult(result, format: format)
        print(output)
    }
}

private func resolveVaultItem(
    type: VaultItemQueryType,
    query: String,
    environment: String?
) throws -> VaultItemQueryResolver.Candidate {
    let payload = try AuthsiaBridgeClient.shared.list()
    return try VaultItemQueryResolver.resolveCandidate(
        type: type,
        query: query,
        environment: environment,
        payload: payload
    )
}

private func environmentReplacement(
    existing: [String],
    add: [String],
    remove: [String],
    clear: Bool
) throws -> [String]? {
    if clear && (!add.isEmpty || !remove.isEmpty) {
        throw ValidationError("--clear-environments cannot be combined with --add-environment or --remove-environment.")
    }
    guard clear || !add.isEmpty || !remove.isEmpty else { return nil }
    if clear { return [] }
    return VaultEnvironmentTags.normalize(
        existing.filter { !VaultEnvironmentTags.contains($0, in: remove) } + add
    )
}

private func resolveNoteContent(content: String?, contentFile: String?) throws -> String? {
    if let contentFile {
        return try StdinReader.readFileOrStdin(contentFile)
    }
    if let content {
        if content == "-" {
            return try StdinReader.readAll()
        }
        throw CLIError.unsupported(
            message: "Passing secret content as a command-line argument is not safe. " +
                "Use '--content -' to read from stdin, or '--content-file <path>' to read from a file. " +
                "Example: authsia edit note Runbook --content-file runbook.md"
        ).asValidationError
    }
    return nil
}

private func resolveOptionalAPIKeySecret(key: String?, token: String?) throws -> String? {
    if key != nil && token != nil {
        throw ValidationError("Use either --key or --token, not both. Example: authsia edit api-key Stripe --key -")
    }
    let optionName = token != nil ? "token" : "key"
    return try StdinReader.resolveOptionalSecret(
        option: key ?? token,
        prompt: "API Key",
        optionName: optionName,
        usageExample: "printf '%s\\n' \"$API_KEY\" | authsia edit api-key Stripe --\(optionName) -"
    )
}
