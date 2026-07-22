import ArgumentParser
import Foundation
import AuthenticatorCore

struct Add: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "add",
        abstract: "Add a new item",
        discussion: """
            Creates vault items in Authsia.

            Subcommands:
              api-key    Add API key credentials
              password   Add username/password credentials
              cert       Add certificate and optional private key
              note       Add secure note content
              ssh        Add SSH key pair metadata

            Examples:
              authsia add api-key --name Stripe --key -
              authsia add api-key --name Stripe --token -
              authsia add password --name GitHub --username dev@example.com --password -
              authsia add cert --name prod-cert --cert-file cert.pem --key-file key.pem
              authsia add note --title "PagerDuty Runbook" --content-file runbook.md
              authsia add ssh --name deploy --public-key id_ed25519.pub --private-key id_ed25519 --comment "deploy@prod" --fingerprint "SHA256:..."
            """,
        subcommands: [AddAPIKey.self, AddPassword.self, AddCertificate.self, AddNote.self, AddSSH.self]
    )
}

struct AddAPIKey: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "api-key",
        abstract: "Add an API key",
        discussion: """
            Adds an API key item.

            Examples:
              authsia add api-key --name Stripe --key -
              authsia add api-key --name Stripe --token - --website https://dashboard.stripe.com
            """
    )

    @Option(name: .long) var name: String
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
    @Option(name: .long, help: "Environment tag (repeatable; use All for every environment; omit for Default)")
    var environment: [String] = []
    @Option(name: .long) var format: OutputFormat = .json

    func run() throws {
        let keyValue = try resolveAPIKeySecret(key: key, token: token, prompt: "API Key")
        let expiry = try expiresAt.map { try ExpiryDateParser.parse($0) }
        let result = try AuthsiaBridgeClient.shared.addAPIKey(
            name: name,
            key: keyValue,
            website: website,
            notes: notes,
            folderPath: normalizeFolderPath(folder),
            expiresAt: expiry,
            environments: environment
        )
        let output = try OutputFormatter.formatWriteResult(result, format: format)
        print(output)
    }
}

struct AddPassword: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "password",
        abstract: "Add a password",
        discussion: """
            Adds a password item.

            Examples:
              authsia add password --name GitHub --username dev@example.com --password -
              authsia add password --name Stripe --username svc --password - --website https://dashboard.stripe.com
            """
    )

    @Option(name: .long) var name: String
    @Option(name: .long) var username: String
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
    @Option(name: .long, help: "Environment tag (repeatable; use All for every environment; omit for Default)")
    var environment: [String] = []
    @Option(name: .long) var format: OutputFormat = .json

    func run() throws {
        let passwordValue = try StdinReader.resolveSecret(option: password, prompt: "Password")
        let expiry = try expiresAt.map { try ExpiryDateParser.parse($0) }
        let result = try AuthsiaBridgeClient.shared.addPassword(
            name: name,
            username: username,
            password: passwordValue,
            website: website,
            notes: notes,
            folderPath: normalizeFolderPath(folder),
            expiresAt: expiry,
            environments: environment
        )
        let output = try OutputFormatter.formatWriteResult(result, format: format)
        print(output)
    }
}

struct AddCertificate: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "cert",
        abstract: "Add a certificate",
        discussion: """
            Adds a certificate item from files or stdin.

            Examples:
              authsia add cert --name prod-cert --cert-file cert.pem
              authsia add cert --name tls-cert --cert-file cert.pem --key-file key.pem --folder PKI/Prod
            """
    )

    @Option(name: .long) var name: String
    @Option(name: [.customLong("cert-file"), .customLong("certificate")]) var certFile: String
    @Option(name: .customLong("key-file")) var keyFile: String?
    @Option(name: .long) var notes: String?
    @Option(
        name: .shortAndLong,
        help: "Folder path (supports nested paths like Team/API)",
        completion: .custom(ShellCompletionMetadata.completeFolders)
    )
    var folder: String?
    @Option(name: .long, help: "Environment tag (repeatable; use All for every environment; omit for Default)")
    var environment: [String] = []
    @Option(name: .long) var format: OutputFormat = .json

    func run() throws {
        let certificate = try StdinReader.readFileOrStdin(certFile)
        let privateKey = try keyFile.map { try StdinReader.readFileOrStdin($0) }
        let result = try AuthsiaBridgeClient.shared.addCertificate(
            name: name,
            certificate: certificate,
            privateKey: privateKey,
            notes: notes,
            folderPath: normalizeFolderPath(folder),
            environments: environment
        )
        let output = try OutputFormatter.formatWriteResult(result, format: format)
        print(output)
    }
}

struct AddNote: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "note",
        abstract: "Add a secure note",
        discussion: """
            Adds a secure note.

            Examples:
              authsia add note --title "Runbook" --content -
              authsia add note --title "Oncall Checklist" --content-file checklist.md --folder Ops/Runbooks
            """
    )

    @Option(name: .long) var title: String
    @Option(name: .long) var content: String?
    @Option(name: .customLong("content-file")) var contentFile: String?
    @Option(
        name: .shortAndLong,
        help: "Folder path (supports nested paths like Team/API)",
        completion: .custom(ShellCompletionMetadata.completeFolders)
    )
    var folder: String?
    @Option(name: .long, help: "Environment tag (repeatable; use All for every environment; omit for Default)")
    var environment: [String] = []
    @Option(name: .long) var format: OutputFormat = .json

    func run() throws {
        let contentValue = try resolveNoteContent(content: content, contentFile: contentFile, requiresValue: true)
        let result = try AuthsiaBridgeClient.shared.addNote(
            title: title,
            content: contentValue,
            folderPath: normalizeFolderPath(folder),
            environments: environment
        )
        let output = try OutputFormatter.formatWriteResult(result, format: format)
        print(output)
    }
}

struct AddSSH: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ssh",
        abstract: "Add an SSH key",
        discussion: """
            Adds an SSH key item. Use 'authsia edit ssh' after adding to set
            approval policy (--approval) and host bindings (--hosts).

            Examples:
              authsia add ssh --name deploy --private-key id_ed25519
              authsia add ssh --name deploy --public-key id_ed25519.pub --private-key id_ed25519 --comment "deploy@prod" --fingerprint "SHA256:..."
              authsia add ssh --name ci-key --public-key ci.pub --private-key ci --comment "ci@runner" --fingerprint "SHA256:..." --folder Infra/CI
            """
    )

    @Option(name: .long) var name: String
    @Option(name: .customLong("public-key")) var publicKey: String?
    @Option(name: .customLong("private-key")) var privateKey: String
    @Option(name: .long) var comment: String?
    @Option(name: .long) var fingerprint: String?
    @Option(
        name: .shortAndLong,
        help: "Folder path (supports nested paths like Team/API)",
        completion: .custom(ShellCompletionMetadata.completeFolders)
    )
    var folder: String?
    @Option(name: .long, help: "Environment tag (repeatable; use All for every environment; omit for Default)")
    var environment: [String] = []
    @Option(name: .long) var format: OutputFormat = .json

    func run() throws {
        let privateKeyValue = try StdinReader.readFileOrStdin(privateKey)
        let metadata: SSHKeyMetadataResolver.Metadata
        if let publicKey {
            let publicKeyValue = try StdinReader.readFileOrStdin(publicKey)
            metadata = try SSHKeyMetadataResolver.parsePublicKeyContent(
                publicKeyValue,
                fallbackComment: (privateKey as NSString).lastPathComponent
            )
        } else {
            metadata = try SSHKeyMetadataResolver.resolveMetadata(
                privateKeyPath: NSString(string: privateKey).expandingTildeInPath,
                publicKeyPath: nil
            )
        }

        let result = try AuthsiaBridgeClient.shared.addSSH(
            name: name,
            publicKey: metadata.publicKey,
            privateKey: privateKeyValue,
            comment: comment ?? metadata.comment,
            fingerprint: fingerprint ?? metadata.fingerprint,
            keyType: metadata.keyType,
            folderPath: normalizeFolderPath(folder),
            environments: environment
        )
        let output = try OutputFormatter.formatWriteResult(result, format: format)
        print(output)
    }
}

private func resolveNoteContent(
    content: String?,
    contentFile: String?,
    requiresValue: Bool
) throws -> String {
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
                "Example: authsia add note --title Runbook --content-file runbook.md"
        ).asValidationError
    }
    if requiresValue {
        throw CLIError.unsupported(
            message: "Provide --content - or --content-file for notes. " +
                "Example: authsia add note --title Runbook --content-file runbook.md"
        ).asValidationError
    }
    return ""
}

private func resolveAPIKeySecret(key: String?, token: String?, prompt: String) throws -> String {
    if key != nil && token != nil {
        throw ValidationError("Use either --key or --token, not both. Example: authsia add api-key --name Stripe --key -")
    }
    let optionName = token != nil ? "token" : "key"
    return try StdinReader.resolveSecret(
        option: key ?? token,
        prompt: prompt,
        optionName: optionName,
        usageExample: "printf '%s\\n' \"$API_KEY\" | authsia add api-key --name Stripe --\(optionName) -"
    )
}
