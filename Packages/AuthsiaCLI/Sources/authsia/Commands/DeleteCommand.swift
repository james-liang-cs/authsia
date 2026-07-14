import ArgumentParser
import Foundation

struct Delete: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "delete",
        abstract: "Delete an item",
        discussion: """
            Deletes vault items.

            Subcommands:
              api-key    Delete API key item
              password   Delete password item
              cert       Delete certificate item
              note       Delete secure note
              ssh        Delete SSH key item
              folder     Delete a vault folder

            Examples:
              authsia delete api-key Stripe --force
              authsia delete password GitHub
              authsia delete password 11111111-1111-1111-1111-111111111111 --force
              authsia delete cert prod-cert --force
              authsia delete note "Runbook" --force
              authsia delete ssh deploy --force
              authsia delete folder Workspaces/demo --force
            """,
        subcommands: [DeleteAPIKey.self, DeletePassword.self, DeleteCertificate.self, DeleteNote.self, DeleteSSH.self, DeleteFolder.self]
    )
}

struct DeleteAPIKey: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "api-key",
        abstract: "Delete an API key",
        discussion: """
            Deletes an API key item by name or ID.

            Examples:
              authsia delete api-key Stripe
              authsia delete api-key 11111111-1111-1111-1111-111111111111 --force
            """
    )

    @Argument var query: String
    @Option(name: .long, help: "Environment tag used to disambiguate the item") var environment: String?
    @Flag(name: .long) var force = false
    @Option(name: .long) var format: OutputFormat = .json

    func run() throws {
        try requireInteractiveDeletion(force: force)
        if !force {
            try confirmDeletion(kind: "API key", query: query)
        }
        let bridgeQuery = try resolveDeleteQuery(type: .apiKey, query: query, environment: environment)
        let result = try AuthsiaBridgeClient.shared.deleteAPIKey(query: bridgeQuery)
        let output = try OutputFormatter.formatWriteResult(result, format: format)
        print(output)
    }
}

struct DeletePassword: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "password",
        abstract: "Delete a password",
        discussion: """
            Deletes a password item by name or ID.

            Examples:
              authsia delete password GitHub
              authsia delete password 11111111-1111-1111-1111-111111111111 --force
              authsia delete password GitHub --force
            """
    )

    @Argument var query: String
    @Option(name: .long, help: "Environment tag used to disambiguate the item") var environment: String?
    @Flag(name: .long) var force = false
    @Option(name: .long) var format: OutputFormat = .json

    func run() throws {
        try requireInteractiveDeletion(force: force)
        if !force {
            try confirmDeletion(kind: "password", query: query)
        }
        let bridgeQuery = try resolveDeleteQuery(type: .password, query: query, environment: environment)
        let result = try AuthsiaBridgeClient.shared.deletePassword(query: bridgeQuery)
        let output = try OutputFormatter.formatWriteResult(result, format: format)
        print(output)
    }
}

struct DeleteCertificate: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "cert",
        abstract: "Delete a certificate",
        discussion: """
            Deletes a certificate item.

            Examples:
              authsia delete cert prod-cert
              authsia delete cert prod-cert --force
            """
    )

    @Argument var query: String
    @Option(name: .long, help: "Environment tag used to disambiguate the item") var environment: String?
    @Flag(name: .long) var force = false
    @Option(name: .long) var format: OutputFormat = .json

    func run() throws {
        try requireInteractiveDeletion(force: force)
        if !force {
            try confirmDeletion(kind: "certificate", query: query)
        }
        let bridgeQuery = try resolveDeleteQuery(type: .certificate, query: query, environment: environment)
        let result = try AuthsiaBridgeClient.shared.deleteCertificate(query: bridgeQuery)
        let output = try OutputFormatter.formatWriteResult(result, format: format)
        print(output)
    }
}

struct DeleteNote: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "note",
        abstract: "Delete a secure note",
        discussion: """
            Deletes a secure note.

            Examples:
              authsia delete note "Runbook"
              authsia delete note "Runbook" --force
            """
    )

    @Argument var query: String
    @Option(name: .long, help: "Environment tag used to disambiguate the item") var environment: String?
    @Flag(name: .long) var force = false
    @Option(name: .long) var format: OutputFormat = .json

    func run() throws {
        try requireInteractiveDeletion(force: force)
        if !force {
            try confirmDeletion(kind: "note", query: query)
        }
        let bridgeQuery = try resolveDeleteQuery(type: .note, query: query, environment: environment)
        let result = try AuthsiaBridgeClient.shared.deleteNote(query: bridgeQuery)
        let output = try OutputFormatter.formatWriteResult(result, format: format)
        print(output)
    }
}

struct DeleteSSH: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ssh",
        abstract: "Delete an SSH key",
        discussion: """
            Deletes an SSH key item.

            Examples:
              authsia delete ssh deploy-key
              authsia delete ssh deploy-key --force
            """
    )

    @Argument var query: String
    @Option(name: .long, help: "Environment tag used to disambiguate the item") var environment: String?
    @Flag(name: .long) var force = false
    @Option(name: .long) var format: OutputFormat = .json

    func run() throws {
        try requireInteractiveDeletion(force: force)
        if !force {
            try confirmDeletion(kind: "ssh key", query: query)
        }
        let bridgeQuery = try resolveDeleteQuery(type: .ssh, query: query, environment: environment)
        let result = try AuthsiaBridgeClient.shared.deleteSSH(query: bridgeQuery)
        let output = try OutputFormatter.formatWriteResult(result, format: format)
        print(output)
    }
}

struct DeleteFolder: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "folder",
        abstract: "Delete a vault folder",
        discussion: """
            Deletes a vault folder and any vault items under it.

            Examples:
              authsia delete folder Workspaces/demo
              authsia delete folder Workspaces/demo --force
            """
    )

    @Argument var path: String
    @Flag(name: .long) var force = false
    @Option(name: .long) var format: OutputFormat = .json

    func run() throws {
        try requireInteractiveDeletion(force: force)
        if !force {
            try confirmDeletion(kind: "vault folder", query: path)
        }
        let result = try AuthsiaBridgeClient.shared.deleteVaultFolder(path: path)
        let output = try OutputFormatter.formatWriteResult(result, format: format)
        print(output)
    }
}

func confirmDeletion(kind: String, query: String) throws {
    StandardError.write("Are you sure you want to delete \(kind) '\(query)'? [y/N] ")
    guard let answer = readLine(), answer.lowercased() == "y" else {
        StandardError.writeLine("Cancelled.")
        throw ExitCode.failure
    }
}

func requireInteractiveDeletion(force: Bool, stdinIsTTY: Bool = TerminalContext.stdinIsTTY) throws {
    if !force && !stdinIsTTY {
        throw ValidationError("Deletion confirmation requires a TTY. Re-run with --force.")
    }
}

private func resolveDeleteQuery(
    type: VaultItemQueryType,
    query: String,
    environment: String?
) throws -> String {
    let payload = try AuthsiaBridgeClient.shared.list()
    return try VaultItemQueryResolver.resolve(
        type: type,
        query: query,
        environment: environment,
        payload: payload
    ).uuidString
}
