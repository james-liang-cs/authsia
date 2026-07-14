import ArgumentParser
import Foundation

struct Convert: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "convert",
        abstract: "Convert vault items between supported categories",
        discussion: """
            Converts one vault item category to another without printing secret material.

            Subcommands:
              password   Convert a password item

            Examples:
              authsia convert password Stripe --to api-key
            """,
        subcommands: [ConvertPassword.self]
    )
}

struct ConvertPassword: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "password",
        abstract: "Convert a password to an API key",
        discussion: """
            Converts a password item to a first-class API key item.
            The password secret becomes the API key, and the username is preserved in notes.

            Examples:
              authsia convert password Stripe --to api-key
            """
    )

    enum Target: String, ExpressibleByArgument {
        case apiKey = "api-key"
    }

    @Argument var query: String
    @Option(name: .long, help: "Conversion target. Supported value: api-key")
    var to: Target
    @Option(name: .long) var format: OutputFormat = .json

    func run() throws {
        guard to == .apiKey else {
            throw ValidationError("Unsupported conversion target. Use: --to api-key")
        }
        let result = try AuthsiaBridgeClient.shared.convertPasswordToAPIKey(query: query)
        let output = try OutputFormatter.formatWriteResult(result, format: format)
        print(output)
    }
}
