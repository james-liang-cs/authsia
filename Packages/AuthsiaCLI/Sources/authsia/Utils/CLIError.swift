import ArgumentParser
import Foundation

enum CLIError: Error, LocalizedError {
    struct MatchDescriptor: Equatable {
        let name: String
        let id: String
        let context: String?
        let commandHint: String?

        init(name: String, id: String, context: String? = nil, commandHint: String? = nil) {
            self.name = name
            self.id = id
            self.context = context
            self.commandHint = commandHint
        }
    }

    case noMatch(kind: String, query: String)
    case multipleMatches(kind: String, query: String, matches: [MatchDescriptor])
    case unsupported(message: String)

    var message: String {
        switch self {
        case .noMatch(let kind, let query):
            let command = Self.listCommand(for: kind)
            return "No \(kind) matches for '\(query)'.\n" +
                "Next: Run `\(command) --format table` to see available items and IDs, " +
                "then retry with an exact name or ID."
        case .multipleMatches(let kind, let query, let matches):
            let lines = matches.map { descriptor in
                if let context = descriptor.context, !context.isEmpty {
                    return "- \(descriptor.name) (\(descriptor.id)) [\(context)]"
                }
                return "- \(descriptor.name) (\(descriptor.id))"
            }.joined(separator: "\n")
            let commandHints = matches.compactMap(\.commandHint)
            let nextStep: String
            if commandHints.isEmpty {
                nextStep = "Next: Rerun with one exact ID from the list above instead of the name."
            } else {
                let commands = commandHints.map { "  \($0)" }.joined(separator: "\n")
                nextStep = "Next: Rerun with one exact ID:\n\(commands)"
            }
            return "Multiple \(kind) matches for '\(query)':\n\(lines)\n\(nextStep)"
        case .unsupported(let message):
            return message
        }
    }

    var errorDescription: String? {
        message
    }

    var asValidationError: ValidationError {
        ValidationError(message)
    }

    private static func listCommand(for kind: String) -> String {
        let normalized = kind.lowercased()
        if normalized.contains("api-key") || normalized.contains("api key") {
            return "authsia list api-keys"
        }
        if normalized.contains("password") {
            return "authsia list passwords"
        }
        if normalized.contains("cert") {
            return "authsia list certs"
        }
        if normalized.contains("note") {
            return "authsia list notes"
        }
        if normalized.contains("ssh") {
            return "authsia list ssh"
        }
        if normalized.contains("otp") || normalized.contains("account") {
            return "authsia list otp"
        }
        return "authsia list"
    }
}
