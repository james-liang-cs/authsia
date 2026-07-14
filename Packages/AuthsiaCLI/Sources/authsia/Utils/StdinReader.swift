import Darwin
import Foundation

struct StdinReader {
    static func readLine(
        from handle: FileHandle = .standardInput,
        usageExample: String = "printf '%s\\n' \"$SECRET\" | authsia add password --name API_KEY --username user --password -"
    ) throws -> String {
        if handle === FileHandle.standardInput {
            guard let line = Swift.readLine() else {
                throw CLIError.unsupported(
                    message: "Failed to read stdin. Pipe a value with '-', for example: \(usageExample)"
                ).asValidationError
            }
            return line
        }

        let data = handle.readDataToEndOfFile()
        guard let text = String(data: data, encoding: .utf8) else {
            throw CLIError.unsupported(message: "Failed to decode stdin as UTF-8. Retry with UTF-8 input.").asValidationError
        }
        return text.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
    }

    static func readAll(from handle: FileHandle = .standardInput) throws -> String {
        let data = handle.readDataToEndOfFile()
        guard let text = String(data: data, encoding: .utf8) else {
            throw CLIError.unsupported(message: "Failed to decode stdin as UTF-8. Retry with UTF-8 input.").asValidationError
        }
        return text
    }

    static func readFileOrStdin(_ path: String) throws -> String {
        if path == "-" {
            return try readAll()
        }
        return try String(contentsOfFile: path, encoding: .utf8)
    }

    /// Prompts the user to enter a secret interactively with echo disabled.
    /// Only works when stdin is a TTY.
    static func promptSecret(_ prompt: String, optionName: String = "password") throws -> String {
        guard isatty(fileno(stdin)) != 0 else {
            throw CLIError.unsupported(
                message: "Cannot prompt for secret in non-interactive mode. Use --\(optionName) - and pipe the value on stdin."
            ).asValidationError
        }
        var original = termios()
        tcgetattr(fileno(stdin), &original)
        var noecho = original
        noecho.c_lflag &= ~tcflag_t(ECHO)
        tcsetattr(fileno(stdin), TCSANOW, &noecho)
        defer {
            var restore = original
            tcsetattr(fileno(stdin), TCSANOW, &restore)
        }
        FileHandle.standardError.write(Data("\(prompt): ".utf8))
        guard let line = Swift.readLine() else {
            throw CLIError.unsupported(message: "Failed to read secret from terminal. Retry in an interactive terminal.").asValidationError
        }
        FileHandle.standardError.write(Data("\n".utf8))
        return line
    }

    /// Resolves a secret option value safely.
    /// - `nil` -> prompt interactively (TTY) or error (non-TTY)
    /// - `"-"` -> read from stdin pipe
    /// - any other value -> reject (secrets must not appear as CLI arguments)
    static func resolveSecret(
        option: String?,
        prompt: String,
        optionName: String = "password",
        usageExample: String = "printf '%s\\n' \"$SECRET\" | authsia add password --name API_KEY --username user --password -"
    ) throws -> String {
        if let option {
            if option == "-" {
                return try readLine(usageExample: usageExample)
            }
            throw CLIError.unsupported(
                message: "Passing secrets as command-line arguments is not safe (visible in shell history and process table). " +
                    "Use '--\(optionName) -' to read from stdin, or omit --\(optionName) to enter interactively."
            ).asValidationError
        }
        return try promptSecret(prompt, optionName: optionName)
    }

    /// Optional variant for edit commands where the field may not be updated.
    static func resolveOptionalSecret(
        option: String?,
        prompt: String,
        optionName: String = "password",
        usageExample: String = "printf '%s\\n' \"$SECRET\" | authsia edit password GitHub --password -"
    ) throws -> String? {
        guard let option else { return nil }
        if option == "-" {
            return try readLine(usageExample: usageExample)
        }
        throw CLIError.unsupported(
            message: "Passing secrets as command-line arguments is not safe (visible in shell history and process table). " +
                "Use '--\(optionName) -' to read from stdin, or omit --\(optionName) to enter interactively."
        ).asValidationError
    }
}
