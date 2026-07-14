import ArgumentParser
import Foundation
import Darwin

struct Inject: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "inject",
        abstract: "Inject resolved secrets into a template",
        discussion: """
            Reads a template from stdin (or --in-file), resolves all authsia://
            references inline, and writes the result to stdout (or --out-file).

            The output contains plaintext secrets — do not commit to version control.
            Safe to pipe directly into another command.

            Examples:
              authsia inject < config.template.yaml > config.yaml
              authsia inject --in-file nginx.template.conf --out-file nginx.conf
              cat docker-compose.template.yml | authsia inject | docker compose -f - up
            """
    )

    @Option(name: .customLong("in-file"), help: "Input template file (default: stdin)")
    var inFile: String?

    @Option(name: .customLong("out-file"), help: "Output file path (default: stdout); sets 0600 permissions")
    var outFile: String?

    mutating func run() throws {
        let inFile = self.inFile
        let outFile = self.outFile
        try AuthsiaBridgeClient.shared.withRequestedCommand(.inject) {
            try Inject.authorizeAutomationAccess()

            // 1. Read template
            let content: String
            if let inFile {
                do {
                    content = try String(contentsOfFile: inFile, encoding: .utf8)
                } catch {
                    throw CLIError.unsupported(
                        message: "Cannot read input file '\(inFile)': \(error.localizedDescription)"
                    )
                }
            } else {
                let stdinData = FileHandle.standardInput.readDataToEndOfFile()
                guard !stdinData.isEmpty, let decoded = String(data: stdinData, encoding: .utf8) else {
                    // Empty or non-UTF-8 stdin — nothing to inject
                    return
                }
                content = decoded
            }

            // 2. Process template
            let result = try Self.processTemplate(content, resolver: AuthsiaBridgeClient.shared)

            // 3. Warn if stderr is a TTY (not stdout, since warning goes to stderr)
            if isatty(STDERR_FILENO) != 0 {
                StandardError.writeLine(
                    "Warning: output contains plaintext secrets — do not commit to version control."
                )
            }

            // 4. Write output
            if let outFile {
                try ReadCmd.writeToFile(value: result, path: outFile)
            } else {
                FileHandle.standardOutput.write(Data(result.utf8))
            }
        }
    }

    // MARK: - Automation access preflight

    static func authorizeAutomationAccess(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        store: AccessCredentialStore = AccessCredentialStore(),
        now: Date = Date()
    ) throws {
        guard let credential = try AutomationAccessResolver.resolveActiveCredential(
            environment: environment,
            store: store,
            now: now
        ) else {
            return
        }
        try AutomationAccessResolver.authorizeCommand(.inject, credential: credential)
    }

    // MARK: - Testable core logic

    /// Find all `authsia://…` URIs in `content`, resolve them via `resolver`,
    /// replace every occurrence, and return the substituted string.
    ///
    /// - Collects ALL resolution errors before failing (never stops at first).
    /// - If no `authsia://` references are found, returns `content` unchanged.
    static func processTemplate(_ content: String, resolver: some SecretResolverClient) throws -> String {
        // 2. Scan for all authsia:// URIs using NSRegularExpression
        let pattern = #"authsia://[^\s"'<>\\]+"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else {
            throw CLIError.unsupported(message: "Internal error: failed to compile URI regex").asValidationError
        }

        let nsContent = content as NSString
        let range = NSRange(location: 0, length: nsContent.length)
        let matches = regex.matches(in: content, range: range)

        guard !matches.isEmpty else {
            // No references — pass through unchanged
            return content
        }

        // 3. Collect unique URIs
        var uniqueURIs: [String] = []
        var seen = Set<String>()
        for match in matches {
            let uri = nsContent.substring(with: match.range)
            if seen.insert(uri).inserted {
                uniqueURIs.append(uri)
            }
        }

        // Resolve all unique URIs, collecting every error before failing
        var resolvedValues: [String: String] = [:]
        var errors: [(uri: String, error: Error)] = []

        let internalResolver = SecretReferenceResolver(client: resolver)
        for uri in uniqueURIs {
            do {
                let ref = try SecretReference.parse(uri)
                let value = try internalResolver.resolve(ref)
                resolvedValues[uri] = value
            } catch {
                errors.append((uri: uri, error: error))
            }
        }

        if !errors.isEmpty {
            let details = errors.map { "  \($0.uri) → \($0.error.localizedDescription)" }
                .joined(separator: "\n")
            let message = "Failed to resolve \(errors.count) secret reference(s):\n\(details)"
            throw CLIError.unsupported(message: message)
        }

        // 4. Replace by position — process matches from last to first so earlier
        //    indices are not invalidated by prior replacements. This avoids cascading
        //    substitution if a resolved secret value happens to contain "authsia://".
        var result = content
        for match in matches.reversed() {
            let uri = nsContent.substring(with: match.range)
            guard let replacement = resolvedValues[uri] else { continue }
            let swiftRange = Range(match.range, in: result)!
            result.replaceSubrange(swiftRange, with: replacement)
        }

        return result
    }
}
