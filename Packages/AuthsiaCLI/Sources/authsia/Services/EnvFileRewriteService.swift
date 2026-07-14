import Foundation

struct EnvFileRewriteService {

    // MARK: - Diff types (mirrors ShellConfigService for display reuse)

    struct ConfigChange {
        let filePath: String
        let originalLine: String
        let replacementLine: String
        let lineNumber: Int
        let secret: DetectedSecret
    }

    struct DiffResult {
        let filePath: String
        let changes: [ConfigChange]
        let additions: Int
        let deletions: Int
    }

    // MARK: - Diff generation

    static func generateDiff(for secrets: [DetectedSecret], folderPath: String? = nil) -> [DiffResult] {
        let grouped = Dictionary(grouping: secrets) { $0.filePath }
        return grouped.map { filePath, fileSecrets in
            let changes = fileSecrets
                .map { secret in
                    ConfigChange(
                        filePath: filePath,
                        originalLine: secret.originalLine,
                        replacementLine: replacementLine(for: secret, folderPath: folderPath),
                        lineNumber: secret.lineNumber,
                        secret: secret
                    )
                }
                .sorted { $0.lineNumber < $1.lineNumber }
            return DiffResult(
                filePath: filePath,
                changes: changes,
                additions: changes.count,
                deletions: changes.count
            )
        }
    }

    // MARK: - Diff display (matches ShellConfigService format)

    static func displayDiff(_ diffs: [DiffResult]) {
        for diff in diffs {
            let firstLine = diff.changes.first?.lineNumber ?? 0
            print("--- \(diff.filePath)")
            print("+++ \(diff.filePath)")
            print("@@ -\(firstLine),\(diff.deletions) +\(firstLine),\(diff.additions) @@")
            for change in diff.changes {
                print("-\(change.secret.redactedOriginalLine)")
                print("+\(change.replacementLine)")
            }
            print("")
        }
    }

    // MARK: - Atomic file rewrite

    /// Replace secret lines in-place with `authsia://` reference URIs.
    /// Reads each file once, patches by 1-based line number (descending to preserve indices), writes atomically.
    static func rewrite(
        secrets: [DetectedSecret],
        folderPath: String? = nil,
        referenceBySecretID: [UUID: String] = [:]
    ) throws {
        let grouped = Dictionary(grouping: secrets) { $0.filePath }

        for (filePath, fileSecrets) in grouped {
            let content = try String(contentsOfFile: filePath, encoding: .utf8)
            var lines = content.components(separatedBy: .newlines)

            // Process descending so earlier insertions don't shift subsequent indices
            let sorted = fileSecrets.sorted { $0.lineNumber > $1.lineNumber }

            for secret in sorted {
                let index = secret.lineNumber - 1   // 1-based → 0-based
                guard index >= 0, index < lines.count else { continue }
                guard lines[index] == secret.originalLine else {
                    throw RewriteError.staleLine(filePath: filePath, lineNumber: secret.lineNumber)
                }
                let comment = "# Migrated to Authsia - Original: \(secret.key)"
                let replacement = "\(secret.key)=\(referenceBySecretID[secret.id] ?? secret.secretReferenceURI(folderPath: folderPath))"
                lines[index] = comment
                lines.insert(replacement, at: index + 1)
            }

            let newContent = lines.joined(separator: "\n")
            try AtomicFileWriter.writeString(newContent, toFile: filePath)
        }
    }

    private static func replacementLine(for secret: DetectedSecret, folderPath: String?) -> String {
        "\(secret.key)=\(secret.secretReferenceURI(folderPath: folderPath))"
    }

    enum RewriteError: LocalizedError {
        case staleLine(filePath: String, lineNumber: Int)

        var errorDescription: String? {
            switch self {
            case .staleLine(let filePath, let lineNumber):
                return "Refusing to rewrite \(filePath): line \(lineNumber) changed after scan."
            }
        }
    }
}
