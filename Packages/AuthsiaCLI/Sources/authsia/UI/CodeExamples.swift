import Foundation

enum CodeExamples {

    static func showMigrationExamples(for secrets: [DetectedSecret], folderPath: String? = nil) {
        let envSecrets = secrets.filter { $0.isEnvFile }
        guard !envSecrets.isEmpty else { return }

        print("")
        print("═══════════════════════════════════════════════════════════════════")
        print("📖 .ENV MIGRATION — REPLACE SECRETS WITH AUTHSIA REFERENCES")
        print("═══════════════════════════════════════════════════════════════════")
        print("")
        print("Secrets have been stored in Authsia. Replace each hardcoded value")
        print("in your .env file with an authsia:// reference URI, then use")
        print("`authsia exec -- <command>` from that folder to run with secrets.")
        print("The file becomes safe to commit — it contains no secret data.")
        print("")

        // Primary recommendation: URI references in .env
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("Recommended: Update your .env file")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("")
        for secret in envSecrets {
            print("  # \(secret.key) (\(secret.type.description))")
            print("  Before: \(secret.redactedOriginalLine.trimmingCharacters(in: .whitespaces))")
            print("  After:  \(secret.key)=\(secret.secretReferenceURI(folderPath: folderPath))")
            print("")
        }
        print("Then run your command with secrets resolved automatically:")
        print("  authsia exec -- <your-command>")
        print("")
        print("Or read a single value:")
        if let first = envSecrets.first {
            print("  authsia read \"\(first.secretReferenceURI(folderPath: folderPath))\"")
        }
        print("")

        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("Shell / .env  (for apps that load .env directly)")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("")

        for secret in envSecrets {
            print(generateShellExample(secret, folderPath: folderPath))
            print("")
        }

        print("═══════════════════════════════════════════════════════════════════")
        print("📝 LINES TO REMOVE FROM YOUR .ENV FILE:")
        print("═══════════════════════════════════════════════════════════════════")
        print("")
        for secret in envSecrets {
            print("  \(secret.filePath):\(secret.lineNumber)")
            print("  - \(secret.redactedOriginalLine.trimmingCharacters(in: .whitespaces))")
            print("  + \(secret.key)=\(secret.secretReferenceURI(folderPath: folderPath))")
            print("")
        }
        print("═══════════════════════════════════════════════════════════════════")
    }

    private static func generateShellExample(_ secret: DetectedSecret, folderPath: String?) -> String {
        let uri = secret.secretReferenceURI(folderPath: folderPath)
        return """
        # Option A — Use authsia exec (recommended, secrets masked in output):
        authsia exec -- <your-command>

        # Option B — Inline with authsia read:
        export \(secret.key)=$(authsia read "\(uri)")
        """
    }
}
