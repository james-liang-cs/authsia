import Foundation

/// Replaces a migrated SSH private key file with a stub comment
/// and annotates .ssh/config entries that reference it.
enum SSHKeyStubService {
    static func looksLikeManagedStub(_ content: String) -> Bool {
        content.contains("# This SSH key is managed by Authsia.")
    }

    static func stubPrivateKeyFile(
        at path: String,
        keyName: String,
        permissions: Int? = nil
    ) throws {
        let resolvedPermissions: Int
        if let permissions {
            resolvedPermissions = permissions
        } else {
            // Existing behavior: preserve current file's permissions
            let attrs = try FileManager.default.attributesOfItem(atPath: path)
            resolvedPermissions = attrs[.posixPermissions] as? Int ?? 0o600
        }

        let today = String(ISO8601DateFormatter().string(from: Date()).prefix(10))
        let stub = """
        # This SSH key is managed by Authsia.
        # Migrated: \(today)
        # Served by the built-in Authsia agent.
        # Shell setup: eval "$(authsia init zsh)"
        """
        try stub.write(toFile: path, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: resolvedPermissions], ofItemAtPath: path)
    }

    /// Inserts a comment above any `IdentityFile <keyPath>` line in the given config file.
    /// Safe to call when the config file doesn't exist (silently skips).
    /// Idempotent — will not insert the comment twice.
    static func annotateSSHConfig(at configPath: String, forKeyPath keyPath: String, keyName: String) {
        guard let content = try? String(contentsOfFile: configPath, encoding: .utf8) else {
            return  // config file doesn't exist or isn't readable — skip silently
        }

        let comment = "    # Key managed by Authsia — served by built-in Authsia agent"
        let normalizedKeyPath = normalizeKeyPath(keyPath)
        var lines = content.components(separatedBy: "\n")
        var insertions: [(index: Int, comment: String)] = []

        for (i, line) in lines.enumerated() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("IdentityFile") else { continue }
            let candidate = trimmed.dropFirst("IdentityFile".count)
                .trimmingCharacters(in: .whitespaces)
            guard normalizeKeyPath(candidate) == normalizedKeyPath else { continue }
            // Check if the Authsia comment already exists above (skip blank lines when looking back)
            var alreadyAnnotated = false
            var lookBack = i - 1
            while lookBack >= 0 {
                let above = lines[lookBack].trimmingCharacters(in: .whitespaces)
                if above.isEmpty {
                    lookBack -= 1
                    continue
                }
                if above.contains("Key managed by Authsia") {
                    alreadyAnnotated = true
                }
                break
            }
            guard !alreadyAnnotated else { continue }
            insertions.append((index: i, comment: comment))
        }

        guard !insertions.isEmpty else { return }

        // Insert comments from bottom to top so indices remain valid
        for insertion in insertions.reversed() {
            lines.insert(insertion.comment, at: insertion.index)
        }

        let updated = lines.joined(separator: "\n")
        try? updated.write(toFile: configPath, atomically: true, encoding: .utf8)
    }

    // MARK: - Private

    private static func normalizeKeyPath(_ path: String) -> String {
        NSString(string: path).expandingTildeInPath
    }
}
