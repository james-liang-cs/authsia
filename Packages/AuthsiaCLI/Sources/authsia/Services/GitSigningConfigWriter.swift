import ArgumentParser
import Foundation

enum GitSigningConfigWriter {
    struct Result: Equatable {
        let gitDirectoryURL: URL
        let configURL: URL
        let allowedSignersURL: URL
    }

    static func configure(
        repositoryPath: String,
        principal: String,
        publicKeyPath: String
    ) throws -> Result {
        let trimmedPrincipal = principal.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedPrincipal.isEmpty else {
            throw ValidationError(
                "Git signing principal cannot be empty. Example: --principal dev@example.com"
            )
        }

        let trimmedPublicKeyPath = publicKeyPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedPublicKeyPath.isEmpty else {
            throw ValidationError("Public key path cannot be empty. Example: --public-key ~/.ssh/id_ed25519.pub")
        }

        let publicKeyURL = URL(fileURLWithPath: trimmedPublicKeyPath)
        guard FileManager.default.fileExists(atPath: publicKeyURL.path) else {
            throw ValidationError(
                "Public key file not found at \(publicKeyURL.path). Generate one with `authsia ssh generate`, " +
                    "or pass an existing .pub file with --public-key."
            )
        }

        let publicKey = try readPublicKey(at: publicKeyURL)
        let repositoryURL = URL(fileURLWithPath: repositoryPath, isDirectory: true)
        let gitDirectoryURL = try resolveGitDirectory(for: repositoryURL)
        let authsiaDirectoryURL = gitDirectoryURL.appendingPathComponent("authsia", isDirectory: true)
        try FileManager.default.createDirectory(at: authsiaDirectoryURL, withIntermediateDirectories: true)

        let allowedSignersURL = authsiaDirectoryURL.appendingPathComponent("allowed_signers")
        let configURL = gitDirectoryURL.appendingPathComponent("config")
        let allowedSignerLine = "\(trimmedPrincipal) \(publicKey)\n"

        try allowedSignerLine.write(to: allowedSignersURL, atomically: true, encoding: .utf8)

        let existingConfig = (try? String(contentsOf: configURL, encoding: .utf8)) ?? ""
        var updatedConfig = existingConfig
        updatedConfig = upsertConfigValue(in: updatedConfig, section: "gpg", subsection: nil, key: "format", value: "ssh")
        updatedConfig = upsertConfigValue(in: updatedConfig, section: "commit", subsection: nil, key: "gpgsign", value: "true")
        updatedConfig = upsertConfigValue(in: updatedConfig, section: "tag", subsection: nil, key: "gpgsign", value: "true")
        updatedConfig = upsertConfigValue(in: updatedConfig, section: "user", subsection: nil, key: "signingkey", value: publicKeyURL.path)
        updatedConfig = upsertConfigValue(
            in: updatedConfig,
            section: "gpg",
            subsection: "ssh",
            key: "allowedSignersFile",
            value: allowedSignersURL.path
        )

        try updatedConfig.write(to: configURL, atomically: true, encoding: .utf8)

        return Result(
            gitDirectoryURL: gitDirectoryURL,
            configURL: configURL,
            allowedSignersURL: allowedSignersURL
        )
    }

    private static func readPublicKey(at url: URL) throws -> String {
        let trimmed = try String(contentsOf: url, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("ssh-") else {
            throw ValidationError(
                "Public key at \(url.path) does not look like an SSH public key. Pass a .pub file such as ~/.ssh/id_ed25519.pub."
            )
        }
        return trimmed
    }

    private static func resolveGitDirectory(for repositoryURL: URL) throws -> URL {
        let gitMarkerURL = repositoryURL.appendingPathComponent(".git")
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: gitMarkerURL.path, isDirectory: &isDirectory) {
            if isDirectory.boolValue {
                return gitMarkerURL
            }

            let contents = try String(contentsOf: gitMarkerURL, encoding: .utf8)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if contents.hasPrefix("gitdir: ") {
                let path = String(contents.dropFirst("gitdir: ".count))
                let resolved = URL(fileURLWithPath: path, relativeTo: repositoryURL).standardizedFileURL
                return resolved
            }
        }

        throw ValidationError(
            "Repository at \(repositoryURL.path) does not contain a .git directory. " +
                "Run from a Git repository or pass --repository <repo-path>."
        )
    }

    private static func upsertConfigValue(
        in content: String,
        section: String,
        subsection: String?,
        key: String,
        value: String
    ) -> String {
        let header = subsection.map { "[\(section) \"\($0)\"]" } ?? "[\(section)]"
        let keyLine = "\t\(key) = \(value)"
        let lines = content.isEmpty ? [] : content.components(separatedBy: .newlines)
        var output: [String] = []
        var index = 0
        var replacedSection = false

        while index < lines.count {
            let line = lines[index]
            if line == header {
                if !replacedSection {
                    output.append(header)
                    index += 1
                    var inserted = false

                    while index < lines.count, !lines[index].hasPrefix("[") {
                        let current = lines[index]
                        let trimmed = current.trimmingCharacters(in: .whitespaces)
                        if trimmed.hasPrefix("\(key) =") || trimmed.hasPrefix("\(key)=") {
                            if !inserted {
                                output.append(keyLine)
                                inserted = true
                            }
                        } else if !current.isEmpty {
                            output.append(current)
                        }
                        index += 1
                    }

                    if !inserted {
                        output.append(keyLine)
                    }
                    replacedSection = true
                    continue
                }

                index += 1
                while index < lines.count, !lines[index].hasPrefix("[") {
                    index += 1
                }
                continue
            }

            output.append(line)
            index += 1
        }

        if !replacedSection {
            if !output.isEmpty, !output.last!.isEmpty {
                output.append("")
            }
            output.append(header)
            output.append(keyLine)
        }

        return output.joined(separator: "\n").trimmingCharacters(in: .newlines) + "\n"
    }
}
