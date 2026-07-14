import Foundation
import CryptoKit
import AuthenticatorCore

enum SSHKeyMetadataResolver {
    struct Metadata: Equatable {
        let publicKey: String
        let comment: String
        let fingerprint: String
        let keyType: SSHKeyType
    }

    enum ResolverError: LocalizedError {
        case unreadablePublicKey(String)
        case invalidPublicKey(String)
        case missingPublicKey(String)
        case publicKeyDerivationFailed(String, String)

        var errorDescription: String? {
            switch self {
            case .unreadablePublicKey(let path):
                return "Could not read SSH public key at \(path). Check the path or pass --public-key <path>."
            case .invalidPublicKey(let value):
                return "Invalid SSH public key: \(value). Pass a .pub file that starts with ssh-ed25519, ssh-rsa, or similar."
            case .missingPublicKey(let path):
                return "No SSH public key found at \(path). Provide --public-key or keep a .pub file next to the private key."
            case .publicKeyDerivationFailed(let path, let reason):
                return "Could not derive SSH public key from \(path): \(reason). Provide --public-key <path>."
            }
        }
    }

    static func parsePublicKeyLine(
        _ line: String,
        fallbackComment: String
    ) throws -> Metadata {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmed.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count >= 2 else {
            throw ResolverError.invalidPublicKey(trimmed)
        }

        let keyData = String(parts[1])
        guard let decodedKey = Data(base64Encoded: keyData) else {
            throw ResolverError.invalidPublicKey(trimmed)
        }

        let comment: String
        if parts.count > 2 {
            comment = String(parts[2]).trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            comment = fallbackComment
        }

        return Metadata(
            publicKey: trimmed,
            comment: comment.isEmpty ? fallbackComment : comment,
            fingerprint: "SHA256:" + Data(SHA256.hash(data: decodedKey)).base64EncodedString(),
            keyType: SSHKeyTypeDetector.detect(publicKey: trimmed)
        )
    }

    static func readPublicKeyFile(
        at path: String,
        fallbackComment: String
    ) throws -> Metadata {
        guard FileManager.default.fileExists(atPath: path) else {
            throw ResolverError.missingPublicKey(path)
        }
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            throw ResolverError.unreadablePublicKey(path)
        }
        return try parsePublicKeyContent(content, fallbackComment: fallbackComment)
    }

    static func parsePublicKeyContent(
        _ content: String,
        fallbackComment: String
    ) throws -> Metadata {
        guard let line = content
            .split(separator: "\n", omittingEmptySubsequences: true)
            .map({ $0.trimmingCharacters(in: .whitespaces) })
            .first(where: { !$0.isEmpty }) else {
            throw ResolverError.invalidPublicKey(content)
        }
        return try parsePublicKeyLine(line, fallbackComment: fallbackComment)
    }

    static func resolveMetadata(
        privateKeyPath: String,
        publicKeyPath: String?
    ) throws -> Metadata {
        let fallbackComment = (privateKeyPath as NSString).lastPathComponent
        let resolvedPublicKeyPath = publicKeyPath ?? "\(privateKeyPath).pub"
        if FileManager.default.fileExists(atPath: resolvedPublicKeyPath) {
            return try readPublicKeyFile(at: resolvedPublicKeyPath, fallbackComment: fallbackComment)
        }
        return try derivePublicKey(from: privateKeyPath, fallbackComment: fallbackComment)
    }

    static func looksLikePrivateKey(_ content: String) -> Bool {
        [
            "BEGIN OPENSSH PRIVATE KEY",
            "BEGIN RSA PRIVATE KEY",
            "BEGIN EC PRIVATE KEY",
            "BEGIN DSA PRIVATE KEY",
        ].contains { content.contains($0) }
    }

    private static func derivePublicKey(from privateKeyPath: String, fallbackComment: String) throws -> Metadata {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = ["-y", "-f", privateKeyPath]
        process.standardInput = FileHandle.nullDevice

        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr

        do {
            try process.run()
        } catch {
            throw ResolverError.publicKeyDerivationFailed(privateKeyPath, error.localizedDescription)
        }
        process.waitUntilExit()

        let stdoutText = String(
            data: stdout.fileHandleForReading.readDataToEndOfFile(),
            encoding: .utf8
        ) ?? ""
        let stderrText = String(
            data: stderr.fileHandleForReading.readDataToEndOfFile(),
            encoding: .utf8
        ) ?? ""

        guard process.terminationStatus == 0 else {
            let reason = stderrText.trimmingCharacters(in: .whitespacesAndNewlines)
            throw ResolverError.publicKeyDerivationFailed(
                privateKeyPath,
                reason.isEmpty ? "ssh-keygen exited with status \(process.terminationStatus)" : reason
            )
        }

        return try parsePublicKeyContent(stdoutText, fallbackComment: fallbackComment)
    }
}
