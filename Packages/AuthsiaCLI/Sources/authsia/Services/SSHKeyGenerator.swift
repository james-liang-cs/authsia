import Foundation
import CryptoKit
import AuthenticatorCore

// MARK: - Vault client protocol

/// Narrow vault-client surface needed by SSHKeyGenerator. AuthsiaBridgeClient
/// conforms in production; tests substitute a fake.
protocol SSHKeyVaultClient {
    func sshKeyExists(named name: String) throws -> Bool
    func addSSH(
        name: String,
        publicKey: String,
        privateKey: String,
        comment: String,
        fingerprint: String,
        passphrase: String?,
        keyType: SSHKeyType?,
        isScraped: Bool,
        folderPath: String?,
        scrapeMachineName: String?,
        scrapeMachineId: String?
    ) throws -> WriteResult
}

extension AuthsiaBridgeClient: SSHKeyVaultClient {}

// MARK: - SSHKeyGenerator

enum SSHKeyGenerator {

    typealias KeyGenInvocation = (
        _ outputStem: URL,
        _ type: String,
        _ bits: Int?,
        _ comment: String
    ) throws -> Void

    enum GenerationError: LocalizedError {
        case emptyName
        case invalidType(String)
        case invalidRSABits(Int)
        case outputPathTaken(String)
        case nameAlreadyInVault(String)
        case vaultUnavailable(underlying: Error)
        case keyGenFailed(underlying: Error)
        case storeFailed(underlying: Error)
        case publicKeyWriteFailedAfterStore(underlying: Error)

        var errorDescription: String? {
            switch self {
            case .emptyName:
                return "SSH key name cannot be empty. Example: authsia ssh generate --name github-work"
            case .invalidType(let type):
                return "Invalid key type '\(type)'. Valid types: ed25519, rsa. Example: --type ed25519"
            case .invalidRSABits(let bits):
                return "Invalid RSA key size \(bits). Valid sizes: 2048, 3072, 4096. Example: --type rsa --bits 4096"
            case .outputPathTaken(let path):
                return "Refusing to overwrite existing SSH key output at \(path). Remove it first or choose a different --name/--path."
            case .nameAlreadyInVault(let name):
                return "An SSH key named '\(name)' already exists in the Authsia vault. Choose a different --name or edit the existing key."
            case .vaultUnavailable(let underlying):
                return "Authsia vault is locked or unreachable: \(underlying.localizedDescription). Run `authsia unlock` and retry."
            case .keyGenFailed(let underlying):
                return "ssh-keygen failed: \(underlying.localizedDescription). Check that ssh-keygen is installed and retry."
            case .storeFailed(let underlying):
                return "Failed to store SSH key in Authsia vault: \(underlying.localizedDescription)"
            case .publicKeyWriteFailedAfterStore(let underlying):
                return "Stored the SSH key in the Authsia vault, but could not write the public key file: \(underlying.localizedDescription). Retrieve it later with `authsia get ssh <name> --field publicKey`."
            }
        }
    }

    @discardableResult
    static func generate(
        name: String,
        directory: String,
        type: String,
        bits: Int?,
        vaultClient: SSHKeyVaultClient,
        keyGenInvocation: KeyGenInvocation
    ) throws -> String {
        // Validation
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw GenerationError.emptyName }

        let validTypes = ["ed25519", "rsa"]
        guard validTypes.contains(type) else {
            throw GenerationError.invalidType(type)
        }

        if type == "rsa" {
            let validBits = [2048, 3072, 4096]
            if let bits, !validBits.contains(bits) {
                throw GenerationError.invalidRSABits(bits)
            }
        }

        // Filesystem preflight (read-only — no directory creation here)
        let directoryURL = URL(fileURLWithPath: directory, isDirectory: true)
        let privateKeyURL = directoryURL.appendingPathComponent(trimmed)
        let publicKeyURL = directoryURL.appendingPathComponent("\(trimmed).pub")

        let privateExists = FileManager.default.fileExists(atPath: privateKeyURL.path)
        let publicExists = FileManager.default.fileExists(atPath: publicKeyURL.path)
        if privateExists || publicExists {
            throw GenerationError.outputPathTaken(privateExists ? privateKeyURL.path : publicKeyURL.path)
        }

        // Vault preflight
        let exists: Bool
        do {
            exists = try vaultClient.sshKeyExists(named: trimmed)
        } catch {
            throw GenerationError.vaultUnavailable(underlying: error)
        }
        if exists {
            throw GenerationError.nameAlreadyInVault(trimmed)
        }

        // Create per-user 0700 temp dir
        let tempParent = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-sshgen-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: tempParent,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )

        // Defer wipe — runs on every exit path including thrown errors
        defer {
            wipeTempDir(at: tempParent)
        }

        let tempStem = tempParent.appendingPathComponent("key")
        let comment = "authsia:\(trimmed)"

        // Invoke key generator (production: ssh-keygen; tests: fake)
        do {
            try keyGenInvocation(tempStem, type, bits, comment)
        } catch {
            throw GenerationError.keyGenFailed(underlying: error)
        }

        // Read keypair into memory
        let tempPubURL = tempParent.appendingPathComponent("key.pub")
        guard let privateKeyData = try? Data(contentsOf: tempStem),
              let privateKey = String(data: privateKeyData, encoding: .utf8),
              let publicKey = try? String(contentsOf: tempPubURL, encoding: .utf8) else {
            throw GenerationError.keyGenFailed(
                underlying: NSError(
                    domain: "SSHKeyGenerator",
                    code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "ssh-keygen produced unreadable output"]
                )
            )
        }

        // Compute fingerprint from public key blob
        let trimmedPublic = publicKey.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmedPublic.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count >= 2,
              let decodedKey = Data(base64Encoded: String(parts[1])) else {
            throw GenerationError.keyGenFailed(
                underlying: NSError(
                    domain: "SSHKeyGenerator",
                    code: 3,
                    userInfo: [NSLocalizedDescriptionKey: "ssh-keygen produced an unparseable public key"]
                )
            )
        }
        let fingerprint = "SHA256:" + Data(SHA256.hash(data: decodedKey)).base64EncodedString()
        let keyType = SSHKeyTypeDetector.detect(publicKey: trimmedPublic)

        // Store in vault
        do {
            _ = try vaultClient.addSSH(
                name: trimmed,
                publicKey: trimmedPublic,
                privateKey: privateKey,
                comment: comment,
                fingerprint: fingerprint,
                passphrase: nil,
                keyType: keyType,
                isScraped: false,
                folderPath: nil,
                scrapeMachineName: nil,
                scrapeMachineId: nil
            )
        } catch {
            throw GenerationError.storeFailed(underlying: error)
        }

        // Create the user-output directory + write public key (0644) at the user-chosen location.
        // The createDirectory was intentionally NOT done in preflight (Task 4 fix) so that a bad
        // --path on a vault-collision retry does not leave an empty parent dir behind. We do it
        // here, lazily, right before the actual write. Vault already has the key — do NOT roll
        // back on failure here.
        do {
            try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
            try publicKey.write(to: publicKeyURL, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: publicKeyURL.path)
        } catch {
            throw GenerationError.publicKeyWriteFailedAfterStore(underlying: error)
        }

        // Write stub at the private key path (0600). The stub is documentation,
        // not a security boundary; a write failure here is logged as a warning
        // and the command still returns success because the vault has the key
        // and the public key file is in place.
        do {
            try SSHKeyStubService.stubPrivateKeyFile(
                at: privateKeyURL.path,
                keyName: trimmed,
                permissions: 0o600
            )
        } catch {
            StandardError.writeLine("Warning: SSH key stored in vault and public key written, but could not write the Authsia stub at \(privateKeyURL.path): \(error.localizedDescription)")
        }

        return privateKeyURL.path
    }

    // MARK: - Private

    private static func wipeTempDir(at url: URL) {
        // Best-effort: overwrite the private key file with zeros, then remove the dir.
        let privateKeyPath = url.appendingPathComponent("key").path
        if FileManager.default.fileExists(atPath: privateKeyPath),
           let handle = try? FileHandle(forWritingTo: URL(fileURLWithPath: privateKeyPath)),
           let size = (try? FileManager.default.attributesOfItem(atPath: privateKeyPath))?[.size] as? Int {
            let zeros = Data(count: size)
            try? handle.write(contentsOf: zeros)
            try? handle.synchronize()
            try? handle.close()
        }
        try? FileManager.default.removeItem(at: url)
    }
}
