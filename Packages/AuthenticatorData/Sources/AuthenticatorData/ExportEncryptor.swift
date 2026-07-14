import Foundation
import CryptoKit
import CommonCrypto

// MARK: - Envelope Model

public struct EncryptedExportEnvelope: Codable, Equatable, Sendable {
    public let version: Int
    public let format: String
    public let kdf: String
    public let kdfIterations: Int
    public let salt: String
    public let iv: String
    public let ciphertext: String
    public let tag: String
}

// MARK: - Errors

public enum ExportEncryptionError: Error, LocalizedError, Sendable {
    case encryptionFailed
    case decryptionFailed
    case invalidEnvelope
    case unsupportedVersion(Int)
    case keyDerivationFailed

    public var errorDescription: String? {
        switch self {
        case .encryptionFailed:
            return "Failed to encrypt export data."
        case .decryptionFailed:
            return "Failed to decrypt — wrong password or corrupted file."
        case .invalidEnvelope:
            return "Invalid encrypted export format."
        case .unsupportedVersion(let v):
            return "Unsupported export version: \(v)."
        case .keyDerivationFailed:
            return "Failed to derive encryption key from password."
        }
    }
}

// MARK: - ExportEncryptor

public enum ExportEncryptor {
    private static let currentVersion = 1
    private static let formatIdentifier = "authsia-encrypted-export"
    private static let kdfIdentifier = "pbkdf2-sha256"
    private static let kdfIterations = 600_000
    private static let saltLength = 32  // 256 bits per NIST SP 800-132 recommendation
    private static let keyLength = 32  // 256 bits for AES-256

    /// Encrypts plaintext data with a password using AES-256-GCM + PBKDF2-SHA256.
    /// Returns the encrypted envelope as JSON data.
    public static func encrypt(data plaintext: Data, password: String) throws -> Data {
        // Generate random salt
        var salt = Data(count: saltLength)
        let saltResult = salt.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, saltLength, $0.baseAddress!)
        }
        guard saltResult == errSecSuccess else { throw ExportEncryptionError.encryptionFailed }

        // Derive 256-bit key from password
        let key = try deriveKey(password: password, salt: salt)

        // Encrypt with AES-256-GCM (CryptoKit generates a random 12-byte nonce)
        let sealedBox = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealedBox.combined else { throw ExportEncryptionError.encryptionFailed }

        // AES.GCM combined = nonce (12 bytes) || ciphertext || tag (16 bytes)
        let nonce = combined.prefix(12)
        let ciphertextAndTag = combined.dropFirst(12)
        let ciphertext = ciphertextAndTag.dropLast(16)
        let tag = ciphertextAndTag.suffix(16)

        let envelope = EncryptedExportEnvelope(
            version: currentVersion,
            format: formatIdentifier,
            kdf: kdfIdentifier,
            kdfIterations: kdfIterations,
            salt: salt.base64EncodedString(),
            iv: nonce.base64EncodedString(),
            ciphertext: ciphertext.base64EncodedString(),
            tag: tag.base64EncodedString()
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(envelope)
    }

    /// Decrypts an encrypted export envelope with a password.
    /// Returns the original plaintext data.
    public static func decrypt(data envelopeData: Data, password: String) throws -> Data {
        let envelope: EncryptedExportEnvelope
        do {
            envelope = try JSONDecoder().decode(EncryptedExportEnvelope.self, from: envelopeData)
        } catch {
            throw ExportEncryptionError.invalidEnvelope
        }

        guard envelope.version == currentVersion else {
            throw ExportEncryptionError.unsupportedVersion(envelope.version)
        }

        guard let salt = Data(base64Encoded: envelope.salt),
              let iv = Data(base64Encoded: envelope.iv),
              let ciphertext = Data(base64Encoded: envelope.ciphertext),
              let tag = Data(base64Encoded: envelope.tag) else {
            throw ExportEncryptionError.invalidEnvelope
        }

        let key = try deriveKey(password: password, salt: salt)

        // Reassemble combined: nonce || ciphertext || tag
        var combined = Data()
        combined.append(iv)
        combined.append(ciphertext)
        combined.append(tag)

        do {
            let sealedBox = try AES.GCM.SealedBox(combined: combined)
            return try AES.GCM.open(sealedBox, using: key)
        } catch {
            throw ExportEncryptionError.decryptionFailed
        }
    }

    /// Returns true if the data is a supported encrypted export envelope.
    public static func isEncryptedExport(data: Data) -> Bool {
        guard let envelope = try? JSONDecoder().decode(EncryptedExportEnvelope.self, from: data) else {
            return false
        }
        return envelope.format == formatIdentifier && envelope.version == currentVersion
    }

    // MARK: - Key Derivation

    private static func deriveKey(password: String, salt: Data) throws -> SymmetricKey {
        let passwordData = Data(password.utf8)
        var derivedKeyBytes = [UInt8](repeating: 0, count: keyLength)

        let result = derivedKeyBytes.withUnsafeMutableBufferPointer { derivedKeyPtr in
            salt.withUnsafeBytes { saltPtr in
                passwordData.withUnsafeBytes { passwordPtr in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordPtr.bindMemory(to: Int8.self).baseAddress,
                        passwordData.count,
                        saltPtr.bindMemory(to: UInt8.self).baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(kdfIterations),
                        derivedKeyPtr.baseAddress,
                        keyLength
                    )
                }
            }
        }

        guard result == kCCSuccess else { throw ExportEncryptionError.keyDerivationFailed }
        return SymmetricKey(data: Data(derivedKeyBytes))
    }
}
