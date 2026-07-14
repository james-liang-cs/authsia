import Foundation

public enum SSHKeyTypeDetector {

    public static func detect(publicKey: String) -> SSHKeyType {
        let trimmed = publicKey.trimmingCharacters(in: .whitespacesAndNewlines)

        if trimmed.hasPrefix("ssh-ed25519 ") {
            return .ed25519
        }

        if trimmed.hasPrefix("ssh-rsa ") {
            return detectRSABits(from: trimmed)
        }

        return .ed25519
    }

    public static func detect(publicKeyData: Data) -> SSHKeyType {
        guard let str = String(data: publicKeyData, encoding: .utf8) else {
            return .ed25519
        }
        return detect(publicKey: str)
    }

    private static func detectRSABits(from publicKey: String) -> SSHKeyType {
        let parts = publicKey.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2 else { return .rsa4096 }

        let blobLength = parts[1].count

        // Base64-encoded RSA public key blob sizes (approximate):
        // 2048-bit: ~360-380 chars
        // 3072-bit: ~520-540 chars
        // 4096-bit: ~680-720 chars
        if blobLength < 450 {
            return .rsa2048
        } else if blobLength < 620 {
            return .rsa3072
        } else {
            return .rsa4096
        }
    }
}
