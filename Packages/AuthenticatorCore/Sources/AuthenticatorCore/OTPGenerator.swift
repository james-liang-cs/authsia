import Foundation
import CryptoKit

public enum OTPAlgorithm: String, Codable, CaseIterable {
    case sha1
    case sha256
    case sha512
    
    var hmacVariant: any HashFunction.Type {
        switch self {
        case .sha1: return Insecure.SHA1.self
        case .sha256: return SHA256.self
        case .sha512: return SHA512.self
        }
    }
}

public struct OTPGenerator {
    
    // MARK: - HOTP (RFC 4226)
    
    /// Generates an HOTP code.
    /// - Parameters:
    ///   - secret: The shared secret key.
    ///   - counter: The counter value (C).
    ///   - digits: Number of digits in the code (usually 6 or 8).
    ///   - algorithm: The hash algorithm to use (default .sha1).
    /// - Returns: The formatted OTP string (e.g., "123456").
    public static func hotp(
        secret: Data,
        counter: UInt64,
        digits: Int = 6,
        algorithm: OTPAlgorithm = .sha1
    ) -> String {
        // 1. Counter to big-endian bytes
        var counterBigEndian = counter.bigEndian
        let counterData = Data(bytes: &counterBigEndian, count: MemoryLayout<UInt64>.size)
        
        // 2. HMAC-SHA-1(K, C)
        let hmac = HMAC_Generic(key: secret, data: counterData, algorithm: algorithm)
        
        // 3. Truncate
        let offset = Int(hmac.last ?? 0) & 0x0f
        
        let truncatedHash = (
            (Int(hmac[offset]) & 0x7f) << 24 |
            (Int(hmac[offset + 1]) & 0xff) << 16 |
            (Int(hmac[offset + 2]) & 0xff) << 8 |
            (Int(hmac[offset + 3]) & 0xff)
        )
        
        // 4. Modulo 10^Digits
        let mod = Int(pow(10.0, Double(digits)))
        let otpValue = truncatedHash % mod
        
        // 5. Pad with zeros
        return String(format: "%0*d", digits, otpValue)
    }
    
    // MARK: - TOTP (RFC 6238)
    
    /// Generates a TOTP code.
    /// - Parameters:
    ///   - secret: The shared secret key.
    ///   - time: The specific time to generate the code for (default: now).
    ///   - period: The time step in seconds (default: 30).
    ///   - digits: Number of digits.
    ///   - algorithm: Hash algorithm.
    /// - Returns: The formatted OTP string.
    public static func totp(
        secret: Data,
        time: Date = Date(),
        period: TimeInterval = 30,
        digits: Int = 6,
        algorithm: OTPAlgorithm = .sha1
    ) -> String {
        let timeInterval = time.timeIntervalSince1970
        let counter = UInt64(floor(timeInterval / period))
        return hotp(secret: secret, counter: counter, digits: digits, algorithm: algorithm)
    }
    
    // Helper to switch on algorithms generically
    private static func HMAC_Generic(key: Data, data: Data, algorithm: OTPAlgorithm) -> Data {
        let key = SymmetricKey(data: key)
        
        switch algorithm {
        case .sha1:
            return Data(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: key))
        case .sha256:
            return Data(HMAC<SHA256>.authenticationCode(for: data, using: key))
        case .sha512:
            return Data(HMAC<SHA512>.authenticationCode(for: data, using: key))
        }
    }
}
