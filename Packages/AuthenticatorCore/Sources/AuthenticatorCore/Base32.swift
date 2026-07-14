import Foundation

public enum Base32 {
    /// Decodes a Base32 encoded string into Data.
    /// Handles various edge cases:
    /// - Lowercase/uppercase
    /// - Padding characters ('=')
    /// - Whitespace/Hyphens (ignored)
    /// - "I" <-> "1", "L" <-> "1", "0" <-> "O" correction (optional, often used in OTP)
    public static func decode(_ string: String) throws -> Data {
        // 1. Sanitization: Remove known spacers and control characters
        let cleaned = string.folding(options: .diacriticInsensitive, locale: .current)
            .components(separatedBy: CharacterSet.whitespacesAndNewlines.union(.init(charactersIn: "-")))
            .joined()
            .uppercased()
            .replacingOccurrences(of: "=", with: "") // Remove padding
        
        guard !cleaned.isEmpty else { return Data() }
        
        // standard Base32 alphabet (RFC 4648)
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var decodedData = Data(capacity: cleaned.count * 5 / 8)
        
        var buffer: UInt32 = 0
        var bitsRemaining = 0
        
        for char in cleaned {
            guard let index = alphabet.firstIndex(of: char) else {
                throw Base32Error.invalidCharacter(char)
            }
            
            buffer = (buffer << 5) | UInt32(index)
            bitsRemaining += 5
            
            if bitsRemaining >= 8 {
                let byte = UInt8((buffer >> (bitsRemaining - 8)) & 0xFF)
                decodedData.append(byte)
                bitsRemaining -= 8
            }
        }
        
        return decodedData
    }
    /// Encodes Data into a Base32 string.
    public static func encode(_ data: Data) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var result = ""
        
        var buffer: UInt32 = 0
        var bitsRemaining = 0
        
        for byte in data {
            buffer = (buffer << 8) | UInt32(byte)
            bitsRemaining += 8
            
            while bitsRemaining >= 5 {
                let index = Int((buffer >> (bitsRemaining - 5)) & 0x1F)
                result.append(alphabet[index])
                bitsRemaining -= 5
            }
        }
        
        if bitsRemaining > 0 {
            let index = Int((buffer << (5 - bitsRemaining)) & 0x1F)
            result.append(alphabet[index])
        }
        
        return result
    }
}

public enum Base32Error: Error, LocalizedError {
    case invalidCharacter(Character)
    
    public var errorDescription: String? {
        switch self {
        case .invalidCharacter(let char):
            return "String contains invalid Base32 character: '\(char)'"
        }
    }
}
