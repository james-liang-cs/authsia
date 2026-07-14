import Foundation
import Security

/// Indicates a non-recoverable failure to read vault/OTP metadata.
///
/// Metadata is canonically stored in Keychain. When the keychain is unavailable,
/// callers must not silently treat that as an empty metadata list.
public enum MetadataLoadError: Error, Equatable {
    case keychainUnavailable(OSStatus?)
    case decodeFailed(String)
}

extension MetadataLoadError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .keychainUnavailable:
            return "Authsia could not read the keychain on this Mac. Open the Authsia app once and grant keychain access when prompted, or ask your administrator to allow team identifier 33M8QU65SP under managed keychain access."
        case .decodeFailed(let message):
            return "Authsia could not decode the keychain metadata: \(message)"
        }
    }
}
