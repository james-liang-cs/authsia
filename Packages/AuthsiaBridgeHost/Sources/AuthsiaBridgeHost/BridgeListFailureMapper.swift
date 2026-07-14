#if os(macOS)
import Foundation
import Security
import AuthenticatorBridge
import AuthenticatorData

public enum BridgeListFailureMapper {
    public static func mapping(for error: Error) -> (code: BridgeErrorCode, message: String) {
        if let metadataError = error as? MetadataLoadError {
            switch metadataError {
            case .keychainUnavailable:
                return (.appUnavailable, metadataError.localizedDescription)
            case .decodeFailed(let message):
                return (.appUnavailable, "Authsia could not decode keychain metadata: \(message)")
            }
        }

        if isKeychainAccessDenied(error) {
            return (
                .appUnavailable,
                "Authsia helper is not authorized to read the keychain on this Mac. " +
                "Open the Authsia app once and grant keychain access when prompted, or " +
                "ask your administrator to allow team identifier 33M8QU65SP under " +
                "managed keychain access."
            )
        }
        return (.appUnavailable, "Failed to list items: \(error.localizedDescription)")
    }

    private static func isKeychainAccessDenied(_ error: Error) -> Bool {
        if case KeychainError.unknown(let status) = error {
            return isKeychainAccessDeniedStatus(status)
        }

        let nsError = error as NSError
        guard nsError.domain == NSOSStatusErrorDomain else { return false }
        return isKeychainAccessDeniedStatus(OSStatus(nsError.code))
    }

    private static func isKeychainAccessDeniedStatus(_ status: OSStatus) -> Bool {
        switch status {
        case errSecMissingEntitlement,
             errSecInteractionNotAllowed,
             errSecAuthFailed,
             errSecUserCanceled:
            return true
        default:
            return false
        }
    }
}
#endif
