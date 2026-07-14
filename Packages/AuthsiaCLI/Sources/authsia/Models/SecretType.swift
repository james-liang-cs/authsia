import Foundation

enum SecretType: String, CaseIterable, CustomStringConvertible {
    case apiKey = "API Key"
    case token = "Token"
    case password = "Password"
    case secret = "Secret"
    case accessKey = "Access Key"
    case certificate = "Certificate"
    case sshKey = "SSH Key"
    case jsonCredential = "JSON Credential"
    case unknown = "Unknown"
    
    var description: String { rawValue }
    
    var authsiaStorageType: String {
        switch self {
        case .apiKey, .token, .secret, .accessKey:
            return "api-key"
        case .password:
            return "password"
        case .sshKey:
            return "ssh"
        case .jsonCredential:
            return "password"
        default:
            return "password"
        }
    }

    var storesAsAPIKey: Bool {
        switch self {
        case .apiKey, .token, .secret, .accessKey:
            return true
        default:
            return false
        }
    }
}
