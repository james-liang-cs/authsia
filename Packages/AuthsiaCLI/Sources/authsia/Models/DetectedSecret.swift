import Foundation
import AuthenticatorCore

struct DetectedSecret: Identifiable, Hashable {
    struct StorageCoverageKey: Hashable {
        let referenceURI: String
        let storedContent: String
    }

    struct SSHMetadata: Hashable {
        let publicKey: String
        let comment: String
        let fingerprint: String
        let passphrase: String?
        let keyType: SSHKeyType

        init(
            publicKey: String,
            comment: String,
            fingerprint: String,
            passphrase: String? = nil,
            keyType: SSHKeyType = .ed25519
        ) {
            self.publicKey = publicKey
            self.comment = comment
            self.fingerprint = fingerprint
            self.passphrase = passphrase
            self.keyType = keyType
        }
    }

    let id = UUID()
    let filePath: String
    let lineNumber: Int
    let originalLine: String
    let key: String
    let value: String
    let rawContent: String?
    let confidence: SecretConfidence
    let type: SecretType
    let entropy: Double
    let description: String
    var isSelected: Bool = false
    let sshMetadata: SSHMetadata?
    let certificateContent: PEMCertificateContent?

    init(
        filePath: String,
        lineNumber: Int,
        originalLine: String,
        key: String,
        value: String,
        rawContent: String?,
        confidence: SecretConfidence,
        type: SecretType,
        entropy: Double,
        description: String,
        sshMetadata: SSHMetadata?,
        certificateContent: PEMCertificateContent? = nil
    ) {
        self.filePath = filePath
        self.lineNumber = lineNumber
        self.originalLine = originalLine
        self.key = key
        self.value = value
        self.rawContent = rawContent
        self.confidence = confidence
        self.type = type
        self.entropy = entropy
        self.description = description
        self.sshMetadata = sshMetadata
        self.certificateContent = certificateContent
    }
    
    /// The key name used for storing in Authsia vault.
    /// Preserves original casing, only replaces spaces and hyphens with underscores.
    var authsiaKey: String {
        key.replacingOccurrences(of: " ", with: "_")
           .replacingOccurrences(of: "-", with: "_")
    }
    
    var maskedValue: String {
        if value.count <= 12 {
            return String(repeating: "•", count: value.count)
        }
        return String(value.prefix(8)) + "..." + String(value.suffix(4))
    }

    var redactedOriginalLine: String {
        let marker = "<concealed by authsia>"
        guard !value.isEmpty else {
            return "\(key)=\(marker)"
        }
        if originalLine.contains(value) {
            return originalLine.replacingOccurrences(of: value, with: marker)
        }
        return "\(key)=\(marker)"
    }
    
    var isShellConfig: Bool {
        let shellConfigs = [".zshrc", ".bashrc", ".bash_profile", ".zprofile", ".profile"]
        let fileName = (filePath as NSString).lastPathComponent
        return shellConfigs.contains(fileName)
    }
    
    var isEnvFile: Bool {
        let fileName = (filePath as NSString).lastPathComponent
        return fileName.hasPrefix(".env") || fileName.hasSuffix(".env")
    }
    
    var addToAuthsiaCommand: String {
        if type == .certificate, resolvedCertificateContent != nil {
            return "authsia add cert --name '\(authsiaKey)' --cert-file -"
        }
        if type.storesAsAPIKey {
            return "echo '<value>' | authsia add api-key --name '\(authsiaKey)' --key -"
        }
        return "echo '<value>' | authsia add password '\(authsiaKey)' --password - --cli-enabled"
    }

    var cliGetCommand: String {
        switch type {
        case .apiKey, .token, .secret, .accessKey:
            return "authsia get api-key \(authsiaKey) --field key"
        case .jsonCredential:
            return "authsia get password \(authsiaKey) --field password"
        case .certificate:
            if let certificateContent = resolvedCertificateContent {
                return "authsia get cert \(authsiaKey) --field \(certificateContent.preferredReferenceField)"
            }
            if rawContent != nil {
                return "authsia get note \(authsiaKey) --field content"
            }
            return "authsia get password \(authsiaKey) --field password"
        case .sshKey:
            return "authsia get ssh \(authsiaKey) --field privateKey"
        default:
            return "authsia get password \(authsiaKey) --field password"
        }
    }

    /// The `authsia://` secret reference URI for this secret.
    /// Used in `.env` file migrations and with `authsia exec --env-file`.
    var secretReferenceURI: String {
        switch type {
        case .apiKey, .token, .secret, .accessKey:
            return "authsia://api-key/\(authsiaKey)/key"
        case .certificate:
            if let certificateContent = resolvedCertificateContent {
                return "authsia://cert/\(authsiaKey)/\(certificateContent.preferredReferenceField)"
            }
            if rawContent != nil {
                return "authsia://note/\(authsiaKey)/content"
            }
            return "authsia://password/\(authsiaKey)/password"
        case .sshKey:
            return "authsia://ssh/\(authsiaKey)/privateKey"
        default:
            return "authsia://password/\(authsiaKey)/password"
        }
    }

    func secretReferenceURI(folderPath: String?) -> String {
        guard let folderPath = Self.normalizedFolderPath(folderPath) else {
            return secretReferenceURI
        }
        return "\(secretReferenceURI)?folder=\(Self.percentEncodeQueryValue(folderPath))"
    }

    func secretReferenceURI(itemQuery: String, folderPath: String?) -> String {
        let base: String
        switch type {
        case .apiKey, .token, .secret, .accessKey:
            base = "authsia://api-key/\(itemQuery)/key"
        case .certificate:
            if let certificateContent = resolvedCertificateContent {
                base = "authsia://cert/\(itemQuery)/\(certificateContent.preferredReferenceField)"
            } else if rawContent != nil {
                base = "authsia://note/\(itemQuery)/content"
            } else {
                base = "authsia://password/\(itemQuery)/password"
            }
        case .sshKey:
            base = "authsia://ssh/\(itemQuery)/privateKey"
        default:
            base = "authsia://password/\(itemQuery)/password"
        }
        guard let folderPath = Self.normalizedFolderPath(folderPath) else { return base }
        return "\(base)?folder=\(Self.percentEncodeQueryValue(folderPath))"
    }

    var storageCoverageKey: StorageCoverageKey {
        StorageCoverageKey(referenceURI: secretReferenceURI, storedContent: storedContent)
    }

    var shellLoadCommand: String {
        shellLoadCommand(folderPath: nil)
    }

    func shellLoadCommand(folderPath: String?) -> String {
        let folderOption = Self.normalizedFolderPath(folderPath)
            .map { " --folder \(Self.shellArgument($0))" } ?? ""
        switch type {
        case .apiKey, .token, .secret, .accessKey:
            return "authsia load api-key \(authsiaKey)\(folderOption) --silent"
        case .certificate:
            if let certificateContent = resolvedCertificateContent {
                return "authsia load cert \(authsiaKey) --field " +
                    "\(certificateContent.preferredReferenceField)\(folderOption) --silent"
            }
            if rawContent != nil {
                return "authsia load note \(authsiaKey)\(folderOption) --silent"
            }
            return "authsia load password \(authsiaKey)\(folderOption) --silent"
        case .sshKey:
            return "authsia load ssh \(authsiaKey)\(folderOption) --silent"
        default:
            return "authsia load password \(authsiaKey)\(folderOption) --silent"
        }
    }
    
    var shellReplacementLine: String {
        shellReplacementLine(folderPath: nil)
    }

    func shellReplacementLine(folderPath: String?) -> String {
        shellLoadCommand(folderPath: folderPath)
    }

    var resolvedCertificateContent: PEMCertificateContent? {
        certificateContent ?? rawContent.flatMap(PEMCertificateParser.parse)
    }

    private var storedContent: String {
        if type == .jsonCredential, let rawContent {
            return rawContent
        }
        if type == .certificate, let content = resolvedCertificateContent {
            return [content.certificate, content.privateKey]
                .compactMap { $0 }
                .joined(separator: "\n")
        }
        if type == .certificate, let rawContent {
            return rawContent
        }
        return value
    }

    private static func normalizedFolderPath(_ folderPath: String?) -> String? {
        guard let folderPath else { return nil }
        let segments = folderPath
            .split(separator: "/")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard !segments.isEmpty else { return nil }
        return segments.joined(separator: "/")
    }

    private static func shellArgument(_ value: String) -> String {
        let quotedCharacters = CharacterSet.whitespacesAndNewlines
            .union(.init(charactersIn: "'\"$\\`"))
        guard value.rangeOfCharacter(from: quotedCharacters) != nil else {
            return value
        }
        return "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }

    private static func percentEncodeQueryValue(_ value: String) -> String {
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: ":#[]@!$&'()*+,;=/?")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }
    
    static func == (lhs: DetectedSecret, rhs: DetectedSecret) -> Bool {
        lhs.id == rhs.id
    }
    
    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}
