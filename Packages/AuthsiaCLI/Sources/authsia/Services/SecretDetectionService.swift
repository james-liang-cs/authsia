import Foundation

actor SecretDetectionService {
    
    private let knownSafePatterns: [String] = [
        "JBSWY3DPEHPK3PXP",
        "aGVsbG8gd29ybGQ=",
        "dGVzdA==",
        "example", "sample", "test", "placeholder",
        "your_api_key", "xxx", "***"
    ]
    
    private let secretKeywords: [String] = [
        "api_key", "apikey", "api_secret", "apisecret",
        "secret", "secret_key", "secretkey",
        "password", "passwd", "pwd",
        "token", "access_token", "auth_token", "session_token",
        "access_key", "accesskey", "private_key", "privatekey",
        "_key", "client_secret", "clientsecret",
        "consumer_key", "consumer_secret"
    ]

    private let pathCredentialVariables: [String] = [
        "google_application_credentials",
        "aws_shared_credentials_file",
        "azure_credentials_file",
        "docker_config",
        "kubeconfig"
    ]

    private let credentialFileExtensions: [String] = [
        ".json", ".yaml", ".yml", ".pem", ".crt", ".cer", ".key"
    ]

    func calculateEntropy(_ string: String) -> Double {
        guard !string.isEmpty else { return 0 }
        
        let length = Double(string.count)
        var frequencies: [Character: Int] = [:]
        
        for char in string {
            frequencies[char, default: 0] += 1
        }
        
        var entropy = 0.0
        for count in frequencies.values {
            let probability = Double(count) / length
            entropy -= probability * log2(probability)
        }
        
        return entropy
    }
    
    func isKnownSafePattern(_ value: String) -> Bool {
        let normalized = value.lowercased().trimmingCharacters(in: .whitespaces)
        
        for pattern in knownSafePatterns {
            if normalized.contains(pattern.lowercased()) {
                return true
            }
        }
        
        return ["true", "false", "yes", "no", "1", "0", "null", "none"].contains(normalized)
    }
    
    func detectSecretType(fromKey key: String) -> SecretType {
        let normalized = key.lowercased()
        
        if normalized.contains("api") && (normalized.contains("key") || normalized.contains("secret")) {
            return .apiKey
        }
        if normalized.contains("token") || normalized.contains("bearer") {
            return .token
        }
        if normalized.contains("password") || normalized.contains("passwd") {
            return .password
        }
        if normalized.contains("access_key") || normalized.contains("accesskey") {
            return .accessKey
        }
        if normalized.contains("secret") {
            return .secret
        }
        if normalized.hasSuffix("_key") {
            return .apiKey
        }
        
        return .unknown
    }

    func detectPathCredentialType(key: String, value: String) -> SecretType? {
        let normalizedKey = key.lowercased()

        // Check if key matches known credential path variables
        for pathVar in pathCredentialVariables {
            if normalizedKey.contains(pathVar) {
                // Check if value looks like a file path with credential extension
                for ext in credentialFileExtensions {
                    if value.lowercased().hasSuffix(ext) {
                        // Determine type based on extension
                        switch ext {
                        case ".json", ".yaml", ".yml":
                            return .jsonCredential
                        case ".pem", ".crt", ".cer", ".key":
                            return .certificate
                        default:
                            return .unknown
                        }
                    }
                }
            }
        }

        // Check if any value is a path to a credential file (heuristic)
        if value.hasPrefix("/") || value.hasPrefix("~/") || value.hasPrefix("./") {
            for ext in credentialFileExtensions {
                if value.lowercased().hasSuffix(ext) {
                    switch ext {
                    case ".json", ".yaml", ".yml":
                        return .jsonCredential
                    case ".pem", ".crt", ".cer", ".key":
                        return .certificate
                    default:
                        return nil
                    }
                }
            }
        }

        return nil
    }

    private let shellConfigKeys: [String] = [
        "path", "home", "user", "shell", "term", "lang", "editor",
        "osh", "zsh", "bash", "fish", "sh",
        "path_helper", "path_prefix", "manpath", "infopath",
        "prompt", "ps1", "ps2", "ps3", "ps4",
        "history", "histfile", "histsize", "savehist",
        "ls_colors", "ls_colors", "term_program", "term_program_version",
        "colorterm", "colortheme", "theme", "colors",
        "xpc_service_name", "xpc_flags", "launchd_socket",
        "ssh_auth_sock", "ssh_agent_launcher", "ssh_askpass",
        "display", "xdg_session_type", "xdg_current_desktop",
        "logname", "hostname", "host", "pwd", "oldpwd",
        "shlvl", "tmux", "tmux_pane", "starship_session_key",
        "star_ship_session_key", "p9k_ssh_tty", "powerline_session_id"
    ]

    private let nonSecretMetadataKeys: Set<String> = [
        "code_sha256",
        "codesha256",
        "cwd",
        "dependencies",
        "diagnostics",
        "guid",
        "id",
        "label",
        "nextcontinuationtoken",
        "nextmarker",
        "object",
        "operation",
        "pch",
        "public_key",
        "publickey",
        "shape",
        "source_file",
        "swiftmodule",
        "versionid",
    ]

    private let packageLockMetadataKeys: Set<String> = [
        "integrity",
        "resolved",
    ]

    private let generatedPaginatorMetadataKeys: Set<String> = [
        "input_token",
        "output_token",
    ]

    private let generatedExampleMetadataKeys: Set<String> = [
        "content",
        "data",
        "granttoken",
        "id",
        "nextcontinuationtoken",
        "nextmarker",
        "versionid",
    ]
    
    func detectSecret(key: String, value: String, originalLine: String, 
                     filePath: String, lineNumber: Int) -> DetectedSecret? {
        let trimmedValue = value.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedKey = key.lowercased()

        guard !trimmedValue.isEmpty else { return nil }
        guard !isKnownSafePattern(trimmedValue) else { return nil }
        
        // Exclude shell/build/generated metadata keys that commonly contain high-entropy paths or checksums.
        if shellConfigKeys.contains(normalizedKey) || isNonSecretMetadataKey(normalizedKey, filePath: filePath) {
            return nil
        }

        let matchedSecretKeyword = secretKeywords.first { normalizedKey.contains($0) }
        guard trimmedValue.count >= 8 || matchedSecretKeyword != nil else { return nil }
        
        let entropy = calculateEntropy(trimmedValue)
        var type = detectSecretType(fromKey: key)

        var score = 0
        var reasons: [String] = []

        // Check for path-based credentials if type is unknown or to boost confidence
        if type == .unknown {
            if let pathType = detectPathCredentialType(key: key, value: trimmedValue) {
                type = pathType
                // Boost confidence for path-based credentials
                score += 30
                reasons.append("credential file path")
            }
        }

        if let matchedSecretKeyword {
            score += 40
            reasons.append("keyword: \(matchedSecretKeyword)")
        }
        
        if entropy > 4.5 {
            score += 30
            reasons.append("high entropy")
        } else if entropy > 3.5 {
            score += 15
            reasons.append("medium entropy")
        }
        
        if matchesSecretPattern(trimmedValue) {
            score += 30
            reasons.append("pattern match")
        }
        
        if hasHighCharacterVariety(trimmedValue) {
            score += 10
            reasons.append("high variety")
        }
        
        let confidence: SecretConfidence
        if score >= 70 {
            confidence = .high
        } else if score >= 40 {
            confidence = .medium
        } else if score >= 25 {
            confidence = .low
        } else {
            return nil
        }
        
        return DetectedSecret(
            filePath: filePath,
            lineNumber: lineNumber,
            originalLine: originalLine,
            key: key,
            value: trimmedValue,
            rawContent: nil,
            confidence: confidence,
            type: type,
            entropy: entropy,
            description: reasons.joined(separator: ", "),
            sshMetadata: nil
        )
    }

    private func isNonSecretMetadataKey(_ normalizedKey: String, filePath: String) -> Bool {
        if nonSecretMetadataKeys.contains(normalizedKey) {
            return true
        }

        let fileName = URL(fileURLWithPath: filePath).lastPathComponent.lowercased()
        if ["package-lock.json", "npm-shrinkwrap.json"].contains(fileName),
           packageLockMetadataKeys.contains(normalizedKey) {
            return true
        }
        if fileName.range(of: #"^paginators-\d+\.js$"#, options: .regularExpression) != nil,
           generatedPaginatorMetadataKeys.contains(normalizedKey) {
            return true
        }
        if fileName.range(of: #"^examples-\d+\.json$"#, options: .regularExpression) != nil,
           generatedExampleMetadataKeys.contains(normalizedKey) {
            return true
        }
        return false
    }
    
    private func matchesSecretPattern(_ value: String) -> Bool {
        let patterns = [
            "^[A-Z2-7]{16,}$",
            "^[A-Za-z0-9+/]{32,}={0,2}$",
            "^[a-f0-9]{32,}$",
            "^eyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*$"
        ]
        
        for pattern in patterns {
            if value.range(of: pattern, options: .regularExpression) != nil {
                return true
            }
        }
        return false
    }
    
    private func hasHighCharacterVariety(_ value: String) -> Bool {
        guard value.count >= 16 else { return false }
        
        let hasUpper = value.range(of: "[A-Z]", options: .regularExpression) != nil
        let hasLower = value.range(of: "[a-z]", options: .regularExpression) != nil
        let hasDigit = value.range(of: "[0-9]", options: .regularExpression) != nil
        let hasSpecial = value.range(of: "[^A-Za-z0-9]", options: .regularExpression) != nil
        
        return [hasUpper, hasLower, hasDigit, hasSpecial].filter { $0 }.count >= 3
    }
}
