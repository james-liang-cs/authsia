import Foundation

/// Shared high-signal secret path rules for Access Center findings and exec post-exit inspection.
public enum AgentSecretPathPolicy {
    private static let benignDotEnvSuffixes: Set<String> = [
        ".example",
        ".sample",
        ".template",
        ".dist",
    ]

    public static func isHighSignalSecretPath(_ path: String) -> Bool {
        let fileName = URL(fileURLWithPath: path).lastPathComponent.lowercased()
        if isHighSignalDotEnvFileName(fileName) {
            return true
        }
        return fileName == ".envrc"
            || fileName == ".netrc"
            || fileName.hasSuffix(".pem")
            || fileName.hasSuffix(".p12")
            || fileName.hasSuffix(".pfx")
            || fileName == "id_rsa"
            || fileName == "id_ed25519"
            || fileName == "id_ecdsa"
    }

    public static func isHighSignalDotEnvPath(_ token: String) -> Bool {
        let fileName = URL(fileURLWithPath: token).lastPathComponent.lowercased()
        return isHighSignalDotEnvFileName(fileName)
    }

    private static func isHighSignalDotEnvFileName(_ fileName: String) -> Bool {
        guard fileName == ".env" || fileName.hasPrefix(".env.") else { return false }
        return !benignDotEnvSuffixes.contains { fileName.hasSuffix($0) }
    }
}
