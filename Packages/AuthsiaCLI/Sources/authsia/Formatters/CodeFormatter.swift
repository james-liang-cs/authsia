import AuthenticatorData

struct CodeFormatter {
    static func format(metadata: AccountMetadata, code: String, remaining: Int) -> String {
        let title = "\(metadata.issuer) (\(metadata.label))"
        return [title, "Code: \(code)", "Expires in: \(remaining)s"].joined(separator: "\n")
    }

    static func formatBridge(issuer: String, label: String, code: String, remaining: Int) -> String {
        let title = "\(issuer) (\(label))"
        return [title, "Code: \(code)", "Expires in: \(remaining)s"].joined(separator: "\n")
    }
}
