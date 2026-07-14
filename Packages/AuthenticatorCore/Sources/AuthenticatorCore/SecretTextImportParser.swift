import Foundation

public enum SecretTextImportError: Error, Equatable {
    case empty
    case tooLarge
}

public enum SecretTextImportKind: Hashable, Sendable {
    case apiKey
    case password
    case secureNote
}

public struct SecretTextImportCandidate: Equatable, Sendable {
    public let kind: SecretTextImportKind
    public let name: String
    public let username: String?
    public let secret: String
    public let redactedSecret: String
    public let requiresName: Bool

    public init(
        kind: SecretTextImportKind,
        name: String,
        username: String?,
        secret: String,
        requiresName: Bool = false
    ) {
        self.kind = kind
        self.name = name
        self.username = username
        self.secret = secret
        self.redactedSecret = Self.redact(secret)
        self.requiresName = requiresName
    }

    private static let maskBullets = String(repeating: "•", count: 4)

    private static func redact(_ value: String) -> String {
        // For a JSON object (e.g. an AWS Secrets Manager blob) keep the keys
        // visible so the structure is recognizable, and mask only the values.
        if let redactedJSON = redactedJSONObject(value) {
            return redactedJSON
        }
        return maskedPrefix(value)
    }

    /// Reveal a leading hint and mask the rest. Always hides at least the last
    /// 4 characters and never reveals more than the first 8, so short secrets
    /// reveal less and the trailing characters/length stay hidden.
    private static func maskedPrefix(_ value: String) -> String {
        let revealCount = min(8, max(0, value.count - 4))
        guard revealCount > 0 else { return maskBullets }
        return "\(value.prefix(revealCount))\(maskBullets)"
    }

    private static func redactedJSONObject(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("{"), trimmed.hasSuffix("}"),
              let data = trimmed.data(using: .utf8),
              let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            return nil
        }
        return redactedJSONFragment(object)
    }

    private static func redactedJSONFragment(_ value: Any) -> String {
        switch value {
        case let dict as [String: Any]:
            let body = dict.keys.sorted()
                .map { "\(quotedJSONString($0)):\(redactedJSONFragment(dict[$0] ?? ""))" }
                .joined(separator: ",")
            return "{\(body)}"
        case let array as [Any]:
            return "[\(array.map(redactedJSONFragment).joined(separator: ","))]"
        case let string as String:
            // Keep a leading hint of string values; mask the rest.
            return "\"\(maskedPrefix(string))\""
        default:
            // Numbers/bools/null: mask entirely so small values don't leak.
            return maskBullets
        }
    }

    private static func quotedJSONString(_ string: String) -> String {
        let escaped = string
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return "\"\(escaped)\""
    }
}

public struct SecretTextImportResult: Equatable, Sendable {
    public let candidates: [SecretTextImportCandidate]

    public init(candidates: [SecretTextImportCandidate]) {
        self.candidates = candidates
    }
}

public enum SecretTextImportParser {
    public static let maxInputBytes = 131_072

    public static func parse(_ text: String) throws -> SecretTextImportResult {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw SecretTextImportError.empty }
        guard Data(text.utf8).count <= maxInputBytes else { throw SecretTextImportError.tooLarge }

        if let envCandidates = parseEnv(trimmed), !envCandidates.isEmpty {
            return SecretTextImportResult(candidates: envCandidates)
        }

        if let keyValueCandidates = parseKeyValue(trimmed), !keyValueCandidates.isEmpty {
            return SecretTextImportResult(candidates: keyValueCandidates)
        }

        if isJSONObject(trimmed) {
            return SecretTextImportResult(candidates: [
                SecretTextImportCandidate(
                    kind: .secureNote,
                    name: "JSON credentials",
                    username: nil,
                    secret: trimmed
                ),
            ])
        }

        return SecretTextImportResult(candidates: [
            SecretTextImportCandidate(
                kind: .password,
                name: "",
                username: nil,
                secret: trimmed,
                requiresName: true
            ),
        ])
    }

    private static func parseEnv(_ text: String) -> [SecretTextImportCandidate]? {
        var candidates: [SecretTextImportCandidate] = []

        for line in text.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            guard let eqIndex = trimmed.firstIndex(of: "=") else { return nil }

            var rawKey = String(trimmed[..<eqIndex]).trimmingCharacters(in: .whitespaces)
            if rawKey.hasPrefix("export ") || rawKey.hasPrefix("export\t") {
                rawKey = String(rawKey.dropFirst(6)).trimmingCharacters(in: .whitespaces)
            }
            guard isValidEnvKey(rawKey) else { return nil }

            var value = String(trimmed[trimmed.index(after: eqIndex)...]).trimmingCharacters(in: .whitespaces)
            if value.isEmpty { continue }
            value = unquote(value)
            candidates.append(candidate(name: rawKey, secret: value))
        }

        return candidates.isEmpty ? nil : candidates
    }

    private static func parseKeyValue(_ text: String) -> [SecretTextImportCandidate]? {
        var candidates: [SecretTextImportCandidate] = []

        for line in text.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            guard let colonIndex = trimmed.firstIndex(of: ":") else { return nil }

            let key = String(trimmed[..<colonIndex]).trimmingCharacters(in: .whitespaces)
            guard isValidKeyValueName(key) else { return nil }

            var value = String(trimmed[trimmed.index(after: colonIndex)...]).trimmingCharacters(in: .whitespaces)
            if value.isEmpty { continue }
            value = unquote(value)
            candidates.append(candidate(name: key, secret: value))
        }

        return candidates.isEmpty ? nil : candidates
    }

    private static func isValidEnvKey(_ key: String) -> Bool {
        key.range(of: #"^[A-Za-z_][A-Za-z0-9_]*$"#, options: .regularExpression) != nil
    }

    private static func isValidKeyValueName(_ key: String) -> Bool {
        key.range(of: #"^[A-Za-z_][A-Za-z0-9_.-]*$"#, options: .regularExpression) != nil
    }

    private static func candidate(name: String, secret: String) -> SecretTextImportCandidate {
        let kind = kind(for: name)
        return SecretTextImportCandidate(
            kind: kind,
            name: name,
            username: kind == .password ? name : nil,
            secret: secret
        )
    }

    private static func kind(for name: String) -> SecretTextImportKind {
        let normalized = name.lowercased()
        if normalized.contains("api_key") ||
            normalized.contains("apikey") ||
            normalized.contains("api-key") ||
            normalized.contains("api.secret") ||
            normalized.contains("api_secret") ||
            normalized.contains("token") ||
            normalized.contains("secret_key") ||
            normalized.contains("access_key") ||
            normalized.contains("accesskey") ||
            normalized.hasSuffix("_key") {
            return .apiKey
        }
        return .password
    }

    private static func unquote(_ value: String) -> String {
        if value.count >= 2,
           let first = value.first,
           let last = value.last,
           (first == "\"" && last == "\"") || (first == "'" && last == "'") {
            return String(value.dropFirst().dropLast())
        }

        if let commentRange = value.range(of: #"\s+#"#, options: .regularExpression) {
            return String(value[..<commentRange.lowerBound]).trimmingCharacters(in: .whitespaces)
        }

        return value
    }

    private static func isJSONObject(_ text: String) -> Bool {
        guard text.hasPrefix("{"), text.hasSuffix("}") else { return false }
        guard let data = text.data(using: .utf8) else { return false }
        return ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any]) != nil
    }
}
