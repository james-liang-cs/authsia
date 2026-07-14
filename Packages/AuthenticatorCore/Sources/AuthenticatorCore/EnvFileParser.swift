import Foundation

public enum EnvFileParser {
    /// Parse a `.env` file into ordered key-value pairs.
    public static func parse(content: String) throws -> [(key: String, value: String)] {
        var entries: [(key: String, value: String)] = []

        for line in content.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty,
                  !trimmed.hasPrefix("#"),
                  let eqIndex = trimmed.firstIndex(of: "=") else {
                continue
            }

            var key = String(trimmed[trimmed.startIndex..<eqIndex])
                .trimmingCharacters(in: .whitespaces)
            if key.hasPrefix("export ") || key.hasPrefix("export\t") {
                key = String(key.dropFirst(6)).trimmingCharacters(in: .whitespaces)
            }
            guard !key.isEmpty else { continue }

            var value = String(trimmed[trimmed.index(after: eqIndex)...])
                .trimmingCharacters(in: .whitespaces)
            if value.hasPrefix("\"") {
                let inner = value.dropFirst()
                value = inner.firstIndex(of: "\"").map { String(inner[..<$0]) } ?? String(inner)
            } else if value.hasPrefix("'") {
                let inner = value.dropFirst()
                value = inner.firstIndex(of: "'").map { String(inner[..<$0]) } ?? String(inner)
            } else {
                if let commentRange = value.range(of: "\\s+#", options: .regularExpression) {
                    value = String(value[value.startIndex..<commentRange.lowerBound])
                }
                value = value.trimmingCharacters(in: .whitespaces)
            }

            entries.append((key: key, value: value))
        }

        return entries
    }

    /// Parse a `.env` file from disk.
    public static func parse(contentsOf path: String) throws -> [(key: String, value: String)] {
        try parse(content: String(contentsOfFile: path, encoding: .utf8))
    }
}
