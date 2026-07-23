import Foundation

struct OutputMasker {
    static let placeholder = "<concealed by authsia>"
    private static let minimumDerivedTokenSecretLength = 4

    /// Secrets and common deterministic encodings sorted longest-first to prevent partial replacements.
    private let sortedSecrets: [String]

    init(secrets: [String]) {
        self.sortedSecrets = Self.maskTokens(for: secrets)
            .sorted { $0.count > $1.count }
    }

    /// Replace all occurrences of any secret in the input with the placeholder.
    func mask(_ input: String) -> String {
        guard !sortedSecrets.isEmpty else { return input }
        let matches = matchedRanges(in: input)
        guard !matches.isEmpty else { return input }

        var result = ""
        var cursor = input.startIndex
        for match in matches {
            guard match.range.lowerBound >= cursor else { continue }
            result.append(contentsOf: input[cursor..<match.range.lowerBound])
            result.append(Self.placeholder)
            cursor = match.range.upperBound
        }
        result.append(contentsOf: input[cursor...])
        return result
    }

    private func matchedRanges(
        in input: String
    ) -> [(range: Range<String.Index>, lowerBound: Int, upperBound: Int)] {
        var matches: [(range: Range<String.Index>, lowerBound: Int, upperBound: Int)] = []

        for secret in sortedSecrets {
            var searchStart = input.startIndex
            while searchStart < input.endIndex,
                  let range = input.range(of: secret, range: searchStart..<input.endIndex) {
                matches.append((
                    range: range,
                    lowerBound: input.distance(from: input.startIndex, to: range.lowerBound),
                    upperBound: input.distance(from: input.startIndex, to: range.upperBound)
                ))
                searchStart = input.index(after: range.lowerBound)
            }
        }

        return matches.sorted { lhs, rhs in
            if lhs.lowerBound != rhs.lowerBound {
                return lhs.lowerBound < rhs.lowerBound
            }
            return lhs.upperBound > rhs.upperBound
        }
    }

    /// Mask a Data buffer. Treats input as UTF-8; non-UTF-8 data passes through unchanged.
    func mask(_ data: Data) -> Data {
        guard !sortedSecrets.isEmpty else { return data }
        guard let text = String(data: data, encoding: .utf8) else { return data }
        return Data(mask(text).utf8)
    }

    func makeStream() -> Stream {
        Stream(masker: self)
    }

    struct Stream {
        private let masker: OutputMasker
        private var pending = ""
        private var pendingUTF8Bytes = Data()

        init(masker: OutputMasker) {
            self.masker = masker
        }

        mutating func mask(_ data: Data) -> Data {
            switch mask(data, policy: .maskedCompatibility) {
            case .success(let output):
                return output
            case .failure:
                return data
            }
        }

        mutating func mask(
            _ data: Data,
            policy: OutputDisclosurePolicy
        ) -> Result<Data, OutputDisclosureFailure> {
            switch policy {
            case .strict:
                return maskStrict(data)
            case .maskedCompatibility:
                return .success(maskCompatibility(data))
            }
        }

        private mutating func maskCompatibility(_ data: Data) -> Data {
            guard !masker.sortedSecrets.isEmpty else { return data }
            guard let text = String(data: data, encoding: .utf8) else {
                return flush() + data
            }

            pending += text

            let holdCount = pendingSecretPrefixCharacterCount()
            var emitCount = max(pending.count - holdCount, 0)
            emitCount = adjustedEmitCountAvoidingSplitSecrets(emitCount)

            guard emitCount > 0 else { return Data() }

            let splitIndex = pending.index(pending.startIndex, offsetBy: emitCount)
            let output = String(pending[..<splitIndex])
            pending = String(pending[splitIndex...])
            return Data(masker.mask(output).utf8)
        }

        mutating func flush() -> Data {
            guard !pending.isEmpty else { return Data() }
            let output = Data(masker.mask(pending).utf8)
            pending = ""
            return output
        }

        mutating func flush(
            policy: OutputDisclosurePolicy
        ) -> Result<Data, OutputDisclosureFailure> {
            if policy == .strict, !pendingUTF8Bytes.isEmpty {
                return .failure(.invalidUTF8)
            }
            return .success(flush())
        }

        private mutating func maskStrict(_ data: Data) -> Result<Data, OutputDisclosureFailure> {
            pendingUTF8Bytes.append(data)
            switch Self.validUTF8PrefixLength(in: pendingUTF8Bytes) {
            case .failure(let failure):
                pendingUTF8Bytes.removeAll(keepingCapacity: false)
                return .failure(failure)
            case .success(let prefixLength):
                guard prefixLength > 0 else { return .success(Data()) }
                let prefix = pendingUTF8Bytes.prefix(prefixLength)
                pendingUTF8Bytes.removeFirst(prefixLength)
                guard let text = String(data: prefix, encoding: .utf8) else {
                    return .failure(.invalidUTF8)
                }
                return .success(maskCompatibility(Data(text.utf8)))
            }
        }

        private static func validUTF8PrefixLength(
            in data: Data
        ) -> Result<Int, OutputDisclosureFailure> {
            let bytes = Array(data)
            var index = 0
            while index < bytes.count {
                let first = bytes[index]
                if first <= 0x7F {
                    index += 1
                    continue
                }

                let length: Int
                switch first {
                case 0xC2...0xDF:
                    length = 2
                case 0xE0...0xEF:
                    length = 3
                case 0xF0...0xF4:
                    length = 4
                default:
                    return .failure(.invalidUTF8)
                }

                guard index + length <= bytes.count else {
                    let available = bytes[(index + 1)..<bytes.count]
                    guard available.allSatisfy({ (0x80...0xBF).contains($0) }) else {
                        return .failure(.invalidUTF8)
                    }
                    return .success(index)
                }
                let continuation = bytes[(index + 1)..<(index + length)]
                guard continuation.allSatisfy({ (0x80...0xBF).contains($0) }) else {
                    return .failure(.invalidUTF8)
                }
                if first == 0xE0, bytes[index + 1] < 0xA0 {
                    return .failure(.invalidUTF8)
                }
                if first == 0xED, bytes[index + 1] > 0x9F {
                    return .failure(.invalidUTF8)
                }
                if first == 0xF0, bytes[index + 1] < 0x90 {
                    return .failure(.invalidUTF8)
                }
                if first == 0xF4, bytes[index + 1] > 0x8F {
                    return .failure(.invalidUTF8)
                }
                index += length
            }
            return .success(index)
        }

        private func pendingSecretPrefixCharacterCount() -> Int {
            var longestPrefixCount = 0

            for secret in masker.sortedSecrets {
                var candidateCount = min(pending.count, secret.count - 1)
                while candidateCount > longestPrefixCount {
                    if pending.suffix(candidateCount) == secret.prefix(candidateCount) {
                        longestPrefixCount = candidateCount
                        break
                    }
                    candidateCount -= 1
                }
            }

            return longestPrefixCount
        }

        private func adjustedEmitCountAvoidingSplitSecrets(_ initialEmitCount: Int) -> Int {
            var emitCount = initialEmitCount
            var changed = true

            while changed {
                changed = false
                for secret in masker.sortedSecrets {
                    for range in ranges(of: secret, in: pending) {
                        guard range.lowerBound < emitCount, range.upperBound > emitCount else {
                            continue
                        }
                        emitCount = min(emitCount, range.lowerBound)
                        changed = true
                    }
                }
            }

            return emitCount
        }

        private func ranges(of secret: String, in text: String) -> [(lowerBound: Int, upperBound: Int)] {
            var ranges: [(lowerBound: Int, upperBound: Int)] = []
            var searchStart = text.startIndex

            while searchStart < text.endIndex,
                  let range = text.range(of: secret, range: searchStart..<text.endIndex) {
                ranges.append((
                    lowerBound: text.distance(from: text.startIndex, to: range.lowerBound),
                    upperBound: text.distance(from: text.startIndex, to: range.upperBound)
                ))
                searchStart = text.index(after: range.lowerBound)
            }

            return ranges
        }
    }

    private static func maskTokens(for secrets: [String]) -> [String] {
        var seen = Set<String>()
        var tokens: [String] = []

        for secret in secrets where !secret.isEmpty {
            append(secret, to: &tokens, seen: &seen)

            guard secret.count >= minimumDerivedTokenSecretLength else { continue }

            for token in derivedTokens(for: secret) {
                append(token, to: &tokens, seen: &seen)
            }
        }

        return tokens
    }

    private static func append(_ token: String, to tokens: inout [String], seen: inout Set<String>) {
        guard !token.isEmpty, !seen.contains(token) else { return }
        seen.insert(token)
        tokens.append(token)
    }

    private static func derivedTokens(for secret: String) -> [String] {
        let bytes = Array(secret.utf8)
        var tokens: [String] = []

        tokens.append(contentsOf: base64Tokens(for: Data(bytes)))
        tokens.append(hexToken(for: bytes, uppercase: false))
        tokens.append(hexToken(for: bytes, uppercase: true))
        tokens.append(percentEncodedToken(for: bytes, uppercaseHex: true))
        tokens.append(percentEncodedToken(for: bytes, uppercaseHex: false))
        tokens.append(formURLEncodedToken(for: bytes, uppercaseHex: true))
        tokens.append(formURLEncodedToken(for: bytes, uppercaseHex: false))
        tokens.append(contentsOf: shellSingleQuotedTokens(for: secret))
        tokens.append(shellBackslashEscapedToken(for: secret))
        tokens.append(contentsOf: htmlEscapedTokens(for: secret))
        if let jsonEscaped = jsonEscapedToken(for: secret) {
            tokens.append(jsonEscaped)
        }

        return tokens
    }

    private static func base64Tokens(for data: Data) -> [String] {
        let padded = data.base64EncodedString()
        let unpadded = padded.trimmingCharacters(in: CharacterSet(charactersIn: "="))
        let urlSafePadded = padded
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
        let urlSafeUnpadded = unpadded
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")

        return [padded, unpadded, urlSafePadded, urlSafeUnpadded]
    }

    private static func hexToken(for bytes: [UInt8], uppercase: Bool) -> String {
        bytes.map { String(format: uppercase ? "%02X" : "%02x", $0) }.joined()
    }

    private static func percentEncodedToken(for bytes: [UInt8], uppercaseHex: Bool) -> String {
        bytes.map { byte in
            if isURLUnreserved(byte) {
                return String(UnicodeScalar(byte))
            }
            return String(format: uppercaseHex ? "%%%02X" : "%%%02x", byte)
        }.joined()
    }

    private static func formURLEncodedToken(for bytes: [UInt8], uppercaseHex: Bool) -> String {
        bytes.map { byte in
            if byte == 0x20 {
                return "+"
            }
            if isURLUnreserved(byte) {
                return String(UnicodeScalar(byte))
            }
            return String(format: uppercaseHex ? "%%%02X" : "%%%02x", byte)
        }.joined()
    }

    private static func isURLUnreserved(_ byte: UInt8) -> Bool {
        switch byte {
        case 0x30...0x39, 0x41...0x5A, 0x61...0x7A, 0x2D, 0x2E, 0x5F, 0x7E:
            return true
        default:
            return false
        }
    }

    private static func shellSingleQuotedTokens(for secret: String) -> [String] {
        [
            "'" + secret.replacingOccurrences(of: "'", with: "'\\''") + "'",
            "'" + secret.replacingOccurrences(of: "'", with: "'\"'\"'") + "'",
        ]
    }

    private static func shellBackslashEscapedToken(for secret: String) -> String {
        secret.unicodeScalars.map { scalar in
            if isShellUnquotedSafe(scalar) {
                return String(scalar)
            }
            return "\\" + String(scalar)
        }.joined()
    }

    private static func isShellUnquotedSafe(_ scalar: UnicodeScalar) -> Bool {
        switch scalar.value {
        case 0x30...0x39, 0x41...0x5A, 0x61...0x7A:
            return true
        case 0x25, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x3A, 0x3D, 0x40, 0x5F:
            return true
        default:
            return false
        }
    }

    private static func htmlEscapedTokens(for secret: String) -> [String] {
        let numericApostrophe = htmlEscapedToken(for: secret, apostrophe: "&#39;")
        let hexadecimalApostrophe = htmlEscapedToken(for: secret, apostrophe: "&#x27;")
        let namedApostrophe = htmlEscapedToken(for: secret, apostrophe: "&apos;")
        return [numericApostrophe, hexadecimalApostrophe, namedApostrophe]
    }

    private static func htmlEscapedToken(for secret: String, apostrophe: String) -> String {
        secret.unicodeScalars.map { scalar in
            switch scalar.value {
            case 0x22:
                return "&quot;"
            case 0x26:
                return "&amp;"
            case 0x27:
                return apostrophe
            case 0x3C:
                return "&lt;"
            case 0x3E:
                return "&gt;"
            default:
                return String(scalar)
            }
        }.joined()
    }

    private static func jsonEscapedToken(for secret: String) -> String? {
        guard let data = try? JSONEncoder().encode(secret),
              let encoded = String(data: data, encoding: .utf8),
              encoded.count >= 2 else {
            return nil
        }
        return String(encoded.dropFirst().dropLast())
    }
}
