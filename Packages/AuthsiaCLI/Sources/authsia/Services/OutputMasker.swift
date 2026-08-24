import Foundation

struct OutputMasker {
    static let placeholder = "<concealed by authsia>"
    private static let minimumDerivedTokenSecretLength = 4
    private static let minimumFlexibleHexTokenLength = 8

    /// One mask token, held as UTF-8 bytes.
    ///
    /// Matching runs on bytes rather than `String`. Every derived token below is a
    /// byte-oriented encoding of the secret, and a byte search costs orders of magnitude
    /// less than Foundation's grapheme-aware `range(of:)` once the relay buffer is
    /// megabytes wide. UTF-8 is self-synchronising and a token is a whole number of
    /// scalars, so a byte match can only ever land on a scalar boundary.
    struct Token {
        let bytes: [UInt8]
        /// Knuth-Morris-Pratt failure table, so the streaming hold-back can find the
        /// longest prefix of this token that is a suffix of the pending buffer in one pass.
        let failure: [Int]
        /// Whether this token can also appear with whitespace between its hex digits.
        /// ASCII hex only: the digits are compared byte-for-byte, so a token carrying
        /// fullwidth hex digits could never match a whitespace-separated hex dump anyway.
        let isFlexibleHex: Bool

        init(bytes: [UInt8]) {
            self.bytes = bytes
            self.failure = Self.failureTable(for: bytes)
            self.isFlexibleHex = bytes.count >= OutputMasker.minimumFlexibleHexTokenLength
                && bytes.count.isMultiple(of: 2)
                && bytes.allSatisfy(OutputMasker.isASCIIHexDigit)
        }

        /// `failure[k]` is the length of the longest proper prefix of `bytes[..<k]` that is
        /// also a suffix of it.
        private static func failureTable(for bytes: [UInt8]) -> [Int] {
            var failure = [Int](repeating: 0, count: bytes.count + 1)
            var length = 0
            var index = 1
            while index < bytes.count {
                while length > 0, bytes[index] != bytes[length] {
                    length = failure[length]
                }
                if bytes[index] == bytes[length] {
                    length += 1
                }
                failure[index + 1] = length
                index += 1
            }
            return failure
        }
    }

    /// Secrets and common deterministic encodings sorted longest-first.
    private let tokens: [Token]

    init(secrets: [String]) {
        self.init(tokenStrings: Self.maskTokens(for: secrets))
    }

    /// Exact-match mode for destructive cleanup. Does not add encoded or escaped derivatives.
    init(exactSecrets: [String]) {
        var seen = Set<String>()
        self.init(tokenStrings: exactSecrets.filter { !$0.isEmpty && seen.insert($0).inserted })
    }

    private init(tokenStrings: [String]) {
        self.tokens = tokenStrings
            .map { Token(bytes: Array($0.utf8)) }
            .sorted { $0.bytes.count > $1.bytes.count }
    }

    /// Replace all occurrences of any secret in the input with the placeholder.
    func mask(_ input: String) -> String {
        guard !tokens.isEmpty else { return input }
        let bytes = Array(input.utf8)
        let matches = matchedRanges(in: bytes)
        guard !matches.isEmpty else { return input }
        return String(decoding: masked(bytes, matches: matches), as: UTF8.self)
    }

    func containsMatch(in input: String) -> Bool {
        guard !tokens.isEmpty else { return false }
        return !matchedRanges(in: Array(input.utf8)).isEmpty
    }

    /// Splice the placeholder over every match, keeping the leftmost one and, where two
    /// start together, the longest.
    private func masked(_ bytes: [UInt8], matches: [Range<Int>]) -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(bytes.count)
        var cursor = 0
        for match in matches where match.lowerBound >= cursor {
            result.append(contentsOf: bytes[cursor..<match.lowerBound])
            result.append(contentsOf: Self.placeholderBytes)
            cursor = match.upperBound
        }
        result.append(contentsOf: bytes[cursor...])
        return result
    }

    private static let placeholderBytes = Array(placeholder.utf8)

    /// Every token occurrence, sorted leftmost first and longest first where two share a
    /// start offset. Overlapping occurrences of the same token are all reported, matching
    /// the byte-by-byte advance below.
    private func matchedRanges(in bytes: [UInt8]) -> [Range<Int>] {
        guard !tokens.isEmpty, !bytes.isEmpty else { return [] }
        var matches: [Range<Int>] = []

        bytes.withUnsafeBufferPointer { haystack in
            for token in tokens {
                token.bytes.withUnsafeBufferPointer { needle in
                    Self.appendRanges(of: needle, in: haystack, to: &matches)
                }
                guard token.isFlexibleHex else { continue }
                Self.appendWhitespaceFlexibleHexRanges(of: token.bytes, in: haystack, to: &matches)
            }
        }

        return matches.sorted { lhs, rhs in
            if lhs.lowerBound != rhs.lowerBound {
                return lhs.lowerBound < rhs.lowerBound
            }
            return lhs.upperBound > rhs.upperBound
        }
    }

    private static func appendRanges(
        of needle: UnsafeBufferPointer<UInt8>,
        in haystack: UnsafeBufferPointer<UInt8>,
        to matches: inout [Range<Int>]
    ) {
        guard let needleBase = needle.baseAddress,
              let haystackBase = haystack.baseAddress,
              !needle.isEmpty,
              haystack.count >= needle.count else { return }

        let limit = haystack.count - needle.count
        var start = 0
        while start <= limit {
            guard let hit = memchr(haystackBase + start, Int32(needle[0]), limit - start + 1) else {
                return
            }
            let offset = UnsafeRawPointer(hit) - UnsafeRawPointer(haystackBase)
            if memcmp(haystackBase + offset, needleBase, needle.count) == 0 {
                matches.append(offset..<(offset + needle.count))
            }
            start = offset + 1
        }
    }

    /// Matches a hex token whose digits are separated by whitespace, as `xxd -p` and
    /// `hexdump` emit. Only ranges that actually contain whitespace are reported; the
    /// contiguous form is already found by the plain byte search.
    private static func appendWhitespaceFlexibleHexRanges(
        of hex: [UInt8],
        in haystack: UnsafeBufferPointer<UInt8>,
        to matches: inout [Range<Int>]
    ) {
        guard let firstDigit = hex.first else { return }
        var search = 0

        while search < haystack.count {
            guard haystack[search] == firstDigit else {
                search += 1
                continue
            }

            var digitIndex = 0
            var cursor = search
            var matchEnd = search
            var sawWhitespace = false

            while digitIndex < hex.count, cursor < haystack.count {
                if let width = whitespaceScalarWidth(in: haystack, at: cursor) {
                    cursor += width
                    sawWhitespace = true
                    continue
                }
                guard haystack[cursor] == hex[digitIndex] else { break }
                digitIndex += 1
                cursor += 1
                matchEnd = cursor
            }

            // Whitespace is only ever skipped between two matched digits, so it always
            // falls inside the reported range.
            if digitIndex == hex.count, sawWhitespace {
                matches.append(search..<matchEnd)
            }
            search += 1
        }
    }

    private static func isASCIIHexDigit(_ byte: UInt8) -> Bool {
        switch byte {
        case 0x30...0x39, 0x41...0x46, 0x61...0x66:
            return true
        default:
            return false
        }
    }

    /// Byte width of the Unicode whitespace scalar starting at `index`, or nil when the
    /// byte there does not begin one. Covers the same scalars as `Character.isWhitespace`.
    private static func whitespaceScalarWidth(
        in bytes: UnsafeBufferPointer<UInt8>,
        at index: Int
    ) -> Int? {
        let byte = bytes[index]
        if byte < 0x80 {
            switch byte {
            case 0x09...0x0D, 0x20:
                return 1
            default:
                return nil
            }
        }

        func byteAt(_ offset: Int) -> UInt8? {
            let position = index + offset
            return position < bytes.count ? bytes[position] : nil
        }

        switch byte {
        case 0xC2:  // U+0085 NEL, U+00A0 no-break space
            guard let second = byteAt(1), second == 0x85 || second == 0xA0 else { return nil }
            return 2
        case 0xE1:  // U+1680 ogham space mark
            guard byteAt(1) == 0x9A, byteAt(2) == 0x80 else { return nil }
            return 3
        case 0xE2:  // U+2000...U+200A, U+2028, U+2029, U+202F, U+205F
            guard let second = byteAt(1), let third = byteAt(2) else { return nil }
            if second == 0x80, (0x80...0x8A).contains(third) { return 3 }
            if second == 0x80, third == 0xA8 || third == 0xA9 || third == 0xAF { return 3 }
            if second == 0x81, third == 0x9F { return 3 }
            return nil
        case 0xE3:  // U+3000 ideographic space
            guard byteAt(1) == 0x80, byteAt(2) == 0x80 else { return nil }
            return 3
        default:
            return nil
        }
    }

    /// Byte width of the whitespace scalar *ending* at `index`, or nil. Used when walking
    /// the pending buffer backwards.
    private static func whitespaceScalarWidthEnding(
        in bytes: UnsafeBufferPointer<UInt8>,
        at index: Int
    ) -> Int? {
        for width in 1...3 where index - width + 1 >= 0 {
            if whitespaceScalarWidth(in: bytes, at: index - width + 1) == width {
                return width
            }
        }
        return nil
    }

    /// Mask a Data buffer. Treats input as UTF-8; non-UTF-8 data passes through unchanged.
    func mask(_ data: Data) -> Data {
        guard !tokens.isEmpty else { return data }
        let bytes = Array(data)
        guard Self.isEntirelyValidUTF8(bytes) else { return data }
        let matches = matchedRanges(in: bytes)
        guard !matches.isEmpty else { return data }
        return Data(masked(bytes, matches: matches))
    }

    static func isEntirelyValidUTF8(_ bytes: [UInt8]) -> Bool {
        guard case .success(let prefixLength) = Stream.validUTF8PrefixLength(in: bytes) else {
            return false
        }
        return prefixLength == bytes.count
    }

    func makeStream() -> Stream {
        Stream(masker: self)
    }

    struct Stream {
        private let masker: OutputMasker
        /// Bytes withheld from the last emit because they may still complete a token.
        private var pending: [UInt8] = []
        /// Strict mode only: a trailing partial UTF-8 scalar awaiting its continuation bytes.
        private var pendingUTF8Bytes: [UInt8] = []

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
                return .success(maskCompatibility(Array(data)))
            }
        }

        private mutating func maskCompatibility(_ bytes: [UInt8]) -> Data {
            guard !masker.tokens.isEmpty else { return Data(bytes) }
            guard OutputMasker.isEntirelyValidUTF8(bytes) else {
                return flush() + Data(bytes)
            }

            pending.append(contentsOf: bytes)

            // Scanned once and reused: the emitted prefix is a prefix of `pending`, so the
            // matches that fall inside it are exactly the matches of that prefix.
            let matches = masker.matchedRanges(in: pending)
            let holdCount = pendingTokenPrefixByteCount()
            var emitCount = max(pending.count - holdCount, 0)
            emitCount = Self.emitCountAvoidingSplitMatches(emitCount, matches: matches)

            guard emitCount > 0 else { return Data() }

            let emitted = Array(pending[..<emitCount])
            pending.removeFirst(emitCount)
            let emittedMatches = matches.filter { $0.upperBound <= emitCount }
            guard !emittedMatches.isEmpty else { return Data(emitted) }
            return Data(masker.masked(emitted, matches: emittedMatches))
        }

        mutating func flush() -> Data {
            guard !pending.isEmpty else { return Data() }
            let matches = masker.matchedRanges(in: pending)
            let output = matches.isEmpty ? pending : masker.masked(pending, matches: matches)
            pending.removeAll(keepingCapacity: false)
            return Data(output)
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
            pendingUTF8Bytes.append(contentsOf: data)
            switch Self.validUTF8PrefixLength(in: pendingUTF8Bytes) {
            case .failure(let failure):
                pendingUTF8Bytes.removeAll(keepingCapacity: false)
                return .failure(failure)
            case .success(let prefixLength):
                guard prefixLength > 0 else { return .success(Data()) }
                let prefix = Array(pendingUTF8Bytes[..<prefixLength])
                pendingUTF8Bytes.removeFirst(prefixLength)
                return .success(maskCompatibility(prefix))
            }
        }

        static func validUTF8PrefixLength(
            in bytes: [UInt8]
        ) -> Result<Int, OutputDisclosureFailure> {
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

        /// Longest suffix of `pending` that is a proper prefix of some token, so a token
        /// split across two reads is never emitted in halves.
        private func pendingTokenPrefixByteCount() -> Int {
            var longest = pending.withUnsafeBufferPointer { buffer -> Int in
                var best = 0
                for token in masker.tokens {
                    best = max(best, Self.tokenPrefixSuffixLength(token, in: buffer))
                }
                return best
            }

            for token in masker.tokens where token.isFlexibleHex {
                longest = max(longest, pendingWhitespaceFlexibleHexPrefixCount(hex: token.bytes))
            }

            return longest
        }

        /// Length of the longest proper prefix of `token` that is a suffix of `buffer`.
        ///
        /// Only the last `token.count - 1` bytes can open a partial match, and running the
        /// token's KMP automaton across that window leaves the answer in its final state.
        /// The cost is bounded by the token, not by the buffer: the descending
        /// `suffix(k) == prefix(k)` probe this replaces re-walked the buffer tail for every
        /// candidate length, which made every read quadratic in the longest token.
        private static func tokenPrefixSuffixLength(
            _ token: Token,
            in buffer: UnsafeBufferPointer<UInt8>
        ) -> Int {
            let tokenCount = token.bytes.count
            guard tokenCount > 1, !buffer.isEmpty else { return 0 }

            var state = 0
            var index = buffer.count - min(buffer.count, tokenCount - 1)
            while index < buffer.count {
                let byte = buffer[index]
                while state > 0, byte != token.bytes[state] {
                    state = token.failure[state]
                }
                if byte == token.bytes[state] {
                    state += 1
                }
                // A complete match is the split-match case below, not a hold-back.
                if state == tokenCount {
                    state = token.failure[tokenCount]
                }
                index += 1
            }
            return state
        }

        private func pendingWhitespaceFlexibleHexPrefixCount(hex: [UInt8]) -> Int {
            pending.withUnsafeBufferPointer { buffer -> Int in
                // Only a bounded tail of `pending` can open a whitespace-flexible hex match:
                // every non-whitespace byte has to match `hex` in order, so the walk stops at
                // the first byte that cannot (and once the tail already holds as many hex
                // digits as `hex` itself, since a longer suffix could only be a complete match
                // rather than the partial one we hold back for).
                var tailStart = buffer.count
                var hexDigitCount = 0
                var index = buffer.count - 1
                while index >= 0 {
                    if let width = OutputMasker.whitespaceScalarWidthEnding(in: buffer, at: index) {
                        tailStart = index - width + 1
                        index -= width
                        continue
                    }
                    guard OutputMasker.isASCIIHexDigit(buffer[index]),
                          hexDigitCount < hex.count else { break }
                    hexDigitCount += 1
                    tailStart = index
                    index -= 1
                }

                // Longest candidate first, so the first match is the longest one.
                var start = tailStart
                while start < buffer.count {
                    guard OutputMasker.isASCIIHexDigit(buffer[start]) else {
                        start += 1
                        continue
                    }

                    var digitIndex = 0
                    var matchesThroughEnd = true
                    var sawHexDigit = false
                    var cursor = start
                    while cursor < buffer.count {
                        if let width = OutputMasker.whitespaceScalarWidth(in: buffer, at: cursor) {
                            cursor += width
                            continue
                        }
                        guard digitIndex < hex.count, buffer[cursor] == hex[digitIndex] else {
                            matchesThroughEnd = false
                            break
                        }
                        digitIndex += 1
                        sawHexDigit = true
                        cursor += 1
                    }

                    if matchesThroughEnd, sawHexDigit, digitIndex < hex.count {
                        return buffer.count - start
                    }
                    start += 1
                }

                return 0
            }
        }

        /// Pull the emit boundary back behind any complete match that straddles it, so a
        /// match is never split across two writes. Repeats because pulling back can expose
        /// an earlier straddling match.
        private static func emitCountAvoidingSplitMatches(
            _ initialEmitCount: Int,
            matches: [Range<Int>]
        ) -> Int {
            var emitCount = initialEmitCount
            var changed = true

            while changed {
                changed = false
                for match in matches {
                    guard match.lowerBound < emitCount, match.upperBound > emitCount else {
                        continue
                    }
                    emitCount = min(emitCount, match.lowerBound)
                    changed = true
                }
            }

            return emitCount
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
