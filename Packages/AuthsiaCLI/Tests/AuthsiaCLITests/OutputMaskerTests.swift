import Testing
import Foundation
@testable import authsia

@Suite("OutputMasker")
struct OutputMaskerTests {

    @Test("masks single secret in a line")
    func maskSingle() {
        let masker = OutputMasker(secrets: ["s3cret"])
        #expect(masker.mask("The password is s3cret here") == "The password is <concealed by authsia> here")
    }

    @Test("masks multiple different secrets")
    func maskMultiple() {
        let masker = OutputMasker(secrets: ["abc123", "xyz789"])
        #expect(masker.mask("keys: abc123 and xyz789") == "keys: <concealed by authsia> and <concealed by authsia>")
    }

    @Test("masks repeated occurrences of same secret")
    func maskRepeated() {
        let masker = OutputMasker(secrets: ["token"])
        #expect(masker.mask("token=token") == "<concealed by authsia>=<concealed by authsia>")
    }

    @Test("masks longest match first to avoid partial replacement")
    func maskLongestFirst() {
        let masker = OutputMasker(secrets: ["pass", "password123"])
        #expect(masker.mask("the password123 value") == "the <concealed by authsia> value")
    }

    @Test("does not remask placeholders when short tokens overlap")
    func doesNotRemaskPlaceholdersWhenShortTokensOverlap() {
        let masker = OutputMasker(secrets: ["abcdef123456", "abcdef", "a"])

        #expect(masker.mask("abcdef") == OutputMasker.placeholder)
        #expect(masker.mask("a") == OutputMasker.placeholder)
    }

    @Test("returns line unchanged when no secrets present")
    func noMatch() {
        let masker = OutputMasker(secrets: ["s3cret"])
        #expect(masker.mask("nothing to see here") == "nothing to see here")
    }

    @Test("handles empty secrets list")
    func emptySecrets() {
        let masker = OutputMasker(secrets: [])
        #expect(masker.mask("some output") == "some output")
    }

    @Test("handles empty input line")
    func emptyInput() {
        let masker = OutputMasker(secrets: ["secret"])
        #expect(masker.mask("") == "")
    }

    @Test("skips empty strings in secrets list")
    func skipsEmptySecrets() {
        let masker = OutputMasker(secrets: ["", "real"])
        #expect(masker.mask("a real thing") == "a <concealed by authsia> thing")
    }

    @Test("masks secret that spans entire line")
    func entireLine() {
        let masker = OutputMasker(secrets: ["wholebuffer"])
        #expect(masker.mask("wholebuffer") == "<concealed by authsia>")
    }

    @Test("masks multiline content line by line")
    func maskLines() {
        let masker = OutputMasker(secrets: ["secret"])
        let lines = ["line1 secret", "line2 ok", "line3 secret end"]
        let results = lines.map { masker.mask($0) }
        #expect(results[0] == "line1 <concealed by authsia>")
        #expect(results[1] == "line2 ok")
        #expect(results[2] == "line3 <concealed by authsia> end")
    }

    @Test("handles special regex characters in secrets")
    func specialChars() {
        let masker = OutputMasker(secrets: ["p@$$w0rd!"])
        #expect(masker.mask("auth: p@$$w0rd!") == "auth: <concealed by authsia>")
    }

    @Test("masks Data buffer")
    func maskData() {
        let masker = OutputMasker(secrets: ["hunter2"])
        let input = Data("password is hunter2".utf8)
        let output = masker.mask(input)
        #expect(String(data: output, encoding: .utf8) == "password is <concealed by authsia>")
    }

    @Test("masks base64 encoded secret")
    func masksBase64EncodedSecret() {
        let masker = OutputMasker(secrets: ["hunter2"])

        #expect(masker.mask("encoded=aHVudGVyMg==") == "encoded=<concealed by authsia>")
    }

    @Test("masks unpadded base64 encoded secret")
    func masksUnpaddedBase64EncodedSecret() {
        let masker = OutputMasker(secrets: ["hunter2"])

        #expect(masker.mask("encoded=aHVudGVyMg") == "encoded=<concealed by authsia>")
    }

    @Test("masks URL-safe base64 encoded secret")
    func masksURLSafeBase64EncodedSecret() {
        let masker = OutputMasker(secrets: ["????"])

        #expect(masker.mask("encoded=Pz8_Pw==") == "encoded=<concealed by authsia>")
    }

    @Test("masks hex encoded secret")
    func masksHexEncodedSecret() {
        let masker = OutputMasker(secrets: ["hunter2"])

        #expect(masker.mask("hex=68756e74657232") == "hex=<concealed by authsia>")
        #expect(masker.mask("hex=68756E74657232") == "hex=<concealed by authsia>")
    }

    @Test("masks percent encoded secret")
    func masksPercentEncodedSecret() {
        let masker = OutputMasker(secrets: ["token/next"])

        #expect(masker.mask("url=token%2Fnext") == "url=<concealed by authsia>")
        #expect(masker.mask("url=token%2fnext") == "url=<concealed by authsia>")
    }

    @Test("masks form URL encoded secret")
    func masksFormURLEncodedSecret() {
        let masker = OutputMasker(secrets: ["token next/ok"])

        #expect(masker.mask("body=token+next%2Fok") == "body=<concealed by authsia>")
        #expect(masker.mask("body=token+next%2fok") == "body=<concealed by authsia>")
    }

    @Test("masks JSON escaped secret")
    func masksJSONEscapedSecret() {
        let masker = OutputMasker(secrets: ["pa\"ss\\word\n"])

        #expect(masker.mask(#"json="pa\"ss\\word\n""#) == "json=\"<concealed by authsia>\"")
    }

    @Test("masks shell escaped secret")
    func masksShellEscapedSecret() {
        let masker = OutputMasker(secrets: ["pa'ss word"])

        #expect(masker.mask(#"shell='pa'\''ss word'"#) == "shell=<concealed by authsia>")
        #expect(masker.mask(#"shell='pa'"'"'ss word'"#) == "shell=<concealed by authsia>")
        #expect(masker.mask(#"shell=pa\'ss\ word"#) == "shell=<concealed by authsia>")
    }

    @Test("masks HTML escaped secret")
    func masksHTMLEscapedSecret() {
        let masker = OutputMasker(secrets: ["a&\"'<b>"])

        #expect(masker.mask("html=a&amp;&quot;&#39;&lt;b&gt;") == "html=<concealed by authsia>")
        #expect(masker.mask("html=a&amp;&quot;&#x27;&lt;b&gt;") == "html=<concealed by authsia>")
        #expect(masker.mask("html=a&amp;&quot;&apos;&lt;b&gt;") == "html=<concealed by authsia>")
    }

    @Test("streaming masker hides secrets split across buffers")
    func streamMasksSplitSecret() {
        let masker = OutputMasker(secrets: ["hunter2"])
        var stream = masker.makeStream()

        let first = stream.mask(Data("password is hun".utf8))
        let second = stream.mask(Data("ter2\n".utf8))
        let flushed = stream.flush()
        let output = String(data: first + second + flushed, encoding: .utf8)

        #expect(output == "password is <concealed by authsia>\n")
    }

    @Test("streaming masker hides base64 secret split across buffers")
    func streamMasksSplitBase64Secret() {
        let masker = OutputMasker(secrets: ["hunter2"])
        var stream = masker.makeStream()

        let first = stream.mask(Data("encoded=aHV".utf8))
        let second = stream.mask(Data("udGVyMg==\n".utf8))
        let flushed = stream.flush()
        let output = String(data: first + second + flushed, encoding: .utf8)

        #expect(output == "encoded=<concealed by authsia>\n")
    }

    @Test("streaming masker emits unrelated output without waiting for a long secret")
    func streamEmitsUnrelatedOutputWithoutLongSecretDelay() {
        let masker = OutputMasker(secrets: [String(repeating: "s", count: 1_024)])
        var stream = masker.makeStream()

        let output = stream.mask(Data("VITE ready\n".utf8))

        #expect(String(data: output, encoding: .utf8) == "VITE ready\n")
    }

    @Test("passes through non-UTF8 data unchanged")
    func nonUTF8Passthrough() {
        let masker = OutputMasker(secrets: ["secret"])
        let data = Data([0xFF, 0xFE, 0x00])  // invalid UTF-8
        #expect(masker.mask(data) == data)
    }

    @Test("strict stream rejects invalid UTF-8 without emitting it")
    func strictStreamRejectsInvalidUTF8() {
        var stream = OutputMasker(secrets: ["secret"]).makeStream()

        let result = stream.mask(Data([0xFF, 0xFE, 0x00]), policy: .strict)

        #expect(result == .failure(.invalidUTF8))
    }

    @Test("strict stream accepts a UTF-8 scalar split across buffers")
    func strictStreamAcceptsSplitUTF8Scalar() {
        var stream = OutputMasker(secrets: ["secret"]).makeStream()
        let bytes = Array("€".utf8)

        let first = stream.mask(Data(bytes.prefix(1)), policy: .strict)
        let second = stream.mask(Data(bytes.dropFirst()), policy: .strict)
        let flushed = stream.flush(policy: .strict)

        #expect(first == .success(Data()))
        #expect(second == .success(Data("€".utf8)))
        #expect(flushed == .success(Data()))
    }

    @Test("strict stream rejects an incomplete UTF-8 scalar at EOF")
    func strictStreamRejectsIncompleteUTF8AtEOF() {
        var stream = OutputMasker(secrets: ["secret"]).makeStream()

        #expect(stream.mask(Data([0xE2]), policy: .strict) == .success(Data()))
        #expect(stream.flush(policy: .strict) == .failure(.invalidUTF8))
    }

    @Test("compatibility stream explicitly preserves invalid bytes")
    func compatibilityStreamPreservesInvalidBytes() {
        var stream = OutputMasker(secrets: ["secret"]).makeStream()
        let data = Data([0xFF, 0xFE, 0x00])

        #expect(stream.mask(data, policy: .maskedCompatibility) == .success(data))
    }
}
