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

    @Test("detects a derived token without producing masked output")
    func detectsDerivedToken() {
        let secret = "synthetic-secret-value"
        let masker = OutputMasker(secrets: [secret])
        let encoded = Data(secret.utf8).base64EncodedString()

        #expect(masker.containsMatch(in: "value=\(encoded)"))
        #expect(!masker.containsMatch(in: "value=ordinary"))
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

    @Test("masks xxd -p wrapped hex without shell transformation tokens")
    func masksXxdPlainWrappedHex() {
        let secret = String(repeating: "a", count: 32)
        let masker = OutputMasker(secrets: [secret])
        let hex = String(repeating: "61", count: 32)
        let wrapped = String(hex.prefix(60)) + "\n" + String(hex.dropFirst(60))

        #expect(masker.mask(wrapped) == OutputMasker.placeholder)
        #expect(masker.mask(wrapped + "\n") == OutputMasker.placeholder + "\n")
        #expect(masker.mask(String(hex.prefix(8))) == String(hex.prefix(8)))
    }

    @Test("masks whitespace-separated hex byte pairs")
    func masksWhitespaceSeparatedHex() {
        let masker = OutputMasker(secrets: ["hunter2"])

        #expect(masker.mask("68 75 6e 74 65 72 32") == OutputMasker.placeholder)
        #expect(masker.mask("68 75\n6e 74 65 72 32") == OutputMasker.placeholder)
    }

    @Test("streaming masker hides xxd -p wrapped hex split across buffers")
    func streamMasksWrappedHexSplitAcrossBuffers() {
        let secret = String(repeating: "a", count: 32)
        let masker = OutputMasker(secrets: [secret])
        var stream = masker.makeStream()
        let hex = String(repeating: "61", count: 32)
        let firstLine = String(hex.prefix(60)) + "\n"
        let secondLine = String(hex.dropFirst(60)) + "\n"

        let first = stream.mask(Data(firstLine.utf8))
        let second = stream.mask(Data(secondLine.utf8))
        let flushed = stream.flush()
        let output = String(data: first + second + flushed, encoding: .utf8)

        #expect(output == OutputMasker.placeholder + "\n")
    }

    @Test("exact secret masker excludes derived encodings")
    func exactSecretMaskerExcludesDerivedEncodings() {
        let exactMasker = OutputMasker(exactSecrets: ["", "abcd", "abcd"])
        let outputMasker = OutputMasker(secrets: ["abcd"])

        #expect(exactMasker.mask("original=abcd") == "original=<concealed by authsia>")
        #expect(exactMasker.mask("base64=YWJjZA==") == "base64=YWJjZA==")
        #expect(exactMasker.mask("hex=61626364") == "hex=61626364")
        #expect(outputMasker.mask("base64=YWJjZA==") == "base64=<concealed by authsia>")
        #expect(outputMasker.mask("hex=61626364") == "hex=<concealed by authsia>")
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

    @Test("streaming a large buffer stays linear in the buffer size")
    func streamLargeBufferStaysLinear() {
        // Two separate quadratics have lived here. Holding back a possible split hex
        // secret rescanned every suffix of the pending buffer; holding back a possible
        // split *plain* secret then re-walked the buffer tail once per candidate length,
        // which cost ~12 minutes to relay a 318 MB `aws dynamodb query` result. 16 MB in
        // under 10s needs only 1.6 MB/s, versus roughly 0.9 MB/s for the latter version.
        let masker = OutputMasker(secrets: [
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "hunter2-p@ssw0rd",
        ])
        var line = ""
        while line.utf8.count < 16 * 1024 * 1024 {
            line += "  { \"id\": \"i-0a1b2c3d4e5f6\", \"vol\": \"deadbeefcafe\" },\n"
        }
        let data = Data(line.utf8)

        let started = DispatchTime.now().uptimeNanoseconds
        var stream = masker.makeStream()
        var offset = 0
        while offset < data.count {
            let end = min(offset + 64 * 1024, data.count)
            _ = stream.mask(data.subdata(in: offset..<end))
            offset = end
        }
        _ = stream.flush()
        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - started) / 1e9

        #expect(elapsed < 10)
    }

    @Test("chunked streaming matches one-shot masking at every chunk size")
    func streamChunkingMatchesOneShot() {
        let masker = OutputMasker(secrets: ["deadbeefcafe", "hunter2"])
        let text = "vol deadbeef cafe id dead\nbeefcafe pw hunter2 tail deadbee"

        expectChunkedStreamMatchesOneShot(masker: masker, text: text)
    }

    @Test("strict streaming masks multi-byte secrets at every chunk size")
    func strictStreamMasksMultiByteSecretsAtEveryChunkSize() {
        // A secret whose UTF-8 bytes do not line up with its grapheme clusters used to
        // reach the terminal in the clear even under `.strict`: the hold-back counted
        // Characters, so a read ending inside "b" + U+0301 emitted the whole secret.
        // `.maskedCompatibility` is deliberately excluded — it forwards any read that
        // splits a scalar, so only `.strict` promises this.
        let secrets = ["ab\u{0301}c", "pässwörd", "秘密鍵", "café"]
        let masker = OutputMasker(secrets: secrets)

        for secret in secrets {
            for text in ["\(secret)", "pre \(secret) post", "\(secret)\(secret)", "é\(secret)🔐"] {
                let data = Data(text.utf8)
                let expected = masker.mask(data)

                for chunkSize in [1, 2, 3, 4, 5, 7, 16, 64] {
                    let label = "chunk \(chunkSize) for \(text.debugDescription)"
                    let result = strictStreamOutput(masker: masker, data: data, chunkSize: chunkSize)

                    #expect(result == .success(expected), "\(label)")
                    if case .success(let output) = result {
                        let rendered = String(data: output, encoding: .utf8) ?? ""
                        #expect(!rendered.contains(secret), "\(label) leaked the secret")
                    }
                }
            }
        }
    }

    private func strictStreamOutput(
        masker: OutputMasker,
        data: Data,
        chunkSize: Int
    ) -> Result<Data, OutputDisclosureFailure> {
        var stream = masker.makeStream()
        var output = Data()
        var offset = 0
        while offset < data.count {
            let end = min(offset + chunkSize, data.count)
            switch stream.mask(data.subdata(in: offset..<end), policy: .strict) {
            case .success(let chunk):
                output += chunk
            case .failure(let failure):
                return .failure(failure)
            }
            offset = end
        }
        switch stream.flush(policy: .strict) {
        case .success(let chunk):
            return .success(output + chunk)
        case .failure(let failure):
            return .failure(failure)
        }
    }

    private func expectChunkedStreamMatchesOneShot(masker: OutputMasker, text: String) {
        let data = Data(text.utf8)
        let expected = masker.mask(data)

        for chunkSize in [1, 2, 3, 7, 16, 64] {
            var stream = masker.makeStream()
            var output = Data()
            var offset = 0
            while offset < data.count {
                let end = min(offset + chunkSize, data.count)
                output += stream.mask(data.subdata(in: offset..<end))
                offset = end
            }
            output += stream.flush()

            #expect(output == expected, "chunk size \(chunkSize) for \(text.debugDescription)")
        }
    }
}
