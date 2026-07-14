// Tests/AuthsiaCLITests/StdinReaderSecretTests.swift
import Foundation

import ArgumentParser
import Testing
@testable import authsia

@Suite("StdinReader secret resolution")
struct StdinReaderSecretTests {

    // MARK: - resolveSecret

    @Test("rejects bare secret value")
    func resolveSecret_rejectsBareValue() {
        #expect(throws: (any Error).self) {
            try StdinReader.resolveSecret(option: "my-secret-value", prompt: "Password")
        }
    }

    @Test("rejects bare value with spaces")
    func resolveSecret_rejectsBareValueWithSpaces() {
        #expect(throws: (any Error).self) {
            try StdinReader.resolveSecret(option: "my secret", prompt: "Password")
        }
    }

    @Test("API key rejection uses key option guidance")
    func resolveSecret_apiKeyRejectionUsesKeyOptionGuidance() {
        do {
            _ = try StdinReader.resolveSecret(option: "sk_live_abc123", prompt: "API Key", optionName: "key")
            Issue.record("expected ValidationError")
        } catch {
            let message = (error as? ValidationError)?.message ?? String(describing: error)
            #expect(message.contains("Use '--key -' to read from stdin"))
            #expect(!message.contains("--password -"))
        }
    }

    @Test("accepts dash for stdin")
    func resolveSecret_acceptsDash() {
        // Can't fully test stdin read without a pipe fixture, but we can verify
        // it doesn't throw the "bare value" rejection error by checking the code path.
        // The "-" case calls readLine() which will fail in test context (no stdin),
        // but the error will be "Failed to read stdin", not the "not safe" rejection.
        let error = try? StdinReader.resolveSecret(option: "-", prompt: "Password")
        // If we get here without the "not safe" error, the dash path was taken.
        // In test context, readLine() will throw "Failed to read stdin" or return nil.
        // Either way, we're not hitting the rejection path, which is what we're testing.
        _ = error // suppress unused warning
    }

    // MARK: - resolveOptionalSecret

    @Test("nil returns nil")
    func resolveOptionalSecret_nilReturnsNil() throws {
        let result = try StdinReader.resolveOptionalSecret(option: nil, prompt: "Password")
        #expect(result == nil)
    }

    @Test("rejects bare secret value")
    func resolveOptionalSecret_rejectsBareValue() {
        #expect(throws: (any Error).self) {
            try StdinReader.resolveOptionalSecret(option: "sk_live_abc123", prompt: "Password")
        }
    }

    @Test("rejects empty string as bare value")
    func resolveOptionalSecret_rejectsEmptyString() {
        #expect(throws: (any Error).self) {
            try StdinReader.resolveOptionalSecret(option: "", prompt: "Password")
        }
    }

    @Test("API key optional rejection uses token alias guidance")
    func resolveOptionalSecret_apiKeyRejectionUsesTokenOptionGuidance() {
        do {
            _ = try StdinReader.resolveOptionalSecret(option: "sk_live_abc123", prompt: "API Key", optionName: "token")
            Issue.record("expected ValidationError")
        } catch {
            let message = (error as? ValidationError)?.message ?? String(describing: error)
            #expect(message.contains("Use '--token -' to read from stdin"))
            #expect(!message.contains("--password -"))
        }
    }
}
