import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
@testable import authsia

@Suite("Chrome autofill command")
struct ChromeAutofillCommandTests {
    @Test("command is hidden from the root help")
    func commandIsHiddenFromRootHelp() {
        #expect(ChromeAutofill.configuration.shouldDisplay == false)
        #expect(!Authsia.helpMessage(columns: 160).contains("chrome-autofill"))
    }

    @Test("matches parses host, url, and kind")
    func matchesParsesHostURLAndKind() throws {
        let command = try ChromeAutofill.Matches.parse([
            "--host", "example.com",
            "--url", "https://example.com/login",
            "--kind", "otp",
            "--chrome-native-host",
        ])

        #expect(command.host == "example.com")
        #expect(command.url == "https://example.com/login")
        #expect(try ChromeAutofill.Matches.credentialKind(command.kind) == .otp)
        #expect(command.chromeNativeHost == true)
    }

    @Test("matches rejects an unknown kind")
    func matchesRejectsUnknownKind() {
        #expect(throws: ValidationError.self) {
            _ = try ChromeAutofill.Matches.credentialKind("api-key")
        }
    }

    @Test("matches requires the chrome native host marker")
    func matchesRequiresChromeNativeHostMarker() throws {
        let command = try ChromeAutofill.Matches.parse(["--host", "example.com"])

        #expect(throws: ValidationError.self) {
            try command.validateChromeNativeHostMarker(processAncestry: [
                AgenticProcessReference(processName: "authsia", bundleIdentifier: nil),
                AgenticProcessReference(processName: "AuthsiaNativeHost", bundleIdentifier: nil),
            ])
        }
    }

    @Test("matches marker requires native host ancestry")
    func matchesMarkerRequiresNativeHostAncestry() throws {
        let command = try ChromeAutofill.Matches.parse([
            "--host", "example.com",
            "--chrome-native-host",
        ])

        try command.validateChromeNativeHostMarker(processAncestry: [
            AgenticProcessReference(processName: "authsia", bundleIdentifier: nil),
            AgenticProcessReference(processName: "AuthsiaNativeHost", bundleIdentifier: nil),
        ])

        #expect(throws: ValidationError.self) {
            try command.validateChromeNativeHostMarker(processAncestry: [
                AgenticProcessReference(processName: "authsia", bundleIdentifier: nil),
                AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
            ])
        }
    }
}
