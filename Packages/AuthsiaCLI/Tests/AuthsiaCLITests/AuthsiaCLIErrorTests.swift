import ArgumentParser
import Foundation
import Testing
@testable import authsia

@Suite("Authsia CLI error routing")
struct AuthsiaCLIErrorTests {
    @Test("automation credential validation errors are runtime messages")
    func automationCredentialValidationErrorsAreRuntimeMessages() {
        let message = Authsia.runtimeValidationMessage(
            for: ValidationError("Automation credential 'abc' has been revoked.")
        )

        #expect(message?.contains("Automation credential 'abc' has been revoked.") == true)
        #expect(message?.contains("unset AUTHSIA_ACCESS_CREDENTIAL") == true)
        #expect(message?.contains("Usage:") == false)
    }

    @Test("ordinary validation errors still use ArgumentParser")
    func ordinaryValidationErrorsStillUseArgumentParser() {
        let message = Authsia.runtimeValidationMessage(
            for: ValidationError("Missing expected argument '<query>'.")
        )

        #expect(message == nil)
    }

    @Test("shared no match errors explain how to inspect ids")
    func sharedNoMatchErrorsExplainHowToInspectIDs() {
        let message = CLIError.noMatch(kind: "password item", query: "Missing").message

        #expect(message.contains("No password item matches for 'Missing'."))
        #expect(message.contains("Run `authsia list passwords --format table` to see available items and IDs"))
    }

    @Test("shared API key no match errors suggest API key list")
    func sharedAPIKeyNoMatchErrorsSuggestAPIKeyList() {
        let message = CLIError.noMatch(kind: "api-key items", query: "Missing").message

        #expect(message.contains("No api-key items matches for 'Missing'."))
        #expect(message.contains("Run `authsia list api-keys --format table` to see available items and IDs"))
    }

    @Test("shared multiple match errors include exact id guidance")
    func sharedMultipleMatchErrorsIncludeExactIDGuidance() {
        let message = CLIError.multipleMatches(
            kind: "password item",
            query: "Shared",
            matches: [
                CLIError.MatchDescriptor(name: "Shared", id: "ID-1"),
                CLIError.MatchDescriptor(name: "Shared", id: "ID-2"),
            ]
        ).message

        #expect(message.contains("Multiple password item matches for 'Shared':"))
        #expect(message.contains("Rerun with one exact ID from the list above instead of the name"))
    }

    @Test("version reads containing app bundle when CLI is bundled")
    func versionReadsContainingAppBundle() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-version-test-\(UUID().uuidString)", isDirectory: true)
        let contentsDir = tempDir.appendingPathComponent("Authsia.app/Contents", isDirectory: true)
        let helpersDir = contentsDir.appendingPathComponent("Helpers", isDirectory: true)
        try FileManager.default.createDirectory(at: helpersDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let info: [String: Any] = [
            "CFBundleShortVersionString": "9.8.7",
        ]
        (info as NSDictionary).write(to: contentsDir.appendingPathComponent("Info.plist"), atomically: true)

        let bundledCLI = helpersDir.appendingPathComponent("authsia")

        #expect(Authsia.version(executableURL: bundledCLI) == "9.8.7")
    }

    @Test("executable URL prefers bundle exec path over a bare argv[0]")
    func resolvesBundlePathOverBareArgv0() {
        // Regression: when run via PATH lookup, argv[0] is the bare word
        // "authsia" which resolves relative to cwd and never finds the bundle,
        // making version fall back. Bundle.main.executableURL must win.
        let bundlePath = URL(fileURLWithPath: "/Applications/Authsia.app/Contents/Helpers/authsia")
        let resolved = Authsia.resolveExecutableURL(bundleExecutableURL: bundlePath, argv0: "authsia")

        #expect(resolved.path.hasPrefix("/"))
        #expect(resolved.path.hasSuffix("Authsia.app/Contents/Helpers/authsia"))
    }

    @Test("executable URL falls back to argv[0] when bundle URL is unavailable")
    func resolvesArgv0WhenNoBundleURL() {
        let resolved = Authsia.resolveExecutableURL(
            bundleExecutableURL: nil,
            argv0: "/Applications/Authsia.app/Contents/Helpers/authsia"
        )

        #expect(resolved.path.hasSuffix("Authsia.app/Contents/Helpers/authsia"))
    }
}
