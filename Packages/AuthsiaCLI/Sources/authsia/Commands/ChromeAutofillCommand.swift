import ArgumentParser
import Foundation
import AuthenticatorBridge

/// Host-scoped autofill lookup used only by the Chrome native host.
///
/// Hidden because it is not a user-facing verb: it exists so the native host can
/// ask "what matches this host?" without pulling the whole vault, which is what
/// used to raise an approval prompt on every credential field.
struct ChromeAutofill: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "chrome-autofill",
        abstract: "Chrome autofill host matching (internal)",
        shouldDisplay: false,
        subcommands: [Matches.self]
    )

    struct Matches: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "List vault items matching a browser host (metadata only)",
            shouldDisplay: false
        )

        @Option(name: .long, help: .hidden)
        var host: String

        @Option(name: .long, help: .hidden)
        var url: String?

        @Option(name: .long, help: .hidden)
        var kind: String?

        @Flag(name: .customLong("chrome-native-host"), help: .hidden)
        var chromeNativeHost = false

        func validateChromeNativeHostMarker(
            processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry()
        ) throws {
            guard chromeNativeHost else {
                throw ValidationError("authsia chrome-autofill requires --chrome-native-host.")
            }
            guard processAncestry.dropFirst().contains(where: {
                BridgeContext.isChromeNativeHostProcessName($0.processName)
            }) else {
                throw ValidationError("--chrome-native-host is reserved for the Authsia Chrome native host.")
            }
        }

        static func credentialKind(_ raw: String?) throws -> ChromeAutofillCredentialKind? {
            guard let raw else { return nil }
            guard let kind = ChromeAutofillCredentialKind(rawValue: raw) else {
                throw ValidationError("--kind must be 'password' or 'otp'.")
            }
            return kind
        }

        func run() throws {
            try validateChromeNativeHostMarker()

            let payload = try AuthsiaBridgeClient.shared.chromeAutofillMatches(
                ChromeAutofillMatchQuery(
                    host: host,
                    currentURL: url,
                    kind: Self.credentialKind(kind)
                )
            )

            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let data = try encoder.encode(payload.matches)
            print(String(decoding: data, as: UTF8.self))
        }
    }
}
