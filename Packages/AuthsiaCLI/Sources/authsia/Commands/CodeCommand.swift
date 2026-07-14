import Foundation
import ArgumentParser

struct Code: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Generate a TOTP code (requires biometric approval)",
        discussion: """
            Generates a time-based one-time password for the matching OTP item.
            Requires biometric authentication or an active session.

            Examples:
              authsia code GitHub                     Show code as JSON
              authsia code GitHub --copy               Show and copy to clipboard
              authsia code GitHub --watch              Refresh every second
              authsia code GitHub --format table        Human-readable output
            """
    )

    @Argument(help: "OTP name or ID to match")
    var query: String

    @Flag(name: .long, help: "Copy code to clipboard")
    var copy = false

    @Option(name: .long, help: "Clear clipboard after N seconds (0 to disable, default: 30)")
    var clipboardTimeout: Int = 30

    @Flag(name: .long, help: "Refresh the code every second until interrupted")
    var watch = false

    @Option(name: .long, help: "Output format: json (default), table")
    var format: OutputFormat = .json

    @Flag(name: .customLong("json"), help: .hidden)
    var json = false

    func run() throws {
        if clipboardTimeout < 0 {
            throw ValidationError("--clipboard-timeout must be 0 or greater. Use 0 to clear immediately after copy.")
        }

        let outputFormat = try resolveOutputFormat(format: format, jsonFlag: json, command: "authsia code")
        let client = AuthsiaBridgeClient.shared

        try client.withRequestedCommand("code", includeAutomationCredential: false) {
            if watch {
                var didCopy = false
                while true {
                    let result = try client.getOTP(query: query)
                    if copy && !didCopy {
                        try ClipboardClient.system.copy(result.code, clipboardTimeout)
                        didCopy = true
                    }
                    print(try OutputFormatter.formatOTPResult(result, format: outputFormat))
                    Thread.sleep(forTimeInterval: 1)
                }
            } else {
                let result = try client.getOTP(query: query)
                if copy { try ClipboardClient.system.copy(result.code, clipboardTimeout) }
                print(try OutputFormatter.formatOTPResult(result, format: outputFormat))
            }
        }
    }
}
