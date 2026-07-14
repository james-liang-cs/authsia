import ArgumentParser
import Foundation

struct Unlock: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Start a timed session (skip per-request approval)",
        discussion: """
            Authenticates once via biometrics and creates a session.
            Subsequent get/code commands skip approval until the session
            expires. Session duration is configured in the Authsia app.

            Examples:
              authsia unlock
              authsia unlock --status    # check session status
              authsia code GitHub        # no approval prompt
              authsia get password Foo   # no approval prompt
            """
    )

    @Flag(name: .long, help: "Show current session status instead of unlocking")
    var status = false

    func run() throws {
        if status {
            showStatus()
            return
        }

        let result = try AuthsiaBridgeClient.shared.unlock()
        print("Session unlocked until \(result.expiresAt.formatted(date: .omitted, time: .standard))")
    }

    private func showStatus() {
        guard let expiresAt = SessionCache.loadExpiresAt() else {
            print("No active session.")
            return
        }

        let remaining = expiresAt.timeIntervalSinceNow
        let minutes = Int(remaining) / 60
        let seconds = Int(remaining) % 60

        print("Session active")
        print("  Expires at: \(expiresAt.formatted(date: .omitted, time: .standard))")
        if minutes > 0 {
            print("  Remaining:  \(minutes)m \(seconds)s")
        } else {
            print("  Remaining:  \(seconds)s")
        }
    }
}
