import ArgumentParser

struct Unguard: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "unguard",
        abstract: "Restart the current tab in normal terminal mode",
        discussion: """
            With Authsia shell integration enabled, restarts the current tab in the
            same directory without workspace guard shims.

            Run `authsia setup --repair`, then open a new terminal before using this command.
            """
    )

    static let shellIntegrationMessage = """
    `authsia unguard` restarts the current terminal, so it requires Authsia shell integration.
    Run `authsia setup --repair`, open a new terminal, then run `authsia unguard`.
    """

    func run() throws {
        throw ValidationError(Self.shellIntegrationMessage)
    }
}
