import ArgumentParser

struct Guard: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "guard",
        abstract: "Activate workspace guard in the current shell",
        discussion: """
            With Authsia shell integration enabled, activates the current workspace's
            guarded terminal environment without using eval manually.

            Run `authsia setup --repair`, then open a new terminal before using this command.
            """
    )

    static let shellIntegrationMessage = """
    `authsia guard` changes the current terminal, so it requires Authsia shell integration.
    Run `authsia setup --repair`, open a new terminal, then run `authsia guard`.
    """

    func run() throws {
        throw ValidationError(Self.shellIntegrationMessage)
    }
}
