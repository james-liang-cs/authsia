import ArgumentParser
import Darwin
import Foundation

@main
struct Authsia: AsyncParsableCommand {
    static let _ignoreSigpipe: Void = {
        signal(SIGPIPE, SIG_IGN)
    }()

    static let configuration = CommandConfiguration(
        commandName: "authsia",
        abstract: "Authsia - Local Secret Manager",
        discussion: """
            Manage secrets stored in Authsia from the command line.
            Requires the Authsia app to be running with CLI access enabled.

            Top-level commands:
              list        List metadata for vault/OTP items
              code        Generate OTP/TOTP codes
              get         Read one secret item
              load        Load one/many items into runtime env vars
              exec        Run a command with secrets injected into its env
              env         Manage environment profiles
              ssh         SSH key generation, host config, and signing setup
              read        Resolve a secret reference URI and print its value
              inject      Inject resolved secrets into a template
              init        Print shell integration script for --silent load
              guard       Activate workspace guard in the current shell
              unguard     Restart the current tab in normal terminal mode
              unlock      Start session to skip repeated prompts
              lock        End active Authsia sessions
              status      Show app, session, shell, ssh agent, and ssh approval status
              doctor      Check setup and suggest fixes
              setup       Set up or repair local CLI integration
              access      Manage automation access
              agent       Configure AI-agent rule files
              workspace   Initialize and run repo-local Authsia workspaces
              add         Create vault items
              edit        Update vault items
              convert     Convert vault items
              delete      Delete vault items
              scrape      Scan files and migrate secrets
              completion  Generate shell completion script

            Examples:
              authsia list passwords --format table
              authsia code GitHub --copy
              authsia get password MyBank --field password
              eval "$(authsia init zsh)"   # zsh
              eval "$(authsia init bash)"  # bash
              authsia load password DB_PASSWORD
              authsia load api-key API_KEY --silent
              authsia env add --name Production --folder Team/API --folder Team/Web
              authsia env add --name Default --all
              authsia env use Production
              authsia ssh generate --name github-work
              authsia ssh generate --name corp-key --type rsa --bits 4096
              authsia ssh config --host github.com --alias github-work --user git --key github-work
              authsia ssh git-signing --principal dev@example.com --public-key ~/.ssh/github-work.pub
              authsia edit ssh deploy --approval always --hosts "prod.internal"
              authsia unlock --status
              authsia lock
              authsia status
              authsia doctor
              authsia setup
              authsia access create --name Claude --scope Team/API --ttl 15m --allow exec
              authsia agent init --agent claude-code
              authsia workspace init --env-file .env --agent codex
              authsia workspace run -- npm start
              authsia guard
              authsia unguard
              authsia access list --format table
              authsia access revoke 8D6A3B75-61A4-4F8A-9D67-11A8E4AA4D48
              authsia add note --title "Runbook" --content-file runbook.md
              authsia edit password MyBank --username ops@example.com
              authsia convert password Stripe --to api-key
              authsia delete ssh deploy-key --force
              authsia scrape --path .env --replace-all --folder Team/API
            """,
        version: Self.version(),
        subcommands: [List.self, Code.self, Get.self, Load.self, Exec.self, Env.self, SSH.self, ReadCmd.self, Inject.self, Init.self, Guard.self, Unguard.self, Unlock.self, Lock.self, Status.self, Doctor.self, Setup.self, Access.self, Agent.self, Workspace.self, Add.self, Edit.self, Convert.self, Delete.self, Scrape.self, Audit.self, Completion.self, SSHAutomationGrantCommand.self],
        defaultSubcommand: List.self
    )

    static let fallbackVersion = "1.0.4"

    static func version(executableURL: URL = currentExecutableURL()) -> String {
        appBundleVersion(containing: executableURL) ?? fallbackVersion
    }

    private static func currentExecutableURL() -> URL {
        resolveExecutableURL(
            bundleExecutableURL: Bundle.main.executableURL,
            argv0: CommandLine.arguments.first
        )
    }

    /// Resolve the running binary's path. `argv[0]` is only the bare command
    /// word (e.g. "authsia") on a PATH lookup, which `URL(fileURLWithPath:)`
    /// treats as relative to the cwd — so it never resolves into the app bundle
    /// and version falls back. `Bundle.main.executableURL` is the kernel exec
    /// path (the resolved PATH entry / symlink), so prefer it.
    static func resolveExecutableURL(bundleExecutableURL: URL?, argv0: String?) -> URL {
        if let bundleExecutableURL {
            return bundleExecutableURL.resolvingSymlinksInPath()
        }
        if let argv0 {
            return URL(fileURLWithPath: argv0).resolvingSymlinksInPath()
        }
        return URL(fileURLWithPath: "/usr/bin/authsia")
    }

    private static func appBundleVersion(containing executableURL: URL) -> String? {
        let contentsURL = executableURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        guard contentsURL.lastPathComponent == "Contents" else {
            return nil
        }

        let infoURL = contentsURL.appendingPathComponent("Info.plist")
        guard let info = NSDictionary(contentsOf: infoURL),
              let version = info["CFBundleShortVersionString"] as? String,
              !version.isEmpty else {
            return nil
        }
        return version
    }

    // Route BridgeClientError to stdout so users see it without needing 2>&1.
    // ArgumentParser sends all errors to stderr by default; bridge errors are
    // user-facing (not found, CLI disabled, etc.) and belong on stdout.
    static func exit(withError error: Error) -> Never {
        if let bridgeError = error as? BridgeClientError,
           let message = bridgeError.errorDescription {
            print("Error: \(message)")
            Darwin.exit(1)
        }
        // CLIError thrown directly (not wrapped in ValidationError) is a runtime
        // failure — the user typed a valid command but something failed at
        // execution time. Print the message without usage help.
        if let cliError = error as? CLIError {
            print("Error: \(cliError.message)")
            Darwin.exit(1)
        }
        if let message = runtimeValidationMessage(for: error) {
            print("Error: \(message)")
            Darwin.exit(1)
        }
        // Let ArgumentParser handle everything else (usage errors, --help, etc.)
        let message = message(for: error)
        if !message.isEmpty {
            FileHandle.standardError.write(Data((message + "\n").utf8))
        }
        Darwin.exit(exitCode(for: error).rawValue)
    }

    static func runtimeValidationMessage(for error: Error) -> String? {
        guard let validationError = error as? ValidationError else {
            return nil
        }
        let message = String(describing: validationError)
        guard message.localizedCaseInsensitiveContains("automation credential") else {
            return nil
        }
        return message + "\nHint: run `unset AUTHSIA_ACCESS_CREDENTIAL`, or create a new scoped credential with " +
            "`authsia access create --name release --scope Authsia --ttl 1h --allow exec`."
    }
}
