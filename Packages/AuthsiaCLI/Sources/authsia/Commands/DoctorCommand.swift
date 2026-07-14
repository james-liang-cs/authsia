import ArgumentParser
import AuthenticatorBridge
import Foundation

struct Doctor: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "doctor",
        abstract: "Check setup and suggest fixes",
        discussion: """
            Runs a small set of health checks for the Authsia CLI runtime.

            Examples:
              authsia doctor
            """
    )

    func run() throws {
        let now = Date()
        let agentSocketPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".authsia/agent.sock").path
        let pingPayload = try? AuthsiaBridgeClient.shared.ping()
        let issues = Self.collectIssues(
            environment: ProcessInfo.processInfo.environment,
            sessionExpiresAt: SessionCache.loadExpiresAt(),
            pingPayload: pingPayload,
            sshAgentRunning: SSHAgentLoader.isAgentRunning(),
            currentDate: now,
            authsiaAgentSocketExists: FileManager.default.fileExists(atPath: agentSocketPath),
            authsiaAgentSocketPath: agentSocketPath,
            runningCLIPath: Self.resolveRunningCLIPath()
        )

        if issues.isEmpty {
            print("Authsia CLI: healthy")
            return
        }

        print(Self.renderIssues(issues))
    }

    static func collectIssues(
        environment: [String: String],
        sessionExpiresAt: Date?,
        pingPayload: BridgePingPayload?,
        sshAgentRunning: Bool,
        currentDate: Date,
        authsiaAgentSocketExists: Bool = false,
        authsiaAgentSocketPath: String? = nil,
        runningCLIPath: String? = nil
    ) -> [DoctorIssue] {
        var issues: [DoctorIssue] = []

        if pingPayload == nil {
            issues.append(
                DoctorIssue(
                    kind: .bridgeUnavailable,
                    title: "Authsia app is not reachable",
                    detail: "The CLI could not connect to the Authsia bridge.",
                    fix: "Start the Authsia app, then Enable CLI Access in Settings > Security."
                )
            )
        }

        if let payload = pingPayload,
           let bundledCLIPath = payload.bundledCLIPath,
           let runningCLIPath,
           !runningCLIPath.isEmpty,
           runningCLIPath != bundledCLIPath {
            issues.append(
                DoctorIssue(
                    kind: .cliBinaryMismatch,
                    title: "CLI is out of sync with the Authsia app",
                    detail: "Running CLI: \(runningCLIPath)\n  Bundled by app: \(bundledCLIPath)",
                    fix: "Open Authsia > Settings > CLI Access > Update CLI to repoint the symlink at the current app bundle."
                )
            )
        }

        if environment["AUTHSIA_SHELL_INTEGRATION"] != "1" {
            issues.append(
                DoctorIssue(
                    kind: .shellIntegrationDisabled,
                    title: "Shell integration is not enabled",
                    detail: "Active-shell export is disabled for authsia load --silent.",
                    fix: "Run `eval \"$(authsia init zsh)\"` or `eval \"$(authsia init bash)\"`."
                )
            )
        }

        if !sshAgentRunning && !authsiaAgentSocketExists {
            issues.append(
                DoctorIssue(
                    kind: .sshAgentMissing,
                    title: "No SSH agent available",
                    detail: "The built-in Authsia SSH agent is not running and no system ssh-agent was found.",
                    fix: "Launch the Authsia app once to register its built-in agent (it then runs on demand, no need to keep it open), or run `eval $(ssh-agent)` for the system agent."
                )
            )
        }

        if authsiaAgentSocketExists,
           let authsiaAgentSocketPath,
           environment["SSH_AUTH_SOCK"] != authsiaAgentSocketPath {
            let current = environment["SSH_AUTH_SOCK"].map { "Current SSH_AUTH_SOCK: \($0)" }
                ?? "SSH_AUTH_SOCK is unset"
            issues.append(
                DoctorIssue(
                    kind: .sshAgentSocketMismatch,
                    title: "This shell is not using the Authsia SSH agent",
                    detail: "\(current)\n  Authsia agent socket: \(authsiaAgentSocketPath)\n"
                        + "  Adopted SSH keys won't work here (e.g. git fails with 'Permission denied (publickey)').",
                    fix: "Run `eval \"$(authsia init zsh)\"` (or open a new terminal) to point SSH_AUTH_SOCK at the Authsia agent."
                )
            )
        }

        if let sessionExpiresAt, sessionExpiresAt <= currentDate {
            issues.append(
                DoctorIssue(
                    kind: .sessionExpired,
                    title: "Cached session has expired",
                    detail: "The current CLI session is no longer valid.",
                    fix: "Run `authsia unlock` to start a new session."
                )
            )
        }

        return issues
    }

    /// Returns the absolute, symlink-resolved path of the currently running CLI binary.
    static func resolveRunningCLIPath(
        argv0: String = CommandLine.arguments.first ?? "",
        fileManager: FileManager = .default
    ) -> String? {
        guard !argv0.isEmpty else { return nil }
        let candidate: String
        if argv0.hasPrefix("/") {
            candidate = argv0
        } else if let executable = Bundle.main.executablePath {
            candidate = executable
        } else {
            return nil
        }
        // realpath follows every symlink in the chain, which is exactly what we
        // want: `~/.local/bin/authsia` resolves to the helper inside the bundle.
        return (candidate as NSString).resolvingSymlinksInPath
    }

    static func renderIssues(_ issues: [DoctorIssue]) -> String {
        issues.map { issue in
            """
            \(issue.title)
              \(issue.detail)
              Fix: \(issue.fix)
            """
        }.joined(separator: "\n")
    }
}

struct DoctorIssue {
    enum Kind {
        case bridgeUnavailable
        case shellIntegrationDisabled
        case sshAgentMissing
        case sshAgentSocketMismatch
        case sessionExpired
        case cliBinaryMismatch
    }

    let kind: Kind
    let title: String
    let detail: String
    let fix: String
}
