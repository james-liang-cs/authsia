import ArgumentParser
import Foundation

struct Setup: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "setup",
        abstract: "Set up or repair local Authsia CLI integration",
        discussion: """
            Runs the local setup work the CLI can safely perform: shell integration repair,
            setup status, and cleanup of Authsia-managed shell files.

            For first-run bridge registration, SSH agent enablement, and starter vault
            creation, open the Authsia app and follow the guided setup.

            Examples:
              authsia setup
              authsia setup --status
              authsia setup --repair
              authsia setup --uninstall-clean
            """
    )

    @Flag(name: .long, help: "Print setup status without changing files")
    var status = false

    @Flag(name: .long, help: "Repair user shell integration")
    var repair = false

    @Flag(name: .long, help: "Remove Authsia-managed shell integration and user symlink")
    var uninstallClean = false

    func run() throws {
        let selected = [status, repair, uninstallClean].filter { $0 }.count
        guard selected <= 1 else {
            throw ValidationError(
                "Use only one of --status, --repair, or --uninstall-clean. " +
                    "Examples: authsia setup --status, authsia setup --repair"
            )
        }

        if uninstallClean {
            let result = try SetupRepairService.uninstallClean()
            print(Self.renderCleanup(result))
            return
        }

        if repair || !status {
            let result = try SetupRepairService.repairShellIntegration()
            print(Self.renderRepair(result))
            print("")
        }

        print(SetupStatusRenderer.render(Self.currentStatus()))
        print("")
        print("Open a new terminal for shell and SSH changes to take effect.")
    }

    static func currentStatus() -> SetupStatus {
        let agentSocketPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".authsia/agent.sock").path
        let shellIntegrationInstalled = SetupRepairService.hasManagedShellIntegration()
        var environment = ProcessInfo.processInfo.environment
        if shellIntegrationInstalled {
            environment["AUTHSIA_SHELL_INTEGRATION"] = "1"
        }
        let pingPayload = try? AuthsiaBridgeClient.shared.ping()
        let issues = Doctor.collectIssues(
            environment: environment,
            sessionExpiresAt: SessionCache.loadExpiresAt(),
            pingPayload: pingPayload,
            sshAgentRunning: SSHAgentLoader.isAgentRunning(),
            currentDate: Date(),
            authsiaAgentSocketExists: FileManager.default.fileExists(atPath: agentSocketPath),
            authsiaAgentSocketPath: agentSocketPath,
            runningCLIPath: Doctor.resolveRunningCLIPath()
        )

        return SetupStatus(
            cliInstalled: true,
            shellIntegrationInstalled: shellIntegrationInstalled,
            bridgeReachable: pingPayload != nil,
            sshAgentSocketExists: FileManager.default.fileExists(atPath: agentSocketPath),
            doctorIssueCount: issues.count
        )
    }

    static func renderRepair(_ result: SetupRepairResult) -> String {
        guard !result.updatedFiles.isEmpty else {
            return "Shell integration is already installed."
        }

        return """
        Updated shell integration:
        \(result.updatedFiles.map { "  \($0)" }.joined(separator: "\n"))
        """
    }

    static func renderCleanup(_ result: SetupRepairResult) -> String {
        var lines: [String] = []
        if !result.updatedFiles.isEmpty {
            lines.append("Cleaned shell files:")
            lines += result.updatedFiles.map { "  \($0)" }
        }
        if !result.removedFiles.isEmpty {
            if !lines.isEmpty { lines.append("") }
            lines.append("Removed managed files:")
            lines += result.removedFiles.map { "  \($0)" }
        }
        if lines.isEmpty {
            lines.append("No Authsia-managed shell integration or user symlink was found.")
        }
        return lines.joined(separator: "\n")
    }
}
