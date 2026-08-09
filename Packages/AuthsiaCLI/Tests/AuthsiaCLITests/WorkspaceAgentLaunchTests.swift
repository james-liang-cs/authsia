import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
@testable import authsia

@Suite("Workspace agent launch")
struct WorkspaceAgentLaunchTests {
    @Test("agent launch builds secret-free commands and open arguments")
    func agentLaunchBuildsSecretFreeCommandsAndOpenArguments() throws {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let defaultAgent = try Workspace.Agent.parse([])
        let guardedPrefix = "cd '/tmp/My Project' && __authsia_guard_env=\"$(authsia workspace guard --print-env)\" && " +
            "eval \"$__authsia_guard_env\" && unset __authsia_guard_env && "

        #expect(defaultAgent.tool == .claudeCode)
        #expect(WorkspaceAgentTool.allCases.map(\.title) == [
            "Codex",
            "Claude Code",
            "VS Code",
            "Cursor",
            "Windsurf",
        ])
        #expect(WorkspaceAgentTool.allCases.map(\.agentPlatform) == [
            "codex",
            "claude-code",
            "copilot",
            "cursor",
            "windsurf",
        ])
        let launchCases: [(WorkspaceAgentTool, String)] = [
            (.codex, "AUTHSIA_AGENT_PLATFORM=codex AUTHSIA_AGENT_INVOKES_AUTHSIA=1 codex)"),
            (.claudeCode, "AUTHSIA_AGENT_PLATFORM=claude-code AUTHSIA_AGENT_INVOKES_AUTHSIA=1 claude)"),
            (.vsCode, "AUTHSIA_AGENT_PLATFORM=copilot AUTHSIA_AGENT_INVOKES_AUTHSIA=1 code .)"),
            (.cursor, "AUTHSIA_AGENT_PLATFORM=cursor AUTHSIA_AGENT_INVOKES_AUTHSIA=1 cursor .)"),
            (.windsurf, "AUTHSIA_AGENT_PLATFORM=windsurf AUTHSIA_AGENT_INVOKES_AUTHSIA=1 windsurf .)"),
        ]
        for (tool, suffix) in launchCases {
            let command = WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: tool).launchCommand
            #expect(command.hasPrefix(guardedPrefix))
            #expect(command.contains("/usr/bin/awk"))
            #expect(command.contains("entry !~ /^authsia-guard-/"))
            #expect(command.hasSuffix(suffix))
        }
        #expect(
            WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .vsCode).openArguments ==
                [
                    "-n",
                    "--env", "AUTHSIA_AGENT_PLATFORM=copilot",
                    "--env", "AUTHSIA_AGENT_INVOKES_AUTHSIA=1",
                    "-a", "Visual Studio Code",
                    "--args",
                    "/tmp/My Project",
                ]
        )
        #expect(
            WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .cursor).openArguments ==
                [
                    "-n",
                    "--env", "AUTHSIA_AGENT_PLATFORM=cursor",
                    "--env", "AUTHSIA_AGENT_INVOKES_AUTHSIA=1",
                    "-a", "Cursor",
                    "--args",
                    "/tmp/My Project",
                ]
        )
        #expect(
            WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .windsurf).openArguments ==
                [
                    "-n",
                    "--env", "AUTHSIA_AGENT_PLATFORM=windsurf",
                    "--env", "AUTHSIA_AGENT_INVOKES_AUTHSIA=1",
                    "-a", "Windsurf",
                    "--args",
                    "/tmp/My Project",
                ]
        )
    }

    @Test("terminal agents have no GUI app but are still launch-eligible")
    func terminalAgentsHaveNoGUIAppButAreStillLaunchEligible() {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        // codex and claude-code have no GUI app to `open -a`; previously this left them
        // print-only (never launched). They must now still be eligible to launch.
        #expect(WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .codex).openArguments == nil)
        #expect(WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .claudeCode).openArguments == nil)
        #expect(Workspace.Agent.shouldOpenTool(
            dryRun: false,
            printLaunchCommand: false,
            hasGoalHandoff: false
        ))
    }

    @Test("terminal agent launch uses exec request and repairs dumb TERM")
    func terminalAgentLaunchUsesExecRequestAndRepairsDumbTERM() {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)

        let request = WorkspaceAgentLauncher.currentTerminalLaunchRequest(
            tool: .codex,
            workingDirectory: root,
            environment: ["TERM": "dumb"]
        )
        let existingTerminal = WorkspaceAgentLauncher.currentTerminalLaunchRequest(
            tool: .claudeCode,
            workingDirectory: root,
            environment: ["TERM": "xterm-ghostty"]
        )

        #expect(request.executable == "codex")
        #expect(request.arguments == ["codex"])
        #expect(request.workingDirectory == root)
        #expect(request.environmentOverrides == [
            "TERM": "xterm-256color",
            "AUTHSIA_AGENT_PLATFORM": "codex",
            "AUTHSIA_AGENT_INVOKES_AUTHSIA": "1",
        ])
        #expect(existingTerminal.environmentOverrides == [
            "AUTHSIA_AGENT_PLATFORM": "claude-code",
            "AUTHSIA_AGENT_INVOKES_AUTHSIA": "1",
        ])
        // No guard shim in the environment: PATH untouched, nothing to unset.
        #expect(request.environmentOverrides["PATH"] == nil)
        #expect(request.environmentUnsets.isEmpty)
    }

    @Test("terminal agent launch strips the guard shim so the agent reaches real tools directly")
    func terminalAgentLaunchStripsGuardShim() {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let shimDir = "/tmp/authsia-guard-ABC"

        // Prefers the saved pre-guard PATH when present.
        let withOriginal = WorkspaceAgentLauncher.currentTerminalLaunchRequest(
            tool: .claudeCode,
            workingDirectory: root,
            environment: [
                "TERM": "xterm-256color",
                "PATH": "\(shimDir):/usr/bin:/bin",
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": shimDir,
                "AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH": "/usr/local/bin:/usr/bin:/bin",
            ]
        )
        #expect(withOriginal.environmentOverrides["PATH"] == "/usr/local/bin:/usr/bin:/bin")
        #expect(withOriginal.environmentUnsets.contains("AUTHSIA_WORKSPACE_GUARD"))
        #expect(withOriginal.environmentUnsets.contains("AUTHSIA_WORKSPACE_GUARD_SHIM_DIR"))
        #expect(withOriginal.environmentUnsets.contains("AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH"))
        #expect(withOriginal.environmentUnsets.contains(WorkspaceGuardedTerminal.shimInvocationEnvironmentName))

        // Falls back to removing the shim entry from PATH when no saved PATH exists.
        let withoutOriginal = WorkspaceAgentLauncher.currentTerminalLaunchRequest(
            tool: .claudeCode,
            workingDirectory: root,
            environment: [
                "TERM": "xterm-256color",
                "PATH": "\(shimDir):/usr/bin:/bin",
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": shimDir,
            ]
        )
        #expect(withoutOriginal.environmentOverrides["PATH"] == "/usr/bin:/bin")
    }

    @Test("terminal agent launch recovers from stale or incomplete guard metadata")
    func terminalAgentLaunchRecoversFromStaleGuardMetadata() {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)

        // Shim entry survives on PATH but the marker variable that recorded it is gone.
        let lostShimDirectory = WorkspaceAgentLauncher.currentTerminalLaunchRequest(
            tool: .claudeCode,
            workingDirectory: root,
            environment: [
                "PATH": "/tmp/authsia-guard-ABC:/usr/bin:/bin",
                "AUTHSIA_WORKSPACE_GUARD": "1",
            ]
        )
        #expect(lostShimDirectory.environmentOverrides["PATH"] == "/usr/bin:/bin")
        #expect(lostShimDirectory.environmentUnsets.contains("AUTHSIA_WORKSPACE_GUARD"))

        // No guard variable at all; only PATH still shows a shim from an earlier session.
        let markersGone = WorkspaceAgentLauncher.currentTerminalLaunchRequest(
            tool: .codex,
            workingDirectory: root,
            environment: ["PATH": "/tmp/authsia-guard-ABC:/usr/bin:/bin"]
        )
        #expect(markersGone.environmentOverrides["PATH"] == "/usr/bin:/bin")

        // A saved pre-guard PATH that itself carries a shim entry is cleaned, not trusted.
        let staleOriginal = WorkspaceAgentLauncher.currentTerminalLaunchRequest(
            tool: .codex,
            workingDirectory: root,
            environment: [
                "PATH": "/tmp/authsia-guard-DEF:/tmp/authsia-guard-ABC:/usr/bin:/bin",
                "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": "/tmp/authsia-guard-DEF",
                "AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH": "/tmp/authsia-guard-ABC:/usr/bin:/bin",
            ]
        )
        #expect(staleOriginal.environmentOverrides["PATH"] == "/usr/bin:/bin")
    }

    @Test("GUI agent launch environment drops guard markers and the shim PATH")
    func guiAgentLaunchEnvironmentDropsGuardMarkersAndShimPath() {
        // `open` hands its own environment to the app it launches, so the IDE would
        // otherwise inherit the guarded tab's shims.
        let unguarded = WorkspaceAgentLauncher.unguardedEnvironment([
            "PATH": "/tmp/authsia-guard-ABC:/usr/bin:/bin",
            "HOME": "/Users/example",
            "AUTHSIA_WORKSPACE_GUARD": "1",
            "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": "/tmp/authsia-guard-ABC",
            "AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH": "/usr/local/bin:/usr/bin:/bin",
            WorkspaceGuardedTerminal.shimInvocationEnvironmentName: "1",
            "AUTHSIA_WORKSPACE_ROOT": "/tmp/My Project",
        ])

        #expect(unguarded["PATH"] == "/usr/local/bin:/usr/bin:/bin")
        #expect(unguarded["AUTHSIA_WORKSPACE_GUARD"] == nil)
        #expect(unguarded["AUTHSIA_WORKSPACE_GUARD_SHIM_DIR"] == nil)
        #expect(unguarded["AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH"] == nil)
        #expect(unguarded[WorkspaceGuardedTerminal.shimInvocationEnvironmentName] == nil)
        // Workspace root stays: it is context for the agent, not guard machinery.
        #expect(unguarded["AUTHSIA_WORKSPACE_ROOT"] == "/tmp/My Project")
        #expect(unguarded["HOME"] == "/Users/example")
    }

    @Test("GUI agent launch leaves an unguarded environment untouched")
    func guiAgentLaunchLeavesUnguardedEnvironmentUntouched() {
        let environment = ["PATH": "/usr/bin:/bin", "HOME": "/Users/example"]

        #expect(WorkspaceAgentLauncher.unguardedEnvironment(environment) == environment)
    }

    @Test("agent launch failures explain install PATH guarded terminal and print fallback")
    func agentLaunchFailuresExplainInstallPathGuardedTerminalAndPrintFallback() {
        let guiFailure = WorkspaceAgentLauncher.openFailureMessage()
        let enterDirectoryFailure = WorkspaceAgentLauncher.enterDirectoryFailureMessage(path: "/tmp/Missing Project")
        let missingProgram = WorkspaceAgentLauncher.missingProgramMessage(program: "codex")
        let launchFailure = WorkspaceAgentLauncher.launchFailureMessage(program: "claude", detail: "permission denied")

        #expect(guiFailure.contains("Make sure the app is installed"))
        #expect(guiFailure.contains("authsia workspace agent --print"))
        #expect(guiFailure.contains("guarded terminal"))
        #expect(enterDirectoryFailure.contains("Could not enter workspace folder /tmp/Missing Project"))
        #expect(enterDirectoryFailure.contains("Make sure the folder still exists"))
        #expect(enterDirectoryFailure.contains("authsia workspace status"))
        #expect(enterDirectoryFailure.contains("authsia workspace agent --print"))
        #expect(missingProgram.contains("Could not find codex on PATH"))
        #expect(missingProgram.contains("Install codex"))
        #expect(missingProgram.contains("same --tool"))
        #expect(missingProgram.contains("authsia workspace agent --print"))
        #expect(launchFailure.contains("Failed to launch claude: permission denied"))
        #expect(launchFailure.contains("same --tool"))
        #expect(launchFailure.contains("guarded terminal"))
    }

    @Test("agent launch render explains JIT boundary without secrets or shell")
    func agentLaunchRenderExplainsJITBoundaryWithoutSecretsOrShell() {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let rendered = WorkspaceAgentLaunchPlan.render(
            WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .codex)
        )

        #expect(rendered.contains("Agentic workspace launch: Codex"))
        #expect(rendered.contains("Command: cd '/tmp/My Project' && __authsia_guard_env="))
        #expect(rendered.contains("authsia workspace guard --print-env"))
        #expect(rendered.contains("/usr/bin/awk"))
        #expect(rendered.contains("entry !~ /^authsia-guard-/"))
        #expect(rendered.contains("AUTHSIA_AGENT_PLATFORM=codex AUTHSIA_AGENT_INVOKES_AUTHSIA=1 codex"))
        #expect(rendered.contains("Authsia injects no managed secrets"))
        #expect(rendered.contains("guarded terminal"))
        #expect(rendered.contains("JIT/automation"))
        #expect(rendered.contains("authsia workspace run -- <command>"))
        #expect(!rendered.contains("authsia workspace shell"))
        #expect(!rendered.contains("SUPER_SECRET_TOKEN"))
    }

    @Test("agent goal handoff renders launch command and secret boundary")
    func agentGoalHandoffRendersLaunchCommandAndSecretBoundary() {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let plan = WorkspaceAgentLaunchPlan(workspaceRoot: root, tool: .codex)
        let guardedLaunch = plan.launchCommand
        let rendered = WorkspaceAgentLaunchPlan.renderHandoff(
            plan,
            goal: "Fix checkout bug without printing $API_KEY"
        )

        #expect(rendered.contains("Agent goal"))
        #expect(rendered.contains("Workspace: My Project"))
        #expect(rendered.contains("Tool: Codex"))
        #expect(rendered.contains("Launch: \(guardedLaunch)"))
        #expect(guardedLaunch.contains("/usr/bin/awk"))
        #expect(guardedLaunch.contains("entry !~ /^authsia-guard-/"))
        #expect(rendered.contains("Fix checkout bug without printing $API_KEY"))
        #expect(rendered.contains("authsia workspace status"))
        #expect(rendered.contains("authsia workspace run --dry-run -- <command>"))
        #expect(rendered.contains("JIT or automation token"))
        #expect(rendered.contains("authsia workspace run -- <command>"))
        #expect(rendered.contains("authsia exec"))
        #expect(!rendered.contains("authsia://"))
        #expect(!rendered.contains("sk_live"))
        #expect(rendered == AgentWorkspaceGoalHandoff.make(
            workspaceName: "My Project",
            toolName: "Codex",
            launchCommand: guardedLaunch,
            goal: "Fix checkout bug without printing $API_KEY"
        )?.clipboardText)
    }

    @Test("agent goal validation rejects pasted secrets but allows placeholders")
    func agentGoalValidationRejectsPastedSecretsButAllowsPlaceholders() throws {
        let stripeKey = "sk_" + "live_51ABCDEF1234567890abcdef"

        #expect(try Workspace.Agent.validatedGoal("Fix checkout using $API_KEY and ${Var}") == "Fix checkout using $API_KEY and ${Var}")
        #expect(try Workspace.Agent.validatedGoal("Use authsia://password/API_KEY/password") == "Use authsia://password/API_KEY/password")

        do {
            _ = try Workspace.Agent.validatedGoal("Debug checkout with \(stripeKey)")
            Issue.record("Expected pasted secret goal to be rejected")
        } catch {
            #expect(String(describing: error).contains("appears to contain a secret"))
        }
    }

    @Test("agent goal file reads the same validated handoff text")
    func agentGoalFileReadsTheSameValidatedHandoffText() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let goalFile = root.appendingPathComponent("agent-goal.txt")
        try "  Fix checkout without printing $API_KEY\n".write(to: goalFile, atomically: true, encoding: .utf8)

        #expect(try Workspace.Agent.resolvedGoal(goal: nil, goalFile: goalFile.path) == "Fix checkout without printing $API_KEY")
    }

    @Test("agent goal file dash reads the same validated handoff text from stdin")
    func agentGoalFileDashReadsTheSameValidatedHandoffTextFromStdin() throws {
        #expect(try Workspace.Agent.resolvedGoal(
            goal: nil,
            goalFile: "-",
            standardInput: { "  Fix checkout from piped task brief using $API_KEY\n" }
        ) == "Fix checkout from piped task brief using $API_KEY")
    }

    @Test("agent goal file rejects ambiguous inline goal")
    func agentGoalFileRejectsAmbiguousInlineGoal() throws {
        do {
            _ = try Workspace.Agent.resolvedGoal(goal: "Fix checkout", goalFile: "/tmp/agent-goal.txt")
            Issue.record("Expected --goal and --goal-file to be mutually exclusive")
        } catch {
            #expect(String(describing: error).contains("Use either --goal or --goal-file"))
        }
    }

    @Test("agent goal handoff is print only")
    func agentGoalHandoffIsPrintOnly() {
        #expect(!Workspace.Agent.shouldOpenTool(
            dryRun: false,
            printLaunchCommand: false,
            hasGoalHandoff: true
        ))
        #expect(Workspace.Agent.shouldOpenTool(
            dryRun: false,
            printLaunchCommand: false,
            hasGoalHandoff: false
        ))
        #expect(!Workspace.Agent.shouldOpenTool(
            dryRun: true,
            printLaunchCommand: false,
            hasGoalHandoff: false
        ))
        #expect(!Workspace.Agent.shouldOpenTool(
            dryRun: false,
            printLaunchCommand: true,
            hasGoalHandoff: false
        ))
    }
}
