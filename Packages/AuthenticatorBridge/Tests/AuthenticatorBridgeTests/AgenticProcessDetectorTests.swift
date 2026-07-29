import Testing
@testable import AuthenticatorBridge

@Suite("Agentic process detector")
struct AgenticProcessDetectorTests {
    @Test("detects known agent processes in ancestry")
    func detectsKnownAgentProcessesInAncestry() {
        let ancestry = [
            AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
            AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
            AgenticProcessReference(processName: "codex", bundleIdentifier: nil),
        ]

        #expect(AgenticProcessDetector.containsAgenticProcess(ancestry))
    }

    @Test("detects Claude Code through runtime wrapper arguments")
    func detectsClaudeCodeThroughRuntimeWrapperArguments() {
        let ancestry = [
            AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
            AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
            AgenticProcessReference(
                processName: "node",
                bundleIdentifier: nil,
                arguments: ["node", "/opt/homebrew/bin/claude", "--output-format", "stream-json"]
            ),
        ]

        #expect(AgenticProcessDetector.containsAgenticProcess(ancestry))
        #expect(
            AgenticProcessDetector.agentPlatform(
                processName: "node",
                bundleIdentifier: nil,
                arguments: ["node", "/opt/homebrew/bin/claude", "--output-format", "stream-json"]
            ) == "claude-code"
        )
    }

    @Test("does not treat documentation filenames as agent platforms")
    func doesNotTreatDocumentationFilenamesAsAgentPlatforms() {
        #expect(
            AgenticProcessDetector.agentPlatform(
                processName: "zsh",
                bundleIdentifier: nil,
                arguments: [
                    "/bin/zsh",
                    "-c",
                    "cat /Users/james/PlayGround/Authsia-Demo/CLAUDE.md ./AGENTS.md",
                ]
            ) == nil
        )
        #expect(
            AgenticProcessDetector.agentPlatform(
                processName: "sh",
                bundleIdentifier: nil,
                arguments: ["/bin/sh", "-c", "head -n 1 ./codex.md"]
            ) == nil
        )
    }

    /// Agent and IDE names double as ordinary English words (fleet, idea, rider, zed)
    /// and as repository names (claude, codex). Scanning every argument as a path meant
    /// `grep codex notes.txt` classified a plain shell command as agentic, which fires a
    /// JIT approval no non-interactive caller can answer. Only real filesystem paths
    /// identify the process; bare tokens and URL targets are command data.
    @Test("ordinary arguments that merely contain an agent or IDE name are not references")
    func ordinaryArgumentsContainingAgentNamesAreNotReferences() {
        func ancestry(_ argv: [String]) -> [AgenticProcessReference] {
            [AgenticProcessReference(processName: "zsh", bundleIdentifier: nil, arguments: argv)]
        }

        for argv in [
            ["grep", "codex", "notes.txt"],
            ["grep", "claude", "README"],
            ["echo", "fleet"],
            ["echo", "idea"],
            ["git", "clone", "https://github.com/example/codex"],
            ["curl", "https://example.com/cursor/api"],
        ] {
            #expect(
                !AgenticProcessDetector.containsAgenticProcess(ancestry(argv)),
                "unexpected agent match: \(argv.joined(separator: " "))"
            )
            #expect(
                !AgenticProcessDetector.containsAutomationSuspectProcess(ancestry(argv)),
                "unexpected automation-suspect match: \(argv.joined(separator: " "))"
            )
        }

        // Genuine executable paths must still resolve.
        #expect(AgenticProcessDetector.containsAgenticProcess(
            ancestry(["node", "/opt/homebrew/lib/claude/cli.js"])
        ))
        #expect(AgenticProcessDetector.containsAutomationSuspectProcess(
            ancestry(["/Applications/Cursor.app/Contents/MacOS/Cursor", "--type=extensionHost"])
        ))
    }

    /// Electron names its child processes `X Helper (Plugin)` / `(Renderer)` / `(GPU)`.
    /// The suspect list holds the base name (`code-helper`), so the extension host — the
    /// process that actually spawns IDE automation — did not match by name, leaving CLI
    /// callers dependent on the `.app` path in argv and host callers on the bundle id.
    @Test("Electron helper role qualifiers do not defeat name matching")
    func electronHelperRoleQualifiersDoNotDefeatNameMatching() {
        for name in [
            "Code Helper (Plugin)",
            "Code Helper (Renderer)",
            "Cursor Helper (Plugin)",
            "Windsurf Helper (Plugin)",
            "Zed Helper (GPU)",
        ] {
            #expect(
                AgenticProcessDetector.isAutomationSuspectProcess(
                    processName: name,
                    bundleIdentifier: nil
                ),
                "expected automation suspect by name alone: \(name)"
            )
        }

        // Unrelated processes must not become suspects.
        for name in ["Terminal", "zsh", "python3", "Finder"] {
            #expect(
                !AgenticProcessDetector.isAutomationSuspectProcess(
                    processName: name,
                    bundleIdentifier: nil
                ),
                "unexpected automation suspect: \(name)"
            )
        }
    }

    /// `codex` on PATH is a symlink to a binary named `codex-aarch64-apple-darwin`, and
    /// `proc_pidpath` resolves it — so the process name never matches the agent list and
    /// argv[0] is the only signal. Requiring a filesystem path for *every* argument
    /// silently disabled JIT for the real agent while the host still demanded a grant.
    @Test("agent invoked through a PATH symlink is identified by argv[0]")
    func agentInvokedThroughPathSymlinkIsIdentifiedByArgv0() {
        #expect(AgenticProcessDetector.containsAgenticProcess([
            AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
            AgenticProcessReference(
                processName: "codex-aarch64-apple-darwin",
                bundleIdentifier: nil,
                arguments: ["codex", "exec", "--full-auto"]
            ),
        ]))

        // The resolved-path form of the same launch must also resolve.
        #expect(AgenticProcessDetector.containsAgenticProcess([
            AgenticProcessReference(
                processName: "codex-aarch64-apple-darwin",
                bundleIdentifier: nil,
                arguments: ["/opt/homebrew/Caskroom/codex/0.145.0/codex-aarch64-apple-darwin"]
            ),
        ]))

        // An operand naming an agent is still not an agent: only argv[0] carries identity.
        #expect(!AgenticProcessDetector.containsAgenticProcess([
            AgenticProcessReference(
                processName: "zsh",
                bundleIdentifier: nil,
                arguments: ["grep", "codex", "notes.txt"]
            ),
        ]))
    }

    @Test("does not treat human terminal hosts as agents")
    func doesNotTreatHumanTerminalHostsAsAgents() {
        let ancestry = [
            AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
            AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
            AgenticProcessReference(processName: "Terminal", bundleIdentifier: "com.apple.Terminal"),
        ]

        #expect(!AgenticProcessDetector.containsAgenticProcess(ancestry))
    }

    @Test("treats IDE helper ancestry as automation suspect without labeling it agentic")
    func treatsIDEHelperAncestryAsAutomationSuspectWithoutLabelingItAgentic() {
        let ancestry = [
            AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
            AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
            AgenticProcessReference(
                processName: "Code Helper",
                bundleIdentifier: "com.microsoft.VSCode",
                arguments: [
                    "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper",
                    "--type=extensionHost",
                ]
            ),
        ]

        #expect(!AgenticProcessDetector.containsAgenticProcess(ancestry))
        #expect(AgenticProcessDetector.containsAutomationSuspectProcess(ancestry))
    }

    @Test("detects GitHub Copilot extension host as agentic")
    func detectsGitHubCopilotExtensionHostAsAgentic() {
        let ancestry = [
            AgenticProcessReference(processName: "npm", bundleIdentifier: nil),
            AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
            AgenticProcessReference(
                processName: "Code Helper",
                bundleIdentifier: "com.microsoft.VSCode",
                arguments: [
                    "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper",
                    "--type=extensionHost",
                    "--extensionDevelopmentPath=/Users/example/.vscode/extensions/github.copilot-chat-1.2.3",
                ]
            ),
        ]

        #expect(AgenticProcessDetector.containsAgenticProcess(ancestry))
    }

    @Test("promotes known agent ancestor above nested CLI parent as host")
    func promotesKnownAgentAncestorAboveNestedCLIParentAsHost() {
        let context = AgenticProcessDetector.parentProcessContext(from: [
            ParentProcessInfo(pid: 41, processName: "authsia", bundleIdentifier: "com.authsia.cli"),
            ParentProcessInfo(pid: 40, processName: "claude.exe", bundleIdentifier: nil),
        ])

        #expect(context.parent?.processName == "authsia")
        #expect(context.host?.processName == "claude.exe")
    }

    @Test("labels IDE hosts with a scope-safe platform name")
    func labelsIDEHostsWithScopeSafePlatformName() {
        #expect(
            AgenticProcessDetector.automationSuspectPlatform(
                processName: "Cursor",
                bundleIdentifier: nil
            ) == "cursor"
        )
        #expect(
            AgenticProcessDetector.automationSuspectPlatform(
                processName: "Cursor Helper (Plugin)",
                bundleIdentifier: nil
            ) == "cursor-helper"
        )
    }

    @Test("does not label shells or ordinary tooling as automation hosts")
    func doesNotLabelShellsOrOrdinaryToolingAsAutomationHosts() {
        for processName in ["zsh", "bash", "login", "git", "ssh"] {
            #expect(
                AgenticProcessDetector.automationSuspectPlatform(
                    processName: processName,
                    bundleIdentifier: nil
                ) == nil
            )
        }
    }

    @Test("does not label a shell that merely references an IDE path")
    func doesNotLabelShellThatMerelyReferencesIDEPath() {
        #expect(
            AgenticProcessDetector.automationSuspectPlatform(
                processName: "zsh",
                bundleIdentifier: nil,
                arguments: ["/bin/zsh", "-c", "source /Applications/Cursor.app/Contents/Resources/shell-integration.zsh"]
            ) == nil
        )
    }
}
