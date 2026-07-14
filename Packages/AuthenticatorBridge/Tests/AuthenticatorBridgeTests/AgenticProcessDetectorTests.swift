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
}
