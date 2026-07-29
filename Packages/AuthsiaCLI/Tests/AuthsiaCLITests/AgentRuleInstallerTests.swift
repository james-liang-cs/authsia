import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
@testable import authsia

@Suite("Agent rule installer")
struct AgentRuleInstallerTests {
    @Test("agent rules describe only selected agent platforms")
    func agentRulesDescribeOnlySelectedAgentPlatforms() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])

        let agentsRules = try read("AGENTS.md", in: root)
        let sharedRules = try read(".authsia/agent-rules.md", in: root)
        for rules in [agentsRules, sharedRules] {
            #expect(rules.contains("AUTHSIA_AGENT_PLATFORM=codex"))
            #expect(rules.contains(
                "Before running an Authsia command, use the full command's `-h` help " +
                    "to confirm its arguments and options."
            ))
            #expect(!rules.contains("AUTHSIA_AGENT_PLATFORM=<claude-code|codex|cursor|windsurf|copilot>"))
            #expect(!rules.contains("AUTHSIA_AGENT_PLATFORM=claude-code"))
            #expect(!rules.contains("AUTHSIA_AGENT_PLATFORM=cursor"))
            #expect(!rules.contains("AUTHSIA_AGENT_PLATFORM=windsurf"))
            #expect(!rules.contains("AUTHSIA_AGENT_PLATFORM=copilot"))
            #expect(!rules.contains("Every GitHub Copilot Authsia terminal command"))
        }
    }
}
