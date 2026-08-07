import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
@testable import authsia

@Suite("Agent rule installer")
struct AgentRuleInstallerTests {
    @Test("agent rules prefer MCP and keep only a selected-platform CLI fallback")
    func agentRulesPreferMCPWithSelectedFallback() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])

        let agentsRules = try read("AGENTS.md", in: root)
        let sharedRules = try read(".authsia/agent-rules.md", in: root)
        for rules in [agentsRules, sharedRules] {
            #expect(rules.contains("use the Authsia MCP tools"))
            #expect(rules.contains("construct the tool input yourself"))
            #expect(rules.contains("Authsia MCP tools are available for the active workspace"))
            #expect(rules.contains("Authsia MCP server must run outside the agent command sandbox"))
            #expect(rules.contains("Do not start `authsia mcp serve` from a sandboxed shell"))
            #expect(rules.contains("`authsia_status`"))
            #expect(rules.contains("`authsia_workspace_inspect`"))
            #expect(rules.contains("`authsia_list` for scoped CLI-enabled Vault item metadata"))
            #expect(rules.contains("`authsia_exec`"))
            #expect(rules.contains("`authsia_access_status`"))
            #expect(rules.contains("`authsia_access_revoke`"))
            #expect(rules.contains("direct argument array"))
            #expect(rules.contains("Do not use `sh -c`"))
            #expect(rules.contains("`authsia exec <type> <query> [options] -- <command> <args>`"))
            #expect(rules.contains("In CLI fallback mode, use attributed `authsia list ...` only for non-secret metadata discovery"))
            #expect(rules.contains("check the complete subcommand's `--help`"))
            #expect(rules.contains("Never use bare `authsia get`, `authsia read`, `authsia load`, `authsia inject`, or `authsia code`"))
            #expect(!rules.contains("`authsia workspace run -- <command> <args>`"))
            #expect(rules.contains("AUTHSIA_AGENT_PLATFORM=codex"))
            #expect(!rules.contains("use the full command's `-h` help"))
            #expect(!rules.contains("Authsia Command History"))
            #expect(!rules.contains("Authsia Sandbox Handling"))
            #expect(!rules.contains("AUTHSIA_AGENT_PLATFORM=<claude-code|codex|cursor|windsurf|copilot>"))
            #expect(!rules.contains("AUTHSIA_AGENT_PLATFORM=claude-code"))
            #expect(!rules.contains("AUTHSIA_AGENT_PLATFORM=cursor"))
            #expect(!rules.contains("AUTHSIA_AGENT_PLATFORM=windsurf"))
            #expect(!rules.contains("AUTHSIA_AGENT_PLATFORM=copilot"))
            #expect(!rules.contains("Every GitHub Copilot Authsia terminal command"))
        }
    }

    @Test("disabled MCP integrations install CLI-only rules with no MCP tool guidance")
    func disabledMCPInstallsCLIOnlyRules() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        _ = try AgentRuleInstaller.install(
            projectRoot: root,
            agents: [.codex],
            includeMCPGuidance: false
        )

        let agentsRules = try read("AGENTS.md", in: root)
        let sharedRules = try read(".authsia/agent-rules.md", in: root)
        for rules in [agentsRules, sharedRules] {
            #expect(rules.contains("MCP integrations are disabled in Authsia"))
            #expect(rules.contains("Every Authsia CLI command Codex runs must start with:"))
            #expect(rules.contains("AUTHSIA_AGENT_PLATFORM=codex"))
            #expect(rules.contains("`authsia exec <type> <query> [options] -- <command> <args>`"))
            #expect(rules.contains("Use attributed `authsia list ...` only for non-secret metadata discovery"))
            #expect(rules.contains("Never ask the user for plaintext secrets"))
            #expect(rules.contains("Never use bare `authsia get`, `authsia read`, `authsia load`, `authsia inject`, or `authsia code`"))

            #expect(!rules.contains("`authsia_status`"))
            #expect(!rules.contains("`authsia_workspace_inspect`"))
            #expect(!rules.contains("`authsia_list`"))
            #expect(!rules.contains("`authsia_exec`"))
            #expect(!rules.contains("`authsia_access_status`"))
            #expect(!rules.contains("`authsia_access_revoke`"))
            #expect(!rules.contains("authsia mcp serve"))
            #expect(!rules.contains("use the Authsia MCP tools"))
            #expect(!rules.contains("CLI fallback"))
        }
    }

    @Test("rules written under one MCP setting are replaced when the setting flips")
    func rulesInstalledUnderOtherMCPSettingAreReplaced() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        _ = try AgentRuleInstaller.install(
            projectRoot: root,
            agents: [.codex],
            includeMCPGuidance: true
        )
        #expect(try read(".authsia/agent-rules.md", in: root).contains("`authsia_exec`"))

        _ = try AgentRuleInstaller.install(
            projectRoot: root,
            agents: [.codex],
            includeMCPGuidance: false
        )
        #expect(try read(".authsia/agent-rules.md", in: root).contains("MCP integrations are disabled"))
        #expect(try !read(".authsia/agent-rules.md", in: root).contains("`authsia_exec`"))
        #expect(try !read("AGENTS.md", in: root).contains("`authsia_exec`"))

        _ = try AgentRuleInstaller.install(
            projectRoot: root,
            agents: [.codex],
            includeMCPGuidance: true
        )
        #expect(try read(".authsia/agent-rules.md", in: root).contains("`authsia_exec`"))
        #expect(try !read(".authsia/agent-rules.md", in: root).contains("MCP integrations are disabled"))
    }
}
