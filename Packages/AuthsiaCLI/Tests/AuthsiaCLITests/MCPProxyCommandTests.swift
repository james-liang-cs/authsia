import Foundation
import Testing
@testable import authsia

@Suite("MCP proxy command")
struct MCPProxyCommandTests {
    @Test("proxy requires --upstream")
    func requiresUpstream() {
        #expect(throws: (any Error).self) {
            _ = try Authsia.parseAsRoot(["mcp", "proxy"])
        }
    }

    @Test("valid upstream names parse")
    func validUpstreamNames() throws {
        for name in ["jira", "Jira", "jira_cloud", "jira-cloud", "A", "a1", "Abcdefghijklmnopqrstuvwxyz012345"] {
            let command = try Authsia.parseAsRoot(["mcp", "proxy", "--upstream", name])
            let proxy = try #require(command as? MCPCommand.Proxy)
            #expect(proxy.upstream == name)
        }
    }

    @Test("invalid upstream names are rejected")
    func invalidUpstreamNames() {
        for name in ["1jira", "_jira", "-jira", "jira.cloud", "jira/cloud", "jira cloud", "Abcdefghijklmnopqrstuvwxyz0123456"] {
            do {
                _ = try MCPCommand.Proxy.parse(["--upstream=\(name)"])
                Issue.record("expected invalid upstream \(name) to fail")
            } catch {
                #expect(
                    String(describing: error).contains("[A-Za-z][A-Za-z0-9_-]{0,31}"),
                    "name: \(name)"
                )
            }
        }
    }

    @Test("workspace flag is accepted and shares serve launch context")
    func workspaceFlagMatchesServe() throws {
        let command = try Authsia.parseAsRoot([
            "mcp", "proxy", "--upstream", "jira", "--workspace", "/tmp/project",
        ])
        let proxy = try #require(command as? MCPCommand.Proxy)
        #expect(proxy.workspace == "/tmp/project")

        let fallback = "/tmp/fallback"
        #expect(MCPCommand.startingDirectory(
            workspace: "/tmp/explicit",
            environment: ["WORKSPACE_FOLDER_PATHS": "/tmp/client"],
            currentDirectoryPath: fallback
        ).path == MCPCommand.Serve.startingDirectory(
            workspace: "/tmp/explicit",
            environment: ["WORKSPACE_FOLDER_PATHS": "/tmp/client"],
            currentDirectoryPath: fallback
        ).path)
        #expect(MCPCommand.startingDirectory(
            workspace: nil,
            environment: ["WORKSPACE_FOLDER_PATHS": "/tmp/client"],
            currentDirectoryPath: fallback
        ).path == "/tmp/client")
        #expect(MCPCommand.startingDirectory(
            workspace: nil,
            environment: ["WORKSPACE_FOLDER_PATHS": "/tmp/one,/tmp/two"],
            currentDirectoryPath: fallback
        ).path == fallback)
    }

    @Test("help describes proxy without a seventh serve tool")
    func helpDoesNotClaimSeventhServeTool() {
        let mcpHelp = MCPCommand.helpMessage(columns: 160)
        let serveHelp = MCPCommand.Serve.helpMessage(columns: 160)
        let proxyHelp = MCPCommand.Proxy.helpMessage(columns: 160)
        let rootHelp = Authsia.helpMessage(columns: 160)

        #expect(mcpHelp.contains("proxy"))
        #expect(mcpHelp.contains("doctor"))
        #expect(mcpHelp.contains("AUTHSIA_MCP_UPSTREAM"))
        #expect(mcpHelp.contains("does not add tools to `mcp serve`"))
        #expect(proxyHelp.contains("--upstream"))
        #expect(proxyHelp.contains("--workspace"))
        #expect(!mcpHelp.lowercased().contains("seven"))
        #expect(!serveHelp.contains("proxy"))
        #expect(!proxyHelp.contains("authsia_status"))
        #expect(!proxyHelp.contains("authsia_exec"))
        #expect(!proxyHelp.contains("authsia_list"))
        #expect(!rootHelp.contains("authsia_status"))
    }
}
