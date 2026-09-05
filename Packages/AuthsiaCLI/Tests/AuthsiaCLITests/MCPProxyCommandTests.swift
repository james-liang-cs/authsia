import AuthenticatorBridge
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

    @Test("activity export filters mcpProxy rows")
    func activityExportFiltersRows() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
            "mcp-activity-\(UUID().uuidString)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let fileURL = directory.appendingPathComponent("history.jsonl")
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = AgentCommandHistoryStore(fileURL: fileURL)
        let grantID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
        try store.record(AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 100),
            agentPlatform: "codex",
            agentID: "proxy:jira",
            agentJITGrantID: grantID,
            captureSource: .mcpProxy,
            workingDirectory: "/tmp/project",
            executable: "jira",
            arguments: ["mcp-tool", "search"],
            command: "jira mcp-tool search",
            mcpProxyOutcome: .succeeded
        ))
        try store.record(AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 200),
            agentPlatform: "codex",
            agentID: "proxy:codegraph",
            captureSource: .mcpProxy,
            workingDirectory: "/tmp/other",
            executable: "codegraph",
            arguments: ["mcp-tool", "query"],
            command: "codegraph mcp-tool query",
            mcpProxyOutcome: .denied
        ))
        try store.record(AgentCommandEvent(
            recordedAt: Date(timeIntervalSince1970: 150),
            agentPlatform: "codex",
            captureSource: .hook,
            executable: "git",
            arguments: ["status"],
            command: "git status"
        ))

        let command = try MCPCommand.Activity.Export.parse([
            "--json",
            "--since", "1970-01-01T00:02:00Z",
            "--unowned",
        ])
        let unowned = try command.filteredEvents(historyFile: fileURL.path)
        #expect(unowned.map(\.executable) == ["codegraph"])

        let upstream = try MCPCommand.Activity.Export.parse(["--json", "--upstream", "jira"])
        #expect(try upstream.filteredEvents(historyFile: fileURL.path).map(\.executable) == ["jira"])

        let workspace = try MCPCommand.Activity.Export.parse(["--json", "--workspace", "/tmp/project"])
        #expect(try workspace.filteredEvents(historyFile: fileURL.path).map(\.executable) == ["jira"])
    }
}
