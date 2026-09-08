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

    @Test("disabled MCP integrations block commands before output, files, IPC or stdio")
    func disabledMCPCommands() async throws {
        let output: (String) -> Void = { _ in Issue.record("disabled command produced output") }
        let controller = MCPManagerControllerFixture()
        var start = try MCPCommand.Start.parse([])
        start.mcpAccessEnabledOverride = false
        #expect(throws: MCPManagementError.mcpAccessDisabled) { try start.run(controller: controller, output: output) }
        #expect(controller.startOpenPortal == nil)
        var restart = try MCPCommand.Restart.parse([])
        restart.mcpAccessEnabledOverride = false
        #expect(throws: MCPManagementError.mcpAccessDisabled) { try restart.run(controller: controller, output: output) }
        #expect(controller.restartOpenPortal == nil)
        var configure = try MCPCommand.Configure.parse(["--client", "codex"])
        configure.mcpAccessEnabledOverride = false
        #expect(throws: MCPManagementError.mcpAccessDisabled) { try configure.run(output: output) }
        var wrap = try MCPCommand.Wrap.parse(["--server", "fixture", "--write", "--yes"])
        wrap.mcpAccessEnabledOverride = false
        #expect(throws: MCPManagementError.mcpAccessDisabled) { try wrap.run(output: output) }
        var unwrap = try MCPCommand.Unwrap.parse(["--server", "fixture", "--write", "--yes"])
        unwrap.mcpAccessEnabledOverride = false
        #expect(throws: MCPManagementError.mcpAccessDisabled) { try unwrap.run(output: output) }
        var declare = try MCPCommand.Declare.parse(["--server", "fixture", "--command", "fixture", "--yes"])
        declare.mcpAccessEnabledOverride = false
        #expect(throws: MCPManagementError.mcpAccessDisabled) { try declare.run(output: output) }
        var catalog = try MCPCommand.Catalog.parse(["--server", "fixture", "--write"])
        catalog.mcpAccessEnabledOverride = false
        await #expect(throws: MCPManagementError.mcpAccessDisabled) { try await catalog.run(output: output) }
        var serve = try MCPCommand.Serve.parse([])
        serve.mcpAccessEnabledOverride = false
        await #expect(throws: MCPManagementError.mcpAccessDisabled) { try await serve.run() }
        var proxy = try MCPCommand.Proxy.parse(["--upstream", "fixture"])
        proxy.mcpAccessEnabledOverride = false
        await #expect(throws: MCPManagementError.mcpAccessDisabled) { try await proxy.run() }
        #expect(MCPManagementError.mcpAccessDisabled.localizedDescription.contains("Settings > Developer Access"))
        #expect(MCPManagementError.mcpAccessDisabled.localizedDescription.contains("then retry"))
    }

    @Test("manager lifecycle commands parse and render controller state")
    func managerLifecycleCommands() throws {
        let controller = MCPManagerControllerFixture()
        var output: [String] = []

        var start = try MCPCommand.Start.parse(["--no-open"])
        start.mcpAccessEnabledOverride = true
        try start.run(controller: controller, output: { output.append($0) })
        #expect(controller.startOpenPortal == false)
        #expect(output.contains("✓ Authsia MCP Manager running"))
        #expect(output.contains("http://127.0.0.1:8787"))

        output.removeAll()
        var status = try MCPCommand.Status.parse(["--json"])
        status.json = true
        try status.run(controller: controller, output: { output.append($0) })
        #expect(output.joined().contains("\"state\" : \"running\""))

        output.removeAll()
        let stop = try MCPCommand.Stop.parse([])
        try stop.run(controller: controller, output: { output.append($0) })
        #expect(output == ["Authsia MCP Manager stopped."])

        output.removeAll()
        var restart = try MCPCommand.Restart.parse(["--no-open"])
        restart.mcpAccessEnabledOverride = true
        try restart.run(controller: controller, output: { output.append($0) })
        #expect(controller.restartOpenPortal == false)
        #expect(output.contains("✓ Authsia MCP Manager running"))
    }

    @Test("declare writes a schema-v3 localhost HTTP upstream with tool policy")
    func declareLocalHTTPUpstream() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let authsia = root.appendingPathComponent(".authsia")
        let home = root.appendingPathComponent("home")
        try FileManager.default.createDirectory(at: authsia, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try Data("""
        {
          "schemaVersion": 1,
          "workspace": {"name": "fixture", "authsiaFolder": "Workspaces/fixture"},
          "managedEnvFiles": []
        }
        """.utf8).write(to: authsia.appendingPathComponent("workspace.json"))

        var command = try MCPCommand.Declare.parse([
            "--server", "internal",
            "--url", "http://127.0.0.1:9000/mcp",
            "--allow", "search",
            "--deny", "delete",
            "--raw-header", "X-API-Key=authsia://api-key/Internal/key",
            "--workspace", root.path,
            "--yes",
        ])
        command.mcpAccessEnabledOverride = true
        command.homeDirectory = home
        try command.run(output: { _ in })

        let config = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        let upstream = try #require(config.mcpUpstreams.first)
        #expect(config.schemaVersion == 3)
        #expect(upstream.transport == .streamableHTTP)
        #expect(upstream.url == "http://127.0.0.1:9000/mcp")
        #expect(upstream.tools.allow == ["search"])
        #expect(upstream.tools.deny == ["delete"])
        #expect(upstream.credentialHeaders == [
            MCPUpstreamCredentialHeader(
                headerName: "X-API-Key",
                reference: "authsia://api-key/Internal/key",
                format: .raw
            ),
        ])
    }
}

private final class MCPManagerControllerFixture: MCPManagerControlling, @unchecked Sendable {
    var startOpenPortal: Bool?
    var restartOpenPortal: Bool?

    func start(openPortal: Bool) throws -> MCPManagerStatusPayload {
        startOpenPortal = openPortal
        return runningStatus
    }

    func status() throws -> MCPManagerStatusPayload { runningStatus }

    func stop() throws -> MCPManagerStatusPayload {
        MCPManagerStatusPayload(state: .stopped)
    }

    func restart(openPortal: Bool) throws -> MCPManagerStatusPayload {
        restartOpenPortal = openPortal
        return runningStatus
    }

    private var runningStatus: MCPManagerStatusPayload {
        MCPManagerStatusPayload(
            state: .running,
            portalURL: "http://127.0.0.1:8787",
            registryLoaded: true
        )
    }
}
