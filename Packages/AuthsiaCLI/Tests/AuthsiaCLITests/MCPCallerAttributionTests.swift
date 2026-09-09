import AuthenticatorBridge
import Foundation
import Testing
@testable import authsia

@Suite("MCP caller attribution")
struct MCPCallerAttributionTests {
    @Test("Coding-agent hook reaches MCP, child CLI, and display without replacing server authority",
          arguments: ["claude-code", "codex-mcp-client"], ["authsia_list", "authsia_exec", "authsia_access_revoke"])
    func hookReachesInvocationAndChild(clientName: String, toolName: String) async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try WorkspaceConfigStore.write(
            WorkspaceConfig(workspace: .init(name: "demo", authsiaFolder: "Demo"), managedEnvFiles: [], agents: nil),
            toWorkspaceRoot: root
        )
        let store = MCPCallerContextStore(fileURL: root.appendingPathComponent("callers.json"))
        let history = AgentCommandHistoryStore(fileURL: root.appendingPathComponent("history.jsonl"))
        let platform = clientName == "codex-mcp-client" ? "codex" : "claude-code"
        let command = try Agent.RecordCommand.parse(["--platform", platform, "--source", "hook"])
        let payload = try JSONSerialization.data(withJSONObject: [
            "hook_event_name": "PreToolUse", "tool_name": "mcp__authsia__\(toolName)",
            "cwd": root.path, "session_id": "session-1", "agent_id": "agent-1",
            "agent_type": "reviewer", "tool_use_id": "tool-1",
            "tool_input": ["query": "synthetic-private-input"],
        ])
        try command.run(store: history, fileActivityStore: nil, stdinData: payload, mcpCallerStore: store)
        #expect(!(try String(contentsOf: store.fileURL, encoding: .utf8)).contains("synthetic-private-input"))
        #expect(try history.loadAll().isEmpty)
        let runtime = MCPRuntimeContext(startingDirectory: root, callerStore: store)
        await runtime.updateClientInfo(name: clientName, version: "1")
        let invocation = await runtime.makeInvocation(toolName: toolName)
        let context = try #require(invocation.agentRuntimeContext)
        #expect(context.sessionID == "mcp:\(runtime.instanceID.uuidString)")
        #expect(context.agentType == "authsia-mcp")
        #expect(context.caller?.agentID == "agent-1")
        #expect(context.caller?.sessionID == "session-1")
        let title = platform == "codex" ? "Codex" : "Claude Code"
        #expect(AgentAttributionPresentation.caption(for: context) == "\(title) / reviewer (agent-1) (reported by hook)")
        let child = AgentRuntimeContextResolver.resolve(environment: invocation.environment)
        #expect(child == context)
        let decoded = try JSONDecoder().decode(AgentRuntimeContext.self, from: JSONEncoder().encode(context))
        #expect(decoded == context)
        #expect(AgentSessionGrouping.codingSessionID(from: context) == "session-1")
        let next = await runtime.makeInvocation(toolName: toolName)
        #expect(next.agentRuntimeContext?.caller?.attributionConfidence == .ambiguous)
    }

    @Test("competing hook records are retired without guessing or later reuse")
    func competingCallsAreUnknown() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let store = MCPCallerContextStore(fileURL: root.appendingPathComponent("callers.json"))
        for id in ["agent-1", "agent-2"] {
            try store.record(tool: "authsia_list", cwd: root.path,
                context: AgentRuntimeContext(platform: "claude-code", agentID: id))
        }
        for _ in 0..<2 {
            let caller = store.consume(tool: "authsia_list", cwd: root.path, platform: "claude-code")
            #expect(caller.attributionConfidence == .ambiguous)
            #expect(caller.agentID == nil)
        }
    }

    @Test("stale, wrong workspace, platform and tool records cannot label a call")
    func mismatchesAreUnknown() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let store = MCPCallerContextStore(fileURL: root.appendingPathComponent("callers.json"))
        let now = Date()
        try store.record(tool: "authsia_list", cwd: root.path,
            context: AgentRuntimeContext(platform: "claude-code", agentID: "agent-1"), now: now)
        #expect(store.consume(tool: "authsia_exec", cwd: root.path, platform: "claude-code", now: now).agentID == nil)
        #expect(store.consume(tool: "authsia_list", cwd: "/other", platform: "claude-code", now: now).agentID == nil)
        #expect(store.consume(tool: "authsia_list", cwd: root.path, platform: "codex", now: now).agentID == nil)
        #expect(store.consume(tool: "authsia_list", cwd: root.path, platform: "claude-code", now: now.addingTimeInterval(61)).agentID == nil)
    }

    @Test("installed coding-agent settings capture MCP calls and lifecycle", arguments: [AgentTool.claudeCode, .codex])
    func installsMCPHook(agent: AgentTool) throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [agent])
        let path = agent == .codex ? ".codex/hooks.json" : ".claude/settings.local.json"
        let data = try Data(contentsOf: root.appendingPathComponent(path))
        let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let hooks = try #require(object["hooks"] as? [String: Any])
        let pre = try #require(hooks["PreToolUse"] as? [[String: Any]])
        #expect(pre.contains { ($0["matcher"] as? String)?.contains("mcp__") == true })
        for tool in ["authsia_list", "authsia_exec", "authsia_access_revoke"] {
            let name = "mcp__authsia__\(tool)"
            #expect(pre.contains { entry in
                guard let pattern = entry["matcher"] as? String else { return false }
                return name.range(of: pattern, options: .regularExpression) != nil
            })
        }
        #expect(hooks["SubagentStart"] != nil)
        #expect(hooks["SubagentStop"] != nil)
    }
}
