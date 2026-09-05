import Testing
import Foundation
import AuthenticatorBridge
@testable import authsia

@Suite("Agent init command")
struct AgentCommandTests {

    @Test("Claude init creates shared rules, Claude rules, and outside-sandbox command settings")
    func claudeInitCreatesRulesAndLocalSettings() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let result = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])

        let shared = try read(".authsia/agent-rules.md", in: root)
        let claudeRules = try read("CLAUDE.md", in: root)
        let settings = try read(".claude/settings.local.json", in: root)

        try expectClaudeSettings(settings)
        #expect(shared.contains("Never ask the user for plaintext secrets."))
        #expect(shared.contains("`authsia_exec`"))
        #expect(shared.contains("outside the sandbox"))
        #expect(!shared.contains("Authsia Command History"))
        #expect(!shared.contains("also run Git network/authentication commands"))
        #expect(!shared.contains("Keep local-only Git commands"))
        #expect(claudeRules.contains(AgentRuleInstaller.managedStartMarker))
        #expect(claudeRules.contains("Authsia Secret Handling"))
        #expect(!settings.contains("Authsia.Bridge"))
        #expect(!settings.contains("Authsia.SSHAgent"))
        #expect(!settings.contains("~/.authsia/agent.sock"))
        #expect(settings.contains("\"hooks\""))
        #expect(settings.contains("\"PreToolUse\""))
        #expect(settings.contains("\"PostToolUse\""))
        #expect(settings.contains("\"SubagentStart\""))
        #expect(settings.contains("\"SubagentStop\""))
        #expect(settings.contains("\"matcher\": \"Bash\""))
        #expect(settings.contains("authsia agent record-command --platform claude-code --source hook"))
        #expect(settings.contains("authsia agent record-lineage --platform claude-code"))
        #expect(result.manualSteps.isEmpty)

        let rendered = AgentRuleInstaller.renderResult(result)
        #expect(rendered.contains("Created:"))
        #expect(rendered.contains(".authsia/agent-rules.md"))
        #expect(rendered.contains(".claude/settings.local.json"))
        #expect(rendered.contains("Authsia agent rules are ready."))
    }

    @Test("hidden recorder writes redacted command metadata")
    func hiddenRecorderWritesRedactedCommandMetadata() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-agent-command-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("events.jsonl")
        let store = AgentCommandHistoryStore(fileURL: fileURL)
        let command = try Agent.RecordCommand.parse([
            "--platform", "claude-code",
            "--source", "hook",
            "--session-id", "session-1",
            "--tool-use-id", "tool-1",
            "--cwd", "/tmp/project",
            "--executable", "npm",
            "--argv-json", #"["npm","run","deploy","--token","raw-token"]"#,
            "--command", "npm run deploy --token raw-token",
            "--exit-status", "0",
        ])

        try command.run(store: store, stdinData: nil)

        let event = try #require(try store.loadAll().first)
        #expect(event.agentPlatform == "claude-code")
        #expect(event.sessionID == "session-1")
        #expect(event.toolUseID == "tool-1")
        #expect(event.captureSource == .hook)
        #expect(event.workingDirectory == "/tmp/project")
        #expect(event.command == "npm run deploy --token [REDACTED]")
        #expect(event.arguments == ["npm", "run", "deploy", "--token", "[REDACTED]"])
        #expect(event.exitStatus == 0)
    }

    @Test("lineage recorder writes SubagentStart without prompt fields")
    func lineageRecorderWritesSubagentStartWithoutPromptFields() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-agent-lineage-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = AgentLineageStore(fileURL: directory.appendingPathComponent("lineage.jsonl"))
        let command = try Agent.RecordLineage.parse(["--platform", "claude-code"])
        let payload = Data("""
        {
          "hook_event_name": "SubagentStart",
          "session_id": "session-1",
          "agent_id": "agent-2",
          "agent_type": "Explore",
          "cwd": "/tmp/project",
          "agent_prompt": "never store this",
          "last_assistant_message": "nor this"
        }
        """.utf8)

        let record = try command.run(store: store, stdinData: payload)
        let stored = try #require(try store.loadAll().first)

        #expect(record?.agentType == "Explore")
        #expect(stored.sessionID == "session-1")
        #expect(stored.agentID == "agent-2")
        #expect(stored.startedAt != nil)
        #expect(stored.endedAt == nil)
        let encoded = try JSONEncoder.agentCommandHistoryLine.encode(stored)
        let json = try #require(String(data: encoded, encoding: .utf8))
        #expect(!json.contains("never store this"))
        #expect(!json.contains("agent_prompt"))
        #expect(!json.contains("last_assistant_message"))
    }

    @Test("hidden recorder parses Copilot native hook payload")
    func hiddenRecorderParsesCopilotNativeHookPayload() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-copilot-command-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let fileURL = directory.appendingPathComponent("events.jsonl")
        let store = AgentCommandHistoryStore(fileURL: fileURL)
        let command = try Agent.RecordCommand.parse([
            "--platform", "copilot",
            "--source", "hook",
        ])
        let payload = Data("""
        {
          "sessionId": "copilot-session-1",
          "cwd": "/tmp/project",
          "toolName": "bash",
          "toolArgs": {
            "command": "npm run deploy --token raw-token",
            "arguments": ["npm", "run", "deploy", "--token", "raw-token"]
          }
        }
        """.utf8)

        try command.run(store: store, stdinData: payload)

        let event = try #require(try store.loadAll().first)
        #expect(event.agentPlatform == "copilot")
        #expect(event.sessionID == "copilot-session-1")
        #expect(event.workingDirectory == "/tmp/project")
        #expect(event.executable == "npm")
        #expect(event.command == "npm run deploy --token [REDACTED]")
        #expect(event.arguments == ["npm", "run", "deploy", "--token", "[REDACTED]"])
    }

    @Test("Claude pre-tool hook blocks environment dump in block mode")
    func claudePreToolHookBlocksEnvironmentDumpInBlockMode() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-claude-response-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = AgentCommandHistoryStore(fileURL: directory.appendingPathComponent("events.jsonl"))
        let command = try Agent.RecordCommand.parse([
            "--platform", "claude-code",
            "--source", "hook",
        ])
        let payload = Data("""
        {
          "hook_event_name": "PreToolUse",
          "tool_name": "Bash",
          "tool_input": {"command": "env"},
          "cwd": "/tmp/project"
        }
        """.utf8)
        var output = Data()

        let decision = try command.run(
            store: store,
            stdinData: payload,
            responseMode: .block,
            decisionOutput: { output.append($0) }
        )

        #expect(decision.outcome == .deny)
        let object = try #require(
            try JSONSerialization.jsonObject(with: output) as? [String: Any]
        )
        let hookOutput = try #require(object["hookSpecificOutput"] as? [String: Any])
        #expect(hookOutput["permissionDecision"] as? String == "deny")
        let event = try #require(try store.loadAll().first)
        #expect(event.responseOutcome == .deny)
        #expect(event.responsePreventedAction == true)
    }

    @Test("Copilot pre-tool hook asks before env file read in confirm mode")
    func copilotPreToolHookAsksBeforeEnvFileReadInConfirmMode() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-copilot-response-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = AgentCommandHistoryStore(fileURL: directory.appendingPathComponent("events.jsonl"))
        let command = try Agent.RecordCommand.parse([
            "--platform", "copilot",
            "--source", "hook",
        ])
        let payload = Data("""
        {
          "hook_event_name": "PreToolUse",
          "tool_name": "Read",
          "tool_input": {"file_path": "/tmp/project/.env"},
          "cwd": "/tmp/project"
        }
        """.utf8)
        var output = Data()

        let decision = try command.run(
            store: store,
            stdinData: payload,
            responseMode: .confirm,
            decisionOutput: { output.append($0) }
        )

        #expect(decision.hookPermissionDecision == .ask)
        let object = try #require(
            try JSONSerialization.jsonObject(with: output) as? [String: Any]
        )
        #expect(object["permissionDecision"] as? String == "ask")
        #expect(try store.loadAll().first?.responseEvidence == .environmentFileRead)
    }

    @Test("hidden recorder parses Claude file tool payload")
    func hiddenRecorderParsesClaudeFileToolPayload() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-claude-file-activity-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let commandStore = AgentCommandHistoryStore(fileURL: directory.appendingPathComponent("commands.jsonl"))
        let fileActivityStore = AgentFileActivityStore(fileURL: directory.appendingPathComponent("files.jsonl"))
        let command = try Agent.RecordCommand.parse([
            "--platform", "claude-code",
            "--source", "hook",
        ])
        let payload = Data("""
        {
          "session_id": "session-1",
          "turn_id": "turn-1",
          "agent_id": "agent-1",
          "agent_type": "coding-agent",
          "tool_use_id": "tool-1",
          "cwd": "/tmp/project",
          "terminal_session_scope": "tty:/dev/ttys002:sid:84",
          "workspace_root": "/tmp/project",
          "tool_name": "Read",
          "tool_input": {
            "file_path": "/tmp/project/Sources/App.swift"
          },
          "tool_response": {
            "exit_status": 0
          }
        }
        """.utf8)

        try command.run(store: commandStore, fileActivityStore: fileActivityStore, stdinData: payload)

        #expect(try commandStore.loadAll().isEmpty)
        let event = try #require(try fileActivityStore.loadAll().first)
        #expect(event.agentPlatform == "claude-code")
        #expect(event.sessionID == "session-1")
        #expect(event.turnID == "turn-1")
        #expect(event.agentID == "agent-1")
        #expect(event.agentType == "coding-agent")
        #expect(event.toolUseID == "tool-1")
        #expect(event.captureSource == .hook)
        #expect(event.workingDirectory == "/tmp/project")
        #expect(event.terminalSessionScope == "tty:/dev/ttys002:sid:84")
        #expect(event.workspaceRoot == "/tmp/project")
        #expect(event.path == "/tmp/project/Sources/App.swift")
        #expect(event.workspaceRelativePath == "Sources/App.swift")
        #expect(event.kind == .file)
        #expect(event.action == .read)
        #expect(event.status == .succeeded)
        #expect(event.confidence == .direct)
    }

    @Test("hidden recorder merges pre and post file tool hooks into confirmed status")
    func hiddenRecorderMergesPreAndPostFileToolHooks() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-file-activity-merge-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let commandStore = AgentCommandHistoryStore(fileURL: directory.appendingPathComponent("commands.jsonl"))
        let fileActivityStore = AgentFileActivityStore(fileURL: directory.appendingPathComponent("files.jsonl"))
        let command = try Agent.RecordCommand.parse([
            "--platform", "claude-code",
            "--source", "hook",
        ])
        let prePayload = Data("""
        {
          "session_id": "session-1",
          "tool_use_id": "tool-1",
          "cwd": "/tmp/project",
          "workspace_root": "/tmp/project",
          "hook_event_name": "PreToolUse",
          "tool_name": "Read",
          "tool_input": {
            "file_path": "/tmp/project/Sources/App.swift"
          }
        }
        """.utf8)
        let postPayload = Data("""
        {
          "session_id": "session-1",
          "tool_use_id": "tool-1",
          "cwd": "/tmp/project",
          "workspace_root": "/tmp/project",
          "hook_event_name": "PostToolUse",
          "tool_name": "Read",
          "tool_input": {
            "file_path": "/tmp/project/Sources/App.swift"
          },
          "tool_response": {}
        }
        """.utf8)

        try command.run(store: commandStore, fileActivityStore: fileActivityStore, stdinData: prePayload)
        try command.run(store: commandStore, fileActivityStore: fileActivityStore, stdinData: postPayload)

        let events = try fileActivityStore.loadAll()
        #expect(events.count == 1)
        let event = try #require(events.first)
        #expect(event.path == "/tmp/project/Sources/App.swift")
        #expect(event.status == .succeeded)
        #expect(event.confidence == .confirmed)
    }

    @Test("hidden recorder records Grep path without leaking pattern")
    func hiddenRecorderRecordsGrepPathWithoutLeakingPattern() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-grep-file-activity-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let commandStore = AgentCommandHistoryStore(fileURL: directory.appendingPathComponent("commands.jsonl"))
        let fileActivityStore = AgentFileActivityStore(fileURL: directory.appendingPathComponent("files.jsonl"))
        let command = try Agent.RecordCommand.parse([
            "--platform", "claude-code",
            "--source", "hook",
        ])
        let sensitivePattern = "api_key=raw-secret"
        let payload = Data("""
        {
          "cwd": "/tmp/project",
          "workspace_root": "/tmp/project",
          "tool_name": "Grep",
          "tool_input": {
            "pattern": "\(sensitivePattern)",
            "path": "/tmp/project/Sources"
          }
        }
        """.utf8)

        try command.run(store: commandStore, fileActivityStore: fileActivityStore, stdinData: payload)

        let event = try #require(try fileActivityStore.loadAll().first)
        #expect(event.path == "/tmp/project/Sources")
        #expect(event.path != sensitivePattern)
        #expect(event.workspaceRelativePath == "Sources")
        #expect(event.kind == .unknown)
        #expect(event.action == .search)
        #expect(event.detail?.contains(sensitivePattern) != true)
    }

    @Test("hidden recorder records Glob cwd without leaking pattern")
    func hiddenRecorderRecordsGlobCwdWithoutLeakingPattern() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-glob-file-activity-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let commandStore = AgentCommandHistoryStore(fileURL: directory.appendingPathComponent("commands.jsonl"))
        let fileActivityStore = AgentFileActivityStore(fileURL: directory.appendingPathComponent("files.jsonl"))
        let command = try Agent.RecordCommand.parse([
            "--platform", "claude-code",
            "--source", "hook",
        ])
        let sensitivePattern = "**/raw-secret/*.swift"
        let payload = Data("""
        {
          "cwd": "/tmp/project",
          "tool_name": "Glob",
          "tool_input": {
            "pattern": "\(sensitivePattern)"
          }
        }
        """.utf8)

        try command.run(store: commandStore, fileActivityStore: fileActivityStore, stdinData: payload)

        let event = try #require(try fileActivityStore.loadAll().first)
        #expect(event.workspaceRoot == "/tmp/project")
        #expect(event.path == "/tmp/project")
        #expect(event.path != sensitivePattern)
        #expect(event.workspaceRelativePath == ".")
        #expect(event.kind == .unknown)
        #expect(event.action == .search)
        #expect(event.detail?.contains(sensitivePattern) != true)
    }

    @Test("hidden recorder defaults missing workspace root to working directory")
    func hiddenRecorderDefaultsMissingWorkspaceRootToWorkingDirectory() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-missing-workspace-root-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let commandStore = AgentCommandHistoryStore(fileURL: directory.appendingPathComponent("commands.jsonl"))
        let fileActivityStore = AgentFileActivityStore(fileURL: directory.appendingPathComponent("files.jsonl"))
        let command = try Agent.RecordCommand.parse([
            "--platform", "claude-code",
            "--source", "hook",
        ])
        let payload = Data("""
        {
          "cwd": "/tmp/project",
          "tool_name": "Read",
          "tool_input": {
            "file_path": "/tmp/project/Sources/App.swift"
          }
        }
        """.utf8)

        try command.run(store: commandStore, fileActivityStore: fileActivityStore, stdinData: payload)

        let event = try #require(try fileActivityStore.loadAll().first)
        #expect(event.workspaceRoot == "/tmp/project")
        #expect(event.path == "/tmp/project/Sources/App.swift")
        #expect(event.workspaceRelativePath == "Sources/App.swift")
    }

    @Test("hidden recorder legacy helper records command history only")
    func hiddenRecorderLegacyHelperRecordsCommandHistoryOnly() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-legacy-recorder-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let commandStore = AgentCommandHistoryStore(fileURL: directory.appendingPathComponent("commands.jsonl"))
        let defaultFileActivityURL = AgentFileActivityStore.defaultFileURL
        let originalDefaultFileActivityData = try? Data(contentsOf: defaultFileActivityURL)
        let defaultFileActivityExisted = FileManager.default.fileExists(atPath: defaultFileActivityURL.path)
        defer {
            if defaultFileActivityExisted, let originalDefaultFileActivityData {
                try? FileManager.default.createDirectory(
                    at: defaultFileActivityURL.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                try? originalDefaultFileActivityData.write(to: defaultFileActivityURL, options: .atomic)
            } else {
                try? FileManager.default.removeItem(at: defaultFileActivityURL)
            }
        }
        try? FileManager.default.removeItem(at: defaultFileActivityURL)
        let command = try Agent.RecordCommand.parse([
            "--platform", "claude-code",
            "--source", "hook",
        ])
        let payload = Data("""
        {
          "cwd": "/tmp/project",
          "command": "cat README.md",
          "tool_name": "Read",
          "tool_input": {
            "file_path": "/tmp/project/README.md"
          }
        }
        """.utf8)

        try command.run(store: commandStore, stdinData: payload)

        #expect(try commandStore.loadAll().count == 1)
        #expect(!FileManager.default.fileExists(atPath: defaultFileActivityURL.path))
    }

    @Test("hidden recorder parses directory list and failed status")
    func hiddenRecorderParsesDirectoryListAndFailedStatus() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-directory-file-activity-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let commandStore = AgentCommandHistoryStore(fileURL: directory.appendingPathComponent("commands.jsonl"))
        let fileActivityStore = AgentFileActivityStore(fileURL: directory.appendingPathComponent("files.jsonl"))
        let command = try Agent.RecordCommand.parse([
            "--platform", "claude-code",
            "--source", "hook",
            "--session-id", "session-1",
            "--tool-use-id", "tool-1",
            "--cwd", "/tmp/project",
            "--terminal-session-scope", "tty:/dev/ttys002:sid:84",
        ])
        let payload = Data("""
        {
          "workspaceRoot": "/tmp/project",
          "toolName": "LS",
          "toolInput": {
            "path": "/tmp/project/Missing"
          },
          "toolResponse": {
            "exitCode": 2
          }
        }
        """.utf8)

        try command.run(store: commandStore, fileActivityStore: fileActivityStore, stdinData: payload)

        #expect(try commandStore.loadAll().isEmpty)
        let event = try #require(try fileActivityStore.loadAll().first)
        #expect(event.agentPlatform == "claude-code")
        #expect(event.sessionID == "session-1")
        #expect(event.toolUseID == "tool-1")
        #expect(event.captureSource == .hook)
        #expect(event.workingDirectory == "/tmp/project")
        #expect(event.terminalSessionScope == "tty:/dev/ttys002:sid:84")
        #expect(event.workspaceRoot == "/tmp/project")
        #expect(event.path == "/tmp/project/Missing")
        #expect(event.workspaceRelativePath == "Missing")
        #expect(event.kind == .directory)
        #expect(event.action == .list)
        #expect(event.status == .failed)
        #expect(event.confidence == .direct)
    }

    @Test("existing Claude local settings merge Authsia hooks and outside-sandbox commands")
    func existingClaudeSettingsMergeAuthsiaHooksAndSandboxPermissions() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("""
        {
          "$schema": "https://json.schemastore.org/claude-code-settings.json",
          "hooks": {
            "PreToolUse": [
              {
                "matcher": "Bash",
                "hooks": [
                  {
                    "type": "command",
                    "command": "echo custom"
                  }
                ]
              },
              {
                "matcher": "Notebook",
                "hooks": [
                  {
                    "type": "command",
                    "command": "echo notebook"
                  }
                ]
              }
            ]
          },
          "permissions": {
            "allow": [
              "Bash(uv sync)"
            ]
          },
          "sandbox": {
            "excludedCommands": [
              "custom-tool *"
            ],
            "network": {
              "allowMachLookup": [
                "Custom.Service"
              ],
              "allowUnixSockets": [
                "~/custom.sock"
              ]
            }
          }
        }
        """, to: ".claude/settings.local.json", in: root)

        let result = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])

        let settings = try read(".claude/settings.local.json", in: root)
        try expectClaudeSettings(settings)
        let object = try expectJSONObject(settings)
        let permissions = try #require(object["permissions"] as? [String: Any])
        #expect((permissions["allow"] as? [String]) == ["Bash(uv sync)"])
        let sandbox = try #require(object["sandbox"] as? [String: Any])
        #expect((sandbox["excludedCommands"] as? [String]) == ["custom-tool *"] + claudeOutsideSandboxCommands)
        let network = try #require(sandbox["network"] as? [String: Any])
        #expect((network["allowMachLookup"] as? [String]) == ["Custom.Service"])
        #expect((network["allowUnixSockets"] as? [String]) == ["~/custom.sock"])
        let hooks = try #require(object["hooks"] as? [String: Any])
        let preToolUse = try #require(hooks["PreToolUse"] as? [[String: Any]])
        let bashHookEntry = try #require(preToolUse.first { $0["matcher"] as? String == "Bash" })
        let bashHookCommands = try #require(bashHookEntry["hooks"] as? [[String: Any]])
            .compactMap { $0["command"] as? String }
        #expect(bashHookCommands.contains("echo custom"))
        #expect(bashHookCommands.contains("authsia agent record-command --platform claude-code --source hook"))
        #expect(preToolUse.contains { $0["matcher"] as? String == "Notebook" })
        #expect(result.updated.contains(".claude/settings.local.json"))
        #expect(result.manualSteps.isEmpty)
    }

    @Test("Claude install removes legacy Authsia Mach lookups and preserves custom services")
    func claudeInstallMigratesLegacyMachLookups() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("""
        {
          "sandbox": {
            "network": {
              "allowMachLookup": [
                "Custom.Service",
                "Authsia.Bridge",
                "Authsia.SSHAgent"
              ],
              "allowUnixSockets": [
                "~/custom.sock"
              ]
            }
          }
        }
        """, to: ".claude/settings.local.json", in: root)

        let result = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])

        let object = try expectJSONObject(try read(".claude/settings.local.json", in: root))
        let sandbox = try #require(object["sandbox"] as? [String: Any])
        let network = try #require(sandbox["network"] as? [String: Any])
        #expect((network["allowMachLookup"] as? [String]) == ["Custom.Service"])
        #expect((network["allowUnixSockets"] as? [String]) == ["~/custom.sock"])
        #expect((sandbox["excludedCommands"] as? [String]) == claudeOutsideSandboxCommands)
        #expect(result.updated.contains(".claude/settings.local.json"))
        #expect(result.manualSteps.isEmpty)
    }

    @Test("Claude install removes an allowMachLookup key containing only legacy Authsia services")
    func claudeInstallRemovesLegacyOnlyMachLookupKey() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("""
        {
          "sandbox": {
            "network": {
              "allowMachLookup": [
                "Authsia.Bridge",
                "Authsia.SSHAgent"
              ]
            }
          }
        }
        """, to: ".claude/settings.local.json", in: root)

        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])

        let object = try expectJSONObject(try read(".claude/settings.local.json", in: root))
        let sandbox = try #require(object["sandbox"] as? [String: Any])
        #expect(sandbox["network"] == nil)
        #expect((sandbox["excludedCommands"] as? [String]) == claudeOutsideSandboxCommands)
    }

    @Test("invalid existing Claude local settings are not mutated and print a manual merge block")
    func invalidClaudeSettingsRequireManualMerge() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("{", to: ".claude/settings.local.json", in: root)

        let result = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])

        #expect(try read(".claude/settings.local.json", in: root) == "{")
        let step = try #require(result.manualSteps.first)
        #expect(step.path == ".claude/settings.local.json")
        #expect(step.reason.contains("could not be parsed"))
        try expectClaudeSettings(step.block)
        #expect(step.block.contains("authsia agent record-command --platform claude-code --source hook"))
        #expect(!result.updated.contains(".claude/settings.local.json"))
    }

    @Test("parseable Claude local settings with an unexpected hook shape fall back to a manual block")
    func wrongShapedClaudeSettingsRequireManualMerge() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        // Valid JSON, but "PreToolUse" is an object rather than the expected array of entries.
        let original = """
        {
          "hooks": {
            "PreToolUse": {
              "userCustom": "keepme"
            }
          }
        }
        """
        try write(original, to: ".claude/settings.local.json", in: root)

        let result = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])

        // The user's file must be left byte-for-byte untouched rather than clobbered.
        #expect(try read(".claude/settings.local.json", in: root) == original)
        #expect(!result.updated.contains(".claude/settings.local.json"))
        let step = try #require(result.manualSteps.first { $0.path == ".claude/settings.local.json" })
        #expect(step.reason.contains("could not be parsed or safely merged"))
        try expectClaudeSettings(step.block)
    }

    @Test("Claude matching hook with incompatible nested hooks requires manual merge without mutation")
    func wrongNestedClaudeHookShapeRequiresManualMergeWithoutMutation() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let original = """
        {
          "hooks": {
            "PreToolUse": [
              {
                "matcher": "Bash",
                "hooks": {
                  "userCustom": "keepme"
                }
              }
            ]
          }
        }
        """
        try write(original, to: ".claude/settings.local.json", in: root)

        let result = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])

        #expect(try read(".claude/settings.local.json", in: root) == original)
        #expect(!result.updated.contains(".claude/settings.local.json"))
        let step = try #require(result.manualSteps.first { $0.path == ".claude/settings.local.json" })
        #expect(step.reason.contains("could not be parsed or safely merged"))
        try expectClaudeSettings(step.block)
    }

    @Test("Claude duplicate matcher with any incompatible hooks requires manual merge without mutation")
    func duplicateClaudeMatcherWithIncompatibleHooksRequiresManualMergeWithoutMutation() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let original = """
        {
          "hooks": {
            "PreToolUse": [
              {
                "matcher": "Bash",
                "hooks": [
                  {
                    "type": "command",
                    "command": "echo custom"
                  }
                ]
              },
              {
                "matcher": "Bash",
                "hooks": {
                  "userCustom": "keepme"
                }
              }
            ]
          }
        }
        """
        try write(original, to: ".claude/settings.local.json", in: root)

        let result = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])

        #expect(try read(".claude/settings.local.json", in: root) == original)
        #expect(!result.updated.contains(".claude/settings.local.json"))
        let step = try #require(result.manualSteps.first { $0.path == ".claude/settings.local.json" })
        #expect(step.reason.contains("could not be parsed or safely merged"))
        try expectClaudeSettings(step.block)
    }

    @Test("Claude uninstall removes merged Authsia settings and preserves custom values")
    func claudeUninstallStructurallyRemovesMergedSettings() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("""
        {
          "customTopLevel": {
            "enabled": true
          },
          "hooks": {
            "PreToolUse": [
              {
                "matcher": "Bash",
                "customEntryField": "preserve",
                "hooks": [
                  {
                    "type": "command",
                    "command": "echo custom"
                  },
                  {
                    "type": "command",
                    "command": "authsia agent record-command --platform claude-code --source hook --custom"
                  }
                ]
              },
              {
                "matcher": "Notebook",
                "hooks": [
                  {
                    "type": "command",
                    "command": "echo notebook"
                  }
                ]
              }
            ]
          },
          "sandbox": {
            "excludedCommands": [
              "custom-tool *"
            ],
            "network": {
              "allowMachLookup": [
                "Custom.Service",
                "Custom.Authsia.Bridge.Helper"
              ],
              "allowUnixSockets": [
                "~/custom.sock",
                "~/.authsia/agent.sock.backup"
              ],
              "customNetworkField": true
            },
            "customSandboxField": "preserve"
          }
        }
        """, to: ".claude/settings.local.json", in: root)

        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])
        let result = try AgentRuleInstaller.uninstall(projectRoot: root, agents: [.claudeCode])

        #expect(fileExists(".claude/settings.local.json", in: root))
        let settings = try read(".claude/settings.local.json", in: root)
        let object = try expectJSONObject(settings)
        let customTopLevel = try #require(object["customTopLevel"] as? [String: Any])
        #expect(customTopLevel["enabled"] as? Bool == true)
        let hooks = try #require(object["hooks"] as? [String: Any])
        let preToolUse = try #require(hooks["PreToolUse"] as? [[String: Any]])
        let bash = try #require(preToolUse.first { $0["matcher"] as? String == "Bash" })
        #expect(bash["customEntryField"] as? String == "preserve")
        #expect((bash["hooks"] as? [[String: Any]])?.contains {
            $0["type"] as? String == "command" && $0["command"] as? String == "echo custom"
        } == true)
        #expect((bash["hooks"] as? [[String: Any]])?.contains {
            $0["command"] as? String ==
                "authsia agent record-command --platform claude-code --source hook --custom"
        } == true)
        #expect(preToolUse.contains { $0["matcher"] as? String == "Notebook" })
        let allHookCommands = hooks.values
            .compactMap { $0 as? [[String: Any]] }
            .flatMap { $0 }
            .compactMap { $0["hooks"] as? [[String: Any]] }
            .flatMap { $0 }
            .compactMap { $0["command"] as? String }
        #expect(!allHookCommands.contains(
            "authsia agent record-command --platform claude-code --source hook"
        ))
        let sandbox = try #require(object["sandbox"] as? [String: Any])
        #expect(sandbox["customSandboxField"] as? String == "preserve")
        #expect((sandbox["excludedCommands"] as? [String]) == ["custom-tool *"])
        let network = try #require(sandbox["network"] as? [String: Any])
        #expect((network["allowMachLookup"] as? [String]) == [
            "Custom.Service",
            "Custom.Authsia.Bridge.Helper",
        ])
        #expect((network["allowUnixSockets"] as? [String]) == [
            "~/custom.sock",
            "~/.authsia/agent.sock.backup",
        ])
        #expect(network["customNetworkField"] as? Bool == true)
        #expect(result.updated.contains(".claude/settings.local.json"))
        #expect(result.manualSteps.isEmpty)
    }

    @Test("Claude uninstall deletes an untouched generated settings file")
    func claudeUninstallDeletesGeneratedSettings() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])

        let result = try AgentRuleInstaller.uninstall(projectRoot: root, agents: [.claudeCode])

        #expect(!fileExists(".claude/settings.local.json", in: root))
        #expect(result.removed.contains(".claude/settings.local.json"))
        #expect(result.manualSteps.isEmpty)
    }

    @Test("Claude uninstall deletes a legacy generated settings file")
    func claudeUninstallDeletesLegacyGeneratedSettings() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])
        let settingsURL = root.appendingPathComponent(".claude/settings.local.json")
        var settings = try expectJSONObject(try String(contentsOf: settingsURL, encoding: .utf8))
        var sandbox = try #require(settings["sandbox"] as? [String: Any])
        sandbox.removeValue(forKey: "excludedCommands")
        sandbox["network"] = [
            "allowMachLookup": ["Authsia.Bridge", "Authsia.SSHAgent"],
            "allowUnixSockets": ["~/.authsia/agent.sock"],
        ]
        settings["sandbox"] = sandbox
        let legacyData = try JSONSerialization.data(withJSONObject: settings, options: [.prettyPrinted, .sortedKeys])
        try legacyData.write(to: settingsURL)

        let result = try AgentRuleInstaller.uninstall(projectRoot: root, agents: [.claudeCode])

        #expect(!fileExists(".claude/settings.local.json", in: root))
        #expect(result.removed.contains(".claude/settings.local.json"))
        #expect(result.manualSteps.isEmpty)
    }

    @Test("repeated Claude install stays unchanged and generated settings still uninstall")
    func repeatedClaudeInstallPreservesGeneratedSettingsRemoval() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])
        let original = try read(".claude/settings.local.json", in: root)

        let secondInstall = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])

        #expect(try read(".claude/settings.local.json", in: root) == original)
        #expect(secondInstall.unchanged.contains(".claude/settings.local.json"))
        #expect(!secondInstall.updated.contains(".claude/settings.local.json"))
        #expect(secondInstall.manualSteps.isEmpty)

        let removal = try AgentRuleInstaller.uninstall(projectRoot: root, agents: [.claudeCode])

        #expect(!fileExists(".claude/settings.local.json", in: root))
        #expect(removal.removed.contains(".claude/settings.local.json"))
        #expect(!removal.updated.contains(".claude/settings.local.json"))
        #expect(removal.manualSteps.isEmpty)
    }

    @Test("Claude uninstall removes duplicate generated hooks from every matching entry")
    func claudeUninstallRemovesAllDuplicateMatchingHooks() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let generatedCommand = "authsia agent record-command --platform claude-code --source hook"
        let generatedHook: [String: Any] = [
            "type": "command",
            "command": generatedCommand,
        ]
        let generatedBashEntry: [String: Any] = [
            "matcher": "Bash",
            "hooks": [generatedHook],
        ]
        let customBashEntry: [String: Any] = [
            "matcher": "Bash",
            "customEntryField": "preserve",
            "hooks": [
                [
                    "type": "command",
                    "command": "echo custom",
                ],
            ],
        ]
        let settings: [String: Any] = [
            "hooks": [
                "PreToolUse": [customBashEntry, generatedBashEntry, generatedBashEntry],
            ],
            "customTopLevel": true,
        ]
        let settingsData = try JSONSerialization.data(withJSONObject: settings, options: [.prettyPrinted])
        try write(
            try #require(String(data: settingsData, encoding: .utf8)),
            to: ".claude/settings.local.json",
            in: root
        )

        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])
        let removal = try AgentRuleInstaller.uninstall(projectRoot: root, agents: [.claudeCode])

        let object = try expectJSONObject(try read(".claude/settings.local.json", in: root))
        let hooks = try #require(object["hooks"] as? [String: Any])
        let preToolUse = try #require(hooks["PreToolUse"] as? [[String: Any]])
        let bashEntries = preToolUse.filter { $0["matcher"] as? String == "Bash" }
        #expect(bashEntries.count == 1)
        let bash = try #require(bashEntries.first)
        #expect(bash["customEntryField"] as? String == "preserve")
        let commands = try #require(bash["hooks"] as? [[String: Any]])
            .compactMap { $0["command"] as? String }
        #expect(commands == ["echo custom"])
        let allCommands = hooks.values
            .compactMap { $0 as? [[String: Any]] }
            .flatMap { $0 }
            .compactMap { $0["hooks"] as? [[String: Any]] }
            .flatMap { $0 }
            .compactMap { $0["command"] as? String }
        #expect(!allCommands.contains(generatedCommand))
        #expect(removal.updated.contains(".claude/settings.local.json"))
        #expect(removal.manualSteps.isEmpty)
    }

    @Test("Claude uninstall leaves unsafe merged settings byte-for-byte unchanged")
    func claudeUninstallRequiresManualRemovalForUnsafeShape() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let original = """
        {
          "hooks": {
            "PreToolUse": {
              "userCustom": "keepme"
            }
          },
          "sandbox": {
            "network": {
              "allowMachLookup": [
                "Custom.Service",
                "Authsia.Bridge",
                "Authsia.SSHAgent"
              ],
              "allowUnixSockets": [
                "~/custom.sock",
                "~/.authsia/agent.sock"
              ]
            }
          }
        }
        """
        try write(original, to: ".claude/settings.local.json", in: root)

        let result = try AgentRuleInstaller.uninstall(projectRoot: root, agents: [.claudeCode])

        #expect(try read(".claude/settings.local.json", in: root) == original)
        #expect(!result.updated.contains(".claude/settings.local.json"))
        let step = try #require(result.manualSteps.first { $0.path == ".claude/settings.local.json" })
        #expect(step.reason.contains("safely"))
    }

    @Test("Claude uninstall is atomic when sandbox network shape is unsafe")
    func claudeUninstallIsAtomicWhenNetworkShapeIsUnsafe() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let original = """
        {
          "hooks": {
            "PreToolUse": [
              {
                "matcher": "Bash",
                "hooks": [
                  {
                    "type": "command",
                    "command": "authsia agent record-command --platform claude-code --source hook"
                  }
                ]
              }
            ]
          },
          "sandbox": {
            "network": {
              "allowMachLookup": {
                "userCustom": "keepme"
              },
              "allowUnixSockets": [
                "~/.authsia/agent.sock"
              ]
            }
          }
        }
        """
        try write(original, to: ".claude/settings.local.json", in: root)

        let result = try AgentRuleInstaller.uninstall(projectRoot: root, agents: [.claudeCode])

        #expect(try read(".claude/settings.local.json", in: root) == original)
        #expect(!result.updated.contains(".claude/settings.local.json"))
        let step = try #require(result.manualSteps.first { $0.path == ".claude/settings.local.json" })
        #expect(step.reason.contains("safely"))
    }

    @Test("Claude uninstall dry run reports structural update without mutation")
    func claudeUninstallDryRunReportsStructuralUpdateWithoutMutation() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("""
        {
          "customTopLevel": true
        }
        """, to: ".claude/settings.local.json", in: root)
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])
        let installed = try read(".claude/settings.local.json", in: root)

        let result = try AgentRuleInstaller.uninstall(
            projectRoot: root,
            agents: [.claudeCode],
            dryRun: true
        )

        #expect(try read(".claude/settings.local.json", in: root) == installed)
        #expect(result.updated.contains(".claude/settings.local.json"))
        #expect(result.manualSteps.isEmpty)
    }

    @Test("Claude uninstall leaves custom-only settings byte-for-byte unchanged")
    func claudeUninstallLeavesCustomOnlySettingsUnchanged() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let original =
            #"{"zCustom":true,"sandbox":{"network":{"allowUnixSockets":["~/custom.sock"],"custom":1,"# +
            #""allowMachLookup":["Custom.Service"]}},"hooks":{"PreToolUse":[{"hooks":[{"command":"# +
            #""echo custom","type":"command"}],"matcher":"Bash","custom":"keep"}]},"aCustom":"first"}"#
        try write(original, to: ".claude/settings.local.json", in: root)

        let result = try AgentRuleInstaller.uninstall(projectRoot: root, agents: [.claudeCode])

        #expect(try read(".claude/settings.local.json", in: root) == original)
        #expect(result.unchanged.contains(".claude/settings.local.json"))
        #expect(!result.updated.contains(".claude/settings.local.json"))
        #expect(!result.removed.contains(".claude/settings.local.json"))
        #expect(result.manualSteps.isEmpty)
    }

    @Test("Codex init creates AGENTS guidance and attribution hooks")
    func codexInitCreatesAgentsGuidanceAndHooks() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let result = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])

        let agents = try read("AGENTS.md", in: root)
        let hooks = try read(".codex/hooks.json", in: root)

        #expect(agents.contains("use the Authsia MCP tools"))
        #expect(agents.contains("construct the tool input yourself"))
        #expect(agents.contains("AUTHSIA_AGENT_PLATFORM=codex"))
        #expect(!agents.contains("Authsia Command History"))
        #expect(!agents.contains("Authsia Sandbox Handling"))
        try expectCodexHooks(hooks)
        #expect(result.created.contains(".codex/hooks.json"))
        #expect(AgentRuleInstaller.isInstalled(projectRoot: root, agent: .codex))
        #expect(!fileExists(".codex/rules/authsia.rules", in: root))
        #expect(result.manualSteps.isEmpty)
        #expect(AgentRuleInstaller.renderResult(result).contains("open /hooks"))
    }

    @Test("Codex init safely merges existing hooks without duplication")
    func codexInitMergesExistingHooks() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("""
        {
          "description": "Project hooks",
          "hooks": {
            "PreToolUse": [
              {
                "matcher": "^Bash$",
                "hooks": [
                  {
                    "type": "command",
                    "command": "echo custom"
                  }
                ]
              }
            ]
          }
        }
        """, to: ".codex/hooks.json", in: root)

        let first = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])
        let installed = try read(".codex/hooks.json", in: root)
        let second = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])

        try expectCodexHooks(installed)
        let object = try expectJSONObject(installed)
        #expect(object["description"] as? String == "Project hooks")
        let hooks = try #require(object["hooks"] as? [String: Any])
        let preToolUse = try #require(hooks["PreToolUse"] as? [[String: Any]])
        let bash = try #require(preToolUse.first { $0["matcher"] as? String == "^Bash$" })
        let commands = try #require(bash["hooks"] as? [[String: Any]])
            .compactMap { $0["command"] as? String }
        #expect(commands.contains("echo custom"))
        #expect(commands.filter { $0 == "authsia agent record-command --platform codex --source hook" }.count == 1)
        #expect(first.updated.contains(".codex/hooks.json"))
        #expect(second.unchanged.contains(".codex/hooks.json"))
        #expect(try read(".codex/hooks.json", in: root) == installed)
    }

    @Test("Codex init leaves inline config hooks unchanged and prints manual guidance")
    func codexInitRequiresManualMergeForInlineConfigHooks() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = """
        model = "gpt-5"

        [[hooks.PreToolUse]]
        matcher = "^Bash$"
        """
        try write(config, to: ".codex/config.toml", in: root)

        let result = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])

        #expect(try read(".codex/config.toml", in: root) == config)
        #expect(!fileExists(".codex/hooks.json", in: root))
        let step = try #require(result.manualSteps.first { $0.path == ".codex/config.toml" })
        #expect(step.reason.contains("inline hooks"))
        #expect(step.block.contains("[[hooks.SubagentStart]]"))
        #expect(step.block.contains("authsia agent record-lineage --platform codex"))
    }

    @Test("Codex init leaves invalid hooks unchanged and prints manual guidance")
    func codexInitRequiresManualMergeForInvalidHooks() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("{", to: ".codex/hooks.json", in: root)

        let result = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])

        #expect(try read(".codex/hooks.json", in: root) == "{")
        let step = try #require(result.manualSteps.first { $0.path == ".codex/hooks.json" })
        #expect(step.reason.contains("could not be parsed or safely merged"))
        try expectCodexHooks(step.block)
        #expect(!result.updated.contains(".codex/hooks.json"))
    }

    @Test("Codex integration is missing when its attribution hooks are absent")
    func codexIntegrationRequiresAttributionHooks() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])
        try FileManager.default.removeItem(at: root.appendingPathComponent(".codex/hooks.json"))

        #expect(!AgentRuleInstaller.isInstalled(projectRoot: root, agent: .codex))
    }

    @Test("Codex integration accepts manually installed inline attribution hooks")
    func codexIntegrationAcceptsInlineAttributionHooks() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])
        try FileManager.default.removeItem(at: root.appendingPathComponent(".codex/hooks.json"))
        try write("""
        [[hooks.PreToolUse]]
        matcher = "^Bash$"

        [[hooks.PreToolUse.hooks]]
        type = "command"
        command = "authsia agent record-command --platform codex --source hook"

        [[hooks.SubagentStart]]
        [[hooks.SubagentStart.hooks]]
        type = "command"
        command = "authsia agent record-lineage --platform codex"

        [[hooks.SubagentStop]]
        [[hooks.SubagentStop.hooks]]
        type = "command"
        command = "authsia agent record-lineage --platform codex"
        """, to: ".codex/config.toml", in: root)

        #expect(AgentRuleInstaller.isInstalled(projectRoot: root, agent: .codex))
    }

    @Test("Codex uninstall removes Authsia hooks and preserves custom hooks")
    func codexUninstallPreservesCustomHooks() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("""
        {
          "description": "Project hooks",
          "hooks": {
            "PreToolUse": [
              {
                "matcher": "^Bash$",
                "hooks": [
                  {
                    "type": "command",
                    "command": "echo custom"
                  }
                ]
              }
            ]
          }
        }
        """, to: ".codex/hooks.json", in: root)
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])

        let result = try AgentRuleInstaller.uninstall(projectRoot: root, agents: [.codex])

        let object = try expectJSONObject(try read(".codex/hooks.json", in: root))
        #expect(object["description"] as? String == "Project hooks")
        let hooks = try #require(object["hooks"] as? [String: Any])
        let commands = hooks.values
            .compactMap { $0 as? [[String: Any]] }
            .flatMap { $0 }
            .compactMap { $0["hooks"] as? [[String: Any]] }
            .flatMap { $0 }
            .compactMap { $0["command"] as? String }
        #expect(commands == ["echo custom"])
        #expect(result.updated.contains(".codex/hooks.json"))
        #expect(result.manualSteps.isEmpty)
    }

    @Test("Codex uninstall deletes untouched generated hooks")
    func codexUninstallDeletesGeneratedHooks() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])

        let result = try AgentRuleInstaller.uninstall(projectRoot: root, agents: [.codex])

        #expect(!fileExists(".codex/hooks.json", in: root))
        #expect(result.removed.contains(".codex/hooks.json"))
        #expect(result.manualSteps.isEmpty)
    }

    @Test("workspace config receives compact MCP-first agent rules")
    func workspaceConfigReceivesCompactMCPFirstAgentRules() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("{}", to: ".authsia/workspace.json", in: root)

        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])

        let agents = try read("AGENTS.md", in: root)
        #expect(agents.contains("`authsia_status`"))
        #expect(agents.contains("`authsia_workspace_inspect`"))
        #expect(agents.contains("If `.authsia/workspace.json` exists, use `authsia_workspace_inspect` to list declared `authsia://` refs from that file and managed env files, including env bindings that point at another vault folder"))
        #expect(agents.contains("Keep declared folders as written"))
        #expect(agents.contains("Do not call `authsia_list` to enumerate this workspace folder or any other folder"))
        #expect(agents.contains("`authsia_list` only when there is no workspace config, or for vault metadata that is not already declared there"))
        #expect(!agents.contains("`authsia_list` for scoped CLI-enabled Vault item metadata"))
        #expect(!agents.contains("do not call `authsia_list` to enumerate the vault"))
        #expect(agents.contains("`authsia_exec`"))
        #expect(agents.contains("`authsia workspace run -- <command> <args>`"))
        #expect(agents.contains("`authsia workspace env list`"))
        #expect(agents.contains("`authsia workspace env use <name>`"))
        #expect(agents.contains("`authsia workspace env use Default`"))
        #expect(agents.contains("`authsia workspace env clear`"))
        #expect(agents.contains("`--environment <name>`"))
        #expect(agents.contains("`--default-only`"))
        #expect(!agents.contains("`authsia exec <type> <query> [options] -- <command> <args>`"))
        #expect(agents.contains("In CLI fallback mode, if `.authsia/workspace.json` exists, list declared `authsia://` refs from that file or `authsia workspace status`, including env bindings that point at another vault folder"))
        #expect(agents.contains("`authsia list <type> --folder <declared-folder> ...`"))
        #expect(!agents.contains("In CLI fallback mode, use attributed `authsia list ...` only for non-secret metadata discovery"))
        #expect(agents.contains("check the complete subcommand's `--help`"))
        #expect(agents.contains("Never use bare `authsia get`, `authsia read`, `authsia load`, `authsia inject`, or `authsia code`"))
        #expect(!agents.contains("Authsia Workspace Handling"))
        #expect(!agents.contains("Implicit guarded-terminal shims"))
    }

    @Test("all agent rules receive MCP workspace and environment guidance")
    func allAgentRulesReceiveMCPWorkspaceAndEnvironmentGuidance() throws {
        for agent in AgentTool.allCases {
            let root = try makeProjectRoot()
            defer { try? FileManager.default.removeItem(at: root) }
            try write("{}", to: ".authsia/workspace.json", in: root)

            _ = try AgentRuleInstaller.install(projectRoot: root, agents: [agent])

            let rules = try read(agent.rulePath, in: root)
            #expect(rules.contains("pass this repository's absolute path as `workspaceRoot`"))
            #expect(rules.contains("pass its name as `environment`"))
            #expect(rules.contains("exact-tagged and `All` items"))
            #expect(rules.contains("`defaultOnly`"))
            #expect(rules.contains("`authsia workspace env list`"))
            #expect(rules.contains("`authsia workspace env use <name>`"))
            #expect(rules.contains("`authsia workspace env use Default`"))
            #expect(rules.contains("`authsia workspace env clear`"))
            #expect(rules.contains("`--environment <name>`"))
            #expect(rules.contains("`--default-only`"))
        }
    }

    @Test("previous workspace rules without environment selection remain recognized")
    func previousWorkspaceRulesWithoutEnvironmentSelectionRemainRecognized() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("{}", to: ".authsia/workspace.json", in: root)
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])
        let current = try read(".authsia/agent-rules.md", in: root)
        let previous = current
            .replacingOccurrences(
                of: "- List workspace environments with `authsia workspace env list`. Persist a named tag with `authsia workspace env use <name>`; return to Default with `authsia workspace env use Default` or `authsia workspace env clear`.\n",
                with: ""
            )
            .replacingOccurrences(
                of: "- This project is an Authsia workspace. In CLI fallback mode, run secret-dependent commands with `authsia workspace run -- <command> <args>` outside the sandbox. Add `--environment <name>` or `--default-only` for one run; omit both to use the saved selection.",
                with: "- This project is an Authsia workspace. In CLI fallback mode, run secret-dependent commands with `authsia workspace run -- <command> <args>` outside the sandbox."
            )

        #expect(previous != current)
        #expect(!previous.contains("`authsia workspace env list`"))
        #expect(!previous.contains("`--environment <name>`"))
        try write(previous, to: ".authsia/agent-rules.md", in: root)
        #expect(AgentRuleInstaller.isInstalled(projectRoot: root, agent: .codex))
    }

    @Test("previous MCP-first shared rules remain recognized")
    func previousMCPFirstSharedRulesRemainRecognized() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("{}", to: ".authsia/workspace.json", in: root)
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])
        let current = try read(".authsia/agent-rules.md", in: root)
        let previous = current
            .replacingOccurrences(
                of: "- For `authsia_status`, `authsia_workspace_inspect`, `authsia_list`, and `authsia_exec`, pass this repository's absolute path as `workspaceRoot`.\n",
                with: ""
            )
            .replacingOccurrences(
                of: "- When the user requests a named workspace environment, pass its name as `environment` to `authsia_workspace_inspect`, `authsia_list`, or `authsia_exec`. For list and execution, exact-tagged and `All` items remain eligible. Use `defaultOnly` on `authsia_exec` for the Default scope, and never combine it with `environment`.\n",
                with: ""
            )

        #expect(previous != current)
        #expect(!previous.contains("workspaceRoot"))
        try write(previous, to: ".authsia/agent-rules.md", in: root)
        #expect(AgentRuleInstaller.isInstalled(projectRoot: root, agent: .codex))
    }

    @Test("previous vault-list agent rules remain recognized")
    func previousVaultListAgentRulesRemainRecognized() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("{}", to: ".authsia/workspace.json", in: root)
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])
        let current = try read(".authsia/agent-rules.md", in: root)
        let previous = current
            .replacingOccurrences(
                of: "- Use `authsia_status` when server readiness is unknown. If `.authsia/workspace.json` exists, use `authsia_workspace_inspect` to list declared `authsia://` refs from that file and managed env files, including env bindings that point at another vault folder.\n- Keep declared folders as written. Do not call `authsia_list` to enumerate this workspace folder or any other folder. Use `authsia_list` only when there is no workspace config, or for vault metadata that is not already declared there.\n",
                with: "- Use `authsia_status` when server readiness is unknown, `authsia_workspace_inspect` for commit-safe workspace metadata, and `authsia_list` for scoped CLI-enabled Vault item metadata.\n"
            )
            .replacingOccurrences(
                of: "- In CLI fallback mode, if `.authsia/workspace.json` exists, list declared `authsia://` refs from that file or `authsia workspace status`, including env bindings that point at another vault folder. Keep those folders as written. Use attributed `authsia list <type> --folder <declared-folder> ...` only when there is no workspace config, or for vault metadata that is not already declared there.\n",
                with: "- In CLI fallback mode, use attributed `authsia list ...` only for non-secret metadata discovery.\n"
            )

        #expect(previous != current)
        #expect(previous.contains("`authsia_list` for scoped CLI-enabled Vault item metadata"))
        #expect(!previous.contains("env bindings that point at another vault folder"))
        try write(previous, to: ".authsia/agent-rules.md", in: root)
        #expect(AgentRuleInstaller.isInstalled(projectRoot: root, agent: .codex))
    }

    @Test("previous workspace-json inventory agent rules remain recognized")
    func previousWorkspaceJSONInventoryAgentRulesRemainRecognized() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("{}", to: ".authsia/workspace.json", in: root)
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])
        let current = try read(".authsia/agent-rules.md", in: root)
        let previous = current
            .replacingOccurrences(
                of: "- Use `authsia_status` when server readiness is unknown. If `.authsia/workspace.json` exists, use `authsia_workspace_inspect` to list declared `authsia://` refs from that file and managed env files, including env bindings that point at another vault folder.\n- Keep declared folders as written. Do not call `authsia_list` to enumerate this workspace folder or any other folder. Use `authsia_list` only when there is no workspace config, or for vault metadata that is not already declared there.\n",
                with: "- Use `authsia_status` when server readiness is unknown. If `.authsia/workspace.json` exists, use `authsia_workspace_inspect` to list this workspace's declared secrets from that file and managed env files; do not call `authsia_list` to enumerate the vault.\n- Use `authsia_list` only when there is no workspace config, or for vault metadata that is not already declared there.\n"
            )
            .replacingOccurrences(
                of: "- In CLI fallback mode, if `.authsia/workspace.json` exists, list declared `authsia://` refs from that file or `authsia workspace status`, including env bindings that point at another vault folder. Keep those folders as written. Use attributed `authsia list <type> --folder <declared-folder> ...` only when there is no workspace config, or for vault metadata that is not already declared there.\n",
                with: "- In CLI fallback mode, if `.authsia/workspace.json` exists, list workspace secrets from that file or `authsia workspace status`; use attributed `authsia list ...` only when there is no workspace config, or for vault metadata that is not already declared there.\n"
            )

        #expect(previous != current)
        #expect(previous.contains("do not call `authsia_list` to enumerate the vault"))
        #expect(!previous.contains("env bindings that point at another vault folder"))
        try write(previous, to: ".authsia/agent-rules.md", in: root)
        #expect(AgentRuleInstaller.isInstalled(projectRoot: root, agent: .codex))
    }

    @Test("previous cross-folder inventory without --folder remains recognized")
    func previousCrossFolderInventoryWithoutFolderFlagRemainsRecognized() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("{}", to: ".authsia/workspace.json", in: root)
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])
        let current = try read(".authsia/agent-rules.md", in: root)
        let previous = current.replacingOccurrences(
            of: "`authsia list <type> --folder <declared-folder> ...`",
            with: "`authsia list ...`"
        )

        #expect(previous != current)
        #expect(previous.contains("env bindings that point at another vault folder"))
        #expect(!previous.contains("--folder <declared-folder>"))
        try write(previous, to: ".authsia/agent-rules.md", in: root)
        #expect(AgentRuleInstaller.isInstalled(projectRoot: root, agent: .codex))
    }

    @Test("legacy workspace shared rules are still recognized")
    func legacyWorkspaceSharedRulesAreStillRecognized() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("{}", to: ".authsia/workspace.json", in: root)
        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])

        let currentShared = AgentRuleInstaller.legacyV1SharedRulesMarkdown(
            for: [.codex],
            includeWorkspaceGuidance: true
        )
        try write(currentShared, to: ".authsia/agent-rules.md", in: root)

        #expect(currentShared.contains("Implicit guarded-terminal shims under agents do not resolve `authsia://` refs"))
        #expect(AgentRuleInstaller.isInstalled(projectRoot: root, agent: .codex))
    }

    @Test("existing Codex rule file is ignored")
    func existingCodexRuleFileIsIgnored() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("# custom", to: ".codex/rules/authsia.rules", in: root)

        let result = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])

        #expect(try read(".codex/rules/authsia.rules", in: root) == "# custom")
        #expect(result.manualSteps.isEmpty)
    }

    @Test("Copilot init teaches explicit Authsia agent marker")
    func copilotInitTeachesExplicitAuthsiaAgentMarker() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let result = try AgentRuleInstaller.install(projectRoot: root, agents: [.copilot])

        let instructions = try read("AGENTS.md", in: root)
        #expect(instructions.contains("AUTHSIA_AGENT_PLATFORM=copilot"))
        #expect(instructions.contains("AUTHSIA_AGENT_INVOKES_AUTHSIA=1"))
        #expect(!fileExists(".github/copilot-instructions.md", in: root))
        #expect(result.manualSteps.isEmpty)
    }

    @Test("Copilot init creates local command-history hook settings")
    func copilotInitCreatesLocalCommandHistoryHookSettings() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let result = try AgentRuleInstaller.install(projectRoot: root, agents: [.copilot])

        let settings = try read(".github/copilot/settings.local.json", in: root)
        try expectCopilotSettings(settings)
        #expect(settings.contains("\"version\": 1"))
        #expect(settings.contains("\"PreToolUse\""))
        #expect(settings.contains("\"matcher\": \"Bash\""))
        #expect(settings.contains("authsia agent record-command --platform copilot --source hook"))
        #expect(settings.contains("|| true"))
        #expect(!settings.contains("\"PostToolUse\""))
        #expect(result.created.contains(".github/copilot/settings.local.json"))
        #expect(result.manualSteps.isEmpty)
    }

    @Test("existing Copilot local settings are not mutated and print a manual merge block")
    func existingCopilotSettingsRequireManualMerge() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("{}", to: ".github/copilot/settings.local.json", in: root)

        let result = try AgentRuleInstaller.install(projectRoot: root, agents: [.copilot])

        #expect(try read(".github/copilot/settings.local.json", in: root) == "{}")
        let step = try #require(result.manualSteps.first)
        #expect(step.path == ".github/copilot/settings.local.json")
        try expectCopilotSettings(step.block)
        #expect(step.block.contains("\"PreToolUse\""))
        #expect(step.block.contains("\"matcher\": \"Bash\""))
        #expect(step.block.contains("authsia agent record-command --platform copilot --source hook"))

        let rendered = AgentRuleInstaller.renderResult(result)
        #expect(rendered.contains("Manual steps:"))
        #expect(rendered.contains(".github/copilot/settings.local.json already exists"))
    }

    @Test("legacy Copilot shared rules without hook guidance are still recognized")
    func legacyCopilotSharedRulesWithoutHookGuidanceAreStillRecognized() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.copilot])
        let currentShared = try read(".authsia/agent-rules.md", in: root)
        let copilotHookGuidance = "- GitHub Copilot command history is captured through the generated Copilot CLI `PreToolUse` hook when `.github/copilot/settings.local.json` can be installed; VS Code Copilot commands use macOS process monitoring fallback."
        let legacyShared = currentShared.replacingOccurrences(
            of: "- GitHub Copilot command history is captured through the generated Copilot CLI `PreToolUse` hook when `.github/copilot/settings.local.json` can be installed; VS Code Copilot commands use macOS process monitoring fallback.\n",
            with: ""
        ).replacingOccurrences(
            of: copilotHookGuidance,
            with: ""
        ).trimmingCharacters(in: .newlines)
        try write(legacyShared, to: ".authsia/agent-rules.md", in: root)

        #expect(!legacyShared.contains("GitHub Copilot command history"))
        #expect(AgentRuleInstaller.isInstalled(projectRoot: root, agent: .copilot))
    }

    @Test("Copilot init forbids bare Authsia secret reads")
    func copilotInitForbidsBareAuthsiaSecretReads() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.copilot])

        let instructions = try read("AGENTS.md", in: root)
        #expect(instructions.contains("GitHub Copilot may use the CLI fallback"))
        #expect(instructions.contains("env AUTHSIA_AGENT_PLATFORM=copilot AUTHSIA_AGENT_INVOKES_AUTHSIA=1"))
        #expect(instructions.contains("Never use bare `authsia get`, `authsia read`, `authsia load`, `authsia inject`, or `authsia code`"))
        #expect(instructions.contains("`authsia_exec`"))
        #expect(instructions.contains("direct argument array"))
    }

    @Test("Copilot init appends Authsia guidance to existing AGENTS file")
    func copilotInitAppendsGuidanceToExistingAgentsFile() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("# Existing Agent Rules\n\nKeep these project rules.", to: "AGENTS.md", in: root)

        let result = try AgentRuleInstaller.install(projectRoot: root, agents: [.copilot])

        let agents = try read("AGENTS.md", in: root)
        #expect(agents.contains("# Existing Agent Rules"))
        #expect(agents.contains("Keep these project rules."))
        #expect(agents.contains(AgentRuleInstaller.managedStartMarker))
        #expect(agents.contains("GitHub Copilot may use the CLI fallback"))
        #expect(!fileExists(".github/copilot-instructions.md", in: root))
        #expect(result.updated.contains("AGENTS.md"))
    }

    @Test("Codex and Copilot share AGENTS guidance without duplicate result entries")
    func codexAndCopilotShareAgentsGuidanceWithoutDuplicateResultEntries() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let result = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex, .copilot])

        let agents = try read("AGENTS.md", in: root)
        let agentPathCount = result.created.filter { $0 == "AGENTS.md" }.count
            + result.updated.filter { $0 == "AGENTS.md" }.count
            + result.unchanged.filter { $0 == "AGENTS.md" }.count
        #expect(agents.contains("AUTHSIA_AGENT_PLATFORM=codex"))
        #expect(agents.contains("AUTHSIA_AGENT_PLATFORM=copilot"))
        #expect(agentPathCount == 1)
    }

    @Test("managed markdown block is replaced without duplication")
    func managedMarkdownBlockIsReplacedWithoutDuplication() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let existing = """
        # Project Rules

        \(AgentRuleInstaller.managedStartMarker)
        old Authsia guidance
        \(AgentRuleInstaller.managedEndMarker)
        """
        try write(existing, to: "AGENTS.md", in: root)

        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])

        let agents = try read("AGENTS.md", in: root)
        #expect(agents.components(separatedBy: AgentRuleInstaller.managedStartMarker).count - 1 == 1)
        #expect(!agents.contains("old Authsia guidance"))
        #expect(agents.contains("# Project Rules"))
        #expect(agents.contains("Authsia Secret Handling"))
    }

    @Test("dry run output uses planned change headings")
    func dryRunOutputUsesPlannedChangeHeadings() {
        let result = AgentRuleInstallResult(
            dryRun: true,
            created: ["AGENTS.md"],
            updated: ["CLAUDE.md"]
        )

        let rendered = AgentRuleInstaller.renderResult(result)

        #expect(rendered.contains("Would create:"))
        #expect(rendered.contains("Would update:"))
        #expect(!rendered.contains("Would Created:"))
        #expect(!rendered.contains("Would Updated:"))
    }

    private func makeProjectRoot() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-agent-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    private func read(_ path: String, in root: URL) throws -> String {
        try String(contentsOf: root.appendingPathComponent(path), encoding: .utf8)
    }

    private func write(_ content: String, to path: String, in root: URL) throws {
        let url = root.appendingPathComponent(path)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try content.write(to: url, atomically: true, encoding: .utf8)
    }

    private func fileExists(_ path: String, in root: URL) -> Bool {
        FileManager.default.fileExists(atPath: root.appendingPathComponent(path).path)
    }

    private var fileToolMatchers: [String] {
        ["Read", "Write", "Edit", "MultiEdit", "LS", "Glob", "Grep"]
    }

    private var claudeOutsideSandboxCommands: [String] {
        [
            "authsia",
            "authsia *",
        ]
    }

    private var claudeCommandsRemovedFromSandboxExclusions: [String] {
        [
            "git clone *",
            "git fetch",
            "git fetch *",
            "git pull",
            "git pull *",
            "git push",
            "git push *",
            "git ls-remote *",
            "git remote update",
            "git remote update *",
            "git submodule add *",
            "git submodule update",
            "git submodule update *",
            "ssh *",
            "scp *",
            "sftp *",
        ]
    }

    private func expectClaudeSettings(_ settings: String) throws {
        let object = try expectJSONObject(settings)
        let hooks = try #require(object["hooks"] as? [String: Any])
        try expectClaudeHookEntries(try #require(hooks["PreToolUse"] as? [[String: Any]]))
        try expectClaudeHookEntries(try #require(hooks["PostToolUse"] as? [[String: Any]]))
        try expectClaudeLineageHookEntries(try #require(hooks["SubagentStart"] as? [[String: Any]]))
        try expectClaudeLineageHookEntries(try #require(hooks["SubagentStop"] as? [[String: Any]]))

        #expect(!object.keys.contains("network"))
        let sandbox = try #require(object["sandbox"] as? [String: Any])
        let excludedCommands = try #require(sandbox["excludedCommands"] as? [String])
        for command in claudeOutsideSandboxCommands {
            #expect(excludedCommands.contains(command))
        }
        for command in claudeCommandsRemovedFromSandboxExclusions {
            #expect(!excludedCommands.contains(command))
        }
        if let network = sandbox["network"] as? [String: Any] {
            let allowMachLookup = (network["allowMachLookup"] as? [String]) ?? []
            #expect(!allowMachLookup.contains("Authsia.Bridge"))
            #expect(!allowMachLookup.contains("Authsia.SSHAgent"))
            let allowUnixSockets = (network["allowUnixSockets"] as? [String]) ?? []
            #expect(!allowUnixSockets.contains("~/.authsia/agent.sock"))
        }
    }

    private func expectClaudeLineageHookEntries(_ entries: [[String: Any]]) throws {
        let commands = entries.compactMap { $0["hooks"] as? [[String: Any]] }.flatMap { $0 }
        #expect(commands.contains {
            $0["type"] as? String == "command" &&
                $0["command"] as? String == "authsia agent record-lineage --platform claude-code"
        })
    }

    private func expectClaudeHookEntries(_ entries: [[String: Any]]) throws {
        let expectedMatchers = Set(["Bash"] + fileToolMatchers)
        #expect(expectedMatchers.isSubset(of: Set(entries.compactMap { $0["matcher"] as? String })))

        for matcher in expectedMatchers {
            let entry = try #require(entries.first { $0["matcher"] as? String == matcher })
            let hooks = try #require(entry["hooks"] as? [[String: Any]])
            #expect(hooks.contains {
                $0["type"] as? String == "command" &&
                    $0["command"] as? String == "authsia agent record-command --platform claude-code --source hook"
            })
        }
    }

    private func expectCodexHooks(_ settings: String) throws {
        let object = try expectJSONObject(settings)
        let hooks = try #require(object["hooks"] as? [String: Any])
        let preToolUse = try #require(hooks["PreToolUse"] as? [[String: Any]])
        let bash = try #require(preToolUse.first { $0["matcher"] as? String == "^Bash$" })
        let bashHooks = try #require(bash["hooks"] as? [[String: Any]])
        #expect(bashHooks.contains {
            $0["type"] as? String == "command" &&
                $0["command"] as? String == "authsia agent record-command --platform codex --source hook" &&
                ($0["timeout"] as? NSNumber)?.intValue == 5
        })
        for event in ["SubagentStart", "SubagentStop"] {
            let entries = try #require(hooks[event] as? [[String: Any]])
            let commands = entries.compactMap { $0["hooks"] as? [[String: Any]] }.flatMap { $0 }
            #expect(commands.contains {
                $0["type"] as? String == "command" &&
                    $0["command"] as? String == "authsia agent record-lineage --platform codex" &&
                    ($0["timeout"] as? NSNumber)?.intValue == 5
            })
        }
    }

    private func expectCopilotSettings(_ settings: String) throws {
        let object = try expectJSONObject(settings)
        let hooks = try #require(object["hooks"] as? [String: Any])
        let entries = try #require(hooks["PreToolUse"] as? [[String: Any]])
        #expect(hooks["PostToolUse"] == nil)

        let expectedMatchers = Set(["Bash"] + fileToolMatchers)
        #expect(Set(entries.compactMap { $0["matcher"] as? String }) == expectedMatchers)

        for matcher in expectedMatchers {
            let entry = try #require(entries.first { $0["matcher"] as? String == matcher })
            #expect(entry["type"] as? String == "command")
            #expect(entry["command"] as? String == "authsia agent record-command --platform copilot --source hook || true")
            #expect((entry["timeoutSec"] as? NSNumber)?.intValue == 5)
        }
    }

    private func expectJSONObject(_ settings: String) throws -> [String: Any] {
        try #require(JSONSerialization.jsonObject(with: Data(settings.utf8)) as? [String: Any])
    }
}
