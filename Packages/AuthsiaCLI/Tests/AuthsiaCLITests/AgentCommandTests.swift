import Testing
import Foundation
import AuthenticatorBridge
@testable import authsia

@Suite("Agent init command")
struct AgentCommandTests {

    @Test("Claude init creates shared rules, Claude rules, and local sandbox settings")
    func claudeInitCreatesRulesAndLocalSettings() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let result = try AgentRuleInstaller.install(projectRoot: root, agents: [.claudeCode])

        let shared = try read(".authsia/agent-rules.md", in: root)
        let claudeRules = try read("CLAUDE.md", in: root)
        let settings = try read(".claude/settings.local.json", in: root)

        try expectClaudeSettings(settings)
        #expect(shared.contains("Never ask the user for plaintext secrets."))
        #expect(shared.contains("authsia exec"))
        #expect(shared.contains("Always run every `authsia ...` CLI command outside the sandbox."))
        #expect(claudeRules.contains(AgentRuleInstaller.managedStartMarker))
        #expect(claudeRules.contains("Authsia Secret Handling"))
        #expect(settings.contains("Authsia.Bridge"))
        #expect(settings.contains("Authsia.SSHAgent"))
        #expect(settings.contains("~/.authsia/agent.sock"))
        #expect(settings.contains("\"hooks\""))
        #expect(settings.contains("\"PreToolUse\""))
        #expect(settings.contains("\"PostToolUse\""))
        #expect(settings.contains("\"matcher\": \"Bash\""))
        #expect(settings.contains("authsia agent record-command --platform claude-code --source hook"))
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

    @Test("existing Claude local settings merge Authsia hooks and sandbox permissions")
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
        let network = try #require(sandbox["network"] as? [String: Any])
        #expect((network["allowMachLookup"] as? [String]) == [
            "Custom.Service",
            "Authsia.Bridge",
            "Authsia.SSHAgent",
        ])
        #expect((network["allowUnixSockets"] as? [String]) == [
            "~/custom.sock",
            "~/.authsia/agent.sock",
        ])
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

    @Test("Codex init creates AGENTS guidance only")
    func codexInitCreatesAgentsGuidanceOnly() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let result = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])

        let agents = try read("AGENTS.md", in: root)

        #expect(agents.contains("Always run every `authsia ...` CLI command outside the sandbox."))
        #expect(agents.contains("If the agent session is sandboxed, request permission to run the Authsia command outside the sandbox before trying it."))
        #expect(agents.contains("Authsia records Codex command history from explicit Authsia markers and macOS process monitoring fallback."))
        #expect(!agents.contains("If sandboxed, request access to `Authsia.Bridge`"))
        #expect(!fileExists(".codex/rules/authsia.rules", in: root))
        #expect(result.manualSteps.isEmpty)
    }

    @Test("workspace config adds workspace run guidance to agent rules")
    func workspaceConfigAddsWorkspaceRunGuidanceToAgentRules() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("{}", to: ".authsia/workspace.json", in: root)

        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])

        let agents = try read("AGENTS.md", in: root)
        #expect(agents.contains("Authsia Workspace Handling"))
        #expect(agents.contains("If `.authsia/workspace.json` exists"))
        #expect(agents.contains("`authsia workspace status`"))
        #expect(agents.contains("selected Authsia agent marker on workspace commands"))
        #expect(agents.contains("`authsia workspace run -- <command>`"))
        #expect(agents.contains("Implicit guarded-terminal shims under agents do not resolve `authsia://` refs"))
        #expect(agents.contains("Always run every `authsia ...` CLI command outside the sandbox."))
    }

    @Test("legacy workspace shared rules without guarded shim guidance are still recognized")
    func legacyWorkspaceSharedRulesWithoutGuardedShimGuidanceAreStillRecognized() throws {
        let root = try makeProjectRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try write("{}", to: ".authsia/workspace.json", in: root)

        _ = try AgentRuleInstaller.install(projectRoot: root, agents: [.codex])
        let currentShared = try read(".authsia/agent-rules.md", in: root)
        #expect(AgentRuleInstaller.isInstalled(projectRoot: root, agent: .codex))
        let guardedShimGuidance = """
        - Implicit guarded-terminal shims under agents do not resolve `authsia://` refs; use explicit `authsia workspace run -- <command>` or `authsia exec` for any command that needs workspace secrets.
        """
        let legacyShared = currentShared.replacingOccurrences(
            of: "\(guardedShimGuidance)\n",
            with: ""
        ).trimmingCharacters(in: .newlines)
        try write(legacyShared, to: ".authsia/agent-rules.md", in: root)

        #expect(currentShared.contains("Implicit guarded-terminal shims under agents do not resolve `authsia://` refs"))
        #expect(!legacyShared.contains("Implicit guarded-terminal shims under agents"))
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
        #expect(instructions.contains("When GitHub Copilot runs Authsia"))
        #expect(instructions.contains("env AUTHSIA_AGENT_PLATFORM=copilot AUTHSIA_AGENT_INVOKES_AUTHSIA=1"))
        #expect(instructions.contains("Never run bare `authsia get`"))
        #expect(instructions.contains("`authsia inject`"))
        #expect(instructions.contains("Unprefixed Authsia commands are treated as direct human CLI"))
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
        #expect(agents.contains("When GitHub Copilot runs Authsia"))
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

    private func expectClaudeSettings(_ settings: String) throws {
        let object = try expectJSONObject(settings)
        let hooks = try #require(object["hooks"] as? [String: Any])
        try expectClaudeHookEntries(try #require(hooks["PreToolUse"] as? [[String: Any]]))
        try expectClaudeHookEntries(try #require(hooks["PostToolUse"] as? [[String: Any]]))

        #expect(!object.keys.contains("network"))
        let sandbox = try #require(object["sandbox"] as? [String: Any])
        let network = try #require(sandbox["network"] as? [String: Any])
        let allowMachLookup = try #require(network["allowMachLookup"] as? [String])
        #expect(allowMachLookup.contains("Authsia.Bridge"))
        #expect(allowMachLookup.contains("Authsia.SSHAgent"))
        let allowUnixSockets = try #require(network["allowUnixSockets"] as? [String])
        #expect(allowUnixSockets.contains("~/.authsia/agent.sock"))
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
