import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
@testable import authsia

@Suite("Workspace config")
struct WorkspaceConfigTests {
    @Test("workspace help exposes update reset guard and agent commands")
    func workspaceHelpExposesUpdateResetGuardAndAgentCommands() {
        let help = Workspace.helpMessage(columns: 160)
        let initHelp = Workspace.Init.helpMessage(columns: 160)
        let updateHelp = Workspace.Update.helpMessage(columns: 160)
        let runHelp = Workspace.Run.helpMessage(columns: 160)
        let syncHelp = Workspace.Sync.helpMessage(columns: 160)
        let guardHelp = Workspace.Guard.helpMessage(columns: 160)
        let agentHelp = Workspace.Agent.helpMessage(columns: 160)
        let resetHelp = Workspace.Reset.helpMessage(columns: 160)

        #expect(help.contains("update"))
        #expect(help.contains("Refresh this repo's Authsia workspace"))
        #expect(help.contains("reset"))
        #expect(help.contains("Remove repo-local Authsia workspace metadata"))
        #expect(help.contains("guard"))
        #expect(help.contains("Prepare an agent-safe guarded terminal"))
        #expect(!help.contains("sessions"))
        #expect(!help.contains("Show safe multi-session workspace commands"))
        #expect(help.contains("agent"))
        #expect(help.contains("Open or print a secret-free AI tool launch"))
        #expect(help.contains("env"))
        #expect(help.contains("Manage workspace env bindings and environment selection"))
        #expect(help.contains("sync"))
        #expect(help.contains("Reconcile workspace vault folder and env bindings"))
        #expect(!help.contains("forget"))
        #expect(initHelp.contains("--recursive-env"))
        #expect(initHelp.contains("--plan-json"))
        #expect(initHelp.contains("--local-preview"))
        #expect(initHelp.contains("--apply-json"))
        #expect(updateHelp.contains("--recursive-env"))
        #expect(updateHelp.contains("--plan-json"))
        #expect(updateHelp.contains("--local-preview"))
        #expect(updateHelp.contains("--apply-json"))
        #expect(agentHelp.contains("--tool"))
        #expect(agentHelp.contains("--dry-run"))
        #expect(agentHelp.contains("--print"))
        #expect(runHelp.contains("--shell"))
        #expect(!runHelp.contains("--cleanup-secret-files"))
        #expect(syncHelp.contains("--plan-json"))
        #expect(syncHelp.contains("--apply-json"))
        #expect(guardHelp.contains("--dry-run"))
        #expect(guardHelp.contains("--print-env"))
        #expect(guardHelp.contains("--auto"))
        #expect(guardHelp.contains("--tool"))
        #expect(guardHelp.contains("curl $API_KEY"))
        #expect(resetHelp.contains("--yes"))
    }

    @Test("workspace help includes examples for every workspace subcommand")
    func workspaceHelpIncludesExamplesForEveryWorkspaceSubcommand() {
        let helpMessages: [(String, String, [String])] = [
            (
                "workspace",
                Workspace.helpMessage(columns: 160),
                [
                    "authsia workspace init --env-file .env --agent codex",
                    "authsia workspace run -- npm test",
                    "authsia workspace env add API_KEY authsia://api-key/API_KEY/key",
                ]
            ),
            (
                "workspace init",
                Workspace.Init.helpMessage(columns: 160),
                [
                    "authsia workspace init --dry-run --recursive-env",
                    "authsia workspace init --yes --env-file .env --folder Workspaces/api",
                    "authsia workspace init --plan-json",
                ]
            ),
            (
                "workspace update",
                Workspace.Update.helpMessage(columns: 160),
                [
                    "authsia workspace update --dry-run --recursive-env",
                    "authsia workspace update --yes --env-file .env.local",
                    "authsia workspace update --plan-json",
                ]
            ),
            (
                "workspace reset",
                Workspace.Reset.helpMessage(columns: 160),
                [
                    "authsia workspace reset --dry-run",
                    "authsia workspace reset --yes",
                ]
            ),
            (
                "workspace run",
                Workspace.Run.helpMessage(columns: 160),
                [
                    "authsia workspace run -- npm test",
                    "authsia workspace run --env-file .env.local -- python scripts/deploy.py",
                    "authsia workspace run --shell \"npm run build && npm test\"",
                ]
            ),
            (
                "workspace status",
                Workspace.Status.helpMessage(columns: 160),
                [
                    "authsia workspace status",
                    "authsia workspace status --format json",
                ]
            ),
            (
                "workspace sync",
                Workspace.Sync.helpMessage(columns: 160),
                [
                    "authsia workspace sync --dry-run",
                    "authsia workspace sync --plan-json",
                    "authsia workspace sync --apply-json workspace-sync-selection.json",
                ]
            ),
            (
                "workspace guard",
                Workspace.Guard.helpMessage(columns: 160),
                [
                    "authsia workspace guard --dry-run",
                    "eval \"$(authsia workspace guard --print-env)\"",
                    "authsia workspace guard --print-env --auto",
                ]
            ),
            (
                "workspace agent",
                Workspace.Agent.helpMessage(columns: 160),
                [
                    "authsia workspace agent --tool codex --print",
                    "authsia workspace agent --tool cursor --dry-run",
                    "authsia workspace agent --tool claude-code --goal-file task.txt",
                ]
            ),
            (
                "workspace env",
                Workspace.Env.helpMessage(columns: 160),
                [
                    "authsia workspace env list",
                    "authsia workspace env add API_KEY authsia://api-key/API_KEY/key",
                    "authsia workspace env validate",
                    "authsia workspace env use Production",
                    "authsia workspace env use Default",
                ]
            ),
        ]

        for (command, help, examples) in helpMessages {
            #expect(help.contains("Examples:"), "\(command) help should include an Examples section")
            for example in examples {
                #expect(help.contains(example), "\(command) help should include example: \(example)")
            }
        }
    }

    @Test("workspace local preview flag parses for setup and update")
    func workspaceLocalPreviewFlagParsesForSetupAndUpdate() throws {
        let initCommand = try Workspace.Init.parse(["--plan-json", "--local-preview"])
        let updateCommand = try Workspace.Update.parse(["--plan-json", "--local-preview"])

        #expect(initCommand.planJson)
        #expect(initCommand.localPreview)
        #expect(updateCommand.planJson)
        #expect(updateCommand.localPreview)
    }

    @Test("workspace env subcommand help includes concrete examples")
    func workspaceEnvSubcommandHelpIncludesConcreteExamples() {
        let helpMessages: [(String, String, [String])] = [
            (
                "workspace env list",
                Workspace.Env.List.helpMessage(columns: 160),
                [
                    "authsia workspace env list",
                    "authsia workspace env list --format json",
                ]
            ),
            (
                "workspace env add",
                Workspace.Env.Add.helpMessage(columns: 160),
                [
                    "authsia workspace env add API_KEY authsia://api-key/API_KEY/key",
                    "authsia workspace env add DB_PASSWORD authsia://password/DB_PASSWORD/password?folder=Workspaces%2Fapi",
                ]
            ),
            (
                "workspace env remove",
                Workspace.Env.Remove.helpMessage(columns: 160),
                ["authsia workspace env remove API_KEY"]
            ),
            (
                "workspace env validate",
                Workspace.Env.Validate.helpMessage(columns: 160),
                ["authsia workspace env validate"]
            ),
            (
                "workspace env use",
                Env.WorkspaceUse.helpMessage(columns: 160),
                [
                    "authsia workspace env use Production",
                    "authsia workspace env use Default",
                ]
            ),
            (
                "workspace env clear",
                Env.WorkspaceClear.helpMessage(columns: 160),
                ["authsia workspace env clear"]
            ),
        ]

        for (command, help, examples) in helpMessages {
            #expect(help.contains("Examples:"), "\(command) help should include an Examples section")
            for example in examples {
                #expect(help.contains(example), "\(command) help should include example: \(example)")
            }
        }
        #expect(
            Workspace.Env.Validate.helpMessage(columns: 160)
                .contains("Validate the active workspace environment against Authsia")
        )
    }

    @Test("store writes commit-safe relative config")
    func storeWritesCommitSafeRelativeConfig() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env", ".env.local"],
            agents: WorkspaceConfig.Agents(rules: ["codex", "claude-code"])
        )

        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let raw = try read(".authsia/workspace.json", in: root)
        #expect(raw.contains("\"schemaVersion\" : 1"))
        #expect(raw.contains("\"authsiaFolder\" : \"Workspaces/api\""))
        #expect(!raw.contains(root.path))
        let loaded = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        #expect(loaded == config)
    }

    @Test("store normalizes workspace folder under Workspaces")
    func storeNormalizesWorkspaceFolderUnderWorkspaces() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Team/API"),
            managedEnvFiles: [],
            agents: nil
        )

        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let raw = try read(".authsia/workspace.json", in: root)
        let loaded = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        #expect(raw.contains("\"authsiaFolder\" : \"Workspaces/Team/API\""))
        #expect(loaded.workspace.authsiaFolder == "Workspaces/Team/API")
    }

    @Test("store exposes schema v2 while preserving v1 until explicit migration")
    func storePreservesV1UntilExplicitMigration() throws {
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: WorkspaceConfig.Agents(rules: ["codex"])
        )

        let preserved = try WorkspaceConfigStore.migrateToCurrentSchema(config)
        let migrated = WorkspaceConfigStore.migratedToV2(config)

        #expect(WorkspaceConfigStore.currentSchemaVersion == 2)
        #expect(preserved == config)
        #expect(migrated.schemaVersion == WorkspaceConfigStore.currentSchemaVersion)
    }

    @Test("schema v2 accepts duplicate binding names while schema v1 rejects them")
    func schemaV2AcceptsDuplicateBindingNames() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let bindings = [
            WorkspaceConfig.EnvBinding(name: "DATABASE_URL", reference: "authsia://api-key/one/key"),
            WorkspaceConfig.EnvBinding(name: "DATABASE_URL", reference: "authsia://api-key/two/key"),
        ]
        let workspace = WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api")

        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.write(
                WorkspaceConfig(schemaVersion: 1, workspace: workspace, managedEnvFiles: [], agents: nil, envBindings: bindings),
                toWorkspaceRoot: root
            )
        }
        try WorkspaceConfigStore.write(
            WorkspaceConfig(schemaVersion: 2, workspace: workspace, managedEnvFiles: [], agents: nil, envBindings: bindings),
            toWorkspaceRoot: root
        )
        let loaded = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        #expect(loaded.schemaVersion == 2)
        #expect(loaded.envBindings.count == 2)
    }

    @Test("store writes commit-safe workspace env bindings")
    func storeWritesCommitSafeWorkspaceEnvBindings() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(
                    name: "HF_TOKEN",
                    reference: "authsia://password/HF_TOKEN/password?folder=Workspaces%2Fapi"
                ),
            ]
        )

        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let raw = try read(".authsia/workspace.json", in: root)
        #expect(raw.contains("\"envBindings\""))
        #expect(!raw.contains("<concealed by authsia>"))
        let loaded = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        #expect(loaded.envBindings == config.envBindings)
    }

    @Test("store decodes legacy workspace config without env bindings")
    func storeDecodesLegacyWorkspaceConfigWithoutEnvBindings() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        try Data(
            """
            {
              "schemaVersion": 1,
              "workspace": {
                "name": "api",
                "authsiaFolder": "Workspaces/api"
              },
              "managedEnvFiles": [],
              "agents": null
            }
            """.utf8
        ).write(to: root.appendingPathComponent(".authsia/workspace.json"), options: .atomic)

        let config = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)

        #expect(config.envBindings.isEmpty)
        #expect(config.mcpUpstreams.isEmpty)
        #expect(config.guardSettings.autoTabs)
        #expect(config.guardSettings.responseMode == .observe)
    }

    @Test("store writes guarded terminal auto tab setting")
    func storeWritesGuardedTerminalAutoTabSetting() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            guardSettings: WorkspaceConfig.GuardSettings(autoTabs: false)
        )

        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let raw = try read(".authsia/workspace.json", in: root)
        #expect(raw.contains("\"guard\""))
        #expect(raw.contains("\"autoTabs\" : false"))
        let loaded = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        #expect(!loaded.guardSettings.autoTabs)
    }

    @Test("store rejects invalid workspace env bindings")
    func storeRejectsInvalidWorkspaceEnvBindings() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let invalidName = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(name: "BAD-NAME", reference: "authsia://password/API/password"),
            ]
        )
        let invalidReference = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(name: "API_KEY", reference: "plain-value"),
            ]
        )

        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.write(invalidName, toWorkspaceRoot: root)
        }
        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.write(invalidReference, toWorkspaceRoot: root)
        }
    }

    @Test("store rejects unsupported schema with recovery guidance")
    func storeRejectsUnsupportedSchemaWithRecoveryGuidance() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        try """
        {
          "schemaVersion": 3,
          "workspace": {
            "name": "api",
            "authsiaFolder": "Workspaces/api"
          },
          "managedEnvFiles": [".env"],
          "agents": {
            "rules": ["codex"]
          }
        }
        """.write(
            to: root.appendingPathComponent(".authsia/workspace.json"),
            atomically: true,
            encoding: .utf8
        )

        do {
            _ = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
            Issue.record("Expected unsupported schema error")
        } catch let error as WorkspaceConfigError {
            #expect(error == .unsupportedSchema(3))
            #expect(error.errorDescription?.contains("supports schema version 2") == true)
            #expect(error.errorDescription?.contains("Update Authsia") == true)
            #expect(error.errorDescription?.contains("authsia workspace update") == true)
        }
    }

    @Test("store rejects invalid workspace config with recovery guidance")
    func storeRejectsInvalidWorkspaceConfigWithRecoveryGuidance() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        try "{ not json".write(
            to: root.appendingPathComponent(".authsia/workspace.json"),
            atomically: true,
            encoding: .utf8
        )

        do {
            _ = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
            Issue.record("Expected invalid workspace config error")
        } catch let error as WorkspaceConfigError {
            #expect(error == .invalidConfigFile)
            #expect(error.errorDescription?.contains(".authsia/workspace.json") == true)
            #expect(error.errorDescription?.contains("Fix the JSON") == true)
            #expect(error.errorDescription?.contains("restore it from version control") == true)
            #expect(error.errorDescription?.contains("remove it and run `authsia workspace init`") == true)
        }
    }

    @Test("store rejects invalid workspace fields with recovery guidance")
    func storeRejectsInvalidWorkspaceFieldsWithRecoveryGuidance() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        try """
        {
          "schemaVersion": 1,
          "workspace": {
            "name": "",
            "authsiaFolder": "Workspaces/api"
          },
          "managedEnvFiles": [".env"],
          "agents": null
        }
        """.write(
            to: root.appendingPathComponent(".authsia/workspace.json"),
            atomically: true,
            encoding: .utf8
        )

        do {
            _ = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
            Issue.record("Expected invalid workspace field error")
        } catch let error as WorkspaceConfigError {
            #expect(error == .emptyWorkspaceName)
            #expect(error.errorDescription?.contains("Workspace name cannot be empty.") == true)
            #expect(error.errorDescription?.contains("Fix .authsia/workspace.json") == true)
            #expect(error.errorDescription?.contains("restore it from version control") == true)
            #expect(error.errorDescription?.contains("remove it and run `authsia workspace init`") == true)
        }
    }

    @Test("missing workspace config guidance names folder setup and app setup")
    func missingWorkspaceConfigGuidanceNamesFolderSetupAndAppSetup() {
        let message = WorkspaceConfigError.missingConfig.errorDescription ?? ""

        #expect(message.contains("this folder or its parents"))
        #expect(message.contains("authsia workspace init"))
        #expect(message.contains("project root"))
        #expect(message.contains("Authsia > Workspace"))
        #expect(message.contains(".authsia/workspace.json"))
        #expect(!message.contains("Run: authsia workspace init"))
    }

    @Test("store rejects absolute managed env files")
    func storeRejectsAbsoluteManagedEnvFiles() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [root.appendingPathComponent(".env").path],
            agents: nil
        )

        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        }
    }

    @Test("schema v1 and v2 files without mcpUpstreams still load")
    func missingMCPUpstreamsStillLoadForSchemaV1AndV2() throws {
        for schemaVersion in [1, 2] {
            let root = try makeWorkspaceRoot()
            defer { try? FileManager.default.removeItem(at: root) }
            try writeWorkspaceJSON(schemaVersion: schemaVersion, extraFields: "", in: root)

            let config = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
            #expect(config.schemaVersion == schemaVersion)
            #expect(config.mcpUpstreams.isEmpty)
        }
    }

    @Test("workspace env add preserves existing mcpUpstreams")
    func envAddDoesNotStripExistingMCPUpstreams() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let knownRootsDirectory = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: knownRootsDirectory) }
        let upstream = MCPUpstreamConfig(
            name: "jira",
            command: "mcp-atlassian",
            env: [
                "JIRA_API_TOKEN": "authsia://api-key/Atlassian/key?folder=Workspaces%2Fapi",
                "JIRA_URL": "https://example.atlassian.net",
            ],
            tools: MCPUpstreamToolPolicy(
                allow: ["jira_get_issue"],
                approve: ["jira_create_issue"],
                deny: ["jira_delete_issue"]
            )
        )
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            mcpUpstreams: [upstream]
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        _ = try Workspace.Env.addBinding(
            name: "API_KEY",
            reference: "authsia://api-key/API_KEY/key",
            workspaceRoot: root,
            knownRootsStore: WorkspaceKnownRootsStore(applicationSupportDirectory: knownRootsDirectory)
        )

        let loaded = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        #expect(loaded.mcpUpstreams == config.mcpUpstreams)
        #expect(loaded.envBindings.map(\.name) == ["API_KEY"])
    }

    @Test("credential-less stdio MCP upstream is a valid admission allowlist entry")
    func credentiallessMCPUpstreamIsValid() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: .init(name: "capability", authsiaFolder: "Workspaces/capability"),
            managedEnvFiles: [],
            agents: nil,
            mcpUpstreams: [
                MCPUpstreamConfig(
                    name: "filesystem",
                    command: "mcp-filesystem",
                    env: [:],
                    tools: MCPUpstreamToolPolicy(allow: ["read_file"]),
                    catalog: [MCPUpstreamToolDescriptor(name: "read_file")]
                ),
            ]
        )

        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let loaded = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        #expect(loaded.mcpUpstreams.first?.env.isEmpty == true)
        #expect(loaded.mcpUpstreams.first?.name == "filesystem")
    }

    @Test("HTTP-only upstream round-trips without command env tools or catalog")
    func httpOnlyUpstreamRoundTripsThroughReadAndStatus() async throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try writeWorkspaceJSON(
            extraFields: """
            "mcpUpstreams": [
              {
                "name": "rovo",
                "transport": "http",
                "url": "https://example.atlassian.net/mcp"
              }
            ]
            """,
            in: root
        )

        let loaded = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        #expect(loaded.mcpUpstreams.count == 1)
        #expect(loaded.mcpUpstreams[0].name == "rovo")
        #expect(loaded.mcpUpstreams[0].transport == .http)
        #expect(loaded.mcpUpstreams[0].url == "https://example.atlassian.net/mcp")
        #expect(loaded.mcpUpstreams[0].command == nil)
        #expect(loaded.mcpUpstreams[0].args.isEmpty)
        #expect(loaded.mcpUpstreams[0].env.isEmpty)
        #expect(loaded.mcpUpstreams[0].tools == MCPUpstreamToolPolicy())
        #expect(loaded.mcpUpstreams[0].catalog.isEmpty)

        try WorkspaceConfigStore.write(loaded, toWorkspaceRoot: root)
        let raw = try JSONSerialization.jsonObject(
            with: Data(contentsOf: root.appendingPathComponent(".authsia/workspace.json"))
        ) as? [String: Any]
        let upstreams = raw?["mcpUpstreams"] as? [[String: Any]]
        #expect(upstreams?.count == 1)
        #expect(Set(upstreams?[0].keys.map { $0 } ?? []) == ["name", "transport", "url"])

        let status = try await WorkspaceStatusReporter.build(workspaceRoot: root)
        #expect(status.config.mcpUpstreams == loaded.mcpUpstreams)
    }

    @Test("stdio MCP upstream with PATH command and catalog round-trips")
    func stdioUpstreamRoundTripsThroughReadNormalizeValidateWrite() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            mcpUpstreams: [
                MCPUpstreamConfig(
                    name: "jira",
                    command: "mcp-atlassian",
                    env: [
                        "JIRA_API_TOKEN": "authsia://api-key/Atlassian/key?folder=Workspaces%2Fapi",
                        "JIRA_URL": "https://example.atlassian.net",
                        "JIRA_USERNAME": "jane@example.atlassian.net",
                    ],
                    tools: MCPUpstreamToolPolicy(
                        allow: ["jira_get_issue", "jira_search"],
                        approve: ["jira_create_issue"],
                        deny: ["jira_delete_issue"]
                    ),
                    catalog: [
                        MCPUpstreamToolDescriptor(
                            name: "jira_get_issue",
                            description: "Get one Jira issue by key",
                            inputSchema: .object([
                                "additionalProperties": .bool(false),
                                "properties": .object([
                                    "issueKey": .object(["type": .string("string")]),
                                ]),
                                "required": .array([.string("issueKey")]),
                                "type": .string("object"),
                            ])
                        ),
                        MCPUpstreamToolDescriptor(name: "jira_search"),
                        MCPUpstreamToolDescriptor(name: "jira_delete_issue"),
                        MCPUpstreamToolDescriptor(name: "other_tool"),
                    ]
                ),
            ]
        )

        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        let loaded = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)

        #expect(loaded.mcpUpstreams.count == 1)
        #expect(loaded.mcpUpstreams[0].command == "mcp-atlassian")
        #expect(loaded.mcpUpstreams[0].catalog.map(\.name) == ["jira_get_issue", "jira_search"])
        #expect(loaded.mcpUpstreams[0].catalog[1].description.isEmpty)
        #expect(loaded.mcpUpstreams[0].catalog[1].inputSchema == .object([
            "additionalProperties": .bool(true),
            "type": .string("object"),
        ]))
        #expect(loaded.schemaVersion == 2)
    }

    @Test("absolute MCP upstream command is rejected")
    func absoluteMCPUpstreamCommandIsRejected() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try writeWorkspaceJSON(
            extraFields: """
            "mcpUpstreams": [
              {
                "name": "jira",
                "command": "/usr/local/bin/mcp-atlassian"
              }
            ]
            """,
            in: root
        )

        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        }
    }

    @Test("shell-shaped MCP upstream command and args are rejected")
    func shellShapedMCPUpstreamCommandIsRejected() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try writeWorkspaceJSON(
            extraFields: """
            "mcpUpstreams": [
              {
                "name": "jira",
                "command": "bash",
                "args": ["-lc", "mcp-atlassian"]
              }
            ]
            """,
            in: root
        )

        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        }
    }

    @Test("relative MCP upstream command is accepted")
    func relativeMCPUpstreamCommandIsAccepted() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try writeWorkspaceJSON(
            extraFields: """
            "mcpUpstreams": [
              {
                "name": "jira",
                "command": "tools/jira-mcp"
              }
            ]
            """,
            in: root
        )

        let loaded = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        #expect(loaded.mcpUpstreams[0].command == "tools/jira-mcp")
    }

    @Test("overlapping MCP tool lists are rejected")
    func overlappingMCPToolListsAreRejected() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try writeWorkspaceJSON(
            extraFields: """
            "mcpUpstreams": [
              {
                "name": "jira",
                "command": "mcp-atlassian",
                "tools": {
                  "allow": ["jira_get_issue"],
                  "deny": ["jira_get_issue"]
                }
              }
            ]
            """,
            in: root
        )

        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        }
    }

    @Test("MCP upstream env TOKEN names require authsia refs and reject OTP SSH refs")
    func mcpUpstreamEnvRefRules() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        try writeWorkspaceJSON(
            extraFields: """
            "mcpUpstreams": [
              {
                "name": "jira",
                "command": "mcp-atlassian",
                "env": { "JIRA_API_TOKEN": "plaintext" }
              }
            ]
            """,
            in: root
        )
        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        }

        try writeWorkspaceJSON(
            extraFields: """
            "mcpUpstreams": [
              {
                "name": "jira",
                "command": "mcp-atlassian",
                "env": { "JIRA_OTP": "authsia://otp/GitHub/code" }
              }
            ]
            """,
            in: root
        )
        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        }

        try writeWorkspaceJSON(
            extraFields: """
            "mcpUpstreams": [
              {
                "name": "jira",
                "command": "mcp-atlassian",
                "env": { "DEPLOY_KEY": "authsia://ssh/deploy/privateKey" }
              }
            ]
            """,
            in: root
        )
        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        }

        try writeWorkspaceJSON(
            extraFields: """
            "mcpUpstreams": [
              {
                "name": "jira",
                "command": "mcp-atlassian",
                "env": {
                  "JIRA_API_TOKEN": "authsia://api-key/Atlassian/key?folder=Workspaces%2Fapi",
                  "JIRA_URL": "https://example.atlassian.net"
                }
              }
            ]
            """,
            in: root
        )
        let loaded = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        #expect(loaded.mcpUpstreams[0].env["JIRA_URL"] == "https://example.atlassian.net")
    }

    @Test("MCP upstream args reject authsia references")
    func mcpUpstreamArgsRejectSecretReferences() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try writeWorkspaceJSON(
            extraFields: """
            "mcpUpstreams": [
              {
                "name": "jira",
                "command": "mcp-atlassian",
                "args": ["authsia://api-key/Atlassian/key"]
              }
            ]
            """,
            in: root
        )

        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        }
    }

    @Test("MCP upstream catalog rejects non-object dollar-ref and oversized schemas")
    func mcpUpstreamCatalogBounds() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        try writeWorkspaceJSON(
            extraFields: """
            "mcpUpstreams": [
              {
                "name": "jira",
                "command": "mcp-atlassian",
                "tools": { "allow": ["jira_get_issue"] },
                "catalog": [
                  {
                    "name": "jira_get_issue",
                    "inputSchema": { "type": "object", "$ref": "#/defs/issue" }
                  }
                ]
              }
            ]
            """,
            in: root
        )
        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        }

        try writeWorkspaceJSON(
            extraFields: """
            "mcpUpstreams": [
              {
                "name": "jira",
                "command": "mcp-atlassian",
                "tools": { "allow": ["jira_get_issue"] },
                "catalog": [
                  {
                    "name": "jira_get_issue",
                    "inputSchema": { "type": "object", "$schema": "https://json-schema.org/draft/2020-12/schema" }
                  }
                ]
              }
            ]
            """,
            in: root
        )
        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        }

        try writeWorkspaceJSON(
            extraFields: """
            "mcpUpstreams": [
              {
                "name": "jira",
                "command": "mcp-atlassian",
                "tools": { "allow": ["jira_get_issue"] },
                "catalog": [
                  {
                    "name": "jira_get_issue",
                    "inputSchema": {
                      "type": "object",
                      "properties": { "url": { "type": "string", "default": "https://example.invalid" } }
                    }
                  }
                ]
              }
            ]
            """,
            in: root
        )
        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        }

        try writeWorkspaceJSON(
            extraFields: """
            "mcpUpstreams": [
              {
                "name": "jira",
                "command": "mcp-atlassian",
                "tools": { "allow": ["jira_get_issue"] },
                "catalog": [
                  { "name": "jira_get_issue", "inputSchema": true }
                ]
              }
            ]
            """,
            in: root
        )
        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        }

        let oversized = String(repeating: "x", count: 65_536)
        try writeWorkspaceJSON(
            extraFields: """
            "mcpUpstreams": [
              {
                "name": "jira",
                "command": "mcp-atlassian",
                "tools": { "allow": ["jira_get_issue"] },
                "catalog": [
                  { "name": "jira_get_issue", "description": "\(oversized)" }
                ]
              }
            ]
            """,
            in: root
        )
        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        }
    }

    @Test("MCP upstream names must be unique and match the name pattern")
    func mcpUpstreamNamesMustBeUniqueAndValid() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        try writeWorkspaceJSON(
            extraFields: """
            "mcpUpstreams": [
              { "name": "1jira", "command": "mcp-atlassian" }
            ]
            """,
            in: root
        )
        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        }

        try writeWorkspaceJSON(
            extraFields: """
            "mcpUpstreams": [
              { "name": "jira", "command": "mcp-atlassian" },
              { "name": "jira", "command": "tools/jira-mcp" }
            ]
            """,
            in: root
        )
        #expect(throws: WorkspaceConfigError.self) {
            try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        }
    }

    @Test("migratedToV2 preserves mcpUpstreams without bumping current schema")
    func migratedToV2PreservesMCPUpstreams() {
        let config = WorkspaceConfig(
            schemaVersion: 1,
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            mcpUpstreams: [MCPUpstreamConfig(name: "jira", command: "mcp-atlassian")]
        )
        let migrated = WorkspaceConfigStore.migratedToV2(config)
        #expect(WorkspaceConfigStore.currentSchemaVersion == 2)
        #expect(migrated.schemaVersion == 2)
        #expect(migrated.mcpUpstreams == config.mcpUpstreams)
    }
}

private func writeWorkspaceJSON(
    schemaVersion: Int = 2,
    extraFields: String,
    in root: URL
) throws {
    try FileManager.default.createDirectory(
        at: root.appendingPathComponent(".authsia"),
        withIntermediateDirectories: true
    )
    let extra = extraFields.trimmingCharacters(in: .whitespacesAndNewlines)
    let extraJSON = extra.isEmpty ? "" : ",\n      \(extra)"
    try """
    {
      "schemaVersion": \(schemaVersion),
      "workspace": {
        "name": "api",
        "authsiaFolder": "Workspaces/api"
      },
      "managedEnvFiles": []\(extraJSON)
    }
    """.write(
        to: root.appendingPathComponent(".authsia/workspace.json"),
        atomically: true,
        encoding: .utf8
    )
}
