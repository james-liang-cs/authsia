import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
@testable import authsia

@Suite("Workspace guarded terminal")
struct WorkspaceGuardedTerminalTests {
    @Test("auto guard flag guides print env shell hook usage")
    func autoGuardFlagGuidesPrintEnvShellHookUsage() throws {
        let command = try Workspace.Guard.parse(["--auto"])

        do {
            try command.run()
            Issue.record("Expected --auto without --print-env to fail with guidance.")
        } catch let error as ValidationError {
            let message = String(describing: error)
            #expect(message.contains("--auto is only valid with --print-env"))
            #expect(message.contains("authsia workspace guard --print-env --auto"))
            #expect(message.contains("remove --auto"))
        }
    }

    @Test("default guarded tools exclude shell expansion and display tools")
    func defaultGuardedToolsExcludeShellExpansionAndDisplayTools() {
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("npm"))
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("npx"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("docker"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("aws"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("terraform"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("tofu"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("kubectl"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("helm"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("gcloud"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("az"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("ansible-playbook"))
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("curl"))
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("echo"))
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("env"))
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("printenv"))
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("sh"))
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("zsh"))
        #expect(WorkspaceGuardedTerminal.blockedDefaultTools.contains("vault"))
        #expect(WorkspaceGuardedTerminal.blockedDefaultTools.contains("op"))
    }

    @Test("default guarded tools exclude agent startup launchers")
    func defaultGuardedToolsExcludeBareJSRuntimes() {
        // These launchers are spawned recursively by agent harnesses, language servers,
        // MCP servers, and plugin hooks. Shimming them routes startup work through
        // `workspace run`, eagerly resolving workspace secrets before a task command.
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("node"))
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("bun"))
        #expect(!WorkspaceGuardedTerminal.defaultTools.contains("npx"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("npm"))
        #expect(WorkspaceGuardedTerminal.defaultTools.contains("uv"))
    }

    @Test("guarded plan creates session exports without parent secrets")
    func guardedPlanCreatesSessionExportsWithoutParentSecrets() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let plan = try WorkspaceGuardedTerminal.plan(
            workspaceRoot: root,
            tools: ["npm"],
            baseTemporaryDirectory: root.appendingPathComponent(".tmp"),
            environment: [
                "PATH": "/opt/homebrew/bin:/usr/bin",
                "SUPER_SECRET_TOKEN": "AUTHSIA_FIXTURE_SECRET_workspaceabcdefghijklmnopqrstuvwxyz123456",
            ]
        )

        #expect(plan.workspaceRoot == root)
        #expect(plan.shimDirectory.path.contains(".tmp/authsia-guard-"))
        #expect(plan.tools == ["npm"])
        #expect(plan.originalSearchPaths == ["/opt/homebrew/bin", "/usr/bin"])
        #expect(plan.environment["AUTHSIA_WORKSPACE_GUARD"] == "1")
        #expect(plan.environment["AUTHSIA_WORKSPACE_ROOT"] == root.path)
        #expect(plan.environment["PATH"] == "\(plan.shimDirectory.path):$PATH")
        #expect(!plan.environment.keys.contains("SUPER_SECRET_TOKEN"))
        #expect(!plan.environment.values.contains { $0.contains("sk_live") })
    }

    @Test("print env adds Python wrappers that survive virtualenv path changes")
    func printEnvAddsPythonWrappersThatSurviveVirtualenvPathChanges() {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let plan = WorkspaceGuardedTerminalPlan(
            workspaceRoot: root,
            shimDirectory: URL(fileURLWithPath: "/tmp/authsia-guard-123", isDirectory: true),
            tools: ["python"],
            environment: [
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": "/tmp/authsia-guard-123",
                "AUTHSIA_WORKSPACE_ROOT": root.path,
                "PATH": "/tmp/authsia-guard-123:$PATH",
            ],
            originalSearchPaths: ["/usr/bin"]
        )

        let rendered = Workspace.Guard.renderShellExports(plan)

        #expect(rendered.contains("export AUTHSIA_WORKSPACE_GUARD_SHIM_DIR='/tmp/authsia-guard-123'"))
        #expect(rendered.contains("awk -v shim=\"$AUTHSIA_WORKSPACE_GUARD_SHIM_DIR\""))
        #expect(rendered.contains("PATH=\"$(_authsia_guard_path_without_shim)\""))
        #expect(rendered.contains("command 'authsia' workspace run -- \"$_authsia_guard_resolved\" \"$@\""))
        #expect(rendered.contains("function python { _authsia_guard_run python \"$@\"; }"))
        #expect(rendered.contains("function python3 { _authsia_guard_run python3 \"$@\"; }"))
        #expect(rendered.contains("function pip { _authsia_guard_run pip \"$@\"; }"))
        #expect(rendered.contains("function pip3 { _authsia_guard_run pip3 \"$@\"; }"))
    }

    @Test("print env routes Python wrappers through the guarded CLI path")
    func printEnvRoutesPythonWrappersThroughGuardedCLIPath() {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let plan = WorkspaceGuardedTerminalPlan(
            workspaceRoot: root,
            shimDirectory: URL(fileURLWithPath: "/tmp/authsia-guard-123", isDirectory: true),
            tools: ["python"],
            environment: [
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": "/tmp/authsia-guard-123",
                "AUTHSIA_WORKSPACE_ROOT": root.path,
                "PATH": "/tmp/authsia-guard-123:$PATH",
            ],
            originalSearchPaths: ["/usr/bin"]
        )

        let rendered = Workspace.Guard.renderShellExports(
            plan,
            authsiaExecutablePath: "/Applications/Authsia.app/Contents/MacOS/authsia"
        )

        #expect(rendered.contains(
            "command '/Applications/Authsia.app/Contents/MacOS/authsia' workspace run -- " +
                "\"$_authsia_guard_resolved\" \"$@\""
        ))
        #expect(!rendered.contains("command authsia workspace run -- \"$_authsia_guard_resolved\" \"$@\""))
    }

    @Test("print env is safe to eval in zsh when Python aliases exist")
    func printEnvIsSafeToEvalInZshWhenPythonAliasesExist() throws {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let plan = WorkspaceGuardedTerminalPlan(
            workspaceRoot: root,
            shimDirectory: URL(fileURLWithPath: "/tmp/authsia-guard-123", isDirectory: true),
            tools: ["python"],
            environment: [
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": "/tmp/authsia-guard-123",
                "AUTHSIA_WORKSPACE_ROOT": root.path,
                "PATH": "/tmp/authsia-guard-123:$PATH",
            ],
            originalSearchPaths: ["/usr/bin"]
        )
        let script = Workspace.Guard.renderShellExports(plan)
        let scriptURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-guard-\(UUID().uuidString).zsh")
        defer { try? FileManager.default.removeItem(at: scriptURL) }
        try script.write(to: scriptURL, atomically: true, encoding: .utf8)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/zsh")
        process.arguments = [
            "-fc",
            """
            alias python='python3'
            original_path="$PATH"
            eval "$(cat \(WorkspaceGuardedTerminal.shellQuoted(scriptURL.path)))"
            eval "$(cat \(WorkspaceGuardedTerminal.shellQuoted(scriptURL.path)))"
            [ "$AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH" = "$original_path" ] && echo guard-original-path-preserved
            whence -w python
            """,
        ]
        let output = Pipe()
        let error = Pipe()
        process.standardOutput = output
        process.standardError = error

        try process.run()
        process.waitUntilExit()

        let stdout = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        _ = error.fileHandleForReading.readDataToEndOfFile()
        #expect(process.terminationStatus == 0)
        #expect(stdout.contains("guard-original-path-preserved"))
        #expect(stdout.contains("python: function"))
    }

    @Test("custom guard tools are persisted and reused")
    func customGuardToolsArePersistedAndReused() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            guardSettings: WorkspaceConfig.GuardSettings(autoTabs: false, tools: ["poetry"])
        )

        let updated = Workspace.Guard.configPersistingRequestedTools(
            config,
            requestedTools: ["rails", "curl", " rails ", "npm"]
        )
        try WorkspaceConfigStore.write(updated, toWorkspaceRoot: root)
        let reloaded = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        let tools = Workspace.Guard.toolsForGuard(config: reloaded, requestedTools: [])

        #expect(reloaded.guardSettings.autoTabs == false)
        #expect(reloaded.guardSettings.tools == ["poetry", "rails"])
        #expect(tools.contains("poetry"))
        #expect(tools.contains("rails"))
        #expect(tools.contains("npm"))
        #expect(!reloaded.guardSettings.tools.contains("curl"))
        #expect(!reloaded.guardSettings.tools.contains("npm"))
    }

    @Test("workspace guard persists an explicit response mode")
    func workspaceGuardPersistsExplicitResponseMode() throws {
        let command = try Workspace.Guard.parse([
            "--response-mode", "block",
            "--dry-run",
        ])
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: WorkspaceConfig.Agents(rules: ["claude-code"]),
            guardSettings: WorkspaceConfig.GuardSettings(responseMode: .confirm)
        )

        let updated = try Workspace.Guard.configPersistingResponseMode(
            config,
            requestedMode: command.responseMode
        )

        #expect(updated.guardSettings.responseMode == .block)
        #expect(updated.guardSettings.autoTabs)
    }

    @Test("print env clears aliases for all shimmed tools")
    func printEnvClearsAliasesForAllShimmedTools() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let plan = try WorkspaceGuardedTerminal.plan(
            workspaceRoot: root,
            tools: ["npm", "aws", "curl", "npm"],
            baseTemporaryDirectory: root.appendingPathComponent(".tmp"),
            environment: ["PATH": "/opt/homebrew/bin:/usr/bin"]
        )
        let rendered = Workspace.Guard.renderShellExports(plan)

        #expect(plan.tools == ["npm", "aws"])
        #expect(plan.aliasTools == ["npm", "aws"])
        #expect(rendered.contains("unalias 'npm' 2>/dev/null || true"))
        #expect(rendered.contains("unalias 'aws' 2>/dev/null || true"))
        #expect(!rendered.contains("unalias 'curl'"))
    }

    @Test("print env clears aliases for custom guard tools")
    func printEnvClearsAliasesForCustomGuardTools() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-custom-alias-\(UUID().uuidString)", isDirectory: true)
        let shimDirectory = base.appendingPathComponent("authsia-guard-123", isDirectory: true)
        try FileManager.default.createDirectory(at: shimDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: base) }
        let rails = shimDirectory.appendingPathComponent("rails")
        try "#!/bin/sh\nexit 0\n".write(to: rails, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: rails.path)
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let plan = WorkspaceGuardedTerminalPlan(
            workspaceRoot: root,
            shimDirectory: shimDirectory,
            tools: ["rails"],
            aliasTools: ["rails"],
            environment: [
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": shimDirectory.path,
                "AUTHSIA_WORKSPACE_ROOT": root.path,
                "PATH": "\(shimDirectory.path):$PATH",
            ],
            originalSearchPaths: ["/usr/bin"]
        )
        let script = Workspace.Guard.renderShellExports(plan)
        let scriptURL = base.appendingPathComponent("guard.zsh")
        try script.write(to: scriptURL, atomically: true, encoding: .utf8)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/zsh")
        process.arguments = [
            "-fc",
            """
            alias rails='echo bypass'
            eval "$(cat \(WorkspaceGuardedTerminal.shellQuoted(scriptURL.path)))"
            command -v rails
            """,
        ]
        let output = Pipe()
        let error = Pipe()
        process.standardOutput = output
        process.standardError = error

        try process.run()
        process.waitUntilExit()

        let stdout = String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        _ = error.fileHandleForReading.readDataToEndOfFile()
        #expect(process.terminationStatus == 0)
        #expect(stdout.trimmingCharacters(in: .whitespacesAndNewlines) == rails.path)
    }

    @Test("print env unsets workspace-managed parent env names but preserves Authsia refs")
    func printEnvUnsetsWorkspaceManagedParentEnvNamesButPreservesAuthsiaRefs() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try writeNestedFile(
            """
            STRIPE_KEY=authsia://password/STRIPE_KEY/password
            NODE_ENV=development
            PATH=authsia://password/PATH/password
            INVALID-NAME=authsia://password/INVALID/password
            """,
            relativePath: ".env",
            in: root
        )
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(
                    name: "API_KEY",
                    reference: "authsia://password/API_KEY/password"
                ),
            ]
        )

        let unsetNames = Workspace.Guard.environmentNamesToUnset(
            config: config,
            workspaceRoot: root
        )
        let plan = WorkspaceGuardedTerminalPlan(
            workspaceRoot: root,
            shimDirectory: URL(fileURLWithPath: "/tmp/authsia-guard-123", isDirectory: true),
            tools: ["npm"],
            unsetEnvironmentNames: unsetNames,
            environment: [
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": "/tmp/authsia-guard-123",
                "AUTHSIA_WORKSPACE_ROOT": root.path,
                "PATH": "/tmp/authsia-guard-123:$PATH",
            ],
            originalSearchPaths: ["/usr/bin"]
        )
        let rendered = Workspace.Guard.renderShellExports(plan)

        #expect(unsetNames == ["API_KEY", "STRIPE_KEY"])
        #expect(rendered.contains("case \"${API_KEY-}\" in authsia://*) ;; *) unset API_KEY 2>/dev/null || true ;; esac"))
        #expect(rendered.contains("case \"${STRIPE_KEY-}\" in authsia://*) ;; *) unset STRIPE_KEY 2>/dev/null || true ;; esac"))
        #expect(!rendered.contains("unset NODE_ENV"))
        #expect(!rendered.contains("unset PATH"))
        #expect(!rendered.contains("unset INVALID-NAME"))
    }

    @Test("guarded plan refuses to shim blocked tools even when explicitly requested")
    func guardedPlanRefusesToShimBlockedTools() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        // Blocked names (shells, secret-printing tools, third-party secret managers)
        // must never be shimmed — a name-based shim gives a false sense of safety
        // (shell expansion happens before the shim sees args) or routes secret output
        // outside Authsia's masking boundary. Enforced even via explicit `--tool`.
        let plan = try WorkspaceGuardedTerminal.plan(
            workspaceRoot: root,
            tools: ["npm", "vault", "sh", "curl", "op"],
            baseTemporaryDirectory: root.appendingPathComponent(".tmp"),
            environment: ["PATH": "/opt/homebrew/bin:/usr/bin"]
        )

        #expect(plan.tools.contains("npm"))
        #expect(!plan.tools.contains("vault"))
        #expect(!plan.tools.contains("sh"))
        #expect(!plan.tools.contains("curl"))
        #expect(!plan.tools.contains("op"))
    }

    @Test("blockedTools reports requested names that will not be shimmed")
    func blockedToolsReportsRequestedNamesThatWillNotBeShimmed() {
        let blocked = WorkspaceGuardedTerminal.blockedTools(in: ["npm", "vault", " sh ", "vault", "uv"])

        #expect(blocked == ["vault", "sh"])
    }

    @Test("cleanup removes stale guard dirs, keeps recent ones, current, and foreign dirs")
    func cleanupRemovesStaleGuardDirectories() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-cleanup-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: base) }

        let now = Date()
        func makeDir(_ name: String, ageSeconds: TimeInterval) throws -> URL {
            let url = base.appendingPathComponent(name, isDirectory: true)
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
            try FileManager.default.setAttributes(
                [.modificationDate: now.addingTimeInterval(-ageSeconds)],
                ofItemAtPath: url.path
            )
            return url
        }

        let stale = try makeDir("authsia-guard-\(UUID().uuidString)", ageSeconds: 7200)   // 2h old → remove
        let recent = try makeDir("authsia-guard-\(UUID().uuidString)", ageSeconds: 600)   // 10m old → keep
        let current = try makeDir("authsia-guard-\(UUID().uuidString)", ageSeconds: 7200) // old but current → keep
        let foreign = try makeDir("some-other-tmp-\(UUID().uuidString)", ageSeconds: 7200) // not ours → keep

        let removed = WorkspaceGuardedTerminal.cleanupStaleShimDirectories(
            in: base,
            keeping: current,
            olderThan: 3600,
            now: now
        )

        #expect(removed.map(\.lastPathComponent) == [stale.lastPathComponent])
        #expect(!FileManager.default.fileExists(atPath: stale.path))
        #expect(FileManager.default.fileExists(atPath: recent.path))
        #expect(FileManager.default.fileExists(atPath: current.path))
        #expect(FileManager.default.fileExists(atPath: foreign.path))
    }

    @Test("cleanup is a no-op when the base directory has no guard dirs")
    func cleanupNoOpWhenNoGuardDirectories() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-cleanup-empty-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: base) }

        let removed = WorkspaceGuardedTerminal.cleanupStaleShimDirectories(in: base, now: Date())

        #expect(removed.isEmpty)
    }

    @Test("shim script preserves caller working directory")
    func shimScriptPreservesCallerWorkingDirectory() {
        let script = WorkspaceGuardedTerminal.shimScript(
            authsiaExecutablePath: "/usr/local/bin/authsia",
            toolPath: "/opt/homebrew/bin/npm"
        )

        #expect(!script.contains("\ncd "))
        #expect(script.contains("exec '/usr/local/bin/authsia' workspace run -- '/opt/homebrew/bin/npm' \"$@\""))
        #expect(!script.contains("env npm"))
    }

    @Test("agent launchers get an unguard shim instead of a mediated one")
    func agentLaunchersGetUnguardShimInsteadOfMediatedOne() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let toolBin = root.appendingPathComponent("bin", isDirectory: true)
        try FileManager.default.createDirectory(at: toolBin, withIntermediateDirectories: true)
        let claude = toolBin.appendingPathComponent("claude")
        try "#!/bin/sh\nexit 0\n".write(to: claude, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: claude.path)

        // Requesting a launcher with `--tool` must not create a mediating shim over it.
        let plan = try WorkspaceGuardedTerminal.plan(
            workspaceRoot: root,
            tools: ["claude"],
            baseTemporaryDirectory: root.appendingPathComponent(".tmp"),
            environment: ["PATH": toolBin.path]
        )
        let result = try WorkspaceGuardedTerminal.install(
            plan,
            authsiaExecutablePath: "/usr/local/bin/authsia",
            fileManager: .default
        )
        let shim = try String(
            contentsOf: result.shimDirectory.appendingPathComponent("claude"),
            encoding: .utf8
        )

        #expect(plan.tools.isEmpty)
        #expect(result.installedTools.isEmpty)
        #expect(result.installedAgentLaunchers == ["claude"])
        #expect(shim.contains(claude.path))
        #expect(shim.contains("-u AUTHSIA_WORKSPACE_GUARD"))
        #expect(!shim.contains("workspace run"))
        #expect(WorkspaceGuardedTerminal.shimmableTools(from: ["npm", "codex", "cursor"]) == ["npm"])
    }

    @Test("agent launcher shim hands the tool an unguarded environment")
    func agentLauncherShimHandsToolUnguardedEnvironment() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let script = root.appendingPathComponent("claude-shim")
        try WorkspaceGuardedTerminal.unguardShimScript(toolPath: "/usr/bin/env")
            .write(to: script, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: script.path)

        let process = Process()
        process.executableURL = script
        // A stale saved PATH that still carries an older session's shim entry.
        process.environment = [
            "PATH": "/tmp/authsia-guard-NEW:/usr/bin:/bin",
            "AUTHSIA_WORKSPACE_GUARD": "1",
            "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": "/tmp/authsia-guard-NEW",
            "AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH": "/tmp/authsia-guard-OLD:/usr/bin:/bin",
            WorkspaceGuardedTerminal.shimInvocationEnvironmentName: "1",
            "AUTHSIA_WORKSPACE_ROOT": root.path,
        ]
        let output = Pipe()
        process.standardOutput = output
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let lines = (String(data: data, encoding: .utf8) ?? "").split(separator: "\n").map(String.init)

        #expect(process.terminationStatus == 0)
        #expect(lines.contains("PATH=/usr/bin:/bin"))
        #expect(!lines.contains { $0.hasPrefix("AUTHSIA_WORKSPACE_GUARD") })
        // Workspace root stays: it is context for the agent, not guard machinery.
        #expect(lines.contains("AUTHSIA_WORKSPACE_ROOT=\(root.path)"))
    }

    @Test("install writes executable shims for resolvable tools")
    func installWritesExecutableShimsForResolvableTools() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let toolBin = root.appendingPathComponent("bin", isDirectory: true)
        try FileManager.default.createDirectory(at: toolBin, withIntermediateDirectories: true)
        let npm = toolBin.appendingPathComponent("npm")
        try "#!/bin/sh\nexit 0\n".write(to: npm, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: npm.path)

        let plan = try WorkspaceGuardedTerminal.plan(
            workspaceRoot: root,
            tools: ["npm", "missing-tool"],
            baseTemporaryDirectory: root.appendingPathComponent(".tmp"),
            environment: ["PATH": toolBin.path]
        )

        let result = try WorkspaceGuardedTerminal.install(
            plan,
            authsiaExecutablePath: "/usr/local/bin/authsia",
            fileManager: .default
        )

        let shim = result.shimDirectory.appendingPathComponent("npm")
        let content = try String(contentsOf: shim, encoding: .utf8)
        let attributes = try FileManager.default.attributesOfItem(atPath: shim.path)
        #expect(FileManager.default.fileExists(atPath: shim.path))
        #expect(content.contains(npm.path))
        #expect(result.installedTools == ["npm"])
        #expect(result.skippedTools == ["missing-tool"])
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o755)
    }

    @Test("print env render emits shell exports and guarded banner")
    func printEnvRenderEmitsShellExportsAndGuardedBanner() {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let plan = WorkspaceGuardedTerminalPlan(
            workspaceRoot: root,
            shimDirectory: URL(fileURLWithPath: "/tmp/authsia-guard-123", isDirectory: true),
            tools: ["npm"],
            environment: [
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "AUTHSIA_WORKSPACE_ROOT": root.path,
                "PATH": "/tmp/authsia-guard-123:$PATH",
            ],
            originalSearchPaths: ["/usr/bin"]
        )

        let rendered = Workspace.Guard.renderShellExports(plan)

        #expect(rendered.contains("export PATH='/tmp/authsia-guard-123':$PATH"))
        #expect(rendered.contains("AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH"))
        #expect(rendered.contains("export AUTHSIA_WORKSPACE_GUARD_ORIGINAL_PATH"))
        #expect(rendered.contains("export AUTHSIA_WORKSPACE_GUARD=1"))
        #expect(rendered.contains("export AUTHSIA_WORKSPACE_ROOT='/tmp/My Project'"))
        #expect(rendered.contains("Authsia guarded terminal active"))
        #expect(rendered.contains("Workspace-managed parent env names cleared"))
        #expect(!rendered.contains("Parent shell has no plaintext secrets"))
        #expect(!rendered.contains("curl $API_KEY"))
    }

    @Test("guarded shell banner identifies a named effective environment")
    func guardedShellBannerIdentifiesNamedEffectiveEnvironment() {
        let root = URL(fileURLWithPath: "/tmp/My Project", isDirectory: true)
        let plan = WorkspaceGuardedTerminalPlan(
            workspaceRoot: root,
            shimDirectory: URL(fileURLWithPath: "/tmp/authsia-guard-123", isDirectory: true),
            tools: ["npm"],
            environment: [
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "AUTHSIA_WORKSPACE_ROOT": root.path,
                "PATH": "/tmp/authsia-guard-123:$PATH",
            ],
            originalSearchPaths: ["/usr/bin"]
        )

        let named = Workspace.Guard.renderShellExports(plan, activeEnvironment: "Production")
        let defaultEnvironment = Workspace.Guard.renderShellExports(plan, activeEnvironment: nil)

        #expect(named.contains("Effective environment: Production."))
        #expect(named.contains("All-environment items remain available."))
        #expect(!defaultEnvironment.contains("Effective environment:"))
    }

    @Test("auto env prints only when enabled and outside a guarded shell")
    func autoEnvPrintsOnlyWhenEnabledAndOutsideGuardedShell() {
        let enabled = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil
        )
        let disabled = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            guardSettings: WorkspaceConfig.GuardSettings(autoTabs: false)
        )

        // Ancestry is pinned: the real one belongs to whoever launched the test runner.
        let humanShell = [AgenticProcessReference(processName: "zsh", bundleIdentifier: nil)]

        #expect(Workspace.Guard.shouldPrintAutoEnv(
            config: enabled,
            environment: [:],
            processAncestry: humanShell
        ))
        #expect(Workspace.Guard.shouldPrintAutoEnv(
            config: enabled,
            environment: ["AUTHSIA_WORKSPACE_GUARD": "1"],
            processAncestry: humanShell
        ))
        #expect(!Workspace.Guard.shouldPrintAutoEnv(
            config: enabled,
            environment: [
                "AUTHSIA_WORKSPACE_GUARD": "1",
                "PATH": "/tmp/authsia-guard-123:/usr/bin",
            ],
            processAncestry: humanShell
        ))
        #expect(!Workspace.Guard.shouldPrintAutoEnv(
            config: disabled,
            environment: [:],
            processAncestry: humanShell
        ))
    }

    @Test("auto env declines shells an agent owns")
    func autoEnvDeclinesShellsAnAgentOwns() {
        let enabled = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil
        )
        let humanShell = [AgenticProcessReference(processName: "zsh", bundleIdentifier: nil)]
        let ideShell = [
            AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
            AgenticProcessReference(processName: "Code Helper", bundleIdentifier: "com.microsoft.VSCode"),
        ]
        let agentShell = humanShell + [AgenticProcessReference(processName: "claude", bundleIdentifier: nil)]

        #expect(Workspace.Guard.shouldPrintAutoEnv(
            config: enabled,
            environment: [:],
            processAncestry: humanShell
        ))
        // An IDE host is not an agent: a human's integrated terminal stays guarded.
        #expect(Workspace.Guard.shouldPrintAutoEnv(
            config: enabled,
            environment: [:],
            processAncestry: ideShell
        ))
        #expect(!Workspace.Guard.shouldPrintAutoEnv(
            config: enabled,
            environment: [:],
            processAncestry: agentShell
        ))
        // The launch marker alone is enough when ancestry cannot be read.
        #expect(!Workspace.Guard.shouldPrintAutoEnv(
            config: enabled,
            environment: [
                "AUTHSIA_AGENT_PLATFORM": "codex",
                "AUTHSIA_AGENT_INVOKES_AUTHSIA": "1",
            ],
            processAncestry: humanShell
        ))
    }

    @Test("auto guard can recover workspace root from guarded shell environment")
    func autoGuardCanRecoverWorkspaceRootFromGuardedShellEnvironment() throws {
        let workspaceRoot = try makeWorkspaceRoot()
        let outsideRoot = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: workspaceRoot) }
        defer { try? FileManager.default.removeItem(at: outsideRoot) }
        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
                managedEnvFiles: [],
                agents: nil
            ),
            toWorkspaceRoot: workspaceRoot
        )
        let guardedEnvironment = [
            "AUTHSIA_WORKSPACE_GUARD": "1",
            "AUTHSIA_WORKSPACE_ROOT": workspaceRoot.path,
        ]

        #expect(Workspace.Guard.workspaceRootForGuard(
            auto: true,
            startingAt: outsideRoot,
            environment: guardedEnvironment
        ) == workspaceRoot.standardizedFileURL)
        #expect(Workspace.Guard.workspaceRootForGuard(
            auto: true,
            startingAt: outsideRoot,
            environment: ["AUTHSIA_WORKSPACE_ROOT": workspaceRoot.path]
        ) == nil)
        #expect(Workspace.Guard.workspaceRootForGuard(
            auto: false,
            startingAt: outsideRoot,
            environment: guardedEnvironment
        ) == nil)
    }

    @Test("shell expansion warning names curl variable boundary")
    func shellExpansionWarningNamesCurlVariableBoundary() {
        let warning = WorkspaceGuardedTerminal.shellExpansionWarning

        #expect(warning.contains("curl $API_KEY"))
        #expect(warning.contains("curl ${API_KEY}"))
        #expect(warning.contains("authsia workspace run --shell -- 'curl \"$API_KEY\"'"))
    }
}
