import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
@testable import authsia

@Suite("Workspace run planner")
struct WorkspaceRunPlannerTests {
    static let humanShimAncestry: [AgenticProcessReference] = [
        AgenticProcessReference(processName: "python3", bundleIdentifier: nil),
        AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
        AgenticProcessReference(processName: "codex", bundleIdentifier: nil),
    ]

    @Test("guarded shim passes through outside any Authsia workspace")
    func guardedShimPassesThroughOutsideWorkspace() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-outside-workspace-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        var environment = ProcessInfo.processInfo.environment
        environment[WorkspaceGuardedTerminal.shimInvocationEnvironmentName] = "1"
        environment["AUTHSIA_WORKSPACE_GUARD"] = "1"
        environment["AUTHSIA_WORKSPACE_ROOT"] = directory.appendingPathComponent("guard-origin").path
        environment["AUTHSIA_FIXTURE_REF"] = "authsia://password/Fixture/password"

        let result = try runBuiltAuthsia(
            arguments: [
                "workspace", "run", "--", "/usr/bin/python3", "-c",
                #"import os; assert "AUTHSIA_FIXTURE_REF" not in os.environ; print("YAML OK")"#,
            ],
            currentDirectory: directory,
            environment: environment
        )

        #expect(result.status == 0)
        #expect(result.stdout == "YAML OK\n")
        #expect(!result.stderr.contains("No Authsia workspace"))
    }

    @Test("explicit workspace run remains fail closed outside a workspace")
    func explicitWorkspaceRunOutsideWorkspaceStillFails() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-explicit-outside-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        var environment = ProcessInfo.processInfo.environment
        environment.removeValue(forKey: WorkspaceGuardedTerminal.shimInvocationEnvironmentName)
        environment.removeValue(forKey: "AUTHSIA_WORKSPACE_GUARD")
        environment.removeValue(forKey: "AUTHSIA_WORKSPACE_ROOT")

        let result = try runBuiltAuthsia(
            arguments: ["workspace", "run", "--", "/usr/bin/python3", "--version"],
            currentDirectory: directory,
            environment: environment
        )

        #expect(result.status != 0)
        #expect(result.stderr.contains("No Authsia workspace"))
    }

    private func runBuiltAuthsia(
        arguments: [String],
        currentDirectory: URL,
        environment: [String: String]
    ) throws -> (status: Int32, stdout: String, stderr: String) {
        var packageRoot = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 {
            packageRoot.deleteLastPathComponent()
        }
        let process = Process()
        process.executableURL = packageRoot.appendingPathComponent(".build/debug/authsia")
        process.arguments = arguments
        process.currentDirectoryURL = currentDirectory
        process.environment = environment
        let output = Pipe()
        let error = Pipe()
        process.standardOutput = output
        process.standardError = error

        try process.run()
        process.waitUntilExit()

        return (
            process.terminationStatus,
            String(data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "",
            String(data: error.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        )
    }

    @Test("managed env files become absolute exec env files")
    func managedEnvFilesBecomeAbsoluteExecEnvFiles() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env", ".env.local"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "".write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)
        try "".write(to: root.appendingPathComponent(".env.local"), atomically: true, encoding: .utf8)

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [".env.production"],
            commandArgs: ["npm", "dev"]
        )

        #expect(plan.envFiles == [
            root.appendingPathComponent(".env").path,
            root.appendingPathComponent(".env.local").path,
            ".env.production",
        ])
        #expect(plan.commandArgs == ["npm", "dev"])
        #expect(!plan.usesShell)
    }

    @Test("workspace run requests exact metadata for active secret references")
    func workspaceRunRequestsExactMetadataForActiveSecretReferences() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let managedEnvFile = root.appendingPathComponent(".env")
        let explicitEnvFile = root.appendingPathComponent(".env.override")
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(
                    name: "API_KEY",
                    reference: "authsia://api-key/API_KEY/key?folder=Workspaces%2Fapi"
                ),
            ]
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "DB_PASSWORD=authsia://password/DB_PASSWORD/password?folder=Workspaces%2Fapi\n".write(
            to: managedEnvFile,
            atomically: true,
            encoding: .utf8
        )
        try "RUNBOOK=authsia://note/Runbook/content?folder=Workspaces%2Fapi\nLITERAL=value\n".write(
            to: explicitEnvFile,
            atomically: true,
            encoding: .utf8
        )
        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [explicitEnvFile.path],
            commandArgs: ["/usr/bin/true"]
        )

        #expect(try Workspace.Run.requiresValidationMetadata(for: plan))
        let request = try Workspace.Run.validationMetadataRequest(for: plan)

        #expect(request.workspaceFolder == "Workspaces/api")
        #expect(request.mode == .validate)
        #expect(Set(request.references) == Set([
            WorkspaceMetadataReference(
                itemType: .apiKey,
                itemName: "API_KEY",
                folderPath: "Workspaces/api"
            ),
            WorkspaceMetadataReference(
                itemType: .password,
                itemName: "DB_PASSWORD",
                folderPath: "Workspaces/api"
            ),
            WorkspaceMetadataReference(
                itemType: .note,
                itemName: "Runbook",
                folderPath: "Workspaces/api"
            ),
        ]))
    }

    @Test("workspace run skips metadata when every configured value is literal")
    func workspaceRunSkipsMetadataWhenEveryConfiguredValueIsLiteral() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let nested = root.appendingPathComponent("services/payments", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        let explicitEnvFile = root.appendingPathComponent(".env.override")
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env", "services/payments/.env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "ROOT_MODE=local\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        try "PAYMENTS_MODE=sandbox\n".write(
            to: nested.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        try "LOG_LEVEL=debug\n".write(
            to: explicitEnvFile,
            atomically: true,
            encoding: .utf8
        )
        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [explicitEnvFile.path],
            commandArgs: ["/usr/bin/true"]
        )

        #expect(try !Workspace.Run.requiresValidationMetadata(for: plan))
    }

    @Test("workspace run requests environment metadata from sibling managed scopes")
    func workspaceRunRequestsEnvironmentMetadataFromSiblingManagedScopes() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let nested = root.appendingPathComponent("services/payments", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        let config = WorkspaceConfig(
            schemaVersion: 2,
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env", "services/payments/.env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "ROOT_KEY=authsia://api-key/ROOT_KEY/key?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        try "PAYMENTS_KEY=authsia://api-key/PAYMENTS_KEY/key?folder=Workspaces%2Fapi%2Fservices\n".write(
            to: nested.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["/usr/bin/true"]
        )

        let request = try Workspace.Run.validationMetadataRequest(for: plan)

        #expect(Set(request.references) == Set([
            WorkspaceMetadataReference(
                itemType: .apiKey,
                itemName: "ROOT_KEY",
                folderPath: "Workspaces/api"
            ),
            WorkspaceMetadataReference(
                itemType: .apiKey,
                itemName: "PAYMENTS_KEY",
                folderPath: "Workspaces/api/services"
            ),
        ]))
    }

    @Test("managed env files follow the command directory scope")
    func managedEnvFilesFollowCommandDirectoryScope() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let nested = root.appendingPathComponent("services/payments", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: ["services/payments/.env", ".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "".write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)
        try "".write(to: nested.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        let rootPlan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["npm", "test"]
        )
        let nestedPlan = try WorkspaceRunPlan.build(
            startingAt: nested,
            extraEnvFiles: [],
            commandArgs: ["npm", "test"]
        )

        #expect(rootPlan.envFiles == [root.appendingPathComponent(".env").path])
        #expect(rootPlan.managedEnvFileCount == 1)
        #expect(nestedPlan.envFiles == [
            root.appendingPathComponent(".env").path,
            nested.appendingPathComponent(".env").path,
        ])
        #expect(nestedPlan.managedEnvFileCount == 2)
    }

    @Test("missing managed env file guidance explains restore or update")
    func missingManagedEnvFileGuidanceExplainsRestoreOrUpdate() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env.missing"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        do {
            _ = try WorkspaceRunPlan.build(
                startingAt: root,
                extraEnvFiles: [],
                commandArgs: ["npm", "dev"]
            )
            Issue.record("Expected missing managed env file to fail")
        } catch {
            let message = String(describing: error)
            #expect(message.contains("Managed env file \".env.missing\" is missing."))
            #expect(message.contains("Restore the file if it should still be managed."))
            #expect(message.contains("Run `authsia workspace update` to remove stale managed env files."))
        }
    }

    @Test("env binding duplicated by managed env file explains how to resolve")
    func envBindingDuplicatedByManagedEnvFileExplainsResolution() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(
                    name: "API_KEY",
                    reference: "authsia://password/API_KEY/password?folder=Workspaces%2Fapi"
                ),
            ]
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "API_KEY=authsia://password/Other/password?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )

        do {
            _ = try WorkspaceRunPlan.build(
                startingAt: root,
                extraEnvFiles: [],
                commandArgs: ["npm", "dev"]
            )
            Issue.record("Expected duplicated env binding to fail")
        } catch {
            let message = String(describing: error)
            #expect(message.contains("Workspace env binding \"API_KEY\" is also defined in managed env file \".env\"."))
            #expect(message.contains("Remove API_KEY from .env"))
            #expect(message.contains("authsia workspace env remove API_KEY"))
        }
    }

    @Test("shell command keeps managed env files and uses Exec shell mode")
    func shellCommandKeepsManagedEnvFilesAndUsesExecShellMode() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "".write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: [],
            shellCommandParts: ["--", "curl", "\"$API_KEY\""]
        )

        #expect(plan.envFiles == [root.appendingPathComponent(".env").path])
        #expect(plan.commandArgs == ["curl", "\"$API_KEY\""])
        #expect(plan.usesShell)
        #expect(Exec.childCommandArguments(command: plan.commandArgs, shell: plan.usesShell) == [
            "/bin/sh",
            "-c",
            "curl \"$API_KEY\"",
        ])
    }

    @Test("plain workspace commands without secret inputs bypass exec")
    func plainWorkspaceCommandsWithoutSecretInputsBypassExec() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["printf", "ok"]
        )

        #expect(!Workspace.Run.shouldDelegateToExec(plan: plan, parentEnvironment: ["PATH": "/usr/bin"]))
    }

    @Test("workspace commands with secret inputs still delegate to exec")
    func workspaceCommandsWithSecretInputsStillDelegateToExec() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "".write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["printf", "ok"]
        )

        #expect(Workspace.Run.shouldDelegateToExec(plan: plan, parentEnvironment: ["PATH": "/usr/bin"]))

        let noEnvRoot = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: noEnvRoot) }
        let noEnvConfig = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "worker", authsiaFolder: "Workspaces/worker"),
            managedEnvFiles: [],
            agents: nil
        )
        try WorkspaceConfigStore.write(noEnvConfig, toWorkspaceRoot: noEnvRoot)
        let noEnvPlan = try WorkspaceRunPlan.build(
            startingAt: noEnvRoot,
            extraEnvFiles: [],
            commandArgs: ["printf", "ok"],
            shellCommandParts: []
        )
        let parentEnvironment = [
            "PATH": "/usr/bin",
            "API_KEY": "authsia://password/API_KEY/password?folder=Workspaces%2Fapi",
        ]

        #expect(Workspace.Run.shouldDelegateToExec(plan: noEnvPlan, parentEnvironment: parentEnvironment))
    }

    @Test("workspace env bindings delegate to exec without managed env files")
    func workspaceEnvBindingsDelegateToExecWithoutManagedEnvFiles() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let binding = WorkspaceConfig.EnvBinding(
            name: "HF_TOKEN",
            reference: "authsia://password/HF_TOKEN/password?folder=Workspaces%2Fapi"
        )
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: [binding]
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["node", "-e", "console.log(process.env.HF_TOKEN)"]
        )
        let exec = Workspace.Run.configuredExec(for: plan)

        #expect(plan.envFiles.isEmpty)
        #expect(plan.envBindings == ["HF_TOKEN": binding.reference])
        #expect(Workspace.Run.shouldDelegateToExec(plan: plan, parentEnvironment: ["PATH": "/usr/bin"]))
        #expect(exec.environmentOverrides == ["HF_TOKEN": binding.reference])
    }

    @Test("workspace run rejects removed secret-file cleanup flag")
    func workspaceRunRejectsRemovedSecretFileCleanupFlag() {
        #expect(throws: (any Error).self) {
            _ = try Workspace.Run.parse([
                "--cleanup-secret-files",
                "--", "npm", "test",
            ])
        }
    }

    @Test("workspace run dry-run names direct or mediated execution path")
    func workspaceRunDryRunNamesDirectOrMediatedExecutionPath() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let directPlan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["printf", "ok"]
        )
        let directOutput = Workspace.Run.renderDryRun(
            directPlan,
            parentEnvironment: ["PATH": "/usr/bin"]
        )

        #expect(directOutput.contains("Execution: direct passthrough (no workspace secrets detected)"))

        try "PLAIN=value\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let plainEnvConfig = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(plainEnvConfig, toWorkspaceRoot: root)
        let plainEnvPlan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["npm", "test"]
        )
        let plainEnvOutput = Workspace.Run.renderDryRun(
            plainEnvPlan,
            parentEnvironment: ["PATH": "/usr/bin"]
        )

        #expect(plainEnvOutput.contains(
            "Execution: authsia exec (workspace env files active; no Authsia references detected)"
        ))

        try "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let mediatedPlan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["npm", "test"]
        )
        let mediatedOutput = Workspace.Run.renderDryRun(
            mediatedPlan,
            parentEnvironment: ["PATH": "/usr/bin"]
        )

        #expect(mediatedOutput.contains(
            "Execution: authsia exec (Authsia references require approval/JIT unless already authorized)"
        ))
    }

    @Test("workspace run dry-run shows env binding names without resolved values")
    func workspaceRunDryRunShowsEnvBindingNamesWithoutResolvedValues() throws {
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

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["node"]
        )
        let output = Workspace.Run.renderDryRun(plan, parentEnvironment: ["PATH": "/usr/bin"])

        #expect(output.contains("Env bindings:"))
        #expect(output.contains("- HF_TOKEN"))
        #expect(!output.contains("authsia://password/HF_TOKEN"))
        #expect(output.contains(
            "Execution: authsia exec (Authsia references require approval/JIT unless already authorized)"
        ))
    }

    @Test("workspace run configures exec defaults for delegated runs")
    func workspaceRunConfiguresExecDefaultsForDelegatedRuns() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "".write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        let shellPlan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: [],
            shellCommandParts: ["--", "printf", "ok"]
        )
        let shellExec = Workspace.Run.configuredExec(for: shellPlan)

        #expect(shellExec.resolvedType == nil)
        #expect(shellExec.resolvedQuery == nil)
        #expect(shellExec.folder == nil)
        #expect(shellExec.env == nil)
        #expect(!shellExec.all)
        #expect(!shellExec.allMachines)
        #expect(shellExec.field == nil)
        #expect(shellExec.envFile == [root.appendingPathComponent(".env").path])
        #expect(shellExec.environmentOverrides.isEmpty)
        #expect(shellExec.shellCommand == "printf ok")
        #expect(shellExec.resolvedCommandArgs == ["printf ok"])

        let directPlan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["printf", "ok"]
        )
        let directExec = Workspace.Run.configuredExec(for: directPlan)

        #expect(directExec.shellCommand == nil)
        #expect(directExec.resolvedCommandArgs == ["printf", "ok"])
    }

    @Test("read-only infra probes bypass exec even with managed secrets")
    func readOnlyInfraProbesBypassExecEvenWithManagedSecrets() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )

        let probes: [[String]] = [
            ["/usr/local/bin/docker", "context", "ls", "--format", "{{json .}}"],
            ["/usr/local/bin/docker", "context", "inspect", "default"],
            ["docker", "version"],
            ["docker", "info"],
            ["/usr/local/bin/npm", "view", "@anthropic-ai/claude-code@latest", "version", "--prefer-online"],
            ["npm", "config", "get", "registry"],
            ["pnpm", "outdated"],
            ["pip", "list"],
            ["pip3", "show", "requests"],
            ["kubectl", "version", "--client"],
            ["kubectl", "version"],
            ["terraform", "version"],
            ["tofu", "version"],
            ["go", "version"],
            ["cargo", "metadata", "--no-deps"],
            ["cargo", "tree"],
            ["gcloud", "version"],
            ["gcloud", "config", "list"],
            ["gcloud", "config", "get-value", "project"],
        ]
        for argv in probes {
            let plan = try WorkspaceRunPlan.build(startingAt: root, extraEnvFiles: [], commandArgs: argv)
            #expect(Workspace.Run.isSecretFreeProbe(plan: plan), "expected probe: \(argv.joined(separator: " "))")
            // A managed .env makes shouldDelegateToExec true; the probe check overrides it.
            #expect(Workspace.Run.shouldDelegateToExec(plan: plan, parentEnvironment: ["PATH": "/usr/bin"]))
        }
    }

    @Test("secret-consuming commands are not treated as probes")
    func secretConsumingCommandsAreNotTreatedAsProbes() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "".write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        let nonProbes: [[String]] = [
            ["/usr/local/bin/docker", "compose", "up"],
            ["docker", "context", "create", "staging"],
            ["docker", "context", "rm", "staging"],
            ["docker", "context", "use", "staging"],
            ["docker", "run", "--rm", "alpine", "env"],
            ["npm", "config", "delete", "registry"],
            ["npm", "config", "edit"],
            ["npm", "config", "set", "registry", "https://registry.npmjs.org/"],
            ["npm", "test"],
            ["npm", "run", "serve"],
            ["pnpm", "config", "set", "store-dir", ".pnpm-store"],
            ["yarn", "config", "set", "npmRegistryServer", "https://registry.yarnpkg.com"],
            ["node", "scripts/deploy.js"],
            ["python3", "app.py"],
            ["printf", "ok"],
            ["pip", "install", "requests"],
            ["pip3", "download", "requests"],
            ["kubectl", "apply", "-f", "deploy.yaml"],
            ["terraform", "apply"],
            ["tofu", "plan"],
            ["go", "run", "main.go"],
            ["cargo", "run"],
            ["gcloud", "config", "set", "project", "demo"],
            ["gcloud", "auth", "login"],
        ]
        for argv in nonProbes {
            let plan = try WorkspaceRunPlan.build(startingAt: root, extraEnvFiles: [], commandArgs: argv)
            #expect(!Workspace.Run.isSecretFreeProbe(plan: plan), "unexpected probe: \(argv.joined(separator: " "))")
        }
    }

    @Test("shell commands are never classified as probes")
    func shellCommandsAreNeverClassifiedAsProbes() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "".write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        // A read-only probe expressed as an opaque shell string is not classifiable
        // (it can chain or expand), so it must still delegate.
        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: [],
            shellCommandParts: ["--", "docker", "context", "ls"]
        )
        #expect(plan.usesShell)
        #expect(!Workspace.Run.isSecretFreeProbe(plan: plan))
    }

    private func makeBindingWorkspaceRoot(
        bindingNames: [String] = ["DATABASE_URL"]
    ) throws -> URL {
        let root = try makeWorkspaceRoot()
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [],
            agents: nil,
            envBindings: bindingNames.map {
                WorkspaceConfig.EnvBinding(
                    name: $0,
                    reference: "authsia://password/\($0)/password?folder=Workspaces%2Fapi"
                )
            }
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        return root
    }

    @Test("inline python that references no workspace binding passes through")
    func inlinePythonWithoutBindingReferencePassesThrough() throws {
        let root = try makeBindingWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let bindingFree: [[String]] = [
            ["python3", "-c", "print(\"ok\")"],
            ["python3", "-c", "import os; print(os.environ[\"DEMO_MASK\"])"],
            ["/usr/bin/python3", "-c", "import json; print(json.dumps({}))"],
            ["python", "-c", "print(1)"],
            // Identifier boundaries: neither DATABASE_URL_V2 nor XDATABASE_URL is the binding.
            ["python3", "-c", "import os; os.environ[\"DATABASE_URL_V2\"]"],
            ["python3", "-c", "x = \"XDATABASE_URL\""],
        ]
        for argv in bindingFree {
            let plan = try WorkspaceRunPlan.build(startingAt: root, extraEnvFiles: [], commandArgs: argv)
            let names = try Workspace.Run.workspaceBindingNames(
                plan: plan,
                parentEnvironment: ["PATH": "/usr/bin"]
            )
            #expect(names == ["DATABASE_URL"])
            #expect(
                Workspace.Run.isBindingFreeInvocation(plan: plan, bindingNames: names),
                "expected passthrough: \(argv.joined(separator: " "))"
            )
            // Bindings make shouldDelegateToExec true; the binding-free check overrides it.
            #expect(Workspace.Run.shouldDelegateToExec(plan: plan, parentEnvironment: ["PATH": "/usr/bin"]))
        }
    }

    @Test("inline python referencing a workspace binding delegates to exec")
    func inlinePythonReferencingBindingDelegates() throws {
        let root = try makeBindingWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let referencing: [[String]] = [
            ["python3", "-c", "import os; connect(os.environ[\"DATABASE_URL\"])"],
            ["python3", "-c", "print(\"DATABASE_URL\")"],
            ["python3", "-c", "import os", "DATABASE_URL"],
        ]
        for argv in referencing {
            let plan = try WorkspaceRunPlan.build(startingAt: root, extraEnvFiles: [], commandArgs: argv)
            let names = try Workspace.Run.workspaceBindingNames(
                plan: plan,
                parentEnvironment: ["PATH": "/usr/bin"]
            )
            #expect(
                !Workspace.Run.isBindingFreeInvocation(plan: plan, bindingNames: names),
                "expected delegate: \(argv.joined(separator: " "))"
            )
        }
    }

    @Test("ambiguous python invocations keep delegating")
    func ambiguousPythonInvocationsKeepDelegating() throws {
        let root = try makeBindingWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        // Code outside argv may read any env name, so only a leading `-c` is classifiable.
        let ambiguous: [[String]] = [
            ["python3", "app.py"],
            ["python3", "-m", "http.server"],
            ["python3"],
            ["python3", "-i", "-c", "print(1)"],
            ["python3", "-B", "-c", "print(1)"],
        ]
        for argv in ambiguous {
            let plan = try WorkspaceRunPlan.build(startingAt: root, extraEnvFiles: [], commandArgs: argv)
            let names = try Workspace.Run.workspaceBindingNames(
                plan: plan,
                parentEnvironment: ["PATH": "/usr/bin"]
            )
            #expect(
                !Workspace.Run.isBindingFreeInvocation(plan: plan, bindingNames: names),
                "expected delegate: \(argv.joined(separator: " "))"
            )
        }
    }

    @Test("python delegates when a binding lives in python's implicit env namespace")
    func pythonDelegatesForImplicitEnvNamespaceBindings() throws {
        let root = try makeBindingWorkspaceRoot(bindingNames: ["PYTHONSTARTUP"])
        defer { try? FileManager.default.removeItem(at: root) }

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["python3", "-c", "print(1)"]
        )
        let names = try Workspace.Run.workspaceBindingNames(
            plan: plan,
            parentEnvironment: ["PATH": "/usr/bin"]
        )
        #expect(!Workspace.Run.isBindingFreeInvocation(plan: plan, bindingNames: names))
    }

    @Test("docker invocations without explicit env forwarding pass through")
    func dockerInvocationsWithoutEnvForwardingPassThrough() throws {
        let root = try makeBindingWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        // Containers only receive env that is explicitly forwarded, so a run
        // without -e/--env/--env-file cannot consume workspace bindings.
        let bindingFree: [[String]] = [
            ["docker", "run", "--rm", "alpine", "env"],
            ["docker", "ps"],
            ["docker", "build", "-t", "img", "."],
        ]
        for argv in bindingFree {
            let plan = try WorkspaceRunPlan.build(startingAt: root, extraEnvFiles: [], commandArgs: argv)
            let names = try Workspace.Run.workspaceBindingNames(
                plan: plan,
                parentEnvironment: ["PATH": "/usr/bin"]
            )
            #expect(
                Workspace.Run.isBindingFreeInvocation(plan: plan, bindingNames: names),
                "expected passthrough: \(argv.joined(separator: " "))"
            )
        }
    }

    @Test("docker env forwarding, env files, and compose delegate to exec")
    func dockerEnvForwardingEnvFilesAndComposeDelegate() throws {
        let root = try makeBindingWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let delegating: [[String]] = [
            ["docker", "run", "-e", "DATABASE_URL", "alpine"],
            ["docker", "run", "--env", "DATABASE_URL=x", "alpine"],
            ["docker", "build", "--build-arg", "DATABASE_URL", "."],
            ["docker", "run", "--env-file", ".env", "alpine"],
            ["docker", "run", "--env-file=.env", "alpine"],
            ["docker", "compose", "up"],
        ]
        for argv in delegating {
            let plan = try WorkspaceRunPlan.build(startingAt: root, extraEnvFiles: [], commandArgs: argv)
            let names = try Workspace.Run.workspaceBindingNames(
                plan: plan,
                parentEnvironment: ["PATH": "/usr/bin"]
            )
            #expect(
                !Workspace.Run.isBindingFreeInvocation(plan: plan, bindingNames: names),
                "expected delegate: \(argv.joined(separator: " "))"
            )
        }
    }

    @Test("docker delegates when a binding lives in docker's implicit env namespace")
    func dockerDelegatesForImplicitEnvNamespaceBindings() throws {
        let root = try makeBindingWorkspaceRoot(bindingNames: ["DOCKER_HOST"])
        defer { try? FileManager.default.removeItem(at: root) }

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["docker", "ps"]
        )
        let names = try Workspace.Run.workspaceBindingNames(
            plan: plan,
            parentEnvironment: ["PATH": "/usr/bin"]
        )
        #expect(!Workspace.Run.isBindingFreeInvocation(plan: plan, bindingNames: names))
    }

    @Test("shell commands are never binding-free invocations")
    func shellCommandsAreNeverBindingFreeInvocations() throws {
        let root = try makeBindingWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: [],
            shellCommandParts: ["--", "python3", "-c", "print(1)"]
        )
        #expect(plan.usesShell)
        let names = try Workspace.Run.workspaceBindingNames(
            plan: plan,
            parentEnvironment: ["PATH": "/usr/bin"]
        )
        #expect(!Workspace.Run.isBindingFreeInvocation(plan: plan, bindingNames: names))
    }

    @Test("binding names include parent environment authsia references")
    func bindingNamesIncludeParentEnvironmentAuthsiaReferences() throws {
        let root = try makeBindingWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["python3", "-c", "import os; os.environ[\"API_KEY\"]"]
        )
        let names = try Workspace.Run.workspaceBindingNames(
            plan: plan,
            parentEnvironment: [
                "PATH": "/usr/bin",
                "API_KEY": "authsia://password/API_KEY/password?folder=Workspaces%2Fapi",
            ]
        )
        #expect(names == ["DATABASE_URL", "API_KEY"])
        #expect(!Workspace.Run.isBindingFreeInvocation(plan: plan, bindingNames: names))
    }

    @Test("managed env file authsia references count as bindings, not just workspace env bind entries")
    func managedEnvFileAuthsiaReferencesCountAsBindings() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try """
        PLAIN=value
        API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi
        """.write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        let unreferencing = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["python3", "-c", "print(\"ok\")"]
        )
        let unreferencingNames = try Workspace.Run.workspaceBindingNames(
            plan: unreferencing,
            parentEnvironment: ["PATH": "/usr/bin"]
        )
        #expect(unreferencingNames == ["API_KEY"])
        #expect(Workspace.Run.isBindingFreeInvocation(plan: unreferencing, bindingNames: unreferencingNames))

        let referencing = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["python3", "-c", "import os; connect(os.environ[\"API_KEY\"])"]
        )
        let referencingNames = try Workspace.Run.workspaceBindingNames(
            plan: referencing,
            parentEnvironment: ["PATH": "/usr/bin"]
        )
        #expect(!Workspace.Run.isBindingFreeInvocation(plan: referencing, bindingNames: referencingNames))
    }

    @Test("workspace run dry-run names binding-free passthrough")
    func workspaceRunDryRunNamesBindingFreePassthrough() throws {
        let root = try makeBindingWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["python3", "-c", "print(\"ok\")"]
        )
        let output = Workspace.Run.renderDryRun(
            plan,
            parentEnvironment: ["PATH": "/usr/bin"],
            processAncestry: Self.humanShimAncestry
        )
        #expect(output.contains(
            "Execution: direct passthrough (command references no workspace binding; secrets not injected)"
        ))
    }

    @Test("direct passthrough scrubs automation credentials")
    func directPassthroughScrubsAutomationCredentials() {
        let environment = Workspace.Run.directPassthroughEnvironment(parentEnvironment: [
            AutomationAccessResolver.environmentKey: "11111111-1111-1111-1111-111111111111",
            AutomationAccessResolver.sshEnvironmentKey: "22222222-2222-2222-2222-222222222222",
            "PATH": "/usr/bin",
        ])

        #expect(environment[AutomationAccessResolver.environmentKey] == nil)
        #expect(environment[AutomationAccessResolver.sshEnvironmentKey] == nil)
        #expect(environment["PATH"] == "/usr/bin")
    }

    @Test("shim script marks guarded shim invocation")
    func shimScriptMarksGuardedShimInvocation() {
        let script = WorkspaceGuardedTerminal.shimScript(
            authsiaExecutablePath: "/usr/local/bin/authsia",
            toolPath: "/opt/homebrew/bin/npm"
        )

        #expect(script.contains("export AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION=1"))
    }

    @Test("shell wrapper functions mark guarded shim invocation")
    func shellWrapperFunctionsMarkGuardedShimInvocation() {
        let exports = WorkspaceGuardedTerminal.shellWrapperExports(authsiaExecutablePath: "authsia")

        #expect(exports.contains(
            "AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION=1 command 'authsia' workspace run --"
        ))
    }

    @Test("agent shim invocations bypass secret injection")
    func agentShimInvocationsBypassSecretInjection() {
        let agentAncestry = [
            AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
            AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
            AgenticProcessReference(processName: "claude", bundleIdentifier: nil),
        ]
        let terminalAncestry = [
            AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
            AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
            AgenticProcessReference(processName: "Terminal", bundleIdentifier: "com.apple.Terminal"),
        ]
        let ideTerminalAncestry = [
            AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
            AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
            AgenticProcessReference(processName: "visual-studio-code", bundleIdentifier: nil),
        ]
        let marked = [
            "PATH": "/usr/bin",
            "AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION": "1",
        ]

        #expect(Workspace.Run.isAgentShimInvocation(
            parentEnvironment: marked,
            processAncestry: agentAncestry,
            stdinIsTTY: false
        ))
        #expect(!Workspace.Run.isAgentShimInvocation(
            parentEnvironment: ["PATH": "/usr/bin"],
            processAncestry: agentAncestry,
            stdinIsTTY: false
        ))
        #expect(!Workspace.Run.isAgentShimInvocation(
            parentEnvironment: marked,
            processAncestry: terminalAncestry,
            stdinIsTTY: false
        ))
        // A human at the IDE's integrated terminal keeps human env resolution.
        #expect(!Workspace.Run.isAgentShimInvocation(
            parentEnvironment: marked,
            processAncestry: ideTerminalAncestry,
            stdinIsTTY: true
        ))
        // An IDE extension host spawning shim traffic has no TTY: treat it like an
        // agent so it runs without secrets instead of firing a JIT approval.
        #expect(Workspace.Run.isAgentShimInvocation(
            parentEnvironment: marked,
            processAncestry: ideTerminalAncestry,
            stdinIsTTY: false
        ))

        var automationEnvironment = marked
        automationEnvironment[AutomationAccessResolver.environmentKey] = "11111111-1111-1111-1111-111111111111"
        #expect(!Workspace.Run.isAgentShimInvocation(
            parentEnvironment: automationEnvironment,
            processAncestry: agentAncestry,
            stdinIsTTY: false
        ))
    }

    /// Opening a guarded workspace with `code .` let the VS Code extension host spawn
    /// shim traffic (Pylance probing pytest options) that the shim check did not treat
    /// as agentic while the JIT check did — so the run delegated to `authsia exec` and
    /// fired an agent approval nobody asked for. Both checks must agree on the ancestry.
    @Test("IDE extension host shim traffic never fires a JIT approval")
    func ideExtensionHostShimTrafficNeverFiresJITApproval() {
        let extensionHostAncestry = [
            AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
            AgenticProcessReference(
                processName: "Code Helper (Plugin)",
                bundleIdentifier: nil,
                arguments: [
                    "/Applications/Visual Studio Code.app/Contents/Frameworks/"
                        + "Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)",
                    "--type=extensionHost",
                ]
            ),
        ]
        let environment = [WorkspaceGuardedTerminal.shimInvocationEnvironmentName: "1"]

        // Suppressing the run and firing a JIT preflight are mutually exclusive: whenever
        // the JIT check calls this ancestry agentic, the shim check must too. The JIT
        // check no longer consults the terminal; the shim check still does, because a
        // human driving a guarded terminal should keep resolving workspace secrets.
        #expect(Exec.shouldRunJITPreflight(
            environment: environment,
            processAncestry: extensionHostAncestry
        ))
        #expect(Workspace.Run.isAgentShimInvocation(
            parentEnvironment: environment,
            processAncestry: extensionHostAncestry,
            stdinIsTTY: false
        ))
    }

    @Test("guarded shim under codex keeps human env resolution when stdin is a TTY")
    func guardedShimUnderCodexKeepsHumanEnvWhenStdinIsTTY() {
        let env = [WorkspaceGuardedTerminal.shimInvocationEnvironmentName: "1"]
        // stdin remains a TTY even if stdout is redirected: NOT an agent shim invocation.
        #expect(!Workspace.Run.isAgentShimInvocation(
            parentEnvironment: env,
            processAncestry: Self.humanShimAncestry,
            stdinIsTTY: true
        ))
        // Agent-spawned shim child without a stdin TTY: IS an agent shim invocation.
        #expect(Workspace.Run.isAgentShimInvocation(
            parentEnvironment: env,
            processAncestry: Self.humanShimAncestry,
            stdinIsTTY: false
        ))
        // Explicit agent marker forces agent treatment even with a stdin TTY.
        #expect(Workspace.Run.isAgentShimInvocation(
            parentEnvironment: env.merging([
                AgentRuntimeContextResolver.environmentPlatformKey: "codex",
                AgentRuntimeContextResolver.environmentInvokesAuthsiaKey: "1",
            ]) { _, new in new },
            processAncestry: Self.humanShimAncestry,
            stdinIsTTY: true
        ))
    }

    @Test("child environments drop the shim invocation marker")
    func childEnvironmentsDropShimInvocationMarker() {
        let passthrough = Workspace.Run.directPassthroughEnvironment(parentEnvironment: [
            "AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION": "1",
            "PATH": "/usr/bin",
        ])
        #expect(passthrough["AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION"] == nil)

        var execChild = [
            "AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION": "1",
            "PATH": "/usr/bin",
        ]
        Exec.removeGuardedTerminalShim(from: &execChild)
        #expect(execChild["AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION"] == nil)
    }

    @Test("agent shim passthrough keeps literal workspace env values")
    func agentShimPassthroughKeepsLiteralWorkspaceEnvValues() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try """
        PLAIN=value
        API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi
        """.write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["python3", "script.py"]
        )
        let passthrough = try Workspace.Run.directPassthroughEnvironment(parentEnvironment: [
            AutomationAccessResolver.environmentKey: "11111111-1111-1111-1111-111111111111",
            "AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION": "1",
            "PATH": "/usr/bin",
        ], plan: plan)

        #expect(passthrough["PLAIN"] == "value")
        #expect(passthrough["API_KEY"] == nil)
        #expect(passthrough[AutomationAccessResolver.environmentKey] == nil)
        #expect(passthrough["AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION"] == nil)
    }

    @Test("agent shim passthrough drops managed secret names")
    func agentShimPassthroughDropsManagedSecretNames() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil,
            envBindings: [
                WorkspaceConfig.EnvBinding(
                    name: "HF_TOKEN",
                    reference: "authsia://password/HF_TOKEN/password?folder=Workspaces%2Fapi"
                ),
            ]
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try """
        API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi
        PLAIN=value
        """.write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )
        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["python3", "script.py"]
        )
        let passthrough = try Workspace.Run.directPassthroughEnvironment(parentEnvironment: [
            "AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION": "1",
            "API_KEY": "ambient-api-key",
            "HF_TOKEN": "ambient-token",
            "PATH": "/usr/bin",
        ], plan: plan)

        #expect(passthrough["PLAIN"] == "value")
        #expect(passthrough["API_KEY"] == nil)
        #expect(passthrough["HF_TOKEN"] == nil)
        #expect(passthrough["PATH"] == "/usr/bin")
    }

    @Test("workspace run dry-run names agent shim passthrough")
    func workspaceRunDryRunNamesAgentShimPassthrough() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["python3", "script.py"]
        )
        let output = Workspace.Run.renderDryRun(
            plan,
            parentEnvironment: [
                "PATH": "/usr/bin",
                "AUTHSIA_WORKSPACE_GUARD_SHIM_INVOCATION": "1",
            ],
            processAncestry: [
                AgenticProcessReference(processName: "claude", bundleIdentifier: nil),
            ]
        )

        #expect(output.contains(
            "Execution: direct passthrough (guarded shim under agent; literal env kept, Authsia refs not resolved)"
        ))
    }

    @Test("workspace run dry-run names read-only probe passthrough")
    func workspaceRunDryRunNamesReadOnlyProbePassthrough() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(name: "api", authsiaFolder: "Workspaces/api"),
            managedEnvFiles: [".env"],
            agents: nil
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)
        try "API_KEY=authsia://password/API_KEY/password?folder=Workspaces%2Fapi\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["docker", "context", "ls"]
        )
        let output = Workspace.Run.renderDryRun(plan, parentEnvironment: ["PATH": "/usr/bin"])

        #expect(output.contains(
            "Execution: direct passthrough (read-only probe; workspace secrets not injected)"
        ))
    }
}
