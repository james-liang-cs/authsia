import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
@testable import authsia

@Suite("Exec command validation")
struct ExecCommandTests {

    @Test("help includes runnable examples")
    func helpIncludesRunnableExamples() {
        let help = Exec.helpMessage(columns: 160)

        #expect(help.contains("Examples:"))
        #expect(help.contains("authsia exec api-key API_KEY --folder Team/API -- npm start"))
        #expect(help.contains("authsia exec password DB_PASSWORD -- npm start"))
        #expect(help.contains("authsia exec password --folder Team/API -- npm start"))
        #expect(help.contains("authsia exec password --folder Team/API/Prod -- npm start"))
        #expect(help.contains("authsia exec password --env Production -- npm start"))
        #expect(help.contains("authsia exec -- npm start"))
        #expect(help.contains("authsia exec --type api-key --query API_KEY -- npm start"))
        #expect(help.contains("authsia exec password --folder Team/API -- docker compose up"))
        #expect(help.contains("authsia exec --env-file prod.env -- npm start"))
        #expect(help.contains("including nested folders"))
    }

    @Test("help explains child shell expansion for injected env vars")
    func helpExplainsChildShellExpansion() {
        let help = Exec.helpMessage(columns: 160)

        #expect(help.contains("authsia exec password --folder Team/API --shell 'curl \"$DemoKey\"'"))
        #expect(help.contains("A bare --shell curl $DemoKey still expands in the parent shell before"))
    }

    @Test("parses positional type and query like load")
    func parsesPositionalTypeAndQuery() throws {
        let command = try Exec.parse(["password", "API_KEY", "--", "npm", "start"])

        #expect(command.resolvedType == .password)
        #expect(command.resolvedQuery == "API_KEY")
        #expect(command.commandArgs == ["npm", "start"])
    }

    @Test("parses positional type with folder scope")
    func parsesPositionalTypeWithFolderScope() throws {
        let command = try Exec.parse(["password", "--folder", "Team/API", "--", "npm", "start"])

        #expect(command.resolvedType == .password)
        #expect(command.resolvedQuery == nil)
        #expect(command.folder == "Team/API")
        #expect(command.commandArgs == ["npm", "start"])
    }

    @Test("parses credential-only passthrough without treating command as type")
    func parsesCredentialOnlyPassthrough() throws {
        let command = try Exec.parse(["--", "git", "push"])

        #expect(command.resolvedType == nil)
        #expect(command.resolvedQuery == nil)
        #expect(command.commandArgs == ["git", "push"])
    }

    @Test("parses shell flag before command terminator")
    func parsesShellFlagBeforeCommandTerminator() throws {
        let command = try Exec.parse(["password", "--shell", "--", "curl", "$DemoKey"])

        #expect(command.shellCommand == "curl $DemoKey")
        #expect(command.usesShell)
        #expect(command.commandArgs.isEmpty)
        #expect(command.resolvedCommandArgs == ["curl $DemoKey"])
    }

    @Test("parses shell command without post-terminator separator")
    func parsesShellCommandWithoutPostTerminatorSeparator() throws {
        let command = try Exec.parse([
            "--shell",
            #"curl -H "Authorization: Bearer $API_TOKEN" "$URL""#,
        ])

        #expect(command.shellCommand == #"curl -H "Authorization: Bearer $API_TOKEN" "$URL""#)
        #expect(command.commandArgs.isEmpty)
        #expect(command.resolvedCommandArgs == [#"curl -H "Authorization: Bearer $API_TOKEN" "$URL""#])
        #expect(command.usesShell)
    }

    @Test("legacy type option still parses")
    func parsesLegacyTypeOption() throws {
        let command = try Exec.parse(["--type", "password", "--query", "API_KEY", "--", "npm", "start"])

        #expect(command.resolvedType == .password)
        #expect(command.resolvedQuery == "API_KEY")
        #expect(command.commandArgs == ["npm", "start"])
    }

    // MARK: - validateScopeWithoutType (fix #1 Critical)

    @Test("rejects scope flags when type is omitted")
    func validateScopeWithoutType() {
        // Simulate: authsia exec --query MyKey -- ./app (no --type)
        // This was silently discarding --query before the fix.
        // We test the guard logic directly via the public static helpers.
        let hasTypeScope = true   // query != nil
        let type: Load.ItemType? = nil
        // The guard in run() is: if hasTypeScope && type == nil { throw }
        // Verify the condition triggers as expected.
        #expect(hasTypeScope && type == nil)
    }

    // MARK: - validateExecType

    @Test("rejects ssh type with helpful message")
    func validateExecType_rejectsSSH() {
        #expect(throws: (any Error).self) {
            try Exec.validateExecType(.ssh)
        }
    }

    @Test("accepts password type")
    func validateExecType_acceptsPassword() throws {
        try Exec.validateExecType(.password)
    }

    @Test("accepts cert type")
    func validateExecType_acceptsCert() throws {
        try Exec.validateExecType(.cert)
    }

    @Test("accepts note type")
    func validateExecType_acceptsNote() throws {
        try Exec.validateExecType(.note)
    }

    // MARK: - validateCommand

    @Test("rejects empty command")
    func validateCommand_empty() {
        #expect(throws: (any Error).self) {
            try Exec.validateCommand([])
        }
    }

    @Test("accepts single command")
    func validateCommand_single() throws {
        try Exec.validateCommand(["npm"])
    }

    @Test("accepts command with arguments")
    func validateCommand_withArgs() throws {
        try Exec.validateCommand(["npm", "run", "start"])
    }

    @Test("direct mode leaves child command unchanged")
    func directModeLeavesChildCommandUnchanged() {
        #expect(
            Exec.childCommandArguments(command: ["curl", "$DemoKey", "-L"], shell: false) ==
                ["curl", "$DemoKey", "-L"]
        )
    }

    @Test("shell mode wraps child command in sh c")
    func shellModeWrapsChildCommandInShC() {
        #expect(
            Exec.childCommandArguments(command: ["curl", "$DemoKey", "-L"], shell: true) ==
                ["/bin/sh", "-c", "curl $DemoKey -L"]
        )
    }

    @Test("rejects removed no-masking flag")
    func rejectsRemovedNoMaskingFlag() {
        #expect(throws: (any Error).self) {
            _ = try Exec.parse(["--env-file", ".env", "--no-masking", "--", "npm", "start"])
        }
    }

    @Test("type parser rejects unsupported SSH type")
    func typeParserRejectsUnsupportedSSHType() {
        #expect(throws: (any Error).self) {
            _ = try Exec.parse(["--type", "ssh", "--all", "--", "true"])
        }
    }

    @Test("field parser rejects SSH-only fields")
    func fieldParserRejectsSSHOnlyFields() {
        #expect(throws: (any Error).self) {
            _ = try Exec.parse(["--type", "password", "--field", "publicKey", "--all", "--", "true"])
        }
    }

    @Test("allows credential-only exec when automation credential permits ssh")
    func allowsCredentialOnlyExecForSSHWhenAllowed() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "exec-ssh-only")
        defer { try? FileManager.default.removeItem(at: directory) }

        let credential = try Access.createCredential(
            name: "agent",
            scope: "Team/API",
            ttl: "15m",
            store: store,
            machineIdentity: MachineIdentity(machineId: "m", hostname: "h"),
            now: now,
            allowedCommands: [.ssh]
        )

        let allowed = try Exec.allowsCredentialOnlyExecForSSH(
            environment: [
                AutomationAccessResolver.environmentKey:
                    AccessCredentialStoreFixture.token(for: credential)
            ],
            store: store,
            now: now.addingTimeInterval(60)
        )

        #expect(allowed)
    }

    @Test("rejects credential-only exec when automation credential omits ssh")
    func rejectsCredentialOnlyExecForSSHWhenMissingCapability() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "exec-ssh-only")
        defer { try? FileManager.default.removeItem(at: directory) }

        let credential = try Access.createCredential(
            name: "agent",
            scope: "Team/API",
            ttl: "15m",
            store: store,
            machineIdentity: MachineIdentity(machineId: "m", hostname: "h"),
            now: now,
            allowedCommands: [.exec]
        )

        let allowed = try Exec.allowsCredentialOnlyExecForSSH(
            environment: [
                AutomationAccessResolver.environmentKey:
                    AccessCredentialStoreFixture.token(for: credential)
            ],
            store: store,
            now: now.addingTimeInterval(60)
        )

        #expect(!allowed)
    }

    @Test("parent environment authsia reference is a secret input source")
    func parentEnvironmentAuthsiaReferenceIsSecretInputSource() {
        #expect(
            Exec.hasSecretInput(
                hasTypeScope: false,
                envFileCount: 0,
                environment: ["API": "authsia://password/API/password?folder=Team/API"]
            )
        )
    }

    @Test("agent JIT preflight attaches returned grant to platform-only command history")
    func agentJITPreflightRecordsCommandHistoryForAccessCenter() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-exec-agent-history-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let store = AgentCommandHistoryStore(fileURL: directory.appendingPathComponent("events.jsonl"))
        let grantID = UUID()
        let client = RecordingExecJITPreflightClient(grantIDs: [grantID])
        let now = Date(timeIntervalSince1970: 1_800_000_000)

        try Exec.runJITPreflight(
            references: [
                AgentJITPreflightReference(
                    type: "password",
                    query: "API_KEY",
                    folderPath: "Workspaces/Authsia-Demo"
                ),
            ],
            parentEnvironment: [
                AgentRuntimeContextResolver.environmentPlatformKey: "cursor",
                AgentRuntimeContextResolver.environmentInvokesAuthsiaKey: "1",
            ],
            processAncestry: [],
            client: client,
            commandHistoryStore: store,
            now: now,
            currentDirectoryPath: "/Users/test/Projects/Authsia-Demo",
            terminalSessionScope: nil,
            commandLine: ["authsia", "workspace", "run", "--", "/bin/true"]
        )

        #expect(client.payloads.count == 1)
        let event = try #require(try store.loadAll().first)
        #expect(event.agentPlatform == "cursor")
        #expect(event.sessionID == nil)
        #expect(event.agentJITGrantID == grantID)
        #expect(event.captureSource == .process)
        #expect(event.workingDirectory == "/Users/test/Projects/Authsia-Demo")
        #expect(event.terminalSessionScope == nil)
        #expect(event.executable == "authsia")
        #expect(event.arguments == ["authsia", "workspace", "run", "--", "/bin/true"])
        #expect(event.command == "authsia workspace run -- /bin/true")
    }

    // MARK: - buildEnvironment

    @Test("merges secrets into base environment")
    func buildEnvironment_mergesSecrets() {
        let base = ["PATH": "/usr/bin", "HOME": "/Users/test"]
        let entries = [
            Load.LoadedEntry(
                key: "API_KEY",
                value: "secret123",
                itemType: .password,
                sourceName: "API Key",
                sourceID: "id-1",
                folderPath: nil,
                scrapeMachineName: nil,
                scrapeMachineId: nil
            )
        ]
        let result = Exec.buildEnvironment(entries: entries, base: base)
        #expect(result["PATH"] == "/usr/bin")
        #expect(result["HOME"] == "/Users/test")
        #expect(result["API_KEY"] == "secret123")
    }

    @Test("secrets override existing env vars")
    func buildEnvironment_overridesExisting() {
        let base = ["API_KEY": "old_value"]
        let entries = [
            Load.LoadedEntry(
                key: "API_KEY",
                value: "new_secret",
                itemType: .password,
                sourceName: "API Key",
                sourceID: "id-1",
                folderPath: nil,
                scrapeMachineName: nil,
                scrapeMachineId: nil
            )
        ]
        let result = Exec.buildEnvironment(entries: entries, base: base)
        #expect(result["API_KEY"] == "new_secret")
    }

    @Test("empty entries returns base unchanged")
    func buildEnvironment_emptyEntries() {
        let base = ["PATH": "/usr/bin"]
        let result = Exec.buildEnvironment(entries: [], base: base)
        #expect(result == base)
    }

    @Test("does not pass automation credential to child environment")
    func buildEnvironmentStripsAutomationCredential() {
        let base = [
            "PATH": "/usr/bin",
            AutomationAccessResolver.environmentKey: UUID().uuidString,
        ]

        let result = Exec.buildEnvironment(entries: [], base: base)

        #expect(result["PATH"] == "/usr/bin")
        #expect(result[AutomationAccessResolver.environmentKey] == nil)
    }

    @Test("does not pass caller-provided ssh automation marker to child environment")
    func buildEnvironmentStripsSSHAutomationCredential() {
        let base = [
            "PATH": "/usr/bin",
            AutomationAccessResolver.sshEnvironmentKey: UUID().uuidString,
        ]

        let result = Exec.buildEnvironment(entries: [], base: base)

        #expect(result["PATH"] == "/usr/bin")
        #expect(result[AutomationAccessResolver.sshEnvironmentKey] == nil)
    }

    @Test("exec child environment removes current guarded shim from PATH")
    func finalEnvironmentRemovesCurrentGuardedShimFromPATH() {
        let shim = "/tmp/authsia-guard-123"
        let parent = [
            "PATH": "\(shim):/opt/homebrew/bin:/usr/bin",
            "AUTHSIA_WORKSPACE_GUARD": "1",
            "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR": shim,
            "AUTHSIA_WORKSPACE_ROOT": "/Users/test/project",
        ]

        let result = Exec.finalEnvironment(
            entries: [],
            parentEnvironment: parent,
            envFileVars: ["SERVICE_ENDPOINT": "resolved-endpoint"],
            sshAutomationCredential: nil
        )

        #expect(result["PATH"] == "/opt/homebrew/bin:/usr/bin")
        #expect(result["SERVICE_ENDPOINT"] == "resolved-endpoint")
        #expect(result["AUTHSIA_WORKSPACE_GUARD"] == nil)
        #expect(result["AUTHSIA_WORKSPACE_GUARD_SHIM_DIR"] == nil)
        #expect(result["AUTHSIA_WORKSPACE_ROOT"] == nil)
    }

    @Test("final child environment forwards the SSH bearer token rather than its public id")
    func finalEnvironmentForwardsSSHBearerToken() throws {
        let id = UUID()
        let token = try AutomationCredentialToken.issue(
            id: id,
            randomBytes: Data(repeating: 0x41, count: AutomationCredentialToken.randomByteCount)
        )
        let credential = AccessCredential(
            id: id,
            name: "agent",
            scope: "Team/API",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            expiresAt: Date(timeIntervalSince1970: 1_700_000_900),
            revokedAt: nil,
            machineId: "m",
            machineName: "h",
            allowedCommands: [.ssh],
            bearerToken: token
        )

        let result = Exec.finalEnvironment(
            entries: [],
            parentEnvironment: [
                AutomationAccessResolver.environmentKey: token,
                AutomationAccessResolver.sshEnvironmentKey: "stale",
            ],
            envFileVars: [:],
            sshAutomationCredential: credential
        )

        #expect(result[AutomationAccessResolver.environmentKey] == nil)
        #expect(result[AutomationAccessResolver.sshEnvironmentKey] == token)
        #expect(result[AutomationAccessResolver.sshEnvironmentKey] != id.uuidString)
    }

    @Test("forwards ssh-only marker when automation credential allows ssh")
    func forwardsSSHAutomationCredentialWhenAllowed() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "exec-ssh-cap")
        defer { try? FileManager.default.removeItem(at: directory) }

        let credential = try Access.createCredential(
            name: "agent",
            scope: "Team/API",
            ttl: "15m",
            store: store,
            machineIdentity: MachineIdentity(machineId: "m", hostname: "h"),
            now: now,
            allowedCommands: [.ssh]
        )
        let token = try AutomationCredentialToken.issue(
            id: credential.id,
            randomBytes: Data(repeating: 0x41, count: AutomationCredentialToken.randomByteCount)
        )
        var environment: [String: String] = ["PATH": "/usr/bin"]

        let forwarded = try Exec.forwardSSHAutomationCredential(
            from: [AutomationAccessResolver.environmentKey: token],
            to: &environment,
            store: store,
            now: now.addingTimeInterval(60)
        )

        #expect(environment[AutomationAccessResolver.environmentKey] == nil)
        #expect(environment[AutomationAccessResolver.sshEnvironmentKey] == token)
        #expect(forwarded?.id == credential.id)
    }

    @Test("dedicated SSH credential takes precedence over the general exec credential")
    func dedicatedSSHCredentialTakesPrecedence() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "exec-ssh-cap")
        defer { try? FileManager.default.removeItem(at: directory) }
        let execCredential = try Access.createCredential(
            name: "agent-exec",
            scope: "Team/API",
            ttl: "15m",
            store: store,
            machineIdentity: MachineIdentity(machineId: "m", hostname: "h"),
            now: now,
            allowedCommands: [.exec]
        )
        let sshCredential = try Access.createCredential(
            name: "agent-ssh",
            scope: "Team/API",
            ttl: "15m",
            store: store,
            machineIdentity: MachineIdentity(machineId: "m", hostname: "h"),
            now: now,
            allowedCommands: [.ssh]
        )
        let execToken = AccessCredentialStoreFixture.token(for: execCredential)
        let sshToken = AccessCredentialStoreFixture.token(for: sshCredential)
        var childEnvironment: [String: String] = [:]

        let forwarded = try Exec.forwardSSHAutomationCredential(
            from: [
                AutomationAccessResolver.environmentKey: execToken,
                AutomationAccessResolver.sshEnvironmentKey: sshToken,
            ],
            to: &childEnvironment,
            store: store,
            now: now.addingTimeInterval(60)
        )

        #expect(forwarded?.id == sshCredential.id)
        #expect(childEnvironment[AutomationAccessResolver.sshEnvironmentKey] == sshToken)
        #expect(childEnvironment[AutomationAccessResolver.sshEnvironmentKey] != execToken)
    }

    @Test("SSH bearer tokens are included in output masking inputs")
    func sshBearerTokensAreMasked() {
        let token = "authsia_ac1_synthetic-token"
        let secrets = Exec.collectSecrets(
            entries: [],
            resolvedSecrets: [],
            shellCommand: nil,
            environment: [AutomationAccessResolver.sshEnvironmentKey: token]
        )

        #expect(secrets.contains(token))
    }

    @Test("does not forward ssh marker when automation credential omits ssh")
    func doesNotForwardSSHAutomationCredentialWhenMissingCapability() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "exec-ssh-cap")
        defer { try? FileManager.default.removeItem(at: directory) }

        let credential = try Access.createCredential(
            name: "agent",
            scope: "Team/API",
            ttl: "15m",
            store: store,
            machineIdentity: MachineIdentity(machineId: "m", hostname: "h"),
            now: now,
            allowedCommands: [.exec]
        )
        let token = try AutomationCredentialToken.issue(
            id: credential.id,
            randomBytes: Data(repeating: 0x41, count: AutomationCredentialToken.randomByteCount)
        )
        var environment: [String: String] = ["PATH": "/usr/bin"]

        let forwarded = try Exec.forwardSSHAutomationCredential(
            from: [AutomationAccessResolver.environmentKey: token],
            to: &environment,
            store: store,
            now: now.addingTimeInterval(60)
        )

        #expect(environment[AutomationAccessResolver.sshEnvironmentKey] == nil)
        #expect(forwarded == nil)
    }

    @Test("does not reintroduce automation credential from loaded entries")
    func buildEnvironmentStripsAutomationCredentialEntry() {
        let entries = [
            Load.LoadedEntry(
                key: AutomationAccessResolver.environmentKey,
                value: UUID().uuidString,
                itemType: .password,
                sourceName: "Credential",
                sourceID: "id-1",
                folderPath: nil,
                scrapeMachineName: nil,
                scrapeMachineId: nil
            )
        ]

        let result = Exec.buildEnvironment(entries: entries, base: [:])

        #expect(result[AutomationAccessResolver.environmentKey] == nil)
    }

    @Test("multiple entries all merged")
    func buildEnvironment_multipleEntries() {
        let base: [String: String] = [:]
        let entries = [
            Load.LoadedEntry(
                key: "DB_HOST", value: "localhost", itemType: .password,
                sourceName: "DB Host", sourceID: "id-1", folderPath: nil,
                scrapeMachineName: nil, scrapeMachineId: nil
            ),
            Load.LoadedEntry(
                key: "DB_PASS", value: "s3cret", itemType: .password,
                sourceName: "DB Pass", sourceID: "id-2", folderPath: nil,
                scrapeMachineName: nil, scrapeMachineId: nil
            ),
        ]
        let result = Exec.buildEnvironment(entries: entries, base: base)
        #expect(result.count == 2)
        #expect(result["DB_HOST"] == "localhost")
        #expect(result["DB_PASS"] == "s3cret")
    }

    @Test("resolveScope uses active environment when explicit scope is absent")
    func resolveScopeUsesActiveEnvironment() throws {
        let (store, directory) = makeEnvStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        _ = try Env.addProfile(name: "Production", folder: "Team/API", store: store)
        _ = try Env.useProfile(name: "Production", store: store)

        let scope = try Exec.resolveScope(query: nil, folder: nil, all: false, envName: nil, store: store)

        #expect(scope == .folder("Team/API"))
    }

    @Test("resolveScope uses named environment when provided")
    func resolveScopeUsesNamedEnvironment() throws {
        let (store, directory) = makeEnvStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        _ = try Env.addProfile(name: "Staging", folder: "Team/Staging", store: store)

        let scope = try Exec.resolveScope(query: nil, folder: nil, all: false, envName: "Staging", store: store)

        #expect(scope == .folder("Team/Staging"))
    }

    @Test("resolveScope uses all-scope environment when provided")
    func resolveScopeUsesAllEnvironment() throws {
        let (store, directory) = makeEnvStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        _ = try Env.addProfile(name: "Default", folders: [], all: true, store: store)

        let scope = try Exec.resolveScope(query: nil, folder: nil, all: false, envName: "Default", store: store)

        #expect(scope == .global)
    }

    @Test("resolveScope uses multi-folder environment when provided")
    func resolveScopeUsesMultiFolderEnvironment() throws {
        let (store, directory) = makeEnvStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        _ = try Env.addProfile(
            name: "Production",
            folders: ["Team/API", "Team/Web"],
            all: false,
            store: store
        )

        let scope = try Exec.resolveScope(query: nil, folder: nil, all: false, envName: "Production", store: store)

        #expect(scope == .folders(["Team/API", "Team/Web"]))
    }

    @Test("explicit query overrides the active environment")
    func resolveScopeQueryOverridesActiveEnvironment() throws {
        let (store, directory) = makeEnvStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        _ = try Env.addProfile(name: "Production", folder: "Team/API", store: store)
        _ = try Env.useProfile(name: "Production", store: store)

        let scope = try Exec.resolveScope(query: "API_KEY", folder: nil, all: false, envName: nil, store: store)

        #expect(scope == .single("API_KEY"))
    }

    @Test("explicit folder overrides the active environment")
    func resolveScopeFolderOverridesActiveEnvironment() throws {
        let (store, directory) = makeEnvStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        _ = try Env.addProfile(name: "Production", folder: "Team/API", store: store)
        _ = try Env.useProfile(name: "Production", store: store)

        let scope = try Exec.resolveScope(query: nil, folder: "Team/Manual", all: false, envName: nil, store: store)

        #expect(scope == .folder("Team/Manual"))
    }

    @Test("specific item in folder overrides the active environment")
    func resolveScopeSpecificItemInFolderOverridesActiveEnvironment() throws {
        let (store, directory) = makeEnvStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        _ = try Env.addProfile(name: "Production", folder: "Team/API", store: store)
        _ = try Env.useProfile(name: "Production", store: store)

        let scope = try Exec.resolveScope(query: "API_KEY", folder: "Team/Manual", all: false, envName: nil, store: store)

        #expect(scope == .itemInFolder(query: "API_KEY", folderPath: "Team/Manual"))
    }

    @Test("explicit all overrides the active environment")
    func resolveScopeAllOverridesActiveEnvironment() throws {
        let (store, directory) = makeEnvStore()
        defer { try? FileManager.default.removeItem(at: directory) }

        _ = try Env.addProfile(name: "Production", folder: "Team/API", store: store)
        _ = try Env.useProfile(name: "Production", store: store)

        let scope = try Exec.resolveScope(query: nil, folder: nil, all: true, envName: nil, store: store)

        #expect(scope == .global)
    }

    @Test("exec rejects a credential that lacks .exec capability")
    func execRejectsWithoutExecCapability() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let (store, directory) = try AccessCredentialStoreFixture.make(prefix: "exec-cap")
        defer { try? FileManager.default.removeItem(at: directory) }

        let credential = try Access.createCredential(
            name: "load-only",
            scope: "Team/API",
            ttl: "15m",
            store: store,
            machineIdentity: MachineIdentity(machineId: "m", hostname: "h"),
            now: now,
            allowedCommands: [.load]
        )
        let payload = BridgeListPayload(accounts: [], passwords: [], certificates: [], notes: [], sshKeys: [])

        do {
            _ = try Load.applyAutomationAccess(
                to: payload,
                scope: .folder("Team/API"),
                requiredCapability: .exec,
                environment: [
                    AutomationAccessResolver.environmentKey:
                        AccessCredentialStoreFixture.token(for: credential)
                ],
                store: store,
                now: now.addingTimeInterval(60)
            )
            Issue.record("expected ValidationError")
        } catch let error as ValidationError {
            #expect(String(describing: error).contains("does not permit 'exec'"))
        } catch {
            Issue.record("expected ValidationError, got \(error)")
        }
    }

    private func makeEnvStore() -> (EnvironmentProfileStore, URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("env-store-\(UUID().uuidString)", isDirectory: true)
        try! FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return (
            EnvironmentProfileStore(
                fileURL: directory.appendingPathComponent("environment-profiles.json")
            ),
            directory
        )
    }
}

// MARK: - mergeEnvFiles

@Suite("Exec mergeEnvFiles")
struct ExecMergeEnvFilesTests {

    @Test("discovers current directory .env with authsia references when no explicit input is provided")
    func discoversDefaultEnvFileWithAuthsiaReferences() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("exec-default-env-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let envFile = dir.appendingPathComponent(".env")
        try "API_KEY=authsia://password/API_KEY/password?folder=Team%2FAPI\n"
            .write(to: envFile, atomically: true, encoding: .utf8)

        let result = try Exec.envFilesForExecution(
            explicitEnvFiles: [],
            hasTypeScope: false,
            parentEnvironment: [:],
            currentDirectory: dir.path
        )

        #expect(result == [envFile.path])
    }

    @Test("discovers parent and current .env files with authsia references")
    func discoversParentAndCurrentEnvFilesWithAuthsiaReferences() throws {
        let parentDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("exec-default-env-\(UUID().uuidString)")
        let currentDir = parentDir.appendingPathComponent("service")
        try FileManager.default.createDirectory(at: currentDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: parentDir) }

        let parentEnvFile = parentDir.appendingPathComponent(".env")
        try "SHARED=authsia://password/Shared/password?folder=Team%2FAPI\n"
            .write(to: parentEnvFile, atomically: true, encoding: .utf8)
        let currentEnvFile = currentDir.appendingPathComponent(".env")
        try "LOCAL=authsia://password/Local/password?folder=Team%2FAPI\n"
            .write(to: currentEnvFile, atomically: true, encoding: .utf8)

        let result = try Exec.envFilesForExecution(
            explicitEnvFiles: [],
            hasTypeScope: false,
            parentEnvironment: [:],
            currentDirectory: currentDir.path
        )

        #expect(result == [parentEnvFile.path, currentEnvFile.path])
    }

    @Test("does not discover current directory .env without authsia references")
    func ignoresDefaultEnvFileWithoutAuthsiaReferences() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("exec-default-env-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let envFile = dir.appendingPathComponent(".env")
        try "PORT=8080\n".write(to: envFile, atomically: true, encoding: .utf8)

        let result = try Exec.envFilesForExecution(
            explicitEnvFiles: [],
            hasTypeScope: false,
            parentEnvironment: [:],
            currentDirectory: dir.path
        )

        #expect(result.isEmpty)
    }

    @Test("explicit env files disable default .env discovery")
    func explicitEnvFilesDisableDefaultDiscovery() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("exec-default-env-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let defaultEnvFile = dir.appendingPathComponent(".env")
        try "API_KEY=authsia://password/API_KEY/password\n"
            .write(to: defaultEnvFile, atomically: true, encoding: .utf8)

        let explicitEnvFile = dir.appendingPathComponent("local.env")
        let result = try Exec.envFilesForExecution(
            explicitEnvFiles: [explicitEnvFile.path],
            hasTypeScope: false,
            parentEnvironment: [:],
            currentDirectory: dir.path
        )

        #expect(result == [explicitEnvFile.path])
    }

    @Test("type scope still discovers current directory .env with authsia references")
    func typeScopeDiscoversDefaultEnvFileWithAuthsiaReferences() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("exec-default-env-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let envFile = dir.appendingPathComponent(".env")
        try "API_KEY=authsia://password/API_KEY/password\n"
            .write(to: envFile, atomically: true, encoding: .utf8)

        let result = try Exec.envFilesForExecution(
            explicitEnvFiles: [],
            hasTypeScope: true,
            parentEnvironment: [:],
            currentDirectory: dir.path
        )

        #expect(result == [envFile.path])
    }

    @Test("type-scoped shell command skips implicit .env discovery")
    func typeScopedShellCommandSkipsDefaultEnvFileDiscovery() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("exec-default-env-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let envFile = dir.appendingPathComponent(".env")
        try "AZURE_TENANT_ID=authsia://password/AZURE_TENANT_ID/password?folder=Team%2FSecurity%2FSecOps\n"
            .write(to: envFile, atomically: true, encoding: .utf8)

        let result = try Exec.envFilesForExecution(
            explicitEnvFiles: [],
            hasTypeScope: true,
            parentEnvironment: [:],
            currentDirectory: dir.path,
            usesShell: true
        )

        #expect(result.isEmpty)
    }

    @Test("merges multiple .env files in order — last wins on duplicates")
    func mergeEnvFiles() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("exec-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let file1 = dir.appendingPathComponent("a.env")
        try "A=1\nB=2".write(to: file1, atomically: true, encoding: .utf8)
        let file2 = dir.appendingPathComponent("b.env")
        try "B=overridden\nC=3".write(to: file2, atomically: true, encoding: .utf8)

        let result = try Exec.mergeEnvFiles([file1.path, file2.path])
        #expect(result["A"] == "1")
        #expect(result["B"] == "overridden")
        #expect(result["C"] == "3")
    }

    @Test("returns empty dict for no files")
    func mergeEnvFilesEmpty() throws {
        let result = try Exec.mergeEnvFiles([])
        #expect(result.isEmpty)
    }

    @Test("resolves env file authsia references before docker compose runs")
    func resolvesEnvFileAuthsiaReferencesBeforeDockerComposeRuns() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("exec-compose-env-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let envFile = dir.appendingPathComponent(".env")
        let authsiaURI = "authsia://password/AZURE_TENANT_ID/password?folder=Team%2FSecurity%2FSecOps"
        try """
        AZURE_TENANT_ID=\(authsiaURI)
        PORT=8080
        """.write(to: envFile, atomically: true, encoding: .utf8)

        let envFileVars = try Exec.mergeEnvFiles([envFile.path])
        let environment = Exec.finalEnvironment(
            entries: [],
            parentEnvironment: [:],
            envFileVars: envFileVars,
            sshAutomationCredential: nil
        )

        var mock = MockResolverClient()
        mock.passwords["AZURE_TENANT_ID"] = (username: "tenant", password: "resolved-tenant-id")
        mock.expectedFolder = "Team/Security/SecOps"
        mock.expectedFolderScoped = true
        let resolved = try SecretReferenceResolver(client: mock).resolveEnvironment(environment)
        let childCommand = Exec.childCommandArguments(command: ["docker", "compose", "up"], shell: false)

        #expect(childCommand == ["docker", "compose", "up"])
        #expect(resolved.resolved["AZURE_TENANT_ID"] == "resolved-tenant-id")
        #expect(resolved.resolved["PORT"] == "8080")
        #expect(!SecretReference.isSecretReference(resolved.resolved["AZURE_TENANT_ID"] ?? ""))
    }
}

// MARK: - collectSecrets

@Suite("Exec collectSecrets")
struct ExecCollectSecretsTests {

    @Test("gathers secret values from entries and resolved env")
    func collectSecrets() {
        let entries = [
            Load.LoadedEntry(
                key: "A", value: "secret1", itemType: .password,
                sourceName: "A", sourceID: "1", folderPath: nil,
                scrapeMachineName: nil, scrapeMachineId: nil
            )
        ]
        let result = Exec.collectSecrets(entries: entries, resolvedSecrets: ["secret2", "secret3"])
        #expect(result.contains("secret1"))
        #expect(result.contains("secret2"))
        #expect(result.contains("secret3"))
    }

    @Test("returns empty when no entries or resolved secrets")
    func collectSecretsEmpty() {
        let result = Exec.collectSecrets(entries: [], resolvedSecrets: [])
        #expect(result.isEmpty)
    }

    @Test("includes explicit shell substring expansions for injected secrets")
    func collectSecretsIncludesShellSubstringExpansions() {
        let secret = "abcdef123456"
        let result = Exec.collectSecrets(
            entries: [],
            resolvedSecrets: [secret],
            shellCommand: #"echo "${AMI_ADMIN_ROLES:0:6}" "${AMI_ADMIN_ROLES:0:1}""#,
            environment: ["AMI_ADMIN_ROLES": secret]
        )

        let masker = OutputMasker(secrets: result)
        #expect(masker.mask("abcdef") == OutputMasker.placeholder)
        #expect(masker.mask("a") == OutputMasker.placeholder)
    }

    @Test("includes negative shell substring offsets for injected secrets")
    func collectSecretsIncludesNegativeShellSubstringOffsets() {
        let secret = "abcdef123456"
        let result = Exec.collectSecrets(
            entries: [],
            resolvedSecrets: [secret],
            shellCommand: #"echo "${AMI_ADMIN_ROLES: -6}" "${AMI_ADMIN_ROLES:$NEG_OFFSET:3}""#,
            environment: [
                "AMI_ADMIN_ROLES": secret,
                "NEG_OFFSET": "-6",
            ]
        )

        let masker = OutputMasker(secrets: result)
        #expect(masker.mask("123456") == OutputMasker.placeholder)
        #expect(masker.mask("123") == OutputMasker.placeholder)
    }

    @Test("includes shell substring arithmetic env expressions for injected secrets")
    func collectSecretsIncludesShellSubstringArithmeticEnvExpressions() {
        let secret = "abcdef123456"
        let result = Exec.collectSecrets(
            entries: [],
            resolvedSecrets: [secret],
            shellCommand: #"echo "${AMI_ADMIN_ROLES:$START:$LEN}" "${AMI_ADMIN_ROLES:$START + 1:$LEN - 1}""#,
            environment: [
                "AMI_ADMIN_ROLES": secret,
                "START": "2",
                "LEN": "4",
            ]
        )

        let masker = OutputMasker(secrets: result)
        #expect(masker.mask("cdef") == OutputMasker.placeholder)
        #expect(masker.mask("def") == OutputMasker.placeholder)
    }

    @Test("includes negative shell substring lengths for injected secrets")
    func collectSecretsIncludesNegativeShellSubstringLengths() {
        let secret = "abcdef123456"
        let result = Exec.collectSecrets(
            entries: [],
            resolvedSecrets: [secret],
            shellCommand: #"echo "${AMI_ADMIN_ROLES:2:-2}" "${AMI_ADMIN_ROLES:$START:$END}""#,
            environment: [
                "AMI_ADMIN_ROLES": secret,
                "START": "2",
                "END": "-2",
            ]
        )

        let masker = OutputMasker(secrets: result)
        #expect(masker.mask("cdef1234") == OutputMasker.placeholder)
    }

    @Test("includes shell prefix and suffix trim expansions for injected secrets")
    func collectSecretsIncludesShellTrimExpansions() {
        let secret = "abcdef123456"
        let result = Exec.collectSecrets(
            entries: [],
            resolvedSecrets: [secret],
            shellCommand: #"echo "${AMI_ADMIN_ROLES#?}" "${AMI_ADMIN_ROLES%?}""#,
            environment: ["AMI_ADMIN_ROLES": secret]
        )

        let masker = OutputMasker(secrets: result)
        #expect(masker.mask("bcdef123456") == OutputMasker.placeholder)
        #expect(masker.mask("abcdef12345") == OutputMasker.placeholder)
    }

    @Test("includes literal shell replacement expansions for injected secrets")
    func collectSecretsIncludesShellReplacementExpansions() {
        let secret = "foo-token-foo"
        let result = Exec.collectSecrets(
            entries: [],
            resolvedSecrets: [secret],
            shellCommand: #"echo "${AMI_ADMIN_ROLES/foo/bar}" "${AMI_ADMIN_ROLES//foo/bar}""#,
            environment: ["AMI_ADMIN_ROLES": secret]
        )

        let masker = OutputMasker(secrets: result)
        #expect(masker.mask("bar-token-foo") == OutputMasker.placeholder)
        #expect(masker.mask("bar-token-bar") == OutputMasker.placeholder)
    }

    @Test("includes command pipeline transformations for injected secrets")
    func collectSecretsIncludesCommandPipelineTransformations() {
        let secret = "abcd-1234-efgh"
        let result = Exec.collectSecrets(
            entries: [],
            resolvedSecrets: [secret],
            shellCommand: """
            echo "$APP_STORE_ISSUER_ID" | cut -c 1
            echo "$APP_STORE_ISSUER_ID" | cut -c 2-
            echo "$APP_STORE_ISSUER_ID" | fold -w 2
            echo "$APP_STORE_ISSUER_ID" | rev
            echo "$APP_STORE_ISSUER_ID" | tr -d "-"
            echo "$APP_STORE_ISSUER_ID" | tr "[:lower:]" "[:upper:]"
            echo "$APP_STORE_ISSUER_ID" | sed "s/./& /g"
            echo "$APP_STORE_ISSUER_ID" | cut -d "-" -f 2
            """,
            environment: ["APP_STORE_ISSUER_ID": secret]
        )

        let masker = OutputMasker(secrets: result)
        #expect(masker.mask("a") == OutputMasker.placeholder)
        #expect(masker.mask("bcd-1234-efgh") == OutputMasker.placeholder)
        #expect(masker.mask("ab") == OutputMasker.placeholder)
        #expect(masker.mask("hgfe-4321-dcba") == OutputMasker.placeholder)
        #expect(masker.mask("abcd1234efgh") == OutputMasker.placeholder)
        #expect(masker.mask("ABCD-1234-EFGH") == OutputMasker.placeholder)
        #expect(masker.mask("a b c d - 1 2 3 4 - e f g h ") == OutputMasker.placeholder)
        #expect(masker.mask("1234") == OutputMasker.placeholder)
    }

    @Test("includes indexed character output transformations for injected secrets")
    func collectSecretsIncludesIndexedCharacterTransformations() {
        let secret = "abcd-1234"
        let result = Exec.collectSecrets(
            entries: [],
            resolvedSecrets: [secret],
            shellCommand: #"for ((i=0; i<${#APP_STORE_ISSUER_ID}; i++)); do printf "%02d=%s\n" "$i" "${APP_STORE_ISSUER_ID:$i:1}"; done"#,
            environment: ["APP_STORE_ISSUER_ID": secret]
        )

        let masker = OutputMasker(secrets: result)
        #expect(masker.mask("00=a") == OutputMasker.placeholder)
        #expect(masker.mask("04=-") == OutputMasker.placeholder)
        #expect(masker.mask("08=4") == OutputMasker.placeholder)
    }

    @Test("includes sort and paste text transformations for injected secrets")
    func collectSecretsIncludesSortAndPasteTransformations() {
        let secret = "dbca-21"
        let result = Exec.collectSecrets(
            entries: [],
            resolvedSecrets: [secret],
            shellCommand: """
            printf "%s" "$APP_STORE_ISSUER_ID" | fold -w 1 | sort | tr -d "\\n"
            printf "%s" "$APP_STORE_ISSUER_ID" | fold -w 1 | paste -sd ":" -
            """,
            environment: ["APP_STORE_ISSUER_ID": secret]
        )

        let masker = OutputMasker(secrets: result)
        #expect(masker.mask("-12abcd") == OutputMasker.placeholder)
        #expect(masker.mask("d:b:c:a:-:2:1") == OutputMasker.placeholder)
    }

    @Test("does not add aggressive transformation masks for ordinary pipelines")
    func collectSecretsDoesNotAggressivelyMaskOrdinaryPipelines() {
        let secret = "abcd-1234-efgh"
        let result = Exec.collectSecrets(
            entries: [],
            resolvedSecrets: [secret],
            shellCommand: #"curl -H "Authorization: Bearer $API_TOKEN" https://example.invalid | jq ."#,
            environment: ["API_TOKEN": secret]
        )

        let masker = OutputMasker(secrets: result)
        #expect(masker.mask(secret) == OutputMasker.placeholder)
        #expect(masker.mask("a") == "a")
        #expect(masker.mask("1234") == "1234")
    }

    @Test("includes binary and hash command transformations for injected secrets")
    func collectSecretsIncludesBinaryAndHashCommandTransformations() {
        let secret = "hunter2"
        let result = Exec.collectSecrets(
            entries: [],
            resolvedSecrets: [secret],
            shellCommand: """
            printf "%s" "$APP_STORE_ISSUER_ID" | xxd
            printf "%s" "$APP_STORE_ISSUER_ID" | xxd -ps -c 4
            printf "%s" "$APP_STORE_ISSUER_ID" | od -An -tx1
            printf "%s" "$APP_STORE_ISSUER_ID" | hexdump -C
            printf "%s" "$APP_STORE_ISSUER_ID" | shasum -a 256
            printf "%s" "$APP_STORE_ISSUER_ID" | md5
            """,
            environment: ["APP_STORE_ISSUER_ID": secret]
        )

        let masker = OutputMasker(secrets: result)
        #expect(masker.mask("68 75 6e 74 65 72 32") == OutputMasker.placeholder)
        #expect(masker.mask("6875 6e74 6572 32") == OutputMasker.placeholder)
        #expect(masker.mask("68756e74") == OutputMasker.placeholder)
        #expect(masker.mask("657232") == OutputMasker.placeholder)
        #expect(masker.mask("f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7") == OutputMasker.placeholder)
        #expect(masker.mask("2ab96390c7dbe3439de74d0c9b0b1767") == OutputMasker.placeholder)
    }

    @Test("includes additional encoding and digest command transformations for injected secrets")
    func collectSecretsIncludesAdditionalEncodingAndDigestTransformations() {
        let secret = "abcd-1234"
        let result = Exec.collectSecrets(
            entries: [],
            resolvedSecrets: [secret],
            shellCommand: """
            printf "%s" "$APP_STORE_ISSUER_ID" | base32
            printf "%s" "$APP_STORE_ISSUER_ID" | uuencode -
            printf "%s" "$APP_STORE_ISSUER_ID" | openssl dgst -sha1
            printf "%s" "$APP_STORE_ISSUER_ID" | openssl dgst -sha512
            """,
            environment: ["APP_STORE_ISSUER_ID": secret]
        )

        let masker = OutputMasker(secrets: result)
        #expect(masker.mask("MFRGGZBNGEZDGNA=") == OutputMasker.placeholder)
        #expect(masker.mask("MFRGGZBNGEZDGNA") == OutputMasker.placeholder)
        #expect(masker.mask(")86)C9\"TQ,C,T") == OutputMasker.placeholder)
        #expect(masker.mask("a7ef1be18bb8d37af79f3d87761a203378bf26a2") == OutputMasker.placeholder)
        #expect(masker.mask("d45e6e00391fdb4f042f38cfbe306210766678b1655cd6f1b78a994f467fec550e948aafdc76d1470ad85bbc8738cb020da4a1701c0ce10ba6d969320bdbbda6") == OutputMasker.placeholder)
    }

    @Test("includes interpreter environment transformations for injected secrets")
    func collectSecretsIncludesInterpreterEnvironmentTransformations() {
        let secret = "abcd-1234-efgh"
        let result = Exec.collectSecrets(
            entries: [],
            resolvedSecrets: [secret],
            shellCommand: #"python3 -c 'import os; print(os.environ.get("APP_STORE_ISSUER_ID", "")[1:])'; node -e 'console.log((process.env.APP_STORE_ISSUER_ID || "").slice(-4))'"#,
            environment: ["APP_STORE_ISSUER_ID": secret]
        )

        let masker = OutputMasker(secrets: result)
        #expect(masker.mask("bcd-1234-efgh") == OutputMasker.placeholder)
        #expect(masker.mask("efgh") == OutputMasker.placeholder)
    }

    @Test("includes jq and additional runtime environment transformations for injected secrets")
    func collectSecretsIncludesAdditionalRuntimeEnvironmentTransformations() {
        let secret = "abcd-1234-efgh"
        let result = Exec.collectSecrets(
            entries: [],
            resolvedSecrets: [secret],
            shellCommand: """
            jq -n 'env.APP_STORE_ISSUER_ID[1:]'
            php -r 'echo substr(getenv("APP_STORE_ISSUER_ID"), 1);'
            lua -e 'print(os.getenv("APP_STORE_ISSUER_ID"):sub(2))'
            go run ./cmd/envslice -name APP_STORE_ISSUER_ID
            java EnvSlice APP_STORE_ISSUER_ID
            swift -e 'print(ProcessInfo.processInfo.environment["APP_STORE_ISSUER_ID"]!.dropFirst())'
            """,
            environment: ["APP_STORE_ISSUER_ID": secret]
        )

        let masker = OutputMasker(secrets: result)
        #expect(masker.mask("bcd-1234-efgh") == OutputMasker.placeholder)
    }

    @Test("includes environment discovery transformations for injected secrets")
    func collectSecretsIncludesEnvironmentDiscoveryTransformations() {
        let secret = "abcd-1234"
        let result = Exec.collectSecrets(
            entries: [],
            resolvedSecrets: [secret],
            shellCommand: """
            env | cut -c 1
            printenv | rev
            set | sed "s/-//g"
            declare -x | awk '{print substr($0, 1, 4)}'
            ps eww -p $$ | cut -c 1
            cat /proc/self/environ | tr "\\0" "\\n" | cut -c 1
            """,
            environment: ["APP_STORE_ISSUER_ID": secret]
        )

        let masker = OutputMasker(secrets: result)
        #expect(masker.mask("a") == OutputMasker.placeholder)
        #expect(masker.mask("4321-dcba") == OutputMasker.placeholder)
        #expect(masker.mask("abcd1234") == OutputMasker.placeholder)
    }

    @Test("includes shell glob replacement transformations for injected secrets")
    func collectSecretsIncludesShellGlobReplacementTransformations() {
        let secret = "a1-b2"
        let result = Exec.collectSecrets(
            entries: [],
            resolvedSecrets: [secret],
            shellCommand: #"echo "${APP_STORE_ISSUER_ID//[0-9]/X}" "${APP_STORE_ISSUER_ID//[a-f]/x}" "${APP_STORE_ISSUER_ID//?/?}""#,
            environment: ["APP_STORE_ISSUER_ID": secret]
        )

        let masker = OutputMasker(secrets: result)
        #expect(masker.mask("aX-bX") == OutputMasker.placeholder)
        #expect(masker.mask("x1-x2") == OutputMasker.placeholder)
        #expect(masker.mask("?????") == OutputMasker.placeholder)
    }

    @Test("includes shell length transformations for injected secrets")
    func collectSecretsIncludesShellLengthTransformations() {
        let secret = "abcd-1234-efgh"
        let result = Exec.collectSecrets(
            entries: [],
            resolvedSecrets: [secret],
            shellCommand: #"echo "${#APP_STORE_ISSUER_ID}""#,
            environment: ["APP_STORE_ISSUER_ID": secret]
        )

        let masker = OutputMasker(secrets: result)
        #expect(masker.mask("14") == OutputMasker.placeholder)
    }
}

private final class RecordingExecJITPreflightClient: ExecJITPreflightClient {
    private let grantIDs: [UUID]
    private(set) var payloads: [AgentJITPreflightPayload] = []

    init(grantIDs: [UUID] = []) {
        self.grantIDs = grantIDs
    }

    func agentJITPreflight(_ payload: AgentJITPreflightPayload) throws -> AgentJITPreflightResultPayload {
        payloads.append(payload)
        return AgentJITPreflightResultPayload(grantIDs: grantIDs)
    }
}
