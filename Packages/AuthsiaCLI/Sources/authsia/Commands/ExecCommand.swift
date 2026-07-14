import Foundation
import CryptoKit
import Darwin
import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore

protocol ExecJITPreflightClient {
    func agentJITPreflight(_ payload: AgentJITPreflightPayload) throws -> AgentJITPreflightResultPayload
}

extension AuthsiaBridgeClient: ExecJITPreflightClient {}

struct Exec: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "exec",
        abstract: "Run a command with vault secrets injected into its environment",
        discussion: """
            Fetches secrets from Authsia and injects them as environment variables
            ONLY into the target command's process. Secrets are masked in stdout/stderr
            by default to prevent leaking into logs.

            Use '--' to separate authsia flags from the command to run.

            Scope selection (use when loading secrets by type):
              - individual item: api-key Stripe
              - individual item: password DB_PASSWORD
              - item in exact folder: api-key API_KEY --folder Team/API
              - folder scope: password --folder Team/API
              - global by type: password --all
              - environment profile: password --env Production (all or one/more folders)
            Bare --folder loads the whole folder tree, including nested folders.

            Secret references in env vars (authsia://type/item/field) are automatically
            resolved. Combine with --env-file for committable .env files.
            When no --env-file or parent env reference is provided, a current-directory
            .env file containing authsia:// references is loaded automatically.
            Type-scoped --shell commands skip implicit .env discovery; pass --env-file
            when a shell command should also load env-file references.
            To use injected env vars in child command arguments, pass a quoted
            command string to --shell.
            A bare --shell curl $DemoKey still expands in the parent shell before
            Authsia injects secrets.
            For Git/SSH, use Authsia shell integration and run git or ssh directly.

            Examples:
              authsia exec api-key Stripe -- npm start
              authsia exec password DB_PASSWORD -- npm start
              authsia exec api-key API_KEY --folder Team/API -- npm start
              authsia exec password --folder Team/API -- npm start
              authsia exec password --folder Team/API/Prod -- npm start
              authsia exec password --env Production -- npm start
              authsia exec password --all -- npm start
              authsia exec -- npm start
              authsia exec --type api-key --query API_KEY -- npm start
              authsia exec password --folder Team/API -- docker compose up
              authsia exec --env-file prod.env -- npm start
              authsia exec password --folder Team/API --shell 'curl "$DemoKey"'
              API=authsia://api-key/API/key?folder=Team/API authsia exec -- env
              authsia exec password --folder CI --env-file prod.env -- ./app
            """
    )

    enum ItemType: String, ExpressibleByArgument, CaseIterable {
        case password
        case apiKey = "api-key"
        case cert
        case note

        static var allValueStrings: [String] { allCases.map(\.rawValue) }

        var loadType: Load.ItemType {
            switch self {
            case .password:
                return .password
            case .apiKey:
                return .apiKey
            case .cert:
                return .cert
            case .note:
                return .note
            }
        }
    }

    enum Field: String, ExpressibleByArgument, CaseIterable {
        case username
        case password
        case key
        case certificate
        case privateKey
        case content

        static var allValueStrings: [String] { allCases.map(\.rawValue) }

        var loadField: Load.Field {
            switch self {
            case .username:
                return .username
            case .password:
                return .password
            case .key:
                return .key
            case .certificate:
                return .certificate
            case .privateKey:
                return .privateKey
            case .content:
                return .content
            }
        }
    }

    @Argument(help: "Item type: password, api-key, cert, note")
    var type: ItemType?

    @Argument(help: "Item name/ID query (for individual load)", completion: .custom(ShellCompletionMetadata.completeItems))
    var query: String?

    @Option(name: [.customShort("t"), .customLong("type")], help: "Item type: password, api-key, cert, note (legacy form)")
    var typeOption: ItemType?

    @Option(
        name: .customLong("query"),
        help: "Item name/ID query (for individual load)",
        completion: .custom(ShellCompletionMetadata.completeItems)
    )
    var queryOption: String?

    var resolvedType: ItemType? {
        type ?? typeOption
    }

    var resolvedQuery: String? {
        query ?? queryOption
    }

    @Option(
        name: .shortAndLong,
        help: "With <query>, match the exact folder; without a query, load this folder tree",
        completion: .custom(ShellCompletionMetadata.completeFolders)
    )
    var folder: String?

    @Option(name: .long, help: "Environment profile name to use when no explicit scope is provided")
    var env: String?

    @Flag(name: .long, help: "Load all items of the given type")
    var all = false

    @Flag(name: .long, help: "Include scraped items from all machines (default: current machine only)")
    var allMachines = false

    @Option(
        name: .long,
        help: "Field to load (defaults: password/certificate/content)",
        completion: .custom(ShellCompletionMetadata.completeExecFields)
    )
    var field: Field?

    @Option(name: .long, help: "Load env vars from a .env file (repeatable)")
    var envFile: [String] = []

    @Option(
        name: .customLong("shell"),
        parsing: .remaining,
        help: "Run a quoted child command string through /bin/sh -c"
    )
    var shellCommandParts: [String] = []

    @Argument(parsing: .postTerminator)
    var commandArgs: [String] = []

    var environmentOverrides: [String: String] = [:]
    var environmentScope: EnvironmentAccessScope?

    var shellCommand: String? {
        let parts = Self.normalizedShellCommandParts(shellCommandParts)
        guard !parts.isEmpty else { return nil }
        return parts.joined(separator: " ")
    }

    var usesShell: Bool {
        shellCommand != nil
    }

    var resolvedCommandArgs: [String] {
        if let shellCommand {
            return [shellCommand]
        }
        return commandArgs
    }

    func run() throws {
        try Self.validateCommand(resolvedCommandArgs)
        try Self.validateInvocation(
            positionalType: type,
            typeOption: typeOption,
            positionalQuery: query,
            queryOption: queryOption
        )

        let parentEnvironment = ProcessInfo.processInfo.environment.merging(environmentOverrides) { _, override in
            override
        }
        let resolvedType = resolvedType
        let resolvedQuery = resolvedQuery
        let hasTypeScope = resolvedType != nil || resolvedQuery != nil || folder != nil || all || env != nil
        if let type = resolvedType {
            try Self.validateExecType(type.loadType)
        }
        let executionEnvFiles = try Self.envFilesForExecution(
            explicitEnvFiles: envFile,
            hasTypeScope: hasTypeScope,
            parentEnvironment: parentEnvironment,
            usesShell: usesShell
        )
        if !Self.hasSecretInput(
            hasTypeScope: hasTypeScope,
            envFileCount: executionEnvFiles.count,
            environment: parentEnvironment
        ) {
            guard try Self.allowsCredentialOnlyExecForSSH() else {
                throw CLIError.unsupported(
                    message: "Provide a type with scope (--query/--folder/--all/--env), --env-file, " +
                        "or an environment variable containing an authsia:// reference.\n" +
                        "  For Git/SSH-only wrapping, set an automation credential that permits 'ssh'."
                ).asValidationError
            }
        }
        // Scope flags without a type are silently ignored — catch and diagnose explicitly.
        if hasTypeScope && resolvedType == nil {
            throw CLIError.unsupported(
                message: "Scope flags (--query/--folder/--all/--env) require an item type.\n" +
                    "  Example: authsia exec password MyKey -- ./app"
            ).asValidationError
        }

        let effectiveEnvironmentScope: EnvironmentAccessScope? = if environmentScope != nil {
            environmentScope
        } else if resolvedType != nil && hasTypeScope {
            try Load.environmentScope(query: resolvedQuery, folder: folder, all: all, envName: env)
        } else {
            nil
        }

        try AuthsiaBridgeClient.shared.withRequestedCommand(.exec) {
            // Phase 1: Load by type+scope (existing behavior)
            var entries: [Load.LoadedEntry] = []
            if let type = resolvedType, hasTypeScope {
                let loadType = type.loadType
                let scope = try Self.resolveScope(
                    query: resolvedQuery,
                    folder: folder,
                    all: all,
                    envName: env
                )
                let client: LoadVaultClient = AuthsiaBridgeClient.shared
                let initialReferences = try Self.initialJITPreflightReferences(
                    type: loadType,
                    scope: scope,
                    field: field?.loadField
                )
                if !initialReferences.isEmpty {
                    try Self.runJITPreflight(
                        references: initialReferences,
                        parentEnvironment: parentEnvironment,
                        environmentScope: effectiveEnvironmentScope
                    )
                }
                let authorizedPayload = try Load.applyAutomationAccess(
                    to: try client.list(),
                    scope: scope,
                    requiredCapability: .exec
                )
                let payload = Load.applyEnvironmentScope(effectiveEnvironmentScope, to: authorizedPayload)
                let currentMachineId = MachineIdentity.load().machineId
                let references = try Load.selectReferences(
                    type: loadType,
                    scope: scope,
                    payload: payload,
                    allMachines: allMachines,
                    currentMachineId: currentMachineId
                )
                try Self.runJITPreflight(
                    type: loadType,
                    references: references,
                    field: field?.loadField,
                    parentEnvironment: parentEnvironment,
                    environmentScope: effectiveEnvironmentScope
                )
                entries = try Load.loadEntries(
                    type: loadType,
                    references: references,
                    field: field?.loadField,
                    client: client
                )
                try Load.validateUniqueKeys(entries)
            }

            // Phase 2: Merge .env files (last file wins on duplicates)
            let envFileVars = try Self.mergeEnvFiles(executionEnvFiles)
            let sshAutomationCredential = try Self.sshAutomationCredential(from: parentEnvironment)

            // Phase 3: Build child env + type-loaded secrets, preserving .env override behavior.
            var environment = Self.finalEnvironment(
                entries: entries,
                parentEnvironment: parentEnvironment,
                envFileVars: envFileVars,
                sshAutomationCredential: sshAutomationCredential
            )

            // Phase 4: Preflight caller/env-file authsia:// references without scanning loaded plaintext entries.
            let preflightEnvironment = Self.jitEnvPreflightEnvironment(from: environment, excluding: entries)
            try Self.rejectUnsupportedAgentJITReferences(
                environment: preflightEnvironment,
                parentEnvironment: parentEnvironment
            )
            try Self.runJITPreflight(
                references: SecretReferenceResolver.preflightReferences(
                    environment: preflightEnvironment
                ),
                parentEnvironment: parentEnvironment,
                environmentScope: effectiveEnvironmentScope
            )

            // Phase 5: Resolve any authsia:// references in the environment
            let resolver = SecretReferenceResolver(client: AuthsiaBridgeClient.shared)
            let resolved = try resolver.resolveEnvironment(environment)
            environment = resolved.resolved

            let childCommand = Self.childCommandArguments(command: resolvedCommandArgs, shell: usesShell)

            // Phase 6: Collect all secret values for masking
            let allSecrets = Self.collectSecrets(
                entries: entries,
                resolvedSecrets: resolved.secrets,
                shellCommand: usesShell ? childCommand.last : nil,
                environment: environment
            )

            // Phase 7: Spawn child process with output masking
            let masker = OutputMasker(secrets: allSecrets)
            let exitCode = Self.runChildProcess(
                command: childCommand,
                environment: environment,
                masker: masker,
                sshAutomationCredential: sshAutomationCredential
            )
            Darwin.exit(exitCode)
        }
    }

    // MARK: - Validation (static, testable)

    static func validateInvocation(
        positionalType: ItemType?,
        typeOption: ItemType?,
        positionalQuery: String?,
        queryOption: String?
    ) throws {
        if positionalType != nil && typeOption != nil {
            throw CLIError.unsupported(
                message: "Use either positional <type> or --type, not both. " +
                    "Example: authsia exec password --query API_KEY -- <command>"
            ).asValidationError
        }
        if positionalQuery != nil && queryOption != nil {
            throw CLIError.unsupported(
                message: "Use either positional <query> or --query, not both. " +
                    "Example: authsia exec api-key API_KEY -- <command>"
            ).asValidationError
        }
    }

    static func validateExecType(_ type: Load.ItemType) throws {
        guard type != .ssh else {
            throw CLIError.unsupported(
                message: "exec does not support SSH keys. Use `authsia load ssh <name-or-id>` " +
                    "to add keys to ssh-agent instead."
            ).asValidationError
        }
    }

    static func resolveScope(
        query: String?,
        folder: String?,
        all: Bool,
        envName: String?,
        store: EnvironmentProfileStore = EnvironmentProfileStore()
    ) throws -> Load.ScopeSelection {
        try Load.resolveScope(query: query, folder: folder, all: all, envName: envName, store: store)
    }

    static func validateCommand(_ args: [String]) throws {
        guard !args.isEmpty else {
            throw CLIError.unsupported(
                message: "No command specified. Use '--' to separate authsia flags from the command.\n" +
                    "  Example: authsia exec password --all -- npm start"
            ).asValidationError
        }
    }

    static func childCommandArguments(command: [String], shell: Bool) -> [String] {
        guard shell else { return command }
        return ["/bin/sh", "-c", command.joined(separator: " ")]
    }

    static func normalizedShellCommandParts(_ parts: [String]) -> [String] {
        guard parts.first == "--" else { return parts }
        return Array(parts.dropFirst())
    }

    static func hasSecretInput(
        hasTypeScope: Bool,
        envFileCount: Int,
        environment: [String: String]
    ) -> Bool {
        hasTypeScope || envFileCount > 0 || environment.values.contains(where: SecretReference.isSecretReference)
    }

    static func allowsCredentialOnlyExecForSSH(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        store: AccessCredentialStore = AccessCredentialStore(),
        now: Date = Date()
    ) throws -> Bool {
        guard let credential = try AutomationAccessResolver.resolveActiveCredential(
            environment: environment,
            store: store,
            now: now
        ) else {
            return false
        }
        return credential.allowedCommands.contains(.ssh)
    }

    static func shouldRunJITPreflight(
        environment: [String: String],
        processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry(),
        stdinIsTTY: Bool = TerminalContext.stdinIsTTY
    ) -> Bool {
        guard environment[AutomationAccessResolver.environmentKey] == nil else {
            return false
        }
        // A confirmed agent marker always forces preflight, even at a human terminal.
        if AgentRuntimeContextResolver.hasExplicitAgentInvocationMarker(environment: environment) {
            return true
        }
        let hasAgenticAncestry = AgenticProcessDetector.containsAgenticProcess(processAncestry)
            || AgenticProcessDetector.containsAutomationSuspectProcess(processAncestry)
        guard hasAgenticAncestry else { return false }
        // An IDE/agent in the ancestry may be where a human developer sits. Only preflight
        // ancestry-only invocations when stdin is not a TTY; redirected stdout does not change
        // whether the human can complete the ordinary biometric/session approval flow.
        return !stdinIsTTY
    }

    static func jitPreflightReferences(
        type: Load.ItemType,
        references: [Load.ItemReference],
        field: Load.Field? = nil
    ) throws -> [AgentJITPreflightReference] {
        try Load.validateField(for: type, field: field)
        return references.map {
            AgentJITPreflightReference(
                type: type.rawValue,
                query: $0.id,
                folderPath: normalizeFolderPath($0.folderPath)
            )
        }
    }

    static func initialJITPreflightReference(
        type: Load.ItemType,
        scope: Load.ScopeSelection,
        field: Load.Field? = nil
    ) throws -> AgentJITPreflightReference? {
        try initialJITPreflightReferences(type: type, scope: scope, field: field).first
    }

    static func initialJITPreflightReferences(
        type: Load.ItemType,
        scope: Load.ScopeSelection,
        field: Load.Field? = nil
    ) throws -> [AgentJITPreflightReference] {
        try Load.validateField(for: type, field: field)
        switch scope {
        case .single(let query):
            return [AgentJITPreflightReference(
                type: type.rawValue,
                query: query,
                folderPath: nil,
                isFolderScoped: false
            )]
        case .itemInFolder(let query, let folderPath):
            return [AgentJITPreflightReference(
                type: type.rawValue,
                query: query,
                folderPath: normalizeFolderPath(folderPath),
                isFolderScoped: true
            )]
        case .folder(let folderPath):
            return [AgentJITPreflightReference(
                type: type.rawValue,
                query: "",
                folderPath: normalizeFolderPath(folderPath),
                isFolderScoped: true
            )]
        case .folders(let folderPaths):
            return folderPaths.map {
                AgentJITPreflightReference(
                    type: type.rawValue,
                    query: "",
                    folderPath: normalizeFolderPath($0),
                    isFolderScoped: true
                )
            }
        case .global:
            return [AgentJITPreflightReference(
                type: type.rawValue,
                query: "",
                folderPath: nil,
                isFolderScoped: false
            )]
        }
    }

    static func rejectUnsupportedAgentJITReferences(
        environment: [String: String],
        parentEnvironment: [String: String],
        processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry()
    ) throws {
        guard shouldRunJITPreflight(environment: parentEnvironment, processAncestry: processAncestry) else {
            return
        }
        let unsupported = try SecretReferenceResolver.unsupportedAgentJITReferences(environment: environment)
        guard !unsupported.isEmpty else { return }
        let types = Array(Set(unsupported.map(\.type.rawValue))).sorted().joined(separator: ", ")
        throw CLIError.unsupported(
            message: "Agent exec JIT does not support \(types) authsia:// references. Use password, api-key, cert, or note references."
        )
    }

    static func runJITPreflight(
        type: Load.ItemType,
        references: [Load.ItemReference],
        field: Load.Field?,
        parentEnvironment: [String: String],
        environmentScope: EnvironmentAccessScope? = nil,
        processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry(),
        client: ExecJITPreflightClient = AuthsiaBridgeClient.shared
    ) throws {
        try runJITPreflight(
            references: try jitPreflightReferences(type: type, references: references, field: field),
            parentEnvironment: parentEnvironment,
            environmentScope: environmentScope,
            processAncestry: processAncestry,
            client: client
        )
    }

    static func runJITPreflight(
        references: [AgentJITPreflightReference],
        parentEnvironment: [String: String],
        environmentScope: EnvironmentAccessScope? = nil,
        processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry(),
        client: ExecJITPreflightClient = AuthsiaBridgeClient.shared,
        commandHistoryStore: AgentCommandHistoryStore = AgentCommandHistoryStore(),
        now: Date = Date(),
        currentDirectoryPath: String = FileManager.default.currentDirectoryPath,
        terminalSessionScope: String? = TerminalSessionScope.currentAncestralScope(),
        commandLine: [String] = CommandLine.arguments
    ) throws {
        guard shouldRunJITPreflight(environment: parentEnvironment, processAncestry: processAncestry),
              !references.isEmpty else { return }
        recordAgentCommandHistory(
            parentEnvironment: parentEnvironment,
            processAncestry: processAncestry,
            store: commandHistoryStore,
            now: now,
            currentDirectoryPath: currentDirectoryPath,
            terminalSessionScope: terminalSessionScope,
            commandLine: commandLine
        )
        _ = try client.agentJITPreflight(
            AgentJITPreflightPayload(
                requestedCommand: "exec",
                references: references,
                environmentScope: environmentScope
            )
        )
    }

    private static func recordAgentCommandHistory(
        parentEnvironment: [String: String],
        processAncestry: [AgenticProcessReference],
        store: AgentCommandHistoryStore,
        now: Date,
        currentDirectoryPath: String,
        terminalSessionScope: String?,
        commandLine: [String]
    ) {
        let context = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: currentDirectoryPath,
            processAncestry: processAncestry,
            environment: parentEnvironment
        )
        let command = commandLine.isEmpty ? nil : commandLine.joined(separator: " ")
        let executable = commandLine.first.map { URL(fileURLWithPath: $0).lastPathComponent }
        let event = AgentCommandEvent(
            recordedAt: now,
            agentPlatform: context?.platform,
            sessionID: context?.sessionID,
            turnID: context?.turnID,
            agentID: context?.agentID,
            agentType: context?.agentType,
            toolUseID: context?.toolUseID,
            captureSource: .process,
            contextExpiresAt: now.addingTimeInterval(60 * 60),
            workingDirectory: currentDirectoryPath,
            terminalSessionScope: terminalSessionScope,
            executable: executable,
            arguments: commandLine,
            command: command,
            exitStatus: nil
        )
        try? store.record(event)
    }

    static func jitEnvPreflightEnvironment(
        from finalEnvironment: [String: String],
        excluding entries: [Load.LoadedEntry]
    ) -> [String: String] {
        var environment = finalEnvironment
        for entry in entries where environment[entry.key] == entry.value {
            environment.removeValue(forKey: entry.key)
        }
        return environment
    }

    static func finalEnvironment(
        entries: [Load.LoadedEntry],
        parentEnvironment: [String: String],
        envFileVars: [String: String],
        sshAutomationCredential: AccessCredential?
    ) -> [String: String] {
        var environment = buildEnvironment(entries: entries, base: parentEnvironment)
        for (key, value) in envFileVars {
            environment[key] = value
        }
        removeAutomationCredentials(from: &environment)
        removeGuardedTerminalShim(from: &environment)
        if let sshAutomationCredential {
            environment[AutomationAccessResolver.sshEnvironmentKey] = sshAutomationCredential.id.uuidString
        }
        return environment
    }

    // MARK: - Environment building (static, testable)

    static func buildEnvironment(
        entries: [Load.LoadedEntry],
        base: [String: String]
    ) -> [String: String] {
        var env = base
        for entry in entries {
            env[entry.key] = entry.value
        }
        removeAutomationCredential(from: &env)
        return env
    }

    static func removeAutomationCredential(from environment: inout [String: String]) {
        removeAutomationCredentials(from: &environment)
    }

    static func removeAutomationCredentials(from environment: inout [String: String]) {
        environment.removeValue(forKey: AutomationAccessResolver.environmentKey)
        environment.removeValue(forKey: AutomationAccessResolver.sshEnvironmentKey)
    }

    static func removeGuardedTerminalShim(from environment: inout [String: String]) {
        let shimDirectory = environment["AUTHSIA_WORKSPACE_GUARD_SHIM_DIR"]
        if let shimDirectory, !shimDirectory.isEmpty, let path = environment["PATH"] {
            let entries = path.split(separator: ":", omittingEmptySubsequences: false)
                .map(String.init)
                .filter { $0 != shimDirectory }
            environment["PATH"] = entries.joined(separator: ":")
        }
        environment.removeValue(forKey: "AUTHSIA_WORKSPACE_GUARD")
        environment.removeValue(forKey: "AUTHSIA_WORKSPACE_GUARD_SHIM_DIR")
        environment.removeValue(forKey: "AUTHSIA_WORKSPACE_ROOT")
        environment.removeValue(forKey: WorkspaceGuardedTerminal.shimInvocationEnvironmentName)
    }

    static func envFilesForExecution(
        explicitEnvFiles: [String],
        hasTypeScope: Bool,
        parentEnvironment: [String: String],
        currentDirectory: String = FileManager.default.currentDirectoryPath,
        fileManager: FileManager = .default,
        usesShell: Bool = false
    ) throws -> [String] {
        guard explicitEnvFiles.isEmpty else { return explicitEnvFiles }
        guard !parentEnvironment.values.contains(where: SecretReference.isSecretReference) else { return [] }
        guard !(hasTypeScope && usesShell) else { return [] }

        let currentDirectoryURL = URL(fileURLWithPath: currentDirectory, isDirectory: true)
        let candidateEnvFiles = [
            currentDirectoryURL.deletingLastPathComponent().appendingPathComponent(".env"),
            currentDirectoryURL.appendingPathComponent(".env"),
        ]
        var discovered: [String] = []
        var seen = Set<String>()

        for envFile in candidateEnvFiles {
            let path = envFile.path
            guard seen.insert(path).inserted,
                  Self.envFileContainsSecretReference(path, fileManager: fileManager) else {
                continue
            }
            discovered.append(path)
        }
        return discovered
    }

    private static func envFileContainsSecretReference(_ path: String, fileManager: FileManager) -> Bool {
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: path, isDirectory: &isDirectory),
              !isDirectory.boolValue,
              let entries = try? EnvFileParser.parse(contentsOf: path),
              entries.contains(where: { SecretReference.isSecretReference($0.value) }) else {
            return false
        }
        return true
    }

    static func sshAutomationCredential(
        from parentEnvironment: [String: String],
        store: AccessCredentialStore = AccessCredentialStore(),
        now: Date = Date()
    ) throws -> AccessCredential? {
        guard let credential = try AutomationAccessResolver.resolveActiveCredential(
            environment: parentEnvironment,
            store: store,
            now: now
        ) else {
            return nil
        }
        guard credential.allowedCommands.contains(.ssh) else { return nil }
        return credential
    }

    @discardableResult
    static func forwardSSHAutomationCredential(
        from parentEnvironment: [String: String],
        to childEnvironment: inout [String: String],
        store: AccessCredentialStore = AccessCredentialStore(),
        now: Date = Date()
    ) throws -> AccessCredential? {
        childEnvironment.removeValue(forKey: AutomationAccessResolver.environmentKey)
        childEnvironment.removeValue(forKey: AutomationAccessResolver.sshEnvironmentKey)
        guard let credential = try sshAutomationCredential(
            from: parentEnvironment,
            store: store,
            now: now
        ) else {
            return nil
        }
        childEnvironment[AutomationAccessResolver.sshEnvironmentKey] = credential.id.uuidString
        return credential
    }

    /// Merge multiple .env files in order; last file wins on duplicate keys.
    static func mergeEnvFiles(_ paths: [String]) throws -> [String: String] {
        var merged: [String: String] = [:]
        for path in paths {
            let entries = try EnvFileParser.parse(contentsOf: path)
            for entry in entries {
                merged[entry.key] = entry.value
            }
        }
        return merged
    }

    /// Collect all plaintext secret values for the output masker.
    static func collectSecrets(entries: [Load.LoadedEntry], resolvedSecrets: [String]) -> [String] {
        var secrets = entries.map(\.value)
        secrets.append(contentsOf: resolvedSecrets)
        return secrets
    }

    static func collectSecrets(
        entries: [Load.LoadedEntry],
        resolvedSecrets: [String],
        shellCommand: String?,
        environment: [String: String]
    ) -> [String] {
        var secrets = collectSecrets(entries: entries, resolvedSecrets: resolvedSecrets)
        guard let shellCommand else { return secrets }
        secrets.append(
            contentsOf: shellSubstringMaskTokens(
                command: shellCommand,
                environment: environment,
                secretValues: secrets
            )
        )
        secrets.append(
            contentsOf: shellTrimMaskTokens(
                command: shellCommand,
                environment: environment,
                secretValues: secrets
            )
        )
        secrets.append(
            contentsOf: shellReplacementMaskTokens(
                command: shellCommand,
                environment: environment,
                secretValues: secrets
            )
        )
        secrets.append(
            contentsOf: shellLengthMaskTokens(
                command: shellCommand,
                environment: environment,
                secretValues: secrets
            )
        )
        secrets.append(
            contentsOf: shellCommandTransformationMaskTokens(
                command: shellCommand,
                environment: environment,
                secretValues: secrets
            )
        )
        return secrets
    }

    static func shellSubstringMaskTokens(
        command: String,
        environment: [String: String],
        secretValues: [String]
    ) -> [String] {
        let secretValues = Set(secretValues.filter { !$0.isEmpty })
        guard !command.isEmpty, !secretValues.isEmpty else { return [] }

        var tokens: [String] = []
        var seen = Set<String>()

        for expansion in shellSubstringExpansions(in: command) {
            guard let value = environment[expansion.name],
                  secretValues.contains(value),
                  let offset = ArithmeticExpressionParser.evaluate(
                    expansion.offsetExpression,
                    environment: environment
                  ) else {
                continue
            }
            let length: Int?
            if let lengthExpression = expansion.lengthExpression {
                guard let evaluatedLength = ArithmeticExpressionParser.evaluate(
                    lengthExpression,
                    environment: environment
                ) else {
                    continue
                }
                length = evaluatedLength
            } else {
                length = nil
            }
            guard let token = shellSubstringToken(value: value, offset: offset, length: length),
                  !seen.contains(token) else {
                continue
            }
            seen.insert(token)
            tokens.append(token)
        }

        return tokens
    }

    static func shellTrimMaskTokens(
        command: String,
        environment: [String: String],
        secretValues: [String]
    ) -> [String] {
        let secretValues = Set(secretValues.filter { !$0.isEmpty })
        guard !command.isEmpty, !secretValues.isEmpty else { return [] }

        var tokens: [String] = []
        var seen = Set<String>()

        for expansion in shellTrimExpansions(in: command) {
            guard let value = environment[expansion.name],
                  secretValues.contains(value),
                  let token = shellTrimToken(
                    value: value,
                    operation: expansion.operation,
                    pattern: expansion.pattern
                  ),
                  !token.isEmpty,
                  !seen.contains(token) else {
                continue
            }
            seen.insert(token)
            tokens.append(token)
        }

        return tokens
    }

    static func shellReplacementMaskTokens(
        command: String,
        environment: [String: String],
        secretValues: [String]
    ) -> [String] {
        let secretValues = Set(secretValues.filter { !$0.isEmpty })
        guard !command.isEmpty, !secretValues.isEmpty else { return [] }

        var tokens: [String] = []
        var seen = Set<String>()

        for expansion in shellReplacementExpansions(in: command) {
            guard let value = environment[expansion.name],
                  secretValues.contains(value),
                  let token = shellReplacementToken(
                    value: value,
                    pattern: expansion.pattern,
                    replacement: expansion.replacement,
                    replaceAll: expansion.replaceAll
                  ),
                  !token.isEmpty,
                  !seen.contains(token) else {
                continue
            }
            seen.insert(token)
            tokens.append(token)
        }

        return tokens
    }

    static func shellLengthMaskTokens(
        command: String,
        environment: [String: String],
        secretValues: [String]
    ) -> [String] {
        let secretValues = Set(secretValues.filter { !$0.isEmpty })
        guard !command.isEmpty, !secretValues.isEmpty else { return [] }

        var tokens: [String] = []
        var seen = Set<String>()

        for (name, value) in environment where secretValues.contains(value) {
            guard command.contains("${#\(name)}") else { continue }
            appendMaskToken(String(value.count), to: &tokens, seen: &seen)
        }

        return tokens
    }

    static func shellCommandTransformationMaskTokens(
        command: String,
        environment: [String: String],
        secretValues: [String]
    ) -> [String] {
        let secretValues = Set(secretValues.filter { !$0.isEmpty })
        guard !command.isEmpty,
              !secretValues.isEmpty,
              commandLooksLikeSecretTransformation(command) else {
            return []
        }

        var tokens: [String] = []
        var seen = Set<String>()

        let discoversEnvironment = commandDiscoversEnvironment(command)
        for (name, value) in environment
            where secretValues.contains(value) &&
                (discoversEnvironment || commandReferencesVariable(name, in: command)) {
            for token in commandTransformationTokens(for: value) {
                appendMaskToken(token, to: &tokens, seen: &seen)
            }
        }

        return tokens
    }

    private static let maxCommandTransformationSubstringSecretLength = 128

    private static func appendMaskToken(_ token: String, to tokens: inout [String], seen: inout Set<String>) {
        guard !token.isEmpty, !seen.contains(token) else { return }
        seen.insert(token)
        tokens.append(token)
    }

    private static func commandLooksLikeSecretTransformation(_ command: String) -> Bool {
        let lowercasedCommand = command.lowercased()
        let markers = [
            "for ((",
            "head -c",
            "tail -c",
            "hashlib",
            "crypto.",
        ]

        if markers.contains(where: { lowercasedCommand.contains($0) }) {
            return true
        }
        if containsShellWord("jq", in: lowercasedCommand),
           lowercasedCommand.contains("env.") ||
            lowercasedCommand.contains("$env.") ||
            lowercasedCommand.contains("--arg") {
            return true
        }

        let transformerWords = [
            "awk",
            "base64",
            "base32",
            "cut",
            "dd",
            "fold",
            "go",
            "head",
            "hexdump",
            "java",
            "lua",
            "md5",
            "md5sum",
            "node",
            "od",
            "openssl",
            "paste",
            "perl",
            "php",
            "python",
            "python3",
            "rev",
            "ruby",
            "sed",
            "sha256sum",
            "shasum",
            "sort",
            "swift",
            "tail",
            "tr",
            "uuencode",
            "xxd",
        ]
        return transformerWords.contains { containsShellWord($0, in: lowercasedCommand) }
    }

    private static func commandReferencesVariable(_ name: String, in command: String) -> Bool {
        if command.contains("${\(name)") || containsBareShellVariable(name, in: command) {
            return true
        }

        let references = [
            "process.env.\(name)",
            "process.env[\"\(name)\"]",
            "process.env['\(name)']",
            #"process.env[\"\#(name)\"]"#,
            "$ENV.\(name)",
            "env.\(name)",
            "os.environ.get(\"\(name)\"",
            "os.environ.get('\(name)'",
            #"os.environ.get(\"\#(name)\""#,
            "os.environ[\"\(name)\"]",
            "os.environ['\(name)']",
            #"os.environ[\"\#(name)\"]"#,
            "os.getenv(\"\(name)\"",
            "os.getenv('\(name)'",
            #"os.getenv(\"\#(name)\""#,
            "getenv(\"\(name)\"",
            "getenv('\(name)'",
            #"getenv(\"\#(name)\""#,
            "os.Getenv(\"\(name)\"",
            "os.Getenv('\(name)'",
            #"os.Getenv(\"\#(name)\""#,
            "System.getenv(\"\(name)\"",
            "System.getenv('\(name)'",
            #"System.getenv(\"\#(name)\""#,
            "ProcessInfo.processInfo.environment[\"\(name)\"]",
            "ProcessInfo.processInfo.environment['\(name)']",
            #"ProcessInfo.processInfo.environment[\"\#(name)\"]"#,
            "$_ENV[\"\(name)\"]",
            "$_ENV['\(name)']",
            #"$_ENV[\"\#(name)\"]"#,
            "$_SERVER[\"\(name)\"]",
            "$_SERVER['\(name)']",
            #"$_SERVER[\"\#(name)\"]"#,
            "ENVIRON[\"\(name)\"]",
            "ENVIRON['\(name)']",
            #"ENVIRON[\"\#(name)\"]"#,
            "$ENV{\(name)}",
            "ENV[\"\(name)\"]",
            "ENV['\(name)']",
            #"ENV[\"\#(name)\"]"#,
        ]

        return references.contains { command.contains($0) }
    }

    private static func commandDiscoversEnvironment(_ command: String) -> Bool {
        let lowercasedCommand = command.lowercased()
        if lowercasedCommand.contains("/proc/") && lowercasedCommand.contains("environ") {
            return true
        }

        let discoveryWords = [
            "compgen",
            "declare",
            "env",
            "export",
            "printenv",
            "ps",
            "set",
            "typeset",
        ]
        return discoveryWords.contains { containsShellWord($0, in: lowercasedCommand) }
    }

    private static func containsBareShellVariable(_ name: String, in command: String) -> Bool {
        let needle = "$\(name)"
        var searchStart = command.startIndex

        while searchStart < command.endIndex,
              let range = command.range(of: needle, range: searchStart..<command.endIndex) {
            let after = range.upperBound
            if after == command.endIndex || !isShellNameCharacter(command[after]) {
                return true
            }
            searchStart = after
        }

        return false
    }

    private static func containsShellWord(_ word: String, in command: String) -> Bool {
        var searchStart = command.startIndex

        while searchStart < command.endIndex,
              let range = command.range(of: word, range: searchStart..<command.endIndex) {
            let hasValidPrefix = range.lowerBound == command.startIndex ||
                !isShellNameCharacter(command[command.index(before: range.lowerBound)])
            let hasValidSuffix = range.upperBound == command.endIndex ||
                !isShellNameCharacter(command[range.upperBound])
            if hasValidPrefix && hasValidSuffix {
                return true
            }
            searchStart = range.upperBound
        }

        return false
    }

    private static func commandTransformationTokens(for value: String) -> [String] {
        var tokens: [String] = []
        var seen = Set<String>()

        for token in substringMaskTokens(for: value) {
            appendMaskToken(token, to: &tokens, seen: &seen)
        }
        appendMaskToken(String(value.reversed()), to: &tokens, seen: &seen)
        appendMaskToken(value.uppercased(), to: &tokens, seen: &seen)
        appendMaskToken(value.lowercased(), to: &tokens, seen: &seen)
        appendMaskToken(value.map(String.init).sorted().joined(), to: &tokens, seen: &seen)

        for token in delimiterTransformTokens(for: value) {
            appendMaskToken(token, to: &tokens, seen: &seen)
        }
        for token in characterFormattingTokens(for: value) {
            appendMaskToken(token, to: &tokens, seen: &seen)
        }
        for token in indexedCharacterTokens(for: value) {
            appendMaskToken(token, to: &tokens, seen: &seen)
        }
        for token in base32Tokens(for: Array(value.utf8)) {
            appendMaskToken(token, to: &tokens, seen: &seen)
        }
        for token in uuencodeTokens(for: Array(value.utf8)) {
            appendMaskToken(token, to: &tokens, seen: &seen)
        }
        for token in hexFormattingTokens(for: value) {
            appendMaskToken(token, to: &tokens, seen: &seen)
        }
        appendMaskToken(hashHexToken(for: value, algorithm: .sha1), to: &tokens, seen: &seen)
        appendMaskToken(hashHexToken(for: value, algorithm: .sha256), to: &tokens, seen: &seen)
        appendMaskToken(hashHexToken(for: value, algorithm: .sha384), to: &tokens, seen: &seen)
        appendMaskToken(hashHexToken(for: value, algorithm: .sha512), to: &tokens, seen: &seen)
        appendMaskToken(hashHexToken(for: value, algorithm: .md5), to: &tokens, seen: &seen)

        return tokens
    }

    private static func substringMaskTokens(for value: String) -> [String] {
        let characters = Array(value)
        guard !characters.isEmpty else { return [] }

        var tokens: [String] = []
        if characters.count <= maxCommandTransformationSubstringSecretLength {
            for start in characters.indices {
                for end in (start + 1)...characters.count {
                    tokens.append(String(characters[start..<end]))
                }
            }
            return tokens
        }

        let maxEdgeLength = min(64, characters.count)
        for length in 1...maxEdgeLength {
            tokens.append(String(characters[..<length]))
            tokens.append(String(characters[(characters.count - length)...]))
        }
        for chunkSize in [1, 2, 4, 8, 16, 32, 64] {
            tokens.append(contentsOf: characterChunks(value, size: chunkSize))
        }
        return tokens
    }

    private static func delimiterTransformTokens(for value: String) -> [String] {
        var tokens: [String] = []
        for delimiter in ["-", "_", ".", ":", "/", " "] {
            tokens.append(value.replacingOccurrences(of: delimiter, with: ""))
        }

        let delimiterSet = CharacterSet(charactersIn: "-_.:/ \t\n")
        tokens.append(
            contentsOf: value.components(separatedBy: delimiterSet)
                .filter { !$0.isEmpty }
        )
        return tokens
    }

    private static func characterFormattingTokens(for value: String) -> [String] {
        let characters = value.map(String.init)
        guard !characters.isEmpty else { return [] }

        var tokens = [
            characters.joined(separator: " "),
            characters.joined(separator: " ") + " ",
            characters.joined(separator: "\n"),
            characters.map { "[\($0)]" }.joined(),
        ]
        for separator in [":", "-", "_", ".", ",", "|", "\t"] {
            tokens.append(characters.joined(separator: separator))
        }

        for chunkSize in [2, 4, 8] {
            let chunked = characterChunks(value, size: chunkSize).joined(separator: " ")
            tokens.append(chunked)
            tokens.append(chunked + " ")
        }
        return tokens
    }

    private static func indexedCharacterTokens(for value: String) -> [String] {
        let characters = Array(value)
        guard !characters.isEmpty, characters.count <= maxCommandTransformationSubstringSecretLength else {
            return []
        }

        var tokens: [String] = []
        for (index, character) in characters.enumerated() {
            let indexLabels = [
                String(index),
                String(format: "%02d", index),
                String(format: "%03d", index),
            ]
            for label in Set(indexLabels) {
                for separator in ["=", ":", " ", "\t"] {
                    tokens.append("\(label)\(separator)\(character)")
                }
            }
        }
        return tokens
    }

    private static func base32Tokens(for bytes: [UInt8]) -> [String] {
        guard !bytes.isEmpty else { return [] }
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var output = ""
        var buffer = 0
        var bitsLeft = 0

        for byte in bytes {
            buffer = (buffer << 8) | Int(byte)
            bitsLeft += 8

            while bitsLeft >= 5 {
                let index = (buffer >> (bitsLeft - 5)) & 0x1F
                output.append(alphabet[index])
                bitsLeft -= 5
            }
        }

        if bitsLeft > 0 {
            let index = (buffer << (5 - bitsLeft)) & 0x1F
            output.append(alphabet[index])
        }

        let paddingLength = (8 - output.count % 8) % 8
        let padded = output + String(repeating: "=", count: paddingLength)
        return padded == output ? [output] : [padded, output]
    }

    private static func uuencodeTokens(for bytes: [UInt8]) -> [String] {
        guard !bytes.isEmpty else { return [] }
        var tokens: [String] = []

        for zeroScalar in [UnicodeScalar(0x20)!, UnicodeScalar(0x60)!] {
            var lines: [String] = []
            var index = 0
            while index < bytes.count {
                let end = min(index + 45, bytes.count)
                lines.append(uuencodeLine(Array(bytes[index..<end]), zeroScalar: zeroScalar))
                index = end
            }
            tokens.append(contentsOf: lines)
            tokens.append(lines.joined(separator: "\n"))
        }

        return tokens
    }

    private static func uuencodeLine(_ bytes: [UInt8], zeroScalar: UnicodeScalar) -> String {
        var scalars = String.UnicodeScalarView()
        scalars.append(uuencodeScalar(UInt8(bytes.count), zeroScalar: zeroScalar))

        var index = 0
        while index < bytes.count {
            let first = bytes[index]
            let second = index + 1 < bytes.count ? bytes[index + 1] : 0
            let third = index + 2 < bytes.count ? bytes[index + 2] : 0

            scalars.append(uuencodeScalar((first >> 2) & 0x3F, zeroScalar: zeroScalar))
            scalars.append(uuencodeScalar(((first << 4) | (second >> 4)) & 0x3F, zeroScalar: zeroScalar))
            scalars.append(uuencodeScalar(((second << 2) | (third >> 6)) & 0x3F, zeroScalar: zeroScalar))
            scalars.append(uuencodeScalar(third & 0x3F, zeroScalar: zeroScalar))
            index += 3
        }

        return String(scalars)
    }

    private static func uuencodeScalar(_ value: UInt8, zeroScalar: UnicodeScalar) -> UnicodeScalar {
        let encoded = UnicodeScalar(Int((value & 0x3F) + 0x20))!
        return encoded.value == 0x20 ? zeroScalar : encoded
    }

    private static func hexFormattingTokens(for value: String) -> [String] {
        let lowerPairs = value.utf8.map { String(format: "%02x", $0) }
        guard !lowerPairs.isEmpty else { return [] }
        let upperPairs = value.utf8.map { String(format: "%02X", $0) }
        let lowerHex = lowerPairs.joined()
        let upperHex = upperPairs.joined()

        var tokens = [
            lowerPairs.joined(separator: " "),
            upperPairs.joined(separator: " "),
            groupedHexPairs(lowerPairs, groupSize: 2),
            groupedHexPairs(upperPairs, groupSize: 2),
            groupedHexPairs(lowerPairs, groupSize: 4),
            groupedHexPairs(upperPairs, groupSize: 4),
        ]

        for chunkSize in [2, 4, 8, 16, 32, 64] {
            tokens.append(contentsOf: characterChunks(lowerHex, size: chunkSize))
            tokens.append(contentsOf: characterChunks(upperHex, size: chunkSize))
        }
        return tokens
    }

    private static func groupedHexPairs(_ pairs: [String], groupSize: Int) -> String {
        guard groupSize > 0 else { return pairs.joined() }
        var groups: [String] = []
        var index = 0
        while index < pairs.count {
            let end = min(index + groupSize, pairs.count)
            groups.append(pairs[index..<end].joined())
            index = end
        }
        return groups.joined(separator: " ")
    }

    private static func characterChunks(_ value: String, size: Int) -> [String] {
        guard size > 0 else { return [] }
        var chunks: [String] = []
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: size, limitedBy: value.endIndex) ?? value.endIndex
            chunks.append(String(value[index..<next]))
            index = next
        }
        return chunks
    }

    private enum HashAlgorithm {
        case sha1
        case sha256
        case sha384
        case sha512
        case md5
    }

    private static func hashHexToken(for value: String, algorithm: HashAlgorithm) -> String {
        let data = Data(value.utf8)
        let digest: Data
        switch algorithm {
        case .sha1:
            digest = Data(Insecure.SHA1.hash(data: data))
        case .sha256:
            digest = Data(SHA256.hash(data: data))
        case .sha384:
            digest = Data(SHA384.hash(data: data))
        case .sha512:
            digest = Data(SHA512.hash(data: data))
        case .md5:
            digest = Data(Insecure.MD5.hash(data: data))
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private struct ShellSubstringExpansion {
        let name: String
        let offsetExpression: String
        let lengthExpression: String?
    }

    private struct ShellTrimExpansion {
        let name: String
        let operation: ShellTrimOperation
        let pattern: String
    }

    private struct ShellReplacementExpansion {
        let name: String
        let pattern: String
        let replacement: String
        let replaceAll: Bool
    }

    private enum ShellTrimOperation {
        case shortestPrefix
        case longestPrefix
        case shortestSuffix
        case longestSuffix
    }

    private static func shellSubstringExpansions(in command: String) -> [ShellSubstringExpansion] {
        var expansions: [ShellSubstringExpansion] = []
        var index = command.startIndex

        while index < command.endIndex {
            guard command[index] == "$",
                  let next = command.index(index, offsetBy: 1, limitedBy: command.endIndex),
                  next < command.endIndex,
                  command[next] == "{" else {
                index = command.index(after: index)
                continue
            }

            let bodyStart = command.index(after: next)
            guard let bodyEnd = shellExpansionBodyEnd(in: command, from: bodyStart) else {
                index = command.index(after: index)
                continue
            }

            let body = String(command[bodyStart..<bodyEnd])
            if let expansion = parseShellSubstringExpansionBody(body) {
                expansions.append(expansion)
            }
            index = command.index(after: bodyEnd)
        }

        return expansions
    }

    private static func shellTrimExpansions(in command: String) -> [ShellTrimExpansion] {
        var expansions: [ShellTrimExpansion] = []
        var index = command.startIndex

        while index < command.endIndex {
            guard command[index] == "$",
                  let next = command.index(index, offsetBy: 1, limitedBy: command.endIndex),
                  next < command.endIndex,
                  command[next] == "{" else {
                index = command.index(after: index)
                continue
            }

            let bodyStart = command.index(after: next)
            guard let bodyEnd = shellExpansionBodyEnd(in: command, from: bodyStart) else {
                index = command.index(after: index)
                continue
            }

            let body = String(command[bodyStart..<bodyEnd])
            if let expansion = parseShellTrimExpansionBody(body) {
                expansions.append(expansion)
            }
            index = command.index(after: bodyEnd)
        }

        return expansions
    }

    private static func shellReplacementExpansions(in command: String) -> [ShellReplacementExpansion] {
        var expansions: [ShellReplacementExpansion] = []
        var index = command.startIndex

        while index < command.endIndex {
            guard command[index] == "$",
                  let next = command.index(index, offsetBy: 1, limitedBy: command.endIndex),
                  next < command.endIndex,
                  command[next] == "{" else {
                index = command.index(after: index)
                continue
            }

            let bodyStart = command.index(after: next)
            guard let bodyEnd = shellExpansionBodyEnd(in: command, from: bodyStart) else {
                index = command.index(after: index)
                continue
            }

            let body = String(command[bodyStart..<bodyEnd])
            if let expansion = parseShellReplacementExpansionBody(body) {
                expansions.append(expansion)
            }
            index = command.index(after: bodyEnd)
        }

        return expansions
    }

    private static func shellExpansionBodyEnd(in command: String, from bodyStart: String.Index) -> String.Index? {
        var index = bodyStart
        var nestedBraceDepth = 0

        while index < command.endIndex {
            if command[index] == "$",
               let next = command.index(index, offsetBy: 1, limitedBy: command.endIndex),
               next < command.endIndex,
               command[next] == "{" {
                nestedBraceDepth += 1
                index = command.index(after: next)
                continue
            }

            if command[index] == "}" {
                if nestedBraceDepth == 0 {
                    return index
                }
                nestedBraceDepth -= 1
            }
            index = command.index(after: index)
        }

        return nil
    }

    private static func parseShellSubstringExpansionBody(_ body: String) -> ShellSubstringExpansion? {
        guard !body.isEmpty else { return nil }
        var index = body.startIndex
        guard isShellNameStart(body[index]) else { return nil }

        let nameStart = index
        index = body.index(after: index)
        while index < body.endIndex, isShellNameCharacter(body[index]) {
            index = body.index(after: index)
        }

        guard index < body.endIndex, body[index] == ":" else { return nil }
        let name = String(body[nameStart..<index])
        let expressionStart = body.index(after: index)
        guard expressionStart < body.endIndex else { return nil }

        let expressionText = String(body[expressionStart...])
        guard expressionText.first != "-" else { return nil }

        let (offsetExpression, lengthExpression) = splitFirstTopLevelColon(expressionText)
        guard !offsetExpression.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return nil
        }
        if let lengthExpression,
           lengthExpression.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return nil
        }

        return ShellSubstringExpansion(
            name: name,
            offsetExpression: offsetExpression,
            lengthExpression: lengthExpression
        )
    }

    private static func parseShellTrimExpansionBody(_ body: String) -> ShellTrimExpansion? {
        guard !body.isEmpty else { return nil }
        var index = body.startIndex
        guard isShellNameStart(body[index]) else { return nil }

        let nameStart = index
        index = body.index(after: index)
        while index < body.endIndex, isShellNameCharacter(body[index]) {
            index = body.index(after: index)
        }

        guard index < body.endIndex else { return nil }

        let operatorCharacter = body[index]
        guard operatorCharacter == "#" || operatorCharacter == "%" else { return nil }

        let nextIndex = body.index(after: index)
        let isDoubleOperator = nextIndex < body.endIndex && body[nextIndex] == operatorCharacter
        let patternStart = isDoubleOperator ? body.index(after: nextIndex) : nextIndex
        guard patternStart < body.endIndex else { return nil }

        let operation: ShellTrimOperation
        switch (operatorCharacter, isDoubleOperator) {
        case ("#", false):
            operation = .shortestPrefix
        case ("#", true):
            operation = .longestPrefix
        case ("%", false):
            operation = .shortestSuffix
        case ("%", true):
            operation = .longestSuffix
        default:
            return nil
        }

        return ShellTrimExpansion(
            name: String(body[nameStart..<index]),
            operation: operation,
            pattern: String(body[patternStart...])
        )
    }

    private static func parseShellReplacementExpansionBody(_ body: String) -> ShellReplacementExpansion? {
        guard !body.isEmpty else { return nil }
        var index = body.startIndex
        guard isShellNameStart(body[index]) else { return nil }

        let nameStart = index
        index = body.index(after: index)
        while index < body.endIndex, isShellNameCharacter(body[index]) {
            index = body.index(after: index)
        }

        guard index < body.endIndex, body[index] == "/" else { return nil }
        let nextIndex = body.index(after: index)
        let replaceAll = nextIndex < body.endIndex && body[nextIndex] == "/"
        let patternStart = replaceAll ? body.index(after: nextIndex) : nextIndex
        guard patternStart < body.endIndex else { return nil }

        let (pattern, replacement) = splitShellReplacementPattern(String(body[patternStart...]))
        guard !pattern.isEmpty,
              isSupportedShellReplacementPattern(pattern),
              isStaticShellReplacement(replacement) else {
            return nil
        }

        return ShellReplacementExpansion(
            name: String(body[nameStart..<index]),
            pattern: pattern,
            replacement: replacement,
            replaceAll: replaceAll
        )
    }

    private static func splitShellReplacementPattern(_ text: String) -> (String, String) {
        var pattern = ""
        var replacement = ""
        var isEscaped = false
        var isReadingReplacement = false

        for character in text {
            if isEscaped {
                if isReadingReplacement {
                    replacement.append(character)
                } else {
                    pattern.append(character)
                }
                isEscaped = false
                continue
            }

            if character == "\\" {
                isEscaped = true
                continue
            }

            if character == "/", !isReadingReplacement {
                isReadingReplacement = true
                continue
            }

            if isReadingReplacement {
                replacement.append(character)
            } else {
                pattern.append(character)
            }
        }

        if isEscaped {
            if isReadingReplacement {
                replacement.append("\\")
            } else {
                pattern.append("\\")
            }
        }

        return (pattern, replacement)
    }

    private static func isLiteralShellReplacementPattern(_ pattern: String) -> Bool {
        !pattern.contains { character in
            character == "*" || character == "?" || character == "["
        }
    }

    private static func isSupportedShellReplacementPattern(_ pattern: String) -> Bool {
        isLiteralShellReplacementPattern(pattern) || isSingleCharacterShellGlobPattern(pattern)
    }

    private static func isSingleCharacterShellGlobPattern(_ pattern: String) -> Bool {
        if pattern == "?" { return true }
        guard pattern.hasPrefix("["),
              pattern.hasSuffix("]"),
              pattern.dropFirst().dropLast().isEmpty == false else {
            return false
        }

        return !pattern.dropFirst().dropLast().contains { character in
            character == "$" || character == "`" || character == "/" || character == "["
        }
    }

    private static func isStaticShellReplacement(_ replacement: String) -> Bool {
        !replacement.contains { character in
            character == "$" || character == "`"
        }
    }

    private static func splitFirstTopLevelColon(_ text: String) -> (String, String?) {
        var index = text.startIndex
        var nestedBraceDepth = 0
        var parenthesisDepth = 0

        while index < text.endIndex {
            if text[index] == "$",
               let next = text.index(index, offsetBy: 1, limitedBy: text.endIndex),
               next < text.endIndex,
               text[next] == "{" {
                nestedBraceDepth += 1
                index = text.index(after: next)
                continue
            }

            if text[index] == "}", nestedBraceDepth > 0 {
                nestedBraceDepth -= 1
                index = text.index(after: index)
                continue
            }

            if nestedBraceDepth == 0 {
                if text[index] == "(" {
                    parenthesisDepth += 1
                } else if text[index] == ")", parenthesisDepth > 0 {
                    parenthesisDepth -= 1
                } else if text[index] == ":", parenthesisDepth == 0 {
                    let next = text.index(after: index)
                    return (String(text[..<index]), String(text[next...]))
                }
            }

            index = text.index(after: index)
        }

        return (text, nil)
    }

    private static func shellSubstringToken(value: String, offset: Int, length: Int?) -> String? {
        let characterCount = value.count
        let startOffset = offset < 0 ? characterCount + offset : offset
        guard startOffset >= 0, startOffset < characterCount else { return nil }

        let endOffset: Int
        if let length, length < 0 {
            endOffset = characterCount + length
            guard endOffset > startOffset else { return nil }
        } else if let length {
            guard length > 0 else { return nil }
            endOffset = min(startOffset + length, characterCount)
        } else {
            endOffset = characterCount
        }

        let start = value.index(value.startIndex, offsetBy: startOffset)
        let end = value.index(value.startIndex, offsetBy: endOffset)
        return String(value[start..<end])
    }

    private static func shellTrimToken(
        value: String,
        operation: ShellTrimOperation,
        pattern: String
    ) -> String? {
        let boundaries = stringBoundaries(in: value)

        switch operation {
        case .shortestPrefix:
            for boundary in boundaries {
                if shellPatternMatches(pattern, String(value[..<boundary])) {
                    return String(value[boundary...])
                }
            }
        case .longestPrefix:
            for boundary in boundaries.reversed() {
                if shellPatternMatches(pattern, String(value[..<boundary])) {
                    return String(value[boundary...])
                }
            }
        case .shortestSuffix:
            for boundary in boundaries.reversed() {
                if shellPatternMatches(pattern, String(value[boundary...])) {
                    return String(value[..<boundary])
                }
            }
        case .longestSuffix:
            for boundary in boundaries {
                if shellPatternMatches(pattern, String(value[boundary...])) {
                    return String(value[..<boundary])
                }
            }
        }

        return nil
    }

    private static func shellReplacementToken(
        value: String,
        pattern: String,
        replacement: String,
        replaceAll: Bool
    ) -> String? {
        guard !pattern.isEmpty else { return nil }

        if isLiteralShellReplacementPattern(pattern) {
            guard value.contains(pattern) else { return nil }
            if replaceAll {
                return value.replacingOccurrences(of: pattern, with: replacement)
            }

            guard let range = value.range(of: pattern) else { return nil }
            var token = value
            token.replaceSubrange(range, with: replacement)
            return token
        }

        guard isSingleCharacterShellGlobPattern(pattern) else { return nil }
        var token = ""
        var didReplace = false
        for character in value {
            if (replaceAll || !didReplace), shellPatternMatches(pattern, String(character)) {
                token.append(replacement)
                didReplace = true
            } else {
                token.append(character)
            }
        }
        return didReplace ? token : nil
    }

    private static func stringBoundaries(in value: String) -> [String.Index] {
        var boundaries = [value.startIndex]
        var index = value.startIndex
        while index < value.endIndex {
            index = value.index(after: index)
            boundaries.append(index)
        }
        return boundaries
    }

    private static func shellPatternMatches(_ pattern: String, _ value: String) -> Bool {
        pattern.withCString { patternPointer in
            value.withCString { valuePointer in
                fnmatch(patternPointer, valuePointer, 0) == 0
            }
        }
    }

    private static func isShellNameStart(_ character: Character) -> Bool {
        character == "_" || character.isLetter
    }

    private static func isShellNameCharacter(_ character: Character) -> Bool {
        character == "_" || character.isLetter || character.isNumber
    }

    private struct ArithmeticExpressionParser {
        private let characters: [Character]
        private let environment: [String: String]
        private var index = 0

        static func evaluate(_ expression: String, environment: [String: String]) -> Int? {
            let trimmed = expression.trimmingCharacters(in: .whitespacesAndNewlines)
            let unwrapped = unwrapArithmeticExpansion(trimmed)
            var parser = ArithmeticExpressionParser(expression: unwrapped, environment: environment)
            guard let value = parser.parseExpression() else { return nil }
            parser.skipWhitespace()
            return parser.isAtEnd ? value : nil
        }

        private static func unwrapArithmeticExpansion(_ expression: String) -> String {
            guard expression.hasPrefix("$(("), expression.hasSuffix("))") else {
                return expression
            }
            return String(expression.dropFirst(3).dropLast(2))
        }

        private init(expression: String, environment: [String: String]) {
            self.characters = Array(expression)
            self.environment = environment
        }

        private var isAtEnd: Bool {
            index >= characters.count
        }

        private mutating func parseExpression() -> Int? {
            guard var value = parseTerm() else { return nil }

            while true {
                skipWhitespace()
                if consume("+") {
                    guard let rhs = parseTerm() else { return nil }
                    value += rhs
                } else if consume("-") {
                    guard let rhs = parseTerm() else { return nil }
                    value -= rhs
                } else {
                    return value
                }
            }
        }

        private mutating func parseTerm() -> Int? {
            guard var value = parseFactor() else { return nil }

            while true {
                skipWhitespace()
                if consume("*") {
                    guard let rhs = parseFactor() else { return nil }
                    value *= rhs
                } else if consume("/") {
                    guard let rhs = parseFactor(), rhs != 0 else { return nil }
                    value /= rhs
                } else if consume("%") {
                    guard let rhs = parseFactor(), rhs != 0 else { return nil }
                    value %= rhs
                } else {
                    return value
                }
            }
        }

        private mutating func parseFactor() -> Int? {
            skipWhitespace()
            if consume("+") {
                return parseFactor()
            }
            if consume("-") {
                guard let value = parseFactor() else { return nil }
                return -value
            }
            if consume("(") {
                guard let value = parseExpression() else { return nil }
                skipWhitespace()
                guard consume(")") else { return nil }
                return value
            }
            if consume("$") {
                return parseVariableReference()
            }
            if let value = parseNumber() {
                return value
            }
            return parseBareVariable()
        }

        private mutating func parseNumber() -> Int? {
            skipWhitespace()
            let start = index
            while !isAtEnd, characters[index].isNumber {
                index += 1
            }
            guard index > start else { return nil }
            return Int(String(characters[start..<index]))
        }

        private mutating func parseVariableReference() -> Int? {
            if consume("{") {
                let start = index
                while !isAtEnd, isShellNameCharacter(characters[index]) {
                    index += 1
                }
                guard index > start, consume("}") else { return nil }
                return environmentInt(String(characters[start..<index]))
            }
            return parseBareVariable()
        }

        private mutating func parseBareVariable() -> Int? {
            skipWhitespace()
            guard !isAtEnd, isShellNameStart(characters[index]) else { return nil }
            let start = index
            index += 1
            while !isAtEnd, isShellNameCharacter(characters[index]) {
                index += 1
            }
            return environmentInt(String(characters[start..<index]))
        }

        private func environmentInt(_ name: String) -> Int? {
            guard let value = environment[name] else { return nil }
            return Int(value.trimmingCharacters(in: .whitespacesAndNewlines))
        }

        private mutating func skipWhitespace() {
            while !isAtEnd, characters[index].isWhitespace {
                index += 1
            }
        }

        private mutating func consume(_ character: Character) -> Bool {
            guard !isAtEnd, characters[index] == character else { return false }
            index += 1
            return true
        }
    }

    // MARK: - Child process with output masking

    static func runChildProcess(
        command: [String],
        environment: [String: String],
        masker: OutputMasker,
        sshAutomationCredential: AccessCredential? = nil
    ) -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = command
        process.environment = environment

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        let signalSources = installSignalForwarding(to: process)
        defer { signalSources.forEach { $0.cancel() } }

        do {
            try process.run()
        } catch {
            StandardError.writeLine("Error: Failed to execute '\(command.first ?? "<unknown>")': \(error.localizedDescription)")
            return 1
        }
        let grant = saveSSHAutomationProcessGrant(
            credential: sshAutomationCredential,
            processID: process.processIdentifier
        )
        defer {
            if let grant {
                SSHAutomationGrantStore.clearGrant(id: grant.id)
            }
        }

        let group = DispatchGroup()

        group.enter()
        streamPipe(stdoutPipe, to: FileHandle.standardOutput, masker: masker) {
            group.leave()
        }

        group.enter()
        streamPipe(stderrPipe, to: FileHandle.standardError, masker: masker) {
            group.leave()
        }

        process.waitUntilExit()
        group.wait()

        // Shell convention: signal-killed process exits with 128 + signum
        // so callers can distinguish `kill -INT` (130) from normal failure (1).
        if process.terminationReason == .uncaughtSignal {
            return 128 + process.terminationStatus
        }
        return process.terminationStatus
    }

    private static func saveSSHAutomationProcessGrant(
        credential: AccessCredential?,
        processID: Int32
    ) -> SSHAutomationGrantRecord? {
        guard let credential else { return nil }
        return try? SSHAutomationGrantStore.saveGrant(
            credentialID: credential.id,
            sessionScope: nil,
            rootProcessID: processID,
            expiresAt: credential.expiresAt
        )
    }

    private static func streamPipe(
        _ source: Pipe,
        to destination: FileHandle,
        masker: OutputMasker,
        completion: @escaping @Sendable () -> Void
    ) {
        let stream = MaskingStreamBox(masker.makeStream())
        source.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty {
                handle.readabilityHandler = nil
                destination.write(stream.flush())
                completion()
                return
            }
            destination.write(stream.mask(data))
        }
    }

    private static func installSignalForwarding(to process: Process) -> [DispatchSourceSignal] {
        let signals: [Int32] = [SIGINT, SIGTERM, SIGHUP]
        return signals.map { sig in
            signal(sig, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            source.setEventHandler {
                if process.isRunning { kill(process.processIdentifier, sig) }
            }
            source.resume()
            return source
        }
    }
}

private final class MaskingStreamBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stream: OutputMasker.Stream

    init(_ stream: OutputMasker.Stream) {
        self.stream = stream
    }

    func mask(_ data: Data) -> Data {
        lock.lock()
        defer { lock.unlock() }
        return stream.mask(data)
    }

    func flush() -> Data {
        lock.lock()
        defer { lock.unlock() }
        return stream.flush()
    }
}
