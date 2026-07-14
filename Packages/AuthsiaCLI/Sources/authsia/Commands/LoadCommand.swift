import ArgumentParser
import Foundation
import AuthenticatorBridge
import AuthenticatorCore
import Darwin

struct Load: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "load",
        abstract: "Load vault values into runtime environment variables",
        discussion: """
            Loads secret values from Authsia and emits shell assignments.
            For active-shell export with --silent, enable one-time shell integration:
              eval "$(authsia init zsh)"   # zsh
              eval "$(authsia init bash)"  # bash

            Select one scope:
              - individual item: provide <query>
              - item in exact folder: provide <query> with --folder Team/API
              - folder scope: --folder Team/API
              - global by type: --all
              - environment profile: --env Production (all or one/more folders)
            Bare --folder loads the whole folder tree, including nested folders.

            Examples:
              authsia load api-key Stripe
              authsia load password DB_PASSWORD
              authsia load password DB_PASSWORD --folder Team/API
              authsia load password --folder Team/API
              authsia load password --folder Team/API/Prod
              authsia load password --all
              authsia load password --env Production
              authsia load password --all --all-machines
              authsia load api-key API_KEY --silent
              authsia load note "Ops Runbook" --format json
            """
    )

    enum ItemType: String, ExpressibleByArgument, CaseIterable, Codable {
        case password
        case apiKey = "api-key"
        case cert
        case note
        case ssh

        static var allValueStrings: [String] { allCases.map(\.rawValue) }

        var supportedFields: [Field] {
            switch self {
            case .password:
                return [.username, .password]
            case .apiKey:
                return [.key]
            case .cert:
                return [.certificate, .privateKey]
            case .note:
                return [.content]
            case .ssh:
                return [.publicKey, .privateKey, .comment, .fingerprint]
            }
        }

        var defaultField: Field {
            switch self {
            case .password:
                return .password
            case .apiKey:
                return .key
            case .cert:
                return .certificate
            case .note:
                return .content
            case .ssh:
                return .privateKey
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
        case publicKey
        case comment
        case fingerprint

        static var allValueStrings: [String] { allCases.map(\.rawValue) }
    }

    enum LoadOutputFormat: String, ExpressibleByArgument, CaseIterable {
        case shell
        case json

        static var allValueStrings: [String] { allCases.map(\.rawValue) }
    }

    enum ScopeSelection: Equatable {
        case single(String)
        case itemInFolder(query: String, folderPath: String)
        case folder(String)
        case folders([String])
        case global
    }

    enum ExecutionMode: Equatable {
        case printOutput
        case shellIntegration
    }

    struct ItemReference: Equatable {
        let id: String
        let name: String
        let folderPath: String?
        let isCliEnabled: Bool
        let isScraped: Bool
        let scrapeMachineName: String?
        let scrapeMachineId: String?
        let sshApprovalPolicy: String?
        let sshBoundHosts: [String]

        init(
            id: String,
            name: String,
            folderPath: String?,
            isCliEnabled: Bool,
            isScraped: Bool,
            scrapeMachineName: String?,
            scrapeMachineId: String?,
            sshApprovalPolicy: String? = nil,
            sshBoundHosts: [String] = []
        ) {
            self.id = id
            self.name = name
            self.folderPath = folderPath
            self.isCliEnabled = isCliEnabled
            self.isScraped = isScraped
            self.scrapeMachineName = scrapeMachineName
            self.scrapeMachineId = scrapeMachineId
            self.sshApprovalPolicy = sshApprovalPolicy
            self.sshBoundHosts = sshBoundHosts
        }
    }

    struct SSHFlagValidation {
        let isValid: Bool
        let errorMessage: String?
    }

    static func validateSSHFlags(
        field: Field?,
        format: LoadOutputFormat,
        silent: Bool,
        systemAgent: Bool,
        ttlSeconds: Int?
    ) -> SSHFlagValidation {
        if field != nil {
            return SSHFlagValidation(
                isValid: false,
                errorMessage: "--field is not applicable for 'load ssh'. Use `authsia get ssh <name-or-id> --field <field>` to print SSH metadata."
            )
        }
        if format != .shell {
            return SSHFlagValidation(
                isValid: false,
                errorMessage: "--format is not applicable for 'load ssh'. Output is always the ssh-add result."
            )
        }
        if silent {
            return SSHFlagValidation(
                isValid: false,
                errorMessage: "--silent is not applicable for 'load ssh'. Run `authsia load ssh <name-or-id> --system-agent --ttl <seconds>`."
            )
        }
        if !systemAgent {
            return SSHFlagValidation(
                isValid: false,
                errorMessage: "Use the built-in Authsia SSH agent for normal SSH access. To copy a key into the external ssh-agent, rerun with --system-agent --ttl <seconds>."
            )
        }
        guard let ttlSeconds, ttlSeconds > 0 else {
            return SSHFlagValidation(
                isValid: false,
                errorMessage: "--ttl must be greater than 0 when using --system-agent. Example: --ttl 3600"
            )
        }
        return SSHFlagValidation(isValid: true, errorMessage: nil)
    }

    static func validateSSHSystemAgentReference(_ reference: ItemReference) throws {
        let hasHostPolicy = !reference.sshBoundHosts.isEmpty
        let hasApprovalPolicy = reference.sshApprovalPolicy.map { $0 != SSHKeyApprovalPolicy.autoApprove.rawValue } ?? false
        guard !hasHostPolicy && !hasApprovalPolicy else {
            throw CLIError.unsupported(
                message: "Refusing to load policy-bound SSH key '\(reference.name)' into the system ssh-agent. Use the built-in Authsia SSH agent so approval policy and bound hosts remain enforced."
            )
        }
    }

    struct LoadedEntry: Codable, Equatable {
        let key: String
        let value: String
        let itemType: ItemType
        let sourceName: String
        let sourceID: String
        let folderPath: String?
        let scrapeMachineName: String?
        let scrapeMachineId: String?
    }

    @Argument(help: "Item type: password, api-key, cert, note, ssh")
    var type: ItemType

    @Argument(help: "Item name/ID query (for individual load)", completion: .custom(ShellCompletionMetadata.completeItems))
    var query: String?

    @Option(
        name: .shortAndLong,
        help: "With <query>, match the exact folder; without <query>, load this folder tree",
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
        help: "Field to load (defaults: password/key/certificate/content/privateKey)",
        completion: .custom(ShellCompletionMetadata.completeLoadFields)
    )
    var field: Field?

    @Option(name: .long, help: "Output format: shell (default), json")
    var format: LoadOutputFormat = .shell

    @Flag(name: .customLong("json"), help: .hidden)
    var json = false

    @Flag(name: .long, help: "Emit KEY=value assignments without 'export ' prefix")
    var noExport = false

    @Flag(name: .long, help: "Apply values to current shell session via shell integration and emit no payload")
    var silent = false

    @Flag(name: .customLong("system-agent"), help: "Unsafe: copy SSH keys into the external ssh-agent instead of using Authsia's built-in agent")
    var systemAgent = false

    @Option(name: .customLong("ttl"), help: "Lifetime in seconds for SSH keys copied to the external ssh-agent")
    var ttlSeconds: Int?

    func run() throws {
        // SSH type routes to ssh-agent, not shell exports
        if type == .ssh {
            try runSSHAgentLoad()
            return
        }
        let outputFormat = try Self.resolveOutputFormat(format: format, jsonFlag: json)
        let shellIntegrationEnabled = Self.isShellIntegrationEnabled()
        let executionMode = try Self.resolveExecutionMode(
            format: outputFormat,
            silent: silent,
            shellIntegrationEnabled: shellIntegrationEnabled
        )
        let normalizedFolder = normalizeFolderPath(folder)
        if Self.isScopeSelectionMissing(query: query, folder: normalizedFolder, all: all, envName: env),
           Self.shouldMirrorErrorsToStdout() {
            print(
                "Error: Select scope with <query>, <query> --folder, --folder, --all, or --env. " +
                    "Example: authsia load api-key API_KEY"
            )
        }
        let scope = try Self.resolveScope(
            query: query,
            folder: normalizedFolder,
            all: all,
            envName: env
        )
        let environmentScope = try Self.environmentScope(
            query: query,
            folder: normalizedFolder,
            all: all,
            envName: env
        )

        try AuthsiaBridgeClient.shared.withRequestedCommand(.load) {
            let client: LoadVaultClient = AuthsiaBridgeClient.shared
            let authorizedPayload = try Self.applyAutomationAccess(
                to: try client.list(),
                scope: scope
            )
            let payload = Self.applyEnvironmentScope(environmentScope, to: authorizedPayload)
            let currentMachine = MachineIdentity.load()
            let references = try Self.selectReferences(
                type: type,
                scope: scope,
                payload: payload,
                allMachines: allMachines,
                currentMachineId: currentMachine.machineId,
                currentMachineName: currentMachine.displayName
            )
            let entries = try Self.loadEntries(
                type: type,
                references: references,
                field: field,
                client: client
            )
            try Self.validateUniqueKeys(entries)

            let output = try Self.render(entries: entries, format: outputFormat, includeExport: !noExport)

            switch executionMode {
            case .printOutput:
                if isatty(fileno(Darwin.stderr)) != 0 {
                    StandardError.writeLine(
                        "Hint: Use 'authsia exec' to inject secrets into a single command without exposing them to the shell."
                    )
                }
                print(output)
            case .shellIntegration:
                try Self.emitShellIntegrationOutput(output)
            }
        }
    }

    private func runSSHAgentLoad() throws {
        let validation = Self.validateSSHFlags(
            field: field,
            format: format,
            silent: silent,
            systemAgent: systemAgent,
            ttlSeconds: ttlSeconds
        )
        if !validation.isValid, let msg = validation.errorMessage {
            throw CLIError.unsupported(message: msg)
        }
        let ttlSeconds = ttlSeconds ?? 0

        // Fail fast: agent is a process-wide requirement
        guard SSHAgentLoader.isAgentRunning() else {
            throw SSHAgentLoader.AgentError.noAgent
        }
        guard !SSHAgentLoader.isUsingAuthsiaBuiltInAgent() else {
            throw CLIError.unsupported(
                message: "--system-agent requires an external ssh-agent, but SSH_AUTH_SOCK points to Authsia's built-in agent. Start one with `eval $(ssh-agent)` in this shell, then rerun the command before `authsia init` resets SSH_AUTH_SOCK."
            )
        }

        let normalizedFolder = normalizeFolderPath(folder)
        if Self.isScopeSelectionMissing(query: query, folder: normalizedFolder, all: all, envName: env),
           Self.shouldMirrorErrorsToStdout() {
            print(
                "Error: Select scope with <query>, <query> --folder, --folder, --all, or --env. " +
                    "Example: authsia load ssh DeployKey --system-agent --ttl 3600"
            )
        }
        let scope = try Self.resolveScope(
            query: query,
            folder: normalizedFolder,
            all: all,
            envName: env
        )
        let environmentScope = try Self.environmentScope(
            query: query,
            folder: normalizedFolder,
            all: all,
            envName: env
        )
        try AuthsiaBridgeClient.shared.withRequestedCommand(.load) {
            let client: LoadVaultClient = AuthsiaBridgeClient.shared
            let authorizedPayload = try Self.applyAutomationAccess(
                to: try client.list(),
                scope: scope
            )
            let payload = Self.applyEnvironmentScope(environmentScope, to: authorizedPayload)
            let currentMachine = MachineIdentity.load()
            let references = try Self.selectReferences(
                type: .ssh,
                scope: scope,
                payload: payload,
                allMachines: allMachines,
                currentMachineId: currentMachine.machineId,
                currentMachineName: currentMachine.displayName
            )

            var loadedCount = 0
            var failures: [String] = []
            for reference in references {
                try Self.validateSSHSystemAgentReference(reference)
                do {
                    let result = try client.getSSH(query: reference.id, field: nil)
                    let output = try SSHAgentLoader.add(
                        privateKey: result.privateKey,
                        passphrase: result.passphrase,
                        keyName: reference.name,
                        ttlSeconds: ttlSeconds
                    )
                    print(output)
                    loadedCount += 1
                } catch {
                    if references.count == 1 {
                        throw error
                    }
                    failures.append("\(reference.name): \(error.localizedDescription)")
                    StandardError.writeLine(
                        "Warning: Failed to load SSH key '\(reference.name)': \(error.localizedDescription)"
                    )
                }
            }
            if loadedCount == 0, !failures.isEmpty {
                throw CLIError.unsupported(
                    message: "No SSH keys were loaded. First failure: \(failures[0])"
                )
            }
        }
    }

    static func resolveOutputFormat(format: LoadOutputFormat, jsonFlag: Bool) throws -> LoadOutputFormat {
        guard jsonFlag else {
            return format
        }
        FileHandle.standardError.write(
            Data("Warning: '--json' is deprecated for 'authsia load'; use '--format json'.\n".utf8)
        )
        return .json
    }

    static func resolveExecutionMode(
        format: LoadOutputFormat,
        silent: Bool,
        shellIntegrationEnabled: Bool
    ) throws -> ExecutionMode {
        guard silent else {
            return .printOutput
        }
        guard format == .shell else {
            throw CLIError.unsupported(
                message: "--silent is only supported with shell output (use --format shell)."
            ).asValidationError
        }
        guard shellIntegrationEnabled else {
            throw CLIError.unsupported(
                message:
                    "--silent requires shell integration. Run 'eval \"$(authsia init zsh)\"' " +
                    "or 'eval \"$(authsia init bash)\"', then add it to your shell startup file."
            ).asValidationError
        }
        return .shellIntegration
    }

    static func isShellIntegrationEnabled(environment: [String: String] = ProcessInfo.processInfo.environment) -> Bool {
        environment["AUTHSIA_SHELL_INTEGRATION"] == "1"
    }

    static func resolveShellExportFileDescriptor(
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> Int32? {
        guard let raw = environment["AUTHSIA_SHELL_EXPORT_FD"] else {
            return nil
        }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let descriptor = Int32(trimmed), descriptor > 2 else {
            return nil
        }
        return descriptor
    }

    static func emitShellIntegrationOutput(
        _ output: String,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) throws {
        guard let descriptor = resolveShellExportFileDescriptor(environment: environment) else {
            print(output)
            return
        }
        do {
            try writeShellExports(output, fileDescriptor: descriptor)
        } catch {
            // Descriptor can become stale (new shell, closed FD). Fall back to shell output.
            let warning =
                "Warning: shell integration pipe unavailable; " +
                "run 'eval \"$(authsia init zsh)\"' (or bash) and retry --silent.\n"
            FileHandle.standardError.write(
                Data(warning.utf8)
            )
            print(output)
        }
    }

    static func writeShellExports(
        _ output: String,
        fileDescriptor: Int32
    ) throws {
        // Explicitly ignore SIGPIPE to prevent the CLI from crashing when
        // writing to a stale or closed file descriptor pipe.
        signal(SIGPIPE, SIG_IGN)

        let payload = output.hasSuffix("\n") ? output : "\(output)\n"
        let framed = "\(payload)__AUTHSIA_EOF__\n"
        let data = Data(framed.utf8)
        let handle = FileHandle(fileDescriptor: fileDescriptor, closeOnDealloc: false)
        try handle.write(contentsOf: data)
    }

    static func resolveScope(query: String?, folder: String?, all: Bool) throws -> ScopeSelection {
        let trimmedQuery = query?.trimmingCharacters(in: .whitespacesAndNewlines)
        let hasQuery = !(trimmedQuery ?? "").isEmpty
        let hasFolder = folder != nil

        if hasQuery && all {
            throw CLIError.unsupported(
                message: "Provide either <query>, <query> with --folder, --folder, or --all. " +
                    "Examples: authsia load api-key API_KEY; authsia load password --folder Team/API"
            ).asValidationError
        }
        if hasFolder && all {
            throw CLIError.unsupported(
                message: "Use either --folder or --all, not both. " +
                    "Example: authsia load password --folder Team/API"
            ).asValidationError
        }
        if hasQuery, let folder {
            return .itemInFolder(query: trimmedQuery ?? "", folderPath: folder)
        }
        if hasQuery {
            return .single(trimmedQuery ?? "")
        }
        if let folder {
            return .folder(folder)
        }
        if all {
            return .global
        }
        throw CLIError.unsupported(
            message: "Select scope with <query>, --folder, or --all. " +
                "Examples: authsia load api-key API_KEY; authsia load password --all"
        ).asValidationError
    }

    static func resolveScope(
        query: String?,
        folder: String?,
        all: Bool,
        envName: String?,
        store: EnvironmentProfileStore = EnvironmentProfileStore()
    ) throws -> ScopeSelection {
        let trimmedQuery = query?.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedFolder = normalizeFolderPath(folder)
        let hasExplicitScope = !(trimmedQuery ?? "").isEmpty || normalizedFolder != nil || all

        if hasExplicitScope {
            return try resolveScope(query: trimmedQuery, folder: normalizedFolder, all: all)
        }

        if let envName = envName?.trimmingCharacters(in: .whitespacesAndNewlines),
           !envName.isEmpty {
            guard let profile = try store.load(named: envName) else {
                throw ValidationError(
                    "No environment profile named '\(envName)' was found. Run `authsia env list`, " +
                        "or create it with `authsia env add --name \(envName) --folder <folder>`."
                )
            }
            return scopeSelection(for: profile)
        }

        if let active = try store.loadActiveProfile() {
            return scopeSelection(for: active)
        }

        throw CLIError.unsupported(
            message: "Select scope with <query>, <query> --folder, --folder, --all, or --env. " +
                "Examples: authsia load api-key API_KEY; authsia load password --env Production"
        ).asValidationError
    }

    static func environmentScope(
        query: String?,
        folder: String?,
        all: Bool,
        envName: String?,
        store: EnvironmentProfileStore = EnvironmentProfileStore()
    ) throws -> EnvironmentAccessScope? {
        let hasExplicitScope = !(query?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "").isEmpty ||
            normalizeFolderPath(folder) != nil || all
        guard !hasExplicitScope else { return nil }
        if let name = envName?.trimmingCharacters(in: .whitespacesAndNewlines), !name.isEmpty {
            guard let profile = try store.load(named: name) else { return nil }
            return .named(profile.name)
        }
        return try store.loadActiveProfile().map { .named($0.name) }
    }

    static func applyEnvironmentScope(
        _ environmentScope: EnvironmentAccessScope?,
        to payload: BridgeListPayload
    ) -> BridgeListPayload {
        AutomationAccessResolver.filterPayload(
            payload,
            allowedScope: nil,
            environmentScope: environmentScope
        )
    }

    private static func scopeSelection(for profile: EnvironmentProfile) -> ScopeSelection {
        switch profile.scope {
        case .all:
            return .global
        case .folders(let paths):
            if paths.count == 1, let path = paths.first {
                return .folder(path)
            }
            return .folders(paths)
        }
    }

    static func isScopeSelectionMissing(query: String?, folder: String?, all: Bool) -> Bool {
        let trimmedQuery = query?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return trimmedQuery.isEmpty && folder == nil && !all
    }

    static func isScopeSelectionMissing(
        query: String?,
        folder: String?,
        all: Bool,
        envName: String?,
        store: EnvironmentProfileStore = EnvironmentProfileStore()
    ) -> Bool {
        guard isScopeSelectionMissing(query: query, folder: folder, all: all) else {
            return false
        }
        if let envName = envName?.trimmingCharacters(in: .whitespacesAndNewlines),
           !envName.isEmpty {
            return false
        }
        return (try? store.loadActiveProfile()) == nil
    }

    static func applyAutomationAccess(
        to payload: BridgeListPayload,
        scope: ScopeSelection,
        requiredCapability: CapabilityCommand = .load,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        store: AccessCredentialStore = AccessCredentialStore(),
        now: Date = Date()
    ) throws -> BridgeListPayload {
        guard let credential = try AutomationAccessResolver.resolveActiveCredential(
            environment: environment,
            store: store,
            now: now
        ) else {
            return payload
        }

        try AutomationAccessResolver.authorizeCommand(requiredCapability, credential: credential)
        try AutomationAccessResolver.validateScopeSelection(scope, allowedScope: credential.scope)
        return AutomationAccessResolver.filterPayload(payload, allowedScope: credential.scope, environmentScope: credential.environmentScope)
    }

    static func shouldMirrorErrorsToStdout() -> Bool {
        let stderrIsTTY = isatty(fileno(Darwin.stderr)) != 0
        let stdoutIsTTY = isatty(fileno(Darwin.stdout)) != 0
        return shouldMirrorErrorsToStdout(stderrIsTTY: stderrIsTTY, stdoutIsTTY: stdoutIsTTY)
    }

    static func shouldMirrorErrorsToStdout(stderrIsTTY: Bool, stdoutIsTTY: Bool) -> Bool {
        !stderrIsTTY && stdoutIsTTY
    }

    static func selectReferences(
        type: ItemType,
        scope: ScopeSelection,
        payload: BridgeListPayload,
        allMachines: Bool = false,
        currentMachineId: String = MachineIdentity.load().machineId,
        currentMachineName: String? = MachineIdentity.load().displayName
    ) throws -> [ItemReference] {
        let references: [ItemReference]
        switch type {
        case .password:
            references = payload.passwords.map {
                ItemReference(
                    id: $0.id.uuidString,
                    name: $0.name,
                    folderPath: $0.folderPath,
                    isCliEnabled: $0.isCliEnabled,
                    isScraped: $0.isScraped,
                    scrapeMachineName: $0.scrapeMachineName,
                    scrapeMachineId: $0.scrapeMachineId
                )
            }
        case .apiKey:
            references = payload.apiKeys.map {
                ItemReference(
                    id: $0.id.uuidString,
                    name: $0.name,
                    folderPath: $0.folderPath,
                    isCliEnabled: $0.isCliEnabled,
                    isScraped: $0.isScraped,
                    scrapeMachineName: $0.scrapeMachineName,
                    scrapeMachineId: $0.scrapeMachineId
                )
            }
        case .cert:
            references = payload.certificates.map {
                ItemReference(
                    id: $0.id.uuidString,
                    name: $0.name,
                    folderPath: $0.folderPath,
                    isCliEnabled: $0.isCliEnabled,
                    isScraped: $0.isScraped,
                    scrapeMachineName: $0.scrapeMachineName,
                    scrapeMachineId: $0.scrapeMachineId
                )
            }
        case .note:
            references = payload.notes.map {
                ItemReference(
                    id: $0.id.uuidString,
                    name: $0.title,
                    folderPath: $0.folderPath,
                    isCliEnabled: $0.isCliEnabled,
                    isScraped: $0.isScraped,
                    scrapeMachineName: $0.scrapeMachineName,
                    scrapeMachineId: $0.scrapeMachineId
                )
            }
        case .ssh:
            references = payload.sshKeys.map {
                ItemReference(
                    id: $0.id.uuidString,
                    name: $0.name,
                    folderPath: $0.folderPath,
                    isCliEnabled: $0.isCliEnabled,
                    isScraped: $0.isScraped,
                    scrapeMachineName: $0.scrapeMachineName,
                    scrapeMachineId: $0.scrapeMachineId,
                    sshApprovalPolicy: $0.approvalPolicy.rawValue,
                    sshBoundHosts: $0.boundHosts
                )
            }
        }

        let visibleReferences = references.filter {
            ScrapedItemMachineSupport.shouldInclude(
                isScraped: $0.isScraped,
                scrapeMachineName: $0.scrapeMachineName,
                scrapeMachineId: $0.scrapeMachineId,
                currentMachineId: currentMachineId,
                currentMachineName: currentMachineName,
                allMachines: allMachines
            )
        }

        switch scope {
        case .single(let query):
            let match = try MatchHelper.findSingle(
                query: query,
                items: visibleReferences,
                kind: "\(type.rawValue) item",
                id: { $0.id },
                searchable: { [$0.name] },
                display: { matchDescriptor(for: $0) }
            )
            // Fail explicitly when the item exists but CLI access is disabled; don't silently skip.
            guard match.isCliEnabled else {
                throw CLIError.unsupported(
                    message: "CLI access is disabled for '\(match.name)'. Enable it in the Authsia app under item settings."
                )
            }
            return [match]
        case .itemInFolder(let query, let folderPath):
            let normalizedFolderPath = normalizeFolderPath(folderPath) ?? folderPath
            let exactFolderReferences = visibleReferences.filter {
                normalizeFolderPath($0.folderPath) == normalizedFolderPath
            }
            let match = try MatchHelper.findSingle(
                query: query,
                items: exactFolderReferences,
                kind: "\(type.rawValue) item",
                id: { $0.id },
                searchable: { [$0.name] },
                display: { matchDescriptor(for: $0) }
            )
            guard match.isCliEnabled else {
                throw CLIError.unsupported(
                    message: "CLI access is disabled for '\(match.name)'. Enable it in the Authsia app under item settings."
                )
            }
            return [match]
        case .folder(let folderPath):
            let filtered = visibleReferences.filter {
                $0.isCliEnabled && folderMatches(itemFolderPath: $0.folderPath, filterFolderPath: folderPath)
            }
            guard !filtered.isEmpty else {
                throw CLIError.noMatch(kind: "\(type.rawValue) items", query: folderPath)
            }
            return sortReferences(filtered)
        case .folders(let folderPaths):
            let filtered = visibleReferences.filter { reference in
                reference.isCliEnabled && folderPaths.contains {
                    folderMatches(itemFolderPath: reference.folderPath, filterFolderPath: $0)
                }
            }
            guard !filtered.isEmpty else {
                throw CLIError.noMatch(kind: "\(type.rawValue) items", query: folderPaths.joined(separator: ", "))
            }
            return sortReferences(filtered)
        case .global:
            let filtered = visibleReferences.filter { $0.isCliEnabled }
            guard !filtered.isEmpty else {
                throw CLIError.noMatch(kind: "\(type.rawValue) items", query: "*")
            }
            return sortReferences(filtered)
        }
    }

    static func selectExactFolderReference(
        type: ItemType,
        query: String,
        folderPath: String,
        payload: BridgeListPayload,
        allMachines: Bool = false,
        currentMachineId: String = MachineIdentity.load().machineId,
        currentMachineName: String? = MachineIdentity.load().displayName
    ) throws -> ItemReference {
        let normalizedFolderPath = normalizeFolderPath(folderPath) ?? folderPath
        let references = try selectReferences(
            type: type,
            scope: .itemInFolder(query: query, folderPath: normalizedFolderPath),
            payload: payload,
            allMachines: allMachines,
            currentMachineId: currentMachineId,
            currentMachineName: currentMachineName
        )
        return references[0]
    }

    static func loadEntries(
        type: ItemType,
        references: [ItemReference],
        field: Field?,
        client: LoadVaultClient
    ) throws -> [LoadedEntry] {
        let resolvedField = try resolveField(for: type, field: field)

        var entries: [LoadedEntry] = []
        entries.reserveCapacity(references.count)
        var failures: [String] = []

        for reference in references {
            let value: String
            do {
                switch type {
                case .password:
                    let result = try client.getPassword(query: reference.id, field: resolvedField.rawValue)
                    switch resolvedField {
                    case .username:
                        value = result.username
                    case .password:
                        value = result.password
                    default:
                        throw CLIError.unsupported(
                            message: "Unsupported field '\(resolvedField.rawValue)' for password."
                        ).asValidationError
                    }
                case .apiKey:
                    let result = try client.getAPIKey(query: reference.id, field: resolvedField.rawValue)
                    switch resolvedField {
                    case .key:
                        value = result.key
                    default:
                        throw CLIError.unsupported(
                            message: "Unsupported field '\(resolvedField.rawValue)' for api-key."
                        ).asValidationError
                    }
                case .cert:
                    let result = try client.getCertificate(query: reference.id, field: resolvedField.rawValue)
                    switch resolvedField {
                    case .certificate:
                        value = result.certificate
                    case .privateKey:
                        guard let privateKey = result.privateKey else {
                            throw CLIError.unsupported(
                                message: "Certificate '\(reference.name)' has no private key to load."
                            ).asValidationError
                        }
                        value = privateKey
                    default:
                        throw CLIError.unsupported(
                            message: "Unsupported field '\(resolvedField.rawValue)' for certificate."
                        ).asValidationError
                    }
                case .note:
                    let result = try client.getNote(query: reference.id)
                    switch resolvedField {
                    case .content:
                        value = result.content
                    default:
                        throw CLIError.unsupported(
                            message: "Unsupported field '\(resolvedField.rawValue)' for note."
                        ).asValidationError
                    }
                case .ssh:
                    // This branch is unreachable: Load.run() returns early via runSSHAgentLoad()
                    // when type == .ssh, before loadEntries is called.
                    // Kept to satisfy exhaustive switch; never executed at runtime.
                    let result = try client.getSSH(query: reference.id, field: resolvedField.rawValue)
                    switch resolvedField {
                    case .publicKey:
                        value = result.publicKey
                    case .privateKey:
                        value = result.privateKey
                    case .comment:
                        value = result.comment
                    case .fingerprint:
                        value = result.fingerprint
                    default:
                        throw CLIError.unsupported(
                            message: "Unsupported field '\(resolvedField.rawValue)' for ssh."
                        ).asValidationError
                    }
                }
                
                entries.append(
                    LoadedEntry(
                        key: environmentKey(from: reference.name),
                        value: value,
                        itemType: type,
                        sourceName: reference.name,
                        sourceID: reference.id,
                        folderPath: reference.folderPath,
                        scrapeMachineName: reference.scrapeMachineName,
                        scrapeMachineId: reference.scrapeMachineId
                    )
                )
            } catch {
                if references.count == 1 {
                    throw error
                }
                failures.append("\(reference.name): \(error.localizedDescription)")
                StandardError.writeLine(
                    "Warning: Failed to load \(type.rawValue) '\(reference.name)': \(error.localizedDescription)"
                )
                continue
            }
        }

        if entries.isEmpty, !failures.isEmpty {
            throw CLIError.unsupported(
                message:
                    "No \(type.rawValue) values were loaded. " +
                    "First failure: \(failures[0])"
            )
        }

        return entries
    }

    static func validateField(for type: ItemType, field: Field?) throws {
        _ = try resolveField(for: type, field: field)
    }

    static func validateUniqueKeys(_ entries: [LoadedEntry]) throws {
        let duplicates = Dictionary(grouping: entries, by: \.key)
            .filter { $0.value.count > 1 }
            .sorted { $0.key < $1.key }

        guard duplicates.isEmpty else {
            let detail = duplicates.map { key, values in
                let names = values.map(\.sourceName).sorted().joined(separator: ", ")
                return "\(key) -> [\(names)]"
            }.joined(separator: "; ")
            throw CLIError.unsupported(
                message: "Duplicate environment keys after normalization: \(detail). " +
                    "Rename vault items to unique variable keys."
            ).asValidationError
        }
    }

    static func render(entries: [LoadedEntry], format: LoadOutputFormat, includeExport: Bool) throws -> String {
        switch format {
        case .shell:
            return entries.map { entry in
                let assignment = "\(entry.key)=\(shellQuote(entry.value))"
                return includeExport ? "export \(assignment)" : assignment
            }.joined(separator: "\n")
        case .json:
            return try OutputFormatter.encodeJSON(entries)
        }
    }

    static func environmentKey(from sourceName: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "_"))
        let mapped = sourceName.unicodeScalars.map { scalar -> Character in
            allowed.contains(scalar) ? Character(scalar) : "_"
        }
        var key = String(mapped)
            .replacingOccurrences(of: "_+", with: "_", options: .regularExpression)
            .trimmingCharacters(in: CharacterSet(charactersIn: "_"))

        if key.isEmpty {
            key = "AUTHSIA_SECRET"
        }
        if let first = key.unicodeScalars.first, CharacterSet.decimalDigits.contains(first) {
            key = "_\(key)"
        }
        return key
    }

    static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }

    private static func resolveField(for type: ItemType, field: Field?) throws -> Field {
        let candidate = field ?? type.defaultField
        guard type.supportedFields.contains(candidate) else {
            let supported = type.supportedFields.map(\.rawValue).joined(separator: ", ")
            throw CLIError.unsupported(
                message: "Field '\(candidate.rawValue)' is not supported for \(type.rawValue). Supported: \(supported). " +
                    "Retry with one of the supported --field values or omit --field for the default."
            ).asValidationError
        }
        return candidate
    }

    private static func sortReferences(_ references: [ItemReference]) -> [ItemReference] {
        references.sorted { lhs, rhs in
            let compared = lhs.name.localizedCaseInsensitiveCompare(rhs.name)
            if compared == .orderedSame {
                return lhs.id < rhs.id
            }
            return compared == .orderedAscending
        }
    }

    private static func matchDescriptor(for reference: ItemReference) -> CLIError.MatchDescriptor {
        let folder = normalizeFolderPath(reference.folderPath) ?? "(root)"
        return CLIError.MatchDescriptor(name: reference.name, id: reference.id, context: "folder: \(folder)")
    }
}

protocol LoadVaultClient {
    func list() throws -> BridgeListPayload
    func getPassword(query: String, field: String?) throws -> PasswordResult
    func getAPIKey(query: String, field: String?) throws -> APIKeyResult
    func getCertificate(query: String, field: String?) throws -> CertificateResult
    func getNote(query: String) throws -> NoteResult
    func getSSH(query: String, field: String?) throws -> SSHKeyResult
}

extension AuthsiaBridgeClient: LoadVaultClient {}
