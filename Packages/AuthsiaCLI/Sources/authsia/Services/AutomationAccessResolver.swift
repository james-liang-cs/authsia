import ArgumentParser
import Foundation
import Darwin
import AuthenticatorBridge
import AuthenticatorCore

enum AutomationAccessResolver {
    static let environmentKey = AutomationCredentialEnvironment.generalCredentialKey
    static let sshEnvironmentKey = AutomationCredentialEnvironment.sshCredentialKey

    static func resolveActiveCredential(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        store: AccessCredentialStore = AccessCredentialStore(),
        now: Date = Date()
    ) throws -> AccessCredential? {
        guard let rawValue = environment[environmentKey]?.trimmingCharacters(in: .whitespacesAndNewlines),
              !rawValue.isEmpty else {
            return nil
        }

        return try resolveActiveCredential(idString: rawValue, store: store, now: now)
    }

    static func resolveActiveSSHCredential(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        store: AccessCredentialStore = AccessCredentialStore(),
        now: Date = Date()
    ) throws -> AccessCredential? {
        if let rawValue = environment[sshEnvironmentKey]?.trimmingCharacters(in: .whitespacesAndNewlines),
           !rawValue.isEmpty {
            return try resolveActiveCredential(idString: rawValue, store: store, now: now)
        }
        return try resolveActiveCredential(environment: environment, store: store, now: now)
    }

    private static func resolveActiveCredential(
        idString rawValue: String,
        store: AccessCredentialStore,
        now: Date
    ) throws -> AccessCredential {
        let parsedToken: AutomationCredentialToken.Parsed
        do {
            parsedToken = try AutomationCredentialToken.parse(rawValue)
        } catch {
            throw ValidationError(
                "Invalid automation credential token. Legacy UUID credentials are disabled; " +
                    "create a new one with `authsia access create`."
            )
        }

        guard let credential = try store.load(id: parsedToken.id) else {
            throw ValidationError(
                "No local metadata found for this automation credential. Run `authsia access list --all`, " +
                    "or create a new one with `authsia access create`."
            )
        }

        switch credential.status(asOf: now) {
        case .active:
            return credential.withBearerToken(rawValue)
        case .expired:
            throw ValidationError(
                "Automation credential '\(credential.name)' (\(credential.id.uuidString)) has expired. " +
                    "Create a new one with `authsia access create`."
            )
        case .revoked:
            throw ValidationError(
                "Automation credential '\(credential.name)' (\(credential.id.uuidString)) has been revoked. " +
                    "Create a new one with `authsia access create`."
            )
        }
    }

    static func validateScopeSelection(
        _ scope: Load.ScopeSelection,
        allowedScope: String?
    ) throws {
        guard let normalizedAllowedScope = AutomationCredentialScope.normalizeStored(allowedScope) else {
            throw ValidationError(
                "Automation credential scope is invalid. Recreate it with `authsia access create --scope <folder>`."
            )
        }
        let allowedScopeName = AutomationCredentialScope.displayName(normalizedAllowedScope)
        if AutomationCredentialScope.isGlobal(normalizedAllowedScope) {
            return
        }

        switch scope {
        case .global:
            throw ValidationError(
                "Automation credential scope '\(allowedScopeName)' does not allow --all. " +
                    "Use a query or --folder inside that scope, or create a wider credential with `authsia access create`."
            )
        case .folder(let folder):
            guard AutomationCredentialScope.contains(itemFolderPath: folder, normalizedScope: normalizedAllowedScope) else {
                throw ValidationError(
                    "Requested folder '\(folder)' is outside automation credential scope '\(allowedScopeName)'. " +
                        "Retry inside that scope or create a credential for this folder."
                )
            }
        case .itemInFolder(_, let folder):
            guard AutomationCredentialScope.contains(itemFolderPath: folder, normalizedScope: normalizedAllowedScope) else {
                throw ValidationError(
                    "Requested folder '\(folder)' is outside automation credential scope '\(allowedScopeName)'. " +
                        "Retry inside that scope or create a credential for this folder."
                )
            }
        case .folders(let folders):
            if let outsideFolder = folders.first(where: {
                !AutomationCredentialScope.contains(itemFolderPath: $0, normalizedScope: normalizedAllowedScope)
            }) {
                throw ValidationError(
                    "Requested folder '\(outsideFolder)' is outside automation credential scope '\(allowedScopeName)'. " +
                        "Retry inside that scope or create a credential for this folder."
                )
            }
        case .single:
            break
        }
    }

    static func filterPayload(
        _ payload: BridgeListPayload,
        allowedScope: String?,
        environmentScope: EnvironmentAccessScope? = nil
    ) -> BridgeListPayload {
        guard let normalizedAllowedScope = AutomationCredentialScope.normalizeStored(allowedScope) else {
            return BridgeListPayload(accounts: [], passwords: [], apiKeys: [], certificates: [], notes: [], sshKeys: [])
        }
        let matches: (String?) -> Bool = {
            AutomationCredentialScope.contains(itemFolderPath: $0, normalizedScope: normalizedAllowedScope)
        }

        return BridgeListPayload(
            accounts: [],
            passwords: environmentFiltered(payload.passwords.filter { matches($0.folderPath) }, scope: environmentScope, name: { $0.name }, environments: { $0.environments }),
            apiKeys: environmentFiltered(payload.apiKeys.filter { matches($0.folderPath) }, scope: environmentScope, name: { $0.name }, environments: { $0.environments }),
            certificates: environmentFiltered(payload.certificates.filter { matches($0.folderPath) }, scope: environmentScope, name: { $0.name }, environments: { $0.environments }),
            notes: environmentFiltered(payload.notes.filter { matches($0.folderPath) }, scope: environmentScope, name: { $0.title }, environments: { $0.environments }),
            sshKeys: environmentFiltered(payload.sshKeys.filter { matches($0.folderPath) }, scope: environmentScope, name: { $0.name }, environments: { $0.environments })
        )
    }

    private static func environmentFiltered<T>(
        _ items: [T],
        scope: EnvironmentAccessScope?,
        name: (T) -> String,
        environments: (T) -> [String]
    ) -> [T] {
        guard let scope else { return items }
        let eligible = items.filter { scope.allows(itemEnvironments: environments($0)) }
        let preferredNames: Set<String>
        switch scope {
        case .defaultOnly:
            preferredNames = Set(
                eligible.filter { environments($0).isEmpty }.map { name($0).lowercased() }
            )
        case .named(let selected):
            preferredNames = Set(
                eligible.filter {
                    VaultEnvironmentTags.contains(selected, in: environments($0))
                }.map { name($0).lowercased() }
            )
        }
        return eligible.filter { item in
            guard preferredNames.contains(name(item).lowercased()) else { return true }
            switch scope {
            case .defaultOnly:
                return environments(item).isEmpty
            case .named(let selected):
                return VaultEnvironmentTags.contains(selected, in: environments(item))
            }
        }
    }

    static func authorizeGetType(_ type: Get.ItemType) throws {
        guard type != .otp else {
            throw ValidationError(
                "Automation credentials do not permit OTP access. Use an interactive terminal for OTP requests."
            )
        }
    }

    /// Enforce that the credential permits the requested CLI command.
    /// Error message names the credential and command so operators can identify
    /// which credential needs widening when a legitimate use case is blocked.
    static func authorizeCommand(
        _ command: CapabilityCommand,
        credential: AccessCredential
    ) throws {
        guard credential.allowedCommands.contains(command) else {
            throw ValidationError(
                "Automation credential '\(credential.name)' does not permit '\(command.rawValue)'. " +
                "Allowed: \(credential.allowedCommands.map(\.rawValue).sorted().joined(separator: ", ")). " +
                "Create a new credential with `authsia access create --allow \(command.rawValue)`."
            )
        }
    }

    static func bridgeContext(
        requestedCommand: String? = nil,
        fullCommand: String? = nil,
        includeAutomationCredential: Bool = true,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        store: AccessCredentialStore = AccessCredentialStore(),
        now: Date = Date(),
        terminalIdentifier: String? = SessionCache.currentTerminalIdentifier(),
        processSessionIdentifier: Int32? = SessionCache.currentProcessSessionIdentifier(),
        ancestralScope: @escaping () -> String? = TerminalSessionScope.currentAncestralScope,
        currentDirectoryPath: String = FileManager.default.currentDirectoryPath,
        processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry(),
        agentRuntimeContextEventsURL: URL = AgentRuntimeContextResolver.defaultEventsURL,
        warningHandler: (String) -> Void = StandardError.writeLine
    ) -> BridgeContext {
        let credential: AccessCredential?
        if includeAutomationCredential {
            do {
                credential = try resolveActiveCredential(environment: environment, store: store, now: now)
            } catch {
                if !(error is ValidationError) {
                    warningHandler("Warning: automation credential not resolved: \(error.localizedDescription)")
                }
                credential = nil
            }
        } else {
            credential = nil
        }
        return BridgeContext(
            isTTY: isatty(FileHandle.standardInput.fileDescriptor) != 0,
            isPiped: isatty(FileHandle.standardOutput.fileDescriptor) == 0,
            isSSH: ProcessInfo.processInfo.environment["SSH_CLIENT"] != nil,
            isCI: ProcessInfo.processInfo.environment["CI"] != nil,
            timestamp: now,
            automationCredentialID: credential?.id.uuidString,
            automationCredentialToken: credential?.bearerToken,
            automationScope: credential?.scope,
            requestedCommand: requestedCommand,
            fullCommand: fullCommand,
            sessionScope: SessionCache.sessionScope(
                environment: environment,
                terminalIdentifier: terminalIdentifier,
                processSessionIdentifier: processSessionIdentifier,
                ancestralScope: ancestralScope,
                processAncestry: processAncestry,
                requestedCommand: requestedCommand
            ) ?? AgentRuntimeContextResolver.explicitAgentSessionScope(
                environment: environment,
                processSessionIdentifier: processSessionIdentifier
            ),
            workingDirectory: currentDirectoryPath,
            agentRuntimeContext: AgentRuntimeContextResolver.resolve(
                now: now,
                currentDirectoryPath: currentDirectoryPath,
                processAncestry: processAncestry,
                eventsURL: agentRuntimeContextEventsURL,
                environment: environment
            ),
            workspaceContext: WorkspaceRuntimeContextResolver.resolve(
                currentDirectoryPath: currentDirectoryPath
            )
        )
    }

    static func bridgeContext(
        requestedCommand: CapabilityCommand,
        includeAutomationCredential: Bool = true,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        store: AccessCredentialStore = AccessCredentialStore(),
        now: Date = Date(),
        terminalIdentifier: String? = SessionCache.currentTerminalIdentifier(),
        processSessionIdentifier: Int32? = SessionCache.currentProcessSessionIdentifier(),
        ancestralScope: @escaping () -> String? = TerminalSessionScope.currentAncestralScope,
        currentDirectoryPath: String = FileManager.default.currentDirectoryPath,
        processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry(),
        agentRuntimeContextEventsURL: URL = AgentRuntimeContextResolver.defaultEventsURL,
        warningHandler: (String) -> Void = StandardError.writeLine
    ) -> BridgeContext {
        bridgeContext(
            requestedCommand: requestedCommand.rawValue,
            includeAutomationCredential: includeAutomationCredential,
            environment: environment,
            store: store,
            now: now,
            terminalIdentifier: terminalIdentifier,
            processSessionIdentifier: processSessionIdentifier,
            ancestralScope: ancestralScope,
            currentDirectoryPath: currentDirectoryPath,
            processAncestry: processAncestry,
            agentRuntimeContextEventsURL: agentRuntimeContextEventsURL,
            warningHandler: warningHandler
        )
    }
}
