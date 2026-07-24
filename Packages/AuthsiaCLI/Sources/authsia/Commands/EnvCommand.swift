import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import Foundation

struct Env: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "env",
        abstract: "Manage environment profiles",
        subcommands: [Add.self, List.self, Show.self, Use.self, Clear.self]
    )

    struct ListItem: Codable, Equatable, Identifiable {
        var id: String { name }

        let name: String
        let scope: String
        let folderPath: String?
        let folderPaths: [String]
        let defaultMachineId: String?
        let isActive: Bool
    }

    struct Add: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "add",
            abstract: "Add an environment profile"
        )

        @Option(name: .long, help: "Environment profile name")
        var name: String

        @Option(
            name: .shortAndLong,
            help: "Folder path to use when no explicit scope is selected; repeat for multiple folders",
            completion: .custom(ShellCompletionMetadata.completeFolders)
        )
        var folder: [String] = []

        @Flag(name: .long, help: "Use all CLI-enabled items of the selected type")
        var all = false

        func run() throws {
            let profile = try Env.addProfile(name: name, folders: folder, all: all)
            print(Env.renderAddMessage(profile))
        }
    }

    struct List: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "list",
            abstract: "List environment profiles"
        )

        @Option(name: .long, help: "Output format: table (default), json")
        var format: OutputFormat = .table

        func run() async throws {
            if let root = Env.currentWorkspaceRoot() {
                print(try await Env.renderWorkspaceList(root: root, format: format))
            } else {
                let items = try Env.listItems()
                print(try Env.renderList(items: items, format: format))
            }
        }
    }

    struct Show: ParsableCommand {
        static let configuration = CommandConfiguration(commandName: "show", abstract: "Show the active workspace environment or profile")

        func run() throws {
            if let root = Env.currentWorkspaceRoot() {
                let active = try WorkspaceEnvironmentSelectionStore().activeEnvironment(for: root)
                print(active.map { "Active workspace environment: \($0)." } ?? "Active workspace environment: Default environment.")
            } else {
                let active = try EnvironmentProfileStore().loadActiveProfileName()
                print(active.map { "Active environment profile: \($0)." } ?? "No active environment profile.")
            }
        }
    }

    struct Use: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "use",
            abstract: "Set the active environment profile"
        )

        @Argument(help: "Environment profile name")
        var name: String

        func run() async throws {
            if let root = Env.currentWorkspaceRoot() {
                let normalized = try await Env.validateWorkspaceEnvironment(name, root: root)
                try WorkspaceEnvironmentSelectionStore().setActiveEnvironment(normalized, for: root)
                print("Active workspace environment set to \(normalized).")
            } else {
                let profile = try Env.useProfile(name: name)
                print("Active environment set to \(profile.name).")
            }
        }
    }

    struct Clear: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "clear",
            abstract: "Clear the active environment profile"
        )

        func run() throws {
            if let root = Env.currentWorkspaceRoot() {
                let cleared = try WorkspaceEnvironmentSelectionStore().clearActiveEnvironment(for: root)
                print(cleared ? "Active workspace environment cleared. Default environment is active." : "Workspace already uses Default environment.")
            } else {
                print(try Env.clearActiveProfile())
            }
        }
    }

    static func addProfile(
        name: String,
        folder: String,
        store: EnvironmentProfileStore = EnvironmentProfileStore()
    ) throws -> EnvironmentProfile {
        try addProfile(name: name, folders: [folder], all: false, store: store)
    }

    static func addProfile(
        name: String,
        folders: [String],
        all: Bool,
        store: EnvironmentProfileStore = EnvironmentProfileStore()
    ) throws -> EnvironmentProfile {
        let normalizedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedName.isEmpty else {
            throw ValidationError("Environment name cannot be empty. Example: authsia env add --name Production --all")
        }

        if all && !folders.isEmpty {
            throw ValidationError(
                "Use either --all or --folder, not both. " +
                    "Example: authsia env add --name Production --folder Team/API"
            )
        }

        let scope: EnvironmentProfileScope
        if all {
            scope = .all
        } else {
            var normalizedFolders: [String] = []
            for folder in folders {
                guard let normalizedFolder = normalizeFolderPath(folder) else {
                    throw ValidationError(
                        "Environment folder cannot be empty. Example: authsia env add --name Production --folder Team/API"
                    )
                }
                if !normalizedFolders.contains(normalizedFolder) {
                    normalizedFolders.append(normalizedFolder)
                }
            }
            guard !normalizedFolders.isEmpty else {
                throw ValidationError(
                    "Provide --all or at least one --folder. " +
                        "Examples: authsia env add --name Production --all; " +
                        "authsia env add --name Production --folder Team/API"
                )
            }
            scope = .folders(normalizedFolders)
        }

        let profile = EnvironmentProfile(
            name: normalizedName,
            scope: scope,
            defaultMachineId: nil
        )
        try store.save(profile)
        return profile
    }

    static func listItems(
        store: EnvironmentProfileStore = EnvironmentProfileStore()
    ) throws -> [ListItem] {
        let activeName = try store.loadActiveProfileName()
        return try store.loadAll()
            .sorted {
                if $0.name != $1.name {
                    return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
                }
                return $0.scopeDisplayName.localizedCaseInsensitiveCompare($1.scopeDisplayName) == .orderedAscending
            }
            .map {
                ListItem(
                    name: $0.name,
                    scope: $0.scopeDisplayName,
                    folderPath: $0.folderPaths.first,
                    folderPaths: $0.folderPaths,
                    defaultMachineId: $0.defaultMachineId,
                    isActive: $0.name == activeName
                )
            }
    }

    static func useProfile(
        name: String,
        store: EnvironmentProfileStore = EnvironmentProfileStore()
    ) throws -> EnvironmentProfile {
        let normalizedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedName.isEmpty else {
            throw ValidationError("Environment name cannot be empty. Run `authsia env list` to see profile names.")
        }
        return try store.setActive(name: normalizedName)
    }

    static func clearActiveProfile(
        store: EnvironmentProfileStore = EnvironmentProfileStore()
    ) throws -> String {
        try store.clearActive() ? "Active environment cleared." : "No active environment profile."
    }

    static func renderAddMessage(_ profile: EnvironmentProfile) -> String {
        "Added environment profile \(profile.name) -> \(profile.scopeDisplayName)."
    }

    static func renderList(
        items: [ListItem],
        format: OutputFormat
    ) throws -> String {
        switch format {
        case .json:
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(items)
            return String(decoding: data, as: UTF8.self)
        case .table:
            return renderTable(items: items)
        }
    }

    private static func renderTable(items: [ListItem]) -> String {
        if items.isEmpty {
            return "No environment profiles found."
        }

        let headers = ["Name", "Scope", "Active", "Machine"]
        let rows = items.map {
            [
                $0.name,
                $0.scope,
                $0.isActive ? "yes" : "no",
                $0.defaultMachineId ?? "",
            ]
        }

        return TableFormatter.renderTable(headers: headers, rows: rows)
    }

    private struct WorkspaceListItem: Codable {
        let name: String
        let isActive: Bool
        let referencedItemCount: Int
        let matchingProfileScope: String?
    }

    private static func renderWorkspaceList(root: URL, format: OutputFormat) async throws -> String {
        let config = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        guard config.schemaVersion >= 2 else {
            return "Workspace uses schema v1. Run `authsia workspace update` to enable workspace environments."
        }
        let status = try await WorkspaceStatusReporter.build(workspaceRoot: root)
        let payload = try AuthsiaBridgeClient.shared.workspaceMetadata(
            Workspace.workspaceStatusMetadataRequest(status),
            requestedCommand: BridgeContext.workspaceEnvListRequestedCommand
        )
        let evaluation = try workspaceEnvironmentEvaluation(
            root: root,
            config: config,
            payload: payload,
            selection: .defaultOnly
        )
        let active = try WorkspaceEnvironmentSelectionStore().activeEnvironment(for: root)
        let profiles = try EnvironmentProfileStore().loadAll()
        let items = workspaceEnvironmentNames(payload).map { name in
            WorkspaceListItem(
                name: name,
                isActive: active.map { VaultEnvironmentTags.contains($0, in: [name]) } ?? false,
                referencedItemCount: referencedItemCount(name, evaluation: evaluation),
                matchingProfileScope: profiles.first(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame })?.scopeDisplayName
            )
        }
        switch format {
        case .json:
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            return String(decoding: try encoder.encode(items), as: UTF8.self)
        case .table:
            if items.isEmpty { return "No tagged workspace items found. Default environment is active." }
            return TableFormatter.renderTable(
                headers: ["Name", "Active", "References", "Matching profile"],
                rows: items.map { [$0.name, $0.isActive ? "yes" : "no", String($0.referencedItemCount), $0.matchingProfileScope ?? ""] }
            )
        }
    }

    private static func validateWorkspaceEnvironment(_ name: String, root: URL) async throws -> String {
        let normalized = VaultEnvironmentTags.normalize([name]).first ?? ""
        let config = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        guard config.schemaVersion >= 2 else {
            throw ValidationError("Workspace environment selection requires schema v2. Run `authsia workspace update` first.")
        }
        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["/usr/bin/true"]
        )
        let payload = try AuthsiaBridgeClient.shared.workspaceMetadata(
            try Workspace.Run.validationMetadataRequest(for: plan),
            requestedCommand: BridgeContext.workspaceEnvUseRequestedCommand
        )
        let status = try await WorkspaceStatusReporter.build(
            workspaceRoot: root,
            vaultIndex: WorkspaceVaultIndex(payload: payload),
            activeEnvironment: normalized
        )
        return try validatedWorkspaceEnvironmentName(normalized, status: status)
    }

    static func validatedWorkspaceEnvironmentName(
        _ name: String,
        status: WorkspaceStatus
    ) throws -> String {
        let normalized = VaultEnvironmentTags.normalize([name]).first ?? ""
        guard !normalized.isEmpty else {
            throw ValidationError("Environment name cannot be empty. Run `authsia env list`.")
        }
        guard let canonicalName = status.availableEnvironments.first(where: {
            VaultEnvironmentTags.contains(normalized, in: [$0])
        }) else {
            throw ValidationError(
                "Environment '\(normalized)' is not referenced by this workspace. Run `authsia env list`."
            )
        }
        guard status.missingReferences.isEmpty,
              status.unverifiedReferences.isEmpty,
              status.environmentIssueCount == 0 else {
            throw ValidationError(
                "Environment '\(canonicalName)' cannot be activated because workspace validation failed. " +
                    "Run `authsia workspace env validate`."
            )
        }
        return canonicalName
    }

    static func workspaceEnvironmentEvaluation(
        root: URL,
        config: WorkspaceConfig,
        payload: BridgeListPayload,
        selection: WorkspaceEnvironmentSelection
    ) throws -> WorkspaceEnvironmentEvaluation {
        let envFiles = config.managedEnvFiles.map { root.appendingPathComponent($0).path }
        return try WorkspaceEnvironmentEvaluation.evaluate(
            config: config,
            envFiles: envFiles,
            payload: payload,
            selection: selection
        )
    }

    static func workspaceEnvironmentNames(_ payload: BridgeListPayload) -> [String] {
        VaultEnvironmentTags.selectableEnvironments(
            payload.passwords.flatMap(\.environments) +
                payload.apiKeys.flatMap(\.environments)
        )
    }

    private static func referencedItemCount(
        _ name: String,
        evaluation: WorkspaceEnvironmentEvaluation
    ) -> Int {
        let candidates = evaluation.resolution.effective +
            evaluation.resolution.overridden +
            evaluation.resolution.inactive
        return candidates.filter { VaultEnvironmentTags.contains(name, in: $0.environments) }.count
    }

    private static func currentWorkspaceRoot() -> URL? {
        WorkspaceRootResolver.findWorkspaceRoot(
            startingAt: URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
        )
    }
}
