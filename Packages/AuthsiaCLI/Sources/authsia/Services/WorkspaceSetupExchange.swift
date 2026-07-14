import ArgumentParser
import AuthenticatorCore
import Foundation

enum WorkspaceSetupExchange {
    static let schemaVersion = 1

    enum Mode: String, Codable {
        case initWorkspace = "init"
        case update
    }

    struct PlanPayload: Codable, Equatable {
        let schemaVersion: Int
        let mode: Mode
        let workspace: WorkspacePayload
        let envFiles: [EnvFilePayload]
        let removedEnvFiles: [String]
        let agentRules: [AgentRulePayload]
        let missingReferences: [ReferencePayload]
        let unverifiedReferences: [ReferencePayload]
    }

    struct WorkspacePayload: Codable, Equatable {
        let name: String
        let root: String
        let authsiaFolder: String
    }

    struct EnvFilePayload: Codable, Equatable {
        let id: String
        let relativePath: String
        let selected: Bool
        let selectedByDefault: Bool
        let authsiaReferenceCount: Int
        let reviewItems: [SecretPayload]
        var suggestedEnvironment: String? = nil
        var environmentSuggestionConfirmed: Bool = false
    }

    struct SecretPayload: Codable, Equatable {
        let id: String
        let key: String
        let itemName: String
        let lineNumber: Int
        let type: String
        let confidence: String
        let selected: Bool
        let selectedByDefault: Bool
        let action: SecretAction
        let hasConflict: Bool
        let conflict: String?
        let storePath: String
        let replacementLine: String
        var environments: [String] = []
    }

    struct AgentRulePayload: Codable, Equatable {
        let id: String
        let label: String
        let targetPath: String
        let selected: Bool
        let selectedByDefault: Bool
        let state: String
    }

    struct ReferencePayload: Codable, Equatable {
        let relativePath: String
        let itemType: String
        let item: String
        let folderPath: String?
        let envBindingName: String?
        let displayLine: String
    }

    struct SyncPlanPayload: Codable, Equatable {
        let schemaVersion: Int
        let workspace: WorkspacePayload
        let rows: [SyncRowPayload]
    }

    struct SyncRowPayload: Codable, Equatable {
        let id: String
        let envName: String
        let itemName: String
        let itemType: String
        let expectedReference: String?
        let localReference: String?
        let folderPath: String
        let status: WorkspaceSyncStatus
        var selected: Bool
        var action: WorkspaceSyncAction
    }

    struct SyncSelectionPayload: Codable, Equatable {
        let schemaVersion: Int
        let rows: [SyncRowSelection]
    }

    struct SyncRowSelection: Codable, Equatable {
        let id: String
        let action: WorkspaceSyncAction
    }

    struct SelectionPayload: Codable, Equatable {
        let schemaVersion: Int
        let mode: Mode
        let authsiaFolder: String?
        let envFiles: [EnvFileSelection]
        let agentRules: [AgentRuleSelection]
    }

    struct EnvFileSelection: Codable, Equatable {
        let relativePath: String
        let selected: Bool
        let secrets: [SecretSelection]
    }

    struct SecretSelection: Codable, Equatable {
        let id: String
        let action: SecretAction
        var selectedEnvironments: [String]? = nil
    }

    struct AgentRuleSelection: Codable, Equatable {
        let id: String
        let selected: Bool
    }

    enum SecretAction: String, Codable, CaseIterable {
        case create
        case update
        case reuse
        case skip
    }

    struct ResolvedSelection {
        let envFiles: [WorkspaceEnvFilePlan]
        let secrets: [WorkspaceSecretSelection]
    }

    static func payload(for plan: WorkspaceInitPlan, mode: Mode) -> PlanPayload {
        let selectedAgents = Set(plan.agents)
        return PlanPayload(
            schemaVersion: schemaVersion,
            mode: mode,
            workspace: WorkspacePayload(
                name: plan.config.workspace.name,
                root: plan.workspaceRoot.path,
                authsiaFolder: plan.config.workspace.authsiaFolder
            ),
            envFiles: plan.envFiles.map { envFile in
                EnvFilePayload(
                    id: envFile.relativePath,
                    relativePath: envFile.relativePath,
                    selected: true,
                    selectedByDefault: true,
                    authsiaReferenceCount: envFile.authsiaReferenceCount,
                    reviewItems: envFile.secrets.map { secretPayload($0, in: envFile, folderPath: plan.config.workspace.authsiaFolder) },
                    suggestedEnvironment: WorkspaceEnvironmentSuggestion.from(path: envFile.relativePath)
                )
            },
            removedEnvFiles: plan.removedEnvFiles,
            agentRules: AgentTool.allCases.map { agent in
                let selected = selectedAgents.contains(agent)
                return AgentRulePayload(
                    id: agent.configName,
                    label: agent.title,
                    targetPath: agent.rulePath,
                    selected: selected,
                    selectedByDefault: selected,
                    state: selected ? "selected" : "available"
                )
            },
            missingReferences: plan.missingReferences.map(referencePayload),
            unverifiedReferences: plan.unverifiedReferences.map(referencePayload)
        )
    }

    static func printPlanJSON(_ plan: WorkspaceInitPlan, mode: Mode) throws {
        let payload = payload(for: plan, mode: mode)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(payload)
        guard let json = String(data: data, encoding: .utf8) else {
            throw ValidationError("Could not encode workspace setup plan.")
        }
        print(json)
    }

    static func syncPayload(for plan: WorkspaceSyncPlan, workspace: WorkspaceConfig.Workspace) -> SyncPlanPayload {
        SyncPlanPayload(
            schemaVersion: schemaVersion,
            workspace: WorkspacePayload(
                name: workspace.name,
                root: plan.workspaceRoot.path,
                authsiaFolder: plan.authsiaFolder
            ),
            rows: plan.rows.map { row in
                SyncRowPayload(
                    id: row.id,
                    envName: row.envName,
                    itemName: row.itemName,
                    itemType: row.itemType,
                    expectedReference: row.expectedReference,
                    localReference: row.localReference,
                    folderPath: row.folderPath,
                    status: row.status,
                    selected: row.selected,
                    action: row.action
                )
            }
        )
    }

    static func encodedSyncPayload(_ payload: SyncPlanPayload) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(payload)
    }

    static func printSyncPlanJSON(_ plan: WorkspaceSyncPlan, workspace: WorkspaceConfig.Workspace) throws {
        let payload = syncPayload(for: plan, workspace: workspace)
        let data = try encodedSyncPayload(payload)
        print(String(decoding: data, as: UTF8.self))
    }

    static func readSyncSelection(from path: String) throws -> SyncSelectionPayload {
        let url = URL(fileURLWithPath: path)
        let data = try Data(contentsOf: url)
        let payload = try JSONDecoder().decode(SyncSelectionPayload.self, from: data)
        guard payload.schemaVersion == schemaVersion else {
            throw ValidationError("Unsupported workspace sync selection schema version \(payload.schemaVersion).")
        }
        return payload
    }

    static func readSelection(from path: String) throws -> SelectionPayload {
        let url = URL(fileURLWithPath: path)
        let data = try Data(contentsOf: url)
        let payload = try JSONDecoder().decode(SelectionPayload.self, from: data)
        guard payload.schemaVersion == schemaVersion else {
            throw ValidationError(
                "Unsupported workspace setup selection schema version \(payload.schemaVersion)."
            )
        }
        return payload
    }

    static func selectedAgents(from selection: SelectionPayload) throws -> [AgentTool] {
        try selection.agentRules.compactMap { rule in
            guard rule.selected else { return nil }
            guard let agent = AgentTool(argument: rule.id) else {
                throw ValidationError("Unsupported workspace agent rule: \(rule.id)")
            }
            return agent
        }
    }

    static func resolve(_ selection: SelectionPayload, against plan: WorkspaceInitPlan) throws -> ResolvedSelection {
        let selectedPathSet = Set(selection.envFiles.filter(\.selected).map(\.relativePath))
        let knownPathSet = Set(plan.envFiles.map(\.relativePath))
        let unknownPaths = selectedPathSet.subtracting(knownPathSet)
        guard unknownPaths.isEmpty else {
            throw ValidationError("Workspace selection references unknown env file(s): \(unknownPaths.sorted().joined(separator: ", "))")
        }

        let envFileSelections = Dictionary(uniqueKeysWithValues: selection.envFiles.map { ($0.relativePath, $0) })
        let selectedEnvFiles = plan.envFiles.filter { selectedPathSet.contains($0.relativePath) }
        var selectedSecrets: [WorkspaceSecretSelection] = []
        var createConflicts: [String] = []
        var knownSecretIDs = Set<String>()
        for envFile in plan.envFiles {
            for secretPlan in envFile.secrets {
                knownSecretIDs.insert(stableSecretID(relativePath: envFile.relativePath, secret: secretPlan.secret))
            }
        }

        for envFile in selectedEnvFiles {
            guard let envSelection = envFileSelections[envFile.relativePath] else { continue }
            let selectionByID = Dictionary(uniqueKeysWithValues: envSelection.secrets.map { ($0.id, $0) })
            for secretPlan in envFile.secrets {
                let id = stableSecretID(relativePath: envFile.relativePath, secret: secretPlan.secret)
                guard let rowSelection = selectionByID[id], rowSelection.action != .skip else { continue }
                let action = rowSelection.action
                if action == .create,
                   let conflict = secretPlan.conflict,
                   environmentTiersOverlap(rowSelection.selectedEnvironments ?? [], conflict.environments) {
                    createConflicts.append("\(envFile.relativePath): \(conflict.displayLine)")
                    continue
                }
                selectedSecrets.append(WorkspaceSecretSelection(
                    secret: secretPlan.secret,
                    action: workspaceAction(for: action),
                    environments: rowSelection.selectedEnvironments.map(VaultEnvironmentTags.normalize)
                ))
            }
        }

        let selectedSecretIDs = Set(selection.envFiles.flatMap { $0.secrets }.filter { $0.action != .skip }.map(\.id))
        let unknownSecretIDs = selectedSecretIDs.subtracting(knownSecretIDs)
        guard unknownSecretIDs.isEmpty else {
            throw ValidationError("Workspace selection references unknown secret row(s). Reopen setup and try again.")
        }
        guard createConflicts.isEmpty else {
            throw ValidationError(
                "Workspace selection contains existing Authsia item(s) that need review:\n" +
                    createConflicts.sorted().map { "- \($0)" }.joined(separator: "\n") +
                    "\nRefresh preview and choose Update or Reuse, or Skip."
            )
        }

        return ResolvedSelection(envFiles: selectedEnvFiles, secrets: selectedSecrets)
    }

    static func environmentTiersOverlap(_ lhs: [String], _ rhs: [String]) -> Bool {
        if lhs.isEmpty || rhs.isEmpty { return lhs.isEmpty && rhs.isEmpty }
        return lhs.contains { VaultEnvironmentTags.contains($0, in: rhs) }
    }

    static func stableSecretID(relativePath: String, secret: DetectedSecret) -> String {
        "\(relativePath):\(secret.lineNumber):\(secret.authsiaKey)"
    }

    private static func secretPayload(
        _ plan: WorkspaceEnvSecretPlan,
        in envFile: WorkspaceEnvFilePlan,
        folderPath: String
    ) -> SecretPayload {
        let hasConflict = plan.conflict != nil
        let selected = !hasConflict
        return SecretPayload(
            id: stableSecretID(relativePath: envFile.relativePath, secret: plan.secret),
            key: plan.secret.key,
            itemName: plan.secret.authsiaKey,
            lineNumber: plan.secret.lineNumber,
            type: plan.secret.type.rawValue.lowercased(),
            confidence: plan.secret.confidence.rawValue,
            selected: selected,
            selectedByDefault: selected,
            action: selected ? .create : .skip,
            hasConflict: hasConflict,
            conflict: plan.conflict?.displayLine,
            storePath: "\(folderPath)/\(plan.secret.authsiaKey)",
            replacementLine: plan.replacementLine
        )
    }

    private static func referencePayload(_ reference: WorkspaceMissingReference) -> ReferencePayload {
        ReferencePayload(
            relativePath: reference.relativePath,
            itemType: reference.itemType,
            item: reference.item,
            folderPath: reference.folderPath,
            envBindingName: reference.envBindingName,
            displayLine: reference.displayLine
        )
    }

    private static func workspaceAction(for action: SecretAction) -> WorkspaceSecretAction {
        switch action {
        case .create, .skip:
            return .create
        case .update:
            return .update
        case .reuse:
            return .reuse
        }
    }
}
