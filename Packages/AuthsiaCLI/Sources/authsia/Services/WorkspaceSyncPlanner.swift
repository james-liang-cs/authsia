import AuthenticatorBridge
import AuthenticatorCore
import Foundation

struct WorkspaceSyncPlan: Equatable {
    let workspaceRoot: URL
    let authsiaFolder: String
    var rows: [WorkspaceSyncRow]

    var satisfied: [WorkspaceSyncRow] { rows.filter { $0.status == .satisfied } }
    var missing: [WorkspaceSyncRow] { rows.filter { $0.status == .missingLocally } }
    var extras: [WorkspaceSyncRow] { rows.filter { $0.status == .localExtra } }
    var mismatches: [WorkspaceSyncRow] { rows.filter { $0.status == .configMismatch } }
}

struct WorkspaceSyncRow: Codable, Equatable, Identifiable {
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

enum WorkspaceSyncStatus: String, Codable, Equatable {
    case satisfied
    case missingLocally
    case localExtra
    case configMismatch
    case unverified
}

enum WorkspaceSyncAction: String, Codable, CaseIterable, Equatable {
    case none
    case create
    case importEncrypted
    case copyExisting
    case moveExisting
    case repairConfig
    case addToConfig
    case skip
}

enum WorkspaceSyncPlanner {
    static func plan(
        workspaceRoot: URL,
        config: WorkspaceConfig,
        vaultPayload: BridgeListPayload?
    ) -> WorkspaceSyncPlan {
        let authsiaFolder = WorkspaceFolderPath.normalize(
            config.workspace.authsiaFolder,
            defaultName: config.workspace.name
        )
        let trackedReferences = trackedReferences(workspaceRoot: workspaceRoot, config: config)
        guard let vaultPayload else {
            return WorkspaceSyncPlan(
                workspaceRoot: workspaceRoot,
                authsiaFolder: authsiaFolder,
                rows: trackedReferences.map { unverifiedRow(for: $0.binding, authsiaFolder: authsiaFolder) }
            )
        }

        let vaultItems = syncItems(from: vaultPayload)
        let workspaceItems = vaultItems.filter {
            $0.folderPath == authsiaFolder && WorkspaceConfigStore.isValidEnvironmentName($0.envName)
        }
        var consumedItemIDs = Set<String>()

        var rows = trackedReferences.map { tracked -> WorkspaceSyncRow in
            let binding = tracked.binding
            guard let reference = try? SecretReference.parse(binding.reference) else {
                return missingRow(
                    binding: binding,
                    itemName: binding.name,
                    itemType: "password",
                    authsiaFolder: authsiaFolder
                )
            }

            if let item = workspaceItems.first(where: { $0.matches(reference) }) {
                consumedItemIDs.insert(item.id)
                return row(
                    envName: binding.name,
                    itemName: item.itemName,
                    itemType: item.itemType,
                    expectedReference: binding.reference,
                    localReference: item.reference,
                    folderPath: authsiaFolder,
                    status: .satisfied,
                    selected: false,
                    action: .none
                )
            }

            if tracked.canRepairConfig,
               let item = workspaceItems.first(where: { $0.envName == binding.name }) {
                consumedItemIDs.insert(item.id)
                return row(
                    envName: binding.name,
                    itemName: item.itemName,
                    itemType: item.itemType,
                    expectedReference: binding.reference,
                    localReference: item.reference,
                    folderPath: authsiaFolder,
                    status: .configMismatch,
                    selected: true,
                    action: .repairConfig
                )
            }

            return missingRow(
                binding: binding,
                itemName: reference.item,
                itemType: reference.type.rawValue,
                authsiaFolder: authsiaFolder
            )
        }

        let configuredEnvNames = Set(trackedReferences.map(\.binding.name))
        let extras = workspaceItems
            .filter { !consumedItemIDs.contains($0.id) && !configuredEnvNames.contains($0.envName) }
            .map { item in
                row(
                    envName: item.envName,
                    itemName: item.itemName,
                    itemType: item.itemType,
                    expectedReference: nil,
                    localReference: item.reference,
                    folderPath: authsiaFolder,
                    status: .localExtra,
                    selected: true,
                    action: .addToConfig
                )
            }
        rows.append(contentsOf: extras)

        return WorkspaceSyncPlan(workspaceRoot: workspaceRoot, authsiaFolder: authsiaFolder, rows: rows)
    }

    private static func trackedReferences(
        workspaceRoot: URL,
        config: WorkspaceConfig
    ) -> [WorkspaceSyncTrackedReference] {
        var seen = Set<String>()
        var references: [WorkspaceSyncTrackedReference] = []

        func append(_ binding: WorkspaceConfig.EnvBinding, canRepairConfig: Bool) {
            let identity = "\(binding.name)\u{0}\(binding.reference)"
            guard seen.insert(identity).inserted else { return }
            references.append(WorkspaceSyncTrackedReference(binding: binding, canRepairConfig: canRepairConfig))
        }

        for binding in config.envBindings {
            append(binding, canRepairConfig: true)
        }
        for relativePath in config.managedEnvFiles {
            let path = workspaceRoot.appendingPathComponent(relativePath).path
            guard let entries = try? EnvFileParser.parse(contentsOf: path) else { continue }
            for entry in entries where WorkspaceConfigStore.isValidEnvironmentName(entry.key) {
                guard SecretReference.isSecretReference(entry.value),
                      (try? SecretReference.parse(entry.value)) != nil else {
                    continue
                }
                append(
                    WorkspaceConfig.EnvBinding(name: entry.key, reference: entry.value),
                    canRepairConfig: false
                )
            }
        }
        return references
    }

    static func applying(
        _ action: WorkspaceSyncAction,
        toSelectedRowsIn plan: WorkspaceSyncPlan
    ) -> WorkspaceSyncPlan {
        var updated = plan
        updated.rows = plan.rows.map { row in
            guard row.selected, isValid(action, for: row.status) else {
                return row
            }
            var row = row
            row.action = action
            return row
        }
        return updated
    }

    private static func unverifiedRow(
        for binding: WorkspaceConfig.EnvBinding,
        authsiaFolder: String
    ) -> WorkspaceSyncRow {
        let reference = try? SecretReference.parse(binding.reference)
        return row(
            envName: binding.name,
            itemName: reference?.item ?? binding.name,
            itemType: reference?.type.rawValue ?? "password",
            expectedReference: binding.reference,
            localReference: nil,
            folderPath: authsiaFolder,
            status: .unverified,
            selected: false,
            action: .none
        )
    }

    private static func missingRow(
        binding: WorkspaceConfig.EnvBinding,
        itemName: String,
        itemType: String,
        authsiaFolder: String
    ) -> WorkspaceSyncRow {
        row(
            envName: binding.name,
            itemName: itemName,
            itemType: itemType,
            expectedReference: binding.reference,
            localReference: nil,
            folderPath: authsiaFolder,
            status: .missingLocally,
            selected: true,
            action: .skip
        )
    }

    private static func row(
        envName: String,
        itemName: String,
        itemType: String,
        expectedReference: String?,
        localReference: String?,
        folderPath: String,
        status: WorkspaceSyncStatus,
        selected: Bool,
        action: WorkspaceSyncAction
    ) -> WorkspaceSyncRow {
        WorkspaceSyncRow(
            id: "\(status.rawValue):\(envName):\(itemType):\(itemName)",
            envName: envName,
            itemName: itemName,
            itemType: itemType,
            expectedReference: expectedReference,
            localReference: localReference,
            folderPath: folderPath,
            status: status,
            selected: selected,
            action: action
        )
    }

    private static func isValid(_ action: WorkspaceSyncAction, for status: WorkspaceSyncStatus) -> Bool {
        switch status {
        case .missingLocally:
            return [.create, .importEncrypted, .copyExisting, .moveExisting, .skip].contains(action)
        case .localExtra:
            return [.addToConfig, .skip].contains(action)
        case .configMismatch:
            return [.repairConfig, .skip].contains(action)
        case .satisfied, .unverified:
            return [.none, .skip].contains(action)
        }
    }

    private static func syncItems(from payload: BridgeListPayload) -> [WorkspaceSyncItem] {
        let passwords = payload.passwords.map {
            WorkspaceSyncItem(
                id: $0.id.uuidString,
                itemType: "password",
                itemName: $0.name,
                field: "password",
                folderPath: $0.folderPath
            )
        }
        let apiKeys = payload.apiKeys.map {
            WorkspaceSyncItem(
                id: $0.id.uuidString,
                itemType: "api-key",
                itemName: $0.name,
                field: "key",
                folderPath: $0.folderPath
            )
        }
        return passwords + apiKeys
    }
}

private struct WorkspaceSyncTrackedReference {
    let binding: WorkspaceConfig.EnvBinding
    let canRepairConfig: Bool
}

private struct WorkspaceSyncItem: Equatable {
    let id: String
    let itemType: String
    let itemName: String
    let field: String
    let folderPath: String?

    var envName: String { itemName }

    var reference: String {
        WorkspaceSyncReferenceBuilder.reference(
            itemType: itemType,
            itemName: itemName,
            field: field,
            folderPath: folderPath
        )
    }

    func matches(_ reference: SecretReference) -> Bool {
        itemType == reference.type.rawValue &&
            itemName == reference.item &&
            field == reference.resolvedField &&
            folderPath == WorkspaceSyncReferenceBuilder.normalizeFolderPath(reference.folder)
    }

    init(id: String, itemType: String, itemName: String, field: String, folderPath: String?) {
        self.id = id
        self.itemType = itemType
        self.itemName = itemName
        self.field = field
        self.folderPath = WorkspaceSyncReferenceBuilder.normalizeFolderPath(folderPath)
    }
}

enum WorkspaceSyncReferenceBuilder {
    static func reference(itemType: String, itemName: String, field: String, folderPath: String?) -> String {
        var uri = "authsia://\(itemType)/\(percentEncode(itemName))/\(percentEncode(field))"
        if let folder = normalizeFolderPath(folderPath) {
            uri += "?folder=\(percentEncode(folder))"
        }
        return uri
    }

    static func normalizeFolderPath(_ value: String?) -> String? {
        guard let value else { return nil }
        let segments = value
            .split(separator: "/")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        return segments.isEmpty ? nil : segments.joined(separator: "/")
    }

    private static func percentEncode(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: uriAllowedCharacters) ?? value
    }

    private static let uriAllowedCharacters = CharacterSet(
        charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    )
}
