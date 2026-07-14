import ArgumentParser
import Foundation
import AuthenticatorBridge

struct AccessCreateApprovalRequest: Equatable {
    let name: String
    let scope: String?
    let ttlSeconds: TimeInterval
    let expiresAt: Date
    let machineId: String
    let machineName: String
    let allowedCommands: Set<CapabilityCommand>
    let environmentScope: EnvironmentAccessScope?
}

protocol AccessCreateApproving {
    func approveAccessCreate(_ request: AccessCreateApprovalRequest) throws
}

struct Access: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "access",
        abstract: "Manage automation access",
        subcommands: [Create.self, List.self, Revoke.self]
    )

    struct Create: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "create",
            abstract: "Create an automation credential",
            discussion: """
                --allow is required. Pick the narrowest set of commands the automation
                actually needs. 'exec' is the safest — secrets stay inside the child
                process and never reach the caller.

                Capabilities:
                  exec    Run a command with secrets injected as env vars (recommended)
                  load    Emit 'export KEY=...' shell lines
                  read    Resolve 'authsia://...' URIs to stdout
                  get     Print individual secret values
                  inject  Substitute 'authsia://...' URIs inside templates
                  ssh     Allow Authsia SSH agent signing for allowed SSH keys
                  list    List CLI-enabled item metadata within the allowed scope

                Examples:
                  authsia access create --name claude --ttl 15m --allow exec
                  authsia access create --name claude --scope Team/API --ttl 15m --allow exec
                  authsia access create --name claude --env Production --ttl 15m --allow exec
                  authsia access create --name ci --scope CI --ttl 1h --allow exec,list
                  authsia access create --name agent --scope Team/API --ttl 15m --allow exec,ssh
                """
        )

        @Option(name: .long, help: "Human-readable credential name")
        var name: String

        @Option(name: .long, help: "Folder scope for the credential. Omit to allow all CLI-enabled items.")
        var scope: String?

        @Option(name: .long, help: "Environment profile whose folder scope should be used for the credential.")
        var env: String?

        @Flag(name: .customLong("default-only"), help: "Restrict the credential to untagged default-environment items")
        var defaultOnly = false

        @Option(name: .long, help: "Time-to-live. Use seconds or suffixes like 15m, 2h, 7d.")
        var ttl: String

        @Option(name: .long, help: "Comma-separated capabilities: exec,load,read,get,inject,ssh,list")
        var allow: String

        func run() throws {
            if defaultOnly && env != nil {
                throw ValidationError("Use either --env or --default-only, not both.")
            }
            try AuthsiaBridgeClient.shared.withRequestedCommand("access", includeAutomationCredential: false) {
                let capabilities = try Self.parseAllowedCommands(allow)
                let credential = try Access.createCredentialAfterApproval(
                    name: name,
                    scope: scope,
                    envName: env,
                    environmentScope: defaultOnly ? .defaultOnly : env.map(EnvironmentAccessScope.named),
                    ttl: ttl,
                    allowedCommands: capabilities,
                    approvalClient: AuthsiaBridgeClient.shared
                )
                print(Access.renderCreateMessage(credential))
            }
        }

        static func parseAllowedCommands(_ raw: String) throws -> Set<CapabilityCommand> {
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                throw ValidationError("--allow cannot be empty. Example: --allow exec")
            }
            var result: Set<CapabilityCommand> = []
            for token in trimmed.split(separator: ",") {
                let key = token.trimmingCharacters(in: .whitespaces)
                guard let cap = CapabilityCommand(rawValue: key) else {
                    let known = CapabilityCommand.allCases.map(\.rawValue).joined(separator: ", ")
                    throw ValidationError(
                        "Unknown capability '\(key)'. Known: \(known). " +
                            "Example: authsia access create --name Agent --ttl 15m --allow exec"
                    )
                }
                result.insert(cap)
            }
            guard !result.isEmpty else {
                throw ValidationError("--allow must include at least one capability. Example: --allow exec")
            }
            return result
        }
    }

    struct List: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "list",
            abstract: "List automation credentials"
        )

        @Option(name: .long, help: "Output format: table (default), json")
        var format: OutputFormat = .table

        @Flag(name: .long, help: "Include revoked and expired credentials")
        var all = false

        func run() throws {
            let items = try Access.listItems(includeAll: all)
            print(try Access.renderList(items: items, format: format))
        }
    }

    struct Revoke: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "revoke",
            abstract: "Revoke an automation credential"
        )

        @Argument(help: "Credential id")
        var id: String

        func run() throws {
            guard let uuid = UUID(uuidString: id) else {
                throw ValidationError("Invalid credential id '\(id)'. Run `authsia access list` and copy an ID.")
            }
            let credential = try Access.revokeCredential(id: uuid)
            print("Revoked access credential \(credential.id.uuidString).")
        }
    }

    struct ListItem: Codable, Equatable, Identifiable {
        enum Status: String, Codable, CaseIterable {
            case active
            case expired
            case revoked
        }

        let id: UUID
        let name: String
        let scope: String?
        let status: Status
        let createdAt: Date
        let expiresAt: Date
        let revokedAt: Date?
        let machineId: String
        let machineName: String
        let allowedCommands: [String]
    }

    static func parseTTL(_ value: String) throws -> TimeInterval {
        guard !value.isEmpty else {
            throw ValidationError("TTL cannot be empty. Use seconds or a suffix, for example --ttl 15m.")
        }

        let units: [(suffix: String, multiplier: TimeInterval)] = [
            ("d", 86_400),
            ("h", 3_600),
            ("m", 60),
        ]

        for unit in units {
            if value.hasSuffix(unit.suffix) {
                let numberPart = String(value.dropLast(unit.suffix.count))
                guard let quantity = Int(numberPart), quantity > 0 else {
                    throw ValidationError("Invalid TTL '\(value)'. Use a positive value like 15m, 2h, 7d, or 900.")
                }
                return TimeInterval(quantity) * unit.multiplier
            }
        }

        guard let seconds = Int(value), seconds > 0 else {
            throw ValidationError("Invalid TTL '\(value)'. Use a positive value like 15m, 2h, 7d, or 900.")
        }
        return TimeInterval(seconds)
    }

    static func createCredential(
        name: String,
        scope: String? = nil,
        envName: String? = nil,
        environmentScope: EnvironmentAccessScope? = nil,
        ttl: String,
        store: AccessCredentialStore = AccessCredentialStore(),
        environmentStore: EnvironmentProfileStore = EnvironmentProfileStore(),
        machineIdentity: MachineIdentity = MachineIdentity.load(),
        now: Date = Date(),
        allowedCommands: Set<CapabilityCommand> = [.exec]
    ) throws -> AccessCredential {
        let credential = try buildCredential(
            name: name,
            scope: scope,
            envName: envName,
            environmentScope: environmentScope,
            ttl: ttl,
            environmentStore: environmentStore,
            machineIdentity: machineIdentity,
            now: now,
            allowedCommands: allowedCommands
        ).credential
        try store.save(credential)
        return credential
    }

    static func createCredentialAfterApproval(
        name: String,
        scope: String? = nil,
        envName: String? = nil,
        environmentScope: EnvironmentAccessScope? = nil,
        ttl: String,
        store: AccessCredentialStore = AccessCredentialStore(),
        environmentStore: EnvironmentProfileStore = EnvironmentProfileStore(),
        machineIdentity: MachineIdentity = MachineIdentity.load(),
        now: Date = Date(),
        allowedCommands: Set<CapabilityCommand> = [.exec],
        approvalClient: AccessCreateApproving
    ) throws -> AccessCredential {
        let draft = try buildCredential(
            name: name,
            scope: scope,
            envName: envName,
            environmentScope: environmentScope,
            ttl: ttl,
            environmentStore: environmentStore,
            machineIdentity: machineIdentity,
            now: now,
            allowedCommands: allowedCommands
        )
        let approvalRequest = AccessCreateApprovalRequest(
            name: draft.credential.name,
            scope: draft.credential.scope,
            ttlSeconds: draft.ttlSeconds,
            expiresAt: draft.credential.expiresAt,
            machineId: draft.credential.machineId,
            machineName: draft.credential.machineName,
            allowedCommands: draft.credential.allowedCommands,
            environmentScope: draft.credential.environmentScope
        )
        try approvalClient.approveAccessCreate(approvalRequest)
        try store.save(draft.credential)
        return draft.credential
    }

    private static func buildCredential(
        name: String,
        scope: String?,
        envName: String?,
        environmentScope: EnvironmentAccessScope?,
        ttl: String,
        environmentStore: EnvironmentProfileStore,
        machineIdentity: MachineIdentity,
        now: Date,
        allowedCommands: Set<CapabilityCommand>
    ) throws -> (credential: AccessCredential, ttlSeconds: TimeInterval) {
        let normalizedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedName.isEmpty else {
            throw ValidationError("Credential name cannot be empty. Example: authsia access create --name Agent --ttl 15m")
        }

        let normalizedScope = try resolveCredentialScope(
            scope: scope,
            envName: envName,
            environmentStore: environmentStore
        )

        let ttlSeconds = try parseTTL(ttl)
        let expiresAt = now.addingTimeInterval(ttlSeconds)
        let credential = AccessCredential(
            id: UUID(),
            name: normalizedName,
            scope: AutomationCredentialScope.storageValue(normalizedScope),
            createdAt: now,
            expiresAt: expiresAt,
            revokedAt: nil,
            machineId: machineIdentity.machineId,
            machineName: machineIdentity.displayName,
            allowedCommands: allowedCommands,
            environmentScope: environmentScope
        )
        return (credential, ttlSeconds)
    }

    private static func resolveCredentialScope(
        scope: String?,
        envName: String?,
        environmentStore: EnvironmentProfileStore
    ) throws -> AutomationCredentialScope.Normalized {
        let trimmedEnvName = envName?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let hasEnv = !trimmedEnvName.isEmpty

        if scope != nil && hasEnv {
            throw ValidationError(
                "Use either --scope or --env, not both. Example: authsia access create --name Agent --env Production"
            )
        }

        if hasEnv {
            guard let profile = try environmentStore.load(named: trimmedEnvName) else {
                throw ValidationError(
                    "No environment profile named '\(trimmedEnvName)' was found. " +
                        "Run `authsia env list`, or create it with `authsia env add --name \(trimmedEnvName) --folder <folder>`."
                )
            }
            return try credentialScope(for: profile)
        }

        guard let normalizedScope = AutomationCredentialScope.normalizeForCreation(scope) else {
            throw ValidationError(
                "Credential scope cannot be empty. Omit --scope to allow all CLI-enabled items, " +
                    "or use --scope Team/API."
            )
        }
        return normalizedScope
    }

    private static func credentialScope(for profile: EnvironmentProfile) throws -> AutomationCredentialScope.Normalized {
        switch profile.scope {
        case .all:
            return .global
        case .folders(let paths):
            guard let normalized = AutomationCredentialScope.normalizeForCreation(folderPaths: paths) else {
                throw ValidationError(
                    "Environment profile '\(profile.name)' has no folders. " +
                        "Create a folder-scoped profile with `authsia env add --name \(profile.name) --folder <folder>`."
                )
            }
            return normalized
        }
    }

    static func revokeCredential(
        id: UUID,
        store: AccessCredentialStore = AccessCredentialStore(),
        now: Date = Date()
    ) throws -> AccessCredential {
        try store.revoke(id: id, revokedAt: now)
    }

    static func listItems(
        store: AccessCredentialStore = AccessCredentialStore(),
        includeAll: Bool = false,
        now: Date = Date()
    ) throws -> [ListItem] {
        let credentials = try store.loadAll()
        let filtered = credentials
            .filter { includeAll || $0.status(asOf: now) == .active }
            .sorted {
                if $0.createdAt != $1.createdAt {
                    return $0.createdAt > $1.createdAt
                }
                return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
            }

        return filtered.map { credential in
            ListItem(
                id: credential.id,
                name: credential.name,
                scope: credential.scope,
                status: ListItem.Status(rawValue: credential.status(asOf: now).rawValue)!,
                createdAt: credential.createdAt,
                expiresAt: credential.expiresAt,
                revokedAt: credential.revokedAt,
                machineId: credential.machineId,
                machineName: credential.machineName,
                allowedCommands: credential.allowedCommands.map(\.rawValue).sorted()
            )
        }
    }

    static func renderList(items: [ListItem], format: OutputFormat) throws -> String {
        switch format {
        case .json:
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(items)
            return String(decoding: data, as: UTF8.self)
        case .table:
            return renderTable(items: items)
        }
    }

    static func renderCreateMessage(_ credential: AccessCredential) -> String {
        let formatter = ISO8601DateFormatter()
        let caps = credential.allowedCommands.map(\.rawValue).sorted().joined(separator: ",")
        let summary = "Created access credential \(credential.id.uuidString) " +
            "for scope \(AutomationCredentialScope.displayName(credential.scope)) allow=\(caps), " +
            "expires \(formatter.string(from: credential.expiresAt))."
        return ([summary, "Copy and paste:", environmentExportLines(for: credential).joined(separator: "\n")])
            .joined(separator: "\n")
    }

    private static func environmentExportLines(for credential: AccessCredential) -> [String] {
        let id = credential.id.uuidString
        let allowsSSH = credential.allowedCommands.contains(.ssh)
        let allowsNonSSH = credential.allowedCommands.contains { $0 != .ssh }
        var lines: [String] = []
        if allowsNonSSH {
            lines.append("export AUTHSIA_ACCESS_CREDENTIAL=\(id)")
        }
        if allowsSSH {
            lines.append("export AUTHSIA_SSH_ACCESS_CREDENTIAL=\(id)")
        }
        return lines
    }

    private static func renderTable(items: [ListItem]) -> String {
        if items.isEmpty {
            return "No access credentials found."
        }

        let headers = ["ID", "Name", "Scope", "Status", "Expires", "Machine", "Allow"]
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short

        let rows = items.map { item in
            [
                item.id.uuidString,
                item.name,
                AutomationCredentialScope.displayName(item.scope),
                item.status.rawValue.capitalized,
                formatter.string(from: item.expiresAt),
                item.machineName,
                item.allowedCommands.joined(separator: ",")
            ]
        }

        return TableFormatter.renderTable(headers: headers, rows: rows)
    }
}
