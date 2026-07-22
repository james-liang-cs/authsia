import ArgumentParser
import Foundation
import AuthenticatorBridge
import AuthenticatorCore

struct List: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "List items by type (no secrets shown)",
        discussion: """
            Lists all items of the given type. No sensitive data is returned.
            Each item shows whether CLI access is enabled (on/off).

            Examples:
              authsia list otp                       List OTP items as JSON
              authsia list api-keys                  List API keys
              authsia list passwords --format table   List passwords as a table
              authsia list passwords --cli-enabled     List only CLI-enabled passwords
              authsia list passwords --folder Team/API
              authsia list passwords --all-machines
              authsia list certs --favorites           List favorite certificates
              authsia list notes                      List secure notes
              authsia list ssh                        List SSH keys
            """
    )

    enum Scope: String, ExpressibleByArgument, CaseIterable {
        case otp
        case apiKeys = "api-keys"
        case passwords
        case certs
        case notes
        case ssh

        static var allValueStrings: [String] { allCases.map(\.rawValue) }
    }

    @Argument(help: "Item type: otp, api-keys, passwords, certs, notes, ssh")
    var scope: Scope

    @Flag(name: .long, help: "Only show favorites")
    var favorites = false

    @Option(
        name: .shortAndLong,
        help: "Filter by folder path (includes nested folders)",
        completion: .custom(ShellCompletionMetadata.completeFolders)
    )
    var folder: String?

    @Flag(name: .long, help: "Include scraped items from all machines (default: current machine only)")
    var allMachines = false

    @Flag(name: .customLong("cli-enabled"), help: "Only show CLI-enabled items")
    var cliEnabledOnly = false

    @Option(name: .long, help: "Only show items available to this environment (exact tag or All)")
    var environment: String?

    @Option(name: .long, help: "Output format: json (default), table")
    var format: OutputFormat = .json

    @Flag(name: .customLong("json"), help: .hidden)
    var json = false

    static func loadPayload(
        scope: Scope,
        folder: String?,
        parentEnvironment: [String: String] = ProcessInfo.processInfo.environment,
        processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry(),
        jitClient: ExecJITPreflightClient = AuthsiaBridgeClient.shared
    ) throws -> BridgeListPayload {
        try AuthsiaBridgeClient.shared.withRequestedCommand(.list) {
            try runJITPreflight(
                scope: scope,
                folder: folder,
                parentEnvironment: parentEnvironment,
                processAncestry: processAncestry,
                client: jitClient
            )
            return try AuthsiaBridgeClient.shared.list()
        }
    }

    static func runJITPreflight(
        scope: Scope,
        folder: String?,
        parentEnvironment: [String: String],
        processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry(),
        client: ExecJITPreflightClient = AuthsiaBridgeClient.shared
    ) throws {
        guard Exec.shouldRunJITPreflight(environment: parentEnvironment, processAncestry: processAncestry),
              let reference = jitPreflightReference(scope: scope, folder: folder) else {
            return
        }
        _ = try client.agentJITPreflight(
            AgentJITPreflightPayload(requestedCommand: "list", references: [reference])
        )
    }

    private static func jitPreflightReference(scope: Scope, folder: String?) -> AgentJITPreflightReference? {
        let type: String
        switch scope {
        case .apiKeys:
            type = "api-key"
        case .passwords:
            type = "password"
        case .certs:
            type = "cert"
        case .notes:
            type = "note"
        case .ssh:
            type = "ssh"
        case .otp:
            return nil
        }
        return AgentJITPreflightReference(
            type: type,
            query: "",
            folderPath: normalizeFolderPath(folder),
            isFolderScoped: folder != nil
        )
    }

    static func authorizeAutomationAccess(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        store: AccessCredentialStore = AccessCredentialStore(),
        now: Date = Date()
    ) throws {
        guard let credential = try AutomationAccessResolver.resolveActiveCredential(
            environment: environment,
            store: store,
            now: now
        ) else {
            return
        }

        try AutomationAccessResolver.authorizeCommand(.list, credential: credential)
    }

    func run() throws {
        if scope == .otp, environment != nil {
            throw ValidationError("--environment is not supported for OTP items.")
        }
        let outputFormat = try resolveOutputFormat(format: format, jsonFlag: json, command: "authsia list")
        try Self.authorizeAutomationAccess()
        let payload = try Self.loadPayload(scope: scope, folder: folder)
        let currentMachine = MachineIdentity.load()
        let currentMachineId = currentMachine.machineId
        let currentMachineName = currentMachine.displayName

        switch scope {
        case .otp:
            print(
                try Self.renderOTP(
                    payload.accounts,
                    favoritesOnly: favorites,
                    cliEnabledOnly: cliEnabledOnly,
                    format: outputFormat
                )
            )
        case .apiKeys:
            print(
                try Self.renderAPIKeys(
                    payload.apiKeys,
                    favoritesOnly: favorites,
                    cliEnabledOnly: cliEnabledOnly,
                    environment: environment,
                    folder: folder,
                    format: outputFormat,
                    allMachines: allMachines,
                    currentMachineId: currentMachineId,
                    currentMachineName: currentMachineName
                )
            )
        case .passwords:
            print(
                try Self.renderPasswords(
                    payload.passwords,
                    favoritesOnly: favorites,
                    cliEnabledOnly: cliEnabledOnly,
                    environment: environment,
                    folder: folder,
                    format: outputFormat,
                    allMachines: allMachines,
                    currentMachineId: currentMachineId,
                    currentMachineName: currentMachineName
                )
            )
        case .certs:
            print(
                try Self.renderCertificates(
                    payload.certificates,
                    favoritesOnly: favorites,
                    cliEnabledOnly: cliEnabledOnly,
                    environment: environment,
                    folder: folder,
                    format: outputFormat,
                    allMachines: allMachines,
                    currentMachineId: currentMachineId,
                    currentMachineName: currentMachineName
                )
            )
        case .notes:
            print(
                try Self.renderNotes(
                    payload.notes,
                    favoritesOnly: favorites,
                    cliEnabledOnly: cliEnabledOnly,
                    environment: environment,
                    folder: folder,
                    format: outputFormat,
                    allMachines: allMachines,
                    currentMachineId: currentMachineId,
                    currentMachineName: currentMachineName
                )
            )
        case .ssh:
            print(
                try Self.renderSSHKeys(
                    payload.sshKeys,
                    favoritesOnly: favorites,
                    cliEnabledOnly: cliEnabledOnly,
                    environment: environment,
                    folder: folder,
                    format: outputFormat,
                    allMachines: allMachines,
                    currentMachineId: currentMachineId,
                    currentMachineName: currentMachineName
                )
            )
        }
    }

    static func renderOTP(
        _ otpItems: [BridgeAccount],
        favoritesOnly: Bool,
        cliEnabledOnly: Bool = false,
        format: OutputFormat
    ) throws -> String {
        let filtered = otpItems.filter {
            (!favoritesOnly || $0.isFavorite) &&
            (!cliEnabledOnly || $0.isCliEnabled)
        }
        return try OutputFormatter.formatOTPList(filtered, format: format)
    }

    static func renderPasswords(
        _ passwords: [BridgePassword],
        favoritesOnly: Bool,
        cliEnabledOnly: Bool = false,
        environment: String? = nil,
        folder: String? = nil,
        format: OutputFormat,
        allMachines: Bool = false,
        currentMachineId: String = MachineIdentity.load().machineId,
        currentMachineName: String? = MachineIdentity.load().displayName
    ) throws -> String {
        let filtered = passwords.filter {
            (!favoritesOnly || $0.isFavorite) &&
            (!cliEnabledOnly || $0.isCliEnabled) &&
            Self.environmentMatches(environment, itemEnvironments: $0.environments) &&
            ScrapedItemMachineSupport.shouldInclude(
                isScraped: $0.isScraped,
                scrapeMachineName: $0.scrapeMachineName,
                scrapeMachineId: $0.scrapeMachineId,
                currentMachineId: currentMachineId,
                currentMachineName: currentMachineName,
                allMachines: allMachines
            ) &&
            folderMatches(itemFolderPath: $0.folderPath, filterFolderPath: folder)
        }
        return try OutputFormatter.formatPasswords(filtered, format: format)
    }

    static func renderAPIKeys(
        _ apiKeys: [BridgeAPIKey],
        favoritesOnly: Bool,
        cliEnabledOnly: Bool = false,
        environment: String? = nil,
        folder: String? = nil,
        format: OutputFormat,
        allMachines: Bool = false,
        currentMachineId: String = MachineIdentity.load().machineId,
        currentMachineName: String? = MachineIdentity.load().displayName
    ) throws -> String {
        let filtered = apiKeys.filter {
            (!favoritesOnly || $0.isFavorite) &&
            (!cliEnabledOnly || $0.isCliEnabled) &&
            Self.environmentMatches(environment, itemEnvironments: $0.environments) &&
            ScrapedItemMachineSupport.shouldInclude(
                isScraped: $0.isScraped,
                scrapeMachineName: $0.scrapeMachineName,
                scrapeMachineId: $0.scrapeMachineId,
                currentMachineId: currentMachineId,
                currentMachineName: currentMachineName,
                allMachines: allMachines
            ) &&
            folderMatches(itemFolderPath: $0.folderPath, filterFolderPath: folder)
        }
        return try OutputFormatter.formatAPIKeys(filtered, format: format)
    }

    static func renderCertificates(
        _ certificates: [BridgeCertificate],
        favoritesOnly: Bool,
        cliEnabledOnly: Bool = false,
        environment: String? = nil,
        folder: String? = nil,
        format: OutputFormat,
        allMachines: Bool = false,
        currentMachineId: String = MachineIdentity.load().machineId,
        currentMachineName: String? = MachineIdentity.load().displayName
    ) throws -> String {
        let filtered = certificates.filter {
            (!favoritesOnly || $0.isFavorite) &&
            (!cliEnabledOnly || $0.isCliEnabled) &&
            Self.environmentMatches(environment, itemEnvironments: $0.environments) &&
            ScrapedItemMachineSupport.shouldInclude(
                isScraped: $0.isScraped,
                scrapeMachineName: $0.scrapeMachineName,
                scrapeMachineId: $0.scrapeMachineId,
                currentMachineId: currentMachineId,
                currentMachineName: currentMachineName,
                allMachines: allMachines
            ) &&
            folderMatches(itemFolderPath: $0.folderPath, filterFolderPath: folder)
        }
        return try OutputFormatter.formatCertificates(filtered, format: format)
    }

    static func renderNotes(
        _ notes: [BridgeNote],
        favoritesOnly: Bool,
        cliEnabledOnly: Bool = false,
        environment: String? = nil,
        folder: String? = nil,
        format: OutputFormat,
        allMachines: Bool = false,
        currentMachineId: String = MachineIdentity.load().machineId,
        currentMachineName: String? = MachineIdentity.load().displayName
    ) throws -> String {
        let filtered = notes.filter {
            (!favoritesOnly || $0.isFavorite) &&
            (!cliEnabledOnly || $0.isCliEnabled) &&
            Self.environmentMatches(environment, itemEnvironments: $0.environments) &&
            ScrapedItemMachineSupport.shouldInclude(
                isScraped: $0.isScraped,
                scrapeMachineName: $0.scrapeMachineName,
                scrapeMachineId: $0.scrapeMachineId,
                currentMachineId: currentMachineId,
                currentMachineName: currentMachineName,
                allMachines: allMachines
            ) &&
            folderMatches(itemFolderPath: $0.folderPath, filterFolderPath: folder)
        }
        return try OutputFormatter.formatNotes(filtered, format: format)
    }

    static func renderSSHKeys(
        _ keys: [BridgeSSHKey],
        favoritesOnly: Bool,
        cliEnabledOnly: Bool = false,
        environment: String? = nil,
        folder: String? = nil,
        format: OutputFormat,
        allMachines: Bool = false,
        currentMachineId: String = MachineIdentity.load().machineId,
        currentMachineName: String? = MachineIdentity.load().displayName
    ) throws -> String {
        let filtered = keys.filter {
            (!favoritesOnly || $0.isFavorite) &&
            (!cliEnabledOnly || $0.isCliEnabled) &&
            Self.environmentMatches(environment, itemEnvironments: $0.environments) &&
            ScrapedItemMachineSupport.shouldInclude(
                isScraped: $0.isScraped,
                scrapeMachineName: $0.scrapeMachineName,
                scrapeMachineId: $0.scrapeMachineId,
                currentMachineId: currentMachineId,
                currentMachineName: currentMachineName,
                allMachines: allMachines
            ) &&
            folderMatches(itemFolderPath: $0.folderPath, filterFolderPath: folder)
        }
        return try OutputFormatter.formatSSHKeys(filtered, format: format)
    }

    static func environmentMatches(_ environment: String?, itemEnvironments: [String]) -> Bool {
        environment.map {
            VaultEnvironmentTags.contains($0, in: itemEnvironments)
                || VaultEnvironmentTags.containsAll(in: itemEnvironments)
        } ?? true
    }
}
