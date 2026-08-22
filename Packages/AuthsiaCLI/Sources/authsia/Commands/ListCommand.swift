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
            Scraped items default to this machine. When other-machine scrapes
            are omitted, stderr reports the count; pass --all-machines to include them.

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

    @Flag(name: .customLong("chrome-native-host"), help: .hidden)
    var chromeNativeHost = false

    static func loadPayload(
        scope: Scope,
        folder: String?,
        parentEnvironment: [String: String] = ProcessInfo.processInfo.environment,
        processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry(),
        chromeNativeHost: Bool = false,
        jitClient: ExecJITPreflightClient = AuthsiaBridgeClient.shared
    ) throws -> BridgeListPayload {
        let requestedCommand = chromeNativeHost
            ? BridgeContext.chromeNativeHostRequestedCommand
            : CapabilityCommand.list.rawValue
        return try AuthsiaBridgeClient.shared.withRequestedCommand(
            requestedCommand,
            includeAutomationCredential: !chromeNativeHost
        ) {
            try loadAfterHostDecision(
                probe: {
                    try AuthsiaBridgeClient.shared.withoutApprovalPrompt {
                        try AuthsiaBridgeClient.shared.list()
                    }
                },
                list: { try AuthsiaBridgeClient.shared.list() },
                preflight: {
                    try runJITPreflight(
                        scope: scope,
                        folder: folder,
                        parentEnvironment: parentEnvironment,
                        processAncestry: processAncestry,
                        chromeNativeHost: chromeNativeHost,
                        honorHostGrantRequirement: true,
                        client: jitClient
                    )
                }
            )
        }
    }

    /// Ask the host first. A paired IDE human list succeeds without opening Agent JIT.
    /// Only a host denial that requires a list grant starts preflight.
    static func loadAfterHostDecision(
        probe: (() throws -> BridgeListPayload)? = nil,
        list: () throws -> BridgeListPayload,
        preflight: () throws -> Void
    ) throws -> BridgeListPayload {
        do {
            if let probe {
                return try probe()
            }
            return try list()
        } catch {
            guard requiresListJITGrant(error) else { throw error }
            try preflight()
            return try list()
        }
    }

    static func requiresListJITGrant(_ error: Error) -> Bool {
        guard case let BridgeClientError.bridgeError(code, message, _) = error else {
            return false
        }
        return code == BridgeErrorCode.policyDenied.rawValue
            && message.contains("JIT preflight grant")
    }

    static func runJITPreflight(
        scope: Scope,
        folder: String?,
        parentEnvironment: [String: String],
        processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry(),
        chromeNativeHost: Bool = false,
        hasCurrentTerminalPairing: () -> Bool = { false },
        honorHostGrantRequirement: Bool = false,
        client: ExecJITPreflightClient = AuthsiaBridgeClient.shared
    ) throws {
        let locallyRequired = Exec.shouldRunJITPreflight(
            environment: parentEnvironment,
            processAncestry: processAncestry
        )
        guard !chromeNativeHost,
              honorHostGrantRequirement || locallyRequired,
              let reference = jitPreflightReference(scope: scope, folder: folder) else {
            return
        }
        // honorHostGrantRequirement is for the host's grant-required denial.
        // The local name list does not know Grok and other unnamed agents;
        // the host already classified the caller. Pairing still skips this.
        guard !hasCurrentTerminalPairing() else { return }
        _ = try client.agentJITPreflight(
            AgentJITPreflightPayload(requestedCommand: "list", references: [reference])
        )
    }

    func validateChromeNativeHostMarker(
        processAncestry: [AgenticProcessReference] = AgenticProcessDetector.currentProcessAncestry()
    ) throws {
        guard chromeNativeHost else { return }
        guard processAncestry.dropFirst().contains(where: {
            BridgeContext.isChromeNativeHostProcessName($0.processName)
        }) else {
            throw ValidationError("--chrome-native-host is reserved for the Authsia Chrome native host.")
        }
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
        try validateChromeNativeHostMarker()
        if scope == .otp, environment != nil {
            throw ValidationError("--environment is not supported for OTP items.")
        }
        let outputFormat = try resolveOutputFormat(format: format, jsonFlag: json, command: "authsia list")
        try Self.authorizeAutomationAccess()
        let payload = try Self.loadPayload(scope: scope, folder: folder, chromeNativeHost: chromeNativeHost)
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
            printListing(
                try Self.renderAPIKeysListing(
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
            printListing(
                try Self.renderPasswordsListing(
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
            printListing(
                try Self.renderCertificatesListing(
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
            printListing(
                try Self.renderNotesListing(
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
            printListing(
                try Self.renderSSHKeysListing(
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

    struct RenderedList: Equatable {
        let output: String
        let omissionWarning: String?
    }

    private func printListing(_ listing: RenderedList) {
        print(listing.output)
        if !chromeNativeHost, let omissionWarning = listing.omissionWarning {
            StandardError.writeLine(omissionWarning)
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
        try renderPasswordsListing(
            passwords,
            favoritesOnly: favoritesOnly,
            cliEnabledOnly: cliEnabledOnly,
            environment: environment,
            folder: folder,
            format: format,
            allMachines: allMachines,
            currentMachineId: currentMachineId,
            currentMachineName: currentMachineName
        ).output
    }

    static func renderPasswordsListing(
        _ passwords: [BridgePassword],
        favoritesOnly: Bool,
        cliEnabledOnly: Bool = false,
        environment: String? = nil,
        folder: String? = nil,
        format: OutputFormat,
        allMachines: Bool = false,
        currentMachineId: String = MachineIdentity.load().machineId,
        currentMachineName: String? = MachineIdentity.load().displayName
    ) throws -> RenderedList {
        try renderedList(
            passwords.filter {
                (!favoritesOnly || $0.isFavorite) &&
                (!cliEnabledOnly || $0.isCliEnabled) &&
                Self.environmentMatches(environment, itemEnvironments: $0.environments) &&
                folderMatches(itemFolderPath: $0.folderPath, filterFolderPath: folder)
            },
            allMachines: allMachines,
            currentMachineId: currentMachineId,
            currentMachineName: currentMachineName,
            format: format,
            formatItems: OutputFormatter.formatPasswords,
            isScraped: \.isScraped,
            scrapeMachineName: \.scrapeMachineName,
            scrapeMachineId: \.scrapeMachineId
        )
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
        try renderAPIKeysListing(
            apiKeys,
            favoritesOnly: favoritesOnly,
            cliEnabledOnly: cliEnabledOnly,
            environment: environment,
            folder: folder,
            format: format,
            allMachines: allMachines,
            currentMachineId: currentMachineId,
            currentMachineName: currentMachineName
        ).output
    }

    static func renderAPIKeysListing(
        _ apiKeys: [BridgeAPIKey],
        favoritesOnly: Bool,
        cliEnabledOnly: Bool = false,
        environment: String? = nil,
        folder: String? = nil,
        format: OutputFormat,
        allMachines: Bool = false,
        currentMachineId: String = MachineIdentity.load().machineId,
        currentMachineName: String? = MachineIdentity.load().displayName
    ) throws -> RenderedList {
        try renderedList(
            apiKeys.filter {
                (!favoritesOnly || $0.isFavorite) &&
                (!cliEnabledOnly || $0.isCliEnabled) &&
                Self.environmentMatches(environment, itemEnvironments: $0.environments) &&
                folderMatches(itemFolderPath: $0.folderPath, filterFolderPath: folder)
            },
            allMachines: allMachines,
            currentMachineId: currentMachineId,
            currentMachineName: currentMachineName,
            format: format,
            formatItems: OutputFormatter.formatAPIKeys,
            isScraped: \.isScraped,
            scrapeMachineName: \.scrapeMachineName,
            scrapeMachineId: \.scrapeMachineId
        )
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
        try renderCertificatesListing(
            certificates,
            favoritesOnly: favoritesOnly,
            cliEnabledOnly: cliEnabledOnly,
            environment: environment,
            folder: folder,
            format: format,
            allMachines: allMachines,
            currentMachineId: currentMachineId,
            currentMachineName: currentMachineName
        ).output
    }

    static func renderCertificatesListing(
        _ certificates: [BridgeCertificate],
        favoritesOnly: Bool,
        cliEnabledOnly: Bool = false,
        environment: String? = nil,
        folder: String? = nil,
        format: OutputFormat,
        allMachines: Bool = false,
        currentMachineId: String = MachineIdentity.load().machineId,
        currentMachineName: String? = MachineIdentity.load().displayName
    ) throws -> RenderedList {
        try renderedList(
            certificates.filter {
                (!favoritesOnly || $0.isFavorite) &&
                (!cliEnabledOnly || $0.isCliEnabled) &&
                Self.environmentMatches(environment, itemEnvironments: $0.environments) &&
                folderMatches(itemFolderPath: $0.folderPath, filterFolderPath: folder)
            },
            allMachines: allMachines,
            currentMachineId: currentMachineId,
            currentMachineName: currentMachineName,
            format: format,
            formatItems: OutputFormatter.formatCertificates,
            isScraped: \.isScraped,
            scrapeMachineName: \.scrapeMachineName,
            scrapeMachineId: \.scrapeMachineId
        )
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
        try renderNotesListing(
            notes,
            favoritesOnly: favoritesOnly,
            cliEnabledOnly: cliEnabledOnly,
            environment: environment,
            folder: folder,
            format: format,
            allMachines: allMachines,
            currentMachineId: currentMachineId,
            currentMachineName: currentMachineName
        ).output
    }

    static func renderNotesListing(
        _ notes: [BridgeNote],
        favoritesOnly: Bool,
        cliEnabledOnly: Bool = false,
        environment: String? = nil,
        folder: String? = nil,
        format: OutputFormat,
        allMachines: Bool = false,
        currentMachineId: String = MachineIdentity.load().machineId,
        currentMachineName: String? = MachineIdentity.load().displayName
    ) throws -> RenderedList {
        try renderedList(
            notes.filter {
                (!favoritesOnly || $0.isFavorite) &&
                (!cliEnabledOnly || $0.isCliEnabled) &&
                Self.environmentMatches(environment, itemEnvironments: $0.environments) &&
                folderMatches(itemFolderPath: $0.folderPath, filterFolderPath: folder)
            },
            allMachines: allMachines,
            currentMachineId: currentMachineId,
            currentMachineName: currentMachineName,
            format: format,
            formatItems: OutputFormatter.formatNotes,
            isScraped: \.isScraped,
            scrapeMachineName: \.scrapeMachineName,
            scrapeMachineId: \.scrapeMachineId
        )
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
        try renderSSHKeysListing(
            keys,
            favoritesOnly: favoritesOnly,
            cliEnabledOnly: cliEnabledOnly,
            environment: environment,
            folder: folder,
            format: format,
            allMachines: allMachines,
            currentMachineId: currentMachineId,
            currentMachineName: currentMachineName
        ).output
    }

    static func renderSSHKeysListing(
        _ keys: [BridgeSSHKey],
        favoritesOnly: Bool,
        cliEnabledOnly: Bool = false,
        environment: String? = nil,
        folder: String? = nil,
        format: OutputFormat,
        allMachines: Bool = false,
        currentMachineId: String = MachineIdentity.load().machineId,
        currentMachineName: String? = MachineIdentity.load().displayName
    ) throws -> RenderedList {
        try renderedList(
            keys.filter {
                (!favoritesOnly || $0.isFavorite) &&
                (!cliEnabledOnly || $0.isCliEnabled) &&
                Self.environmentMatches(environment, itemEnvironments: $0.environments) &&
                folderMatches(itemFolderPath: $0.folderPath, filterFolderPath: folder)
            },
            allMachines: allMachines,
            currentMachineId: currentMachineId,
            currentMachineName: currentMachineName,
            format: format,
            formatItems: OutputFormatter.formatSSHKeys,
            isScraped: \.isScraped,
            scrapeMachineName: \.scrapeMachineName,
            scrapeMachineId: \.scrapeMachineId
        )
    }

    private static func renderedList<Item>(
        _ items: [Item],
        allMachines: Bool,
        currentMachineId: String,
        currentMachineName: String?,
        format: OutputFormat,
        formatItems: ([Item], OutputFormat) throws -> String,
        isScraped: KeyPath<Item, Bool>,
        scrapeMachineName: KeyPath<Item, String?>,
        scrapeMachineId: KeyPath<Item, String?>
    ) throws -> RenderedList {
        let scoped = ScrapedItemMachineSupport.partition(
            items,
            allMachines: allMachines,
            currentMachineId: currentMachineId,
            currentMachineName: currentMachineName,
            isScraped: isScraped,
            scrapeMachineName: scrapeMachineName,
            scrapeMachineId: scrapeMachineId
        )
        return RenderedList(
            output: try formatItems(scoped.included, format),
            omissionWarning: ScrapedItemMachineSupport.omissionWarning(
                omittedCount: scoped.omittedCount,
                machineLabels: scoped.omittedMachineLabels
            )
        )
    }

    static func environmentMatches(_ environment: String?, itemEnvironments: [String]) -> Bool {
        environment.map {
            VaultEnvironmentTags.contains($0, in: itemEnvironments)
                || VaultEnvironmentTags.containsAll(in: itemEnvironments)
        } ?? true
    }
}
