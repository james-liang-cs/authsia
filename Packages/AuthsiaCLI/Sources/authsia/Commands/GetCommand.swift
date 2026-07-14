import ArgumentParser
import Foundation
import AuthenticatorBridge

struct Get: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Retrieve a secret (requires biometric approval)",
        discussion: """
            Fetches the full secret for a single item. Requires biometric
            authentication or an active session (see 'authsia unlock').
            Use --folder with password/api-key/cert/note/ssh when duplicate item names
            exist in different vault folders. Folder-qualified get selects the
            exact folder only; child folders are not included.

            Item types:
              password    Retrieve a stored password
              api-key     Retrieve a stored API key
              cert        Retrieve a certificate (and optional private key)
              note        Retrieve a secure note
              ssh         Retrieve an SSH key
              otp         Retrieve a TOTP code

            Fields (--field):
              password:   username, password, all (default)
              api-key:    key, all (default)
              cert:       certificate, privateKey, all (default)
              note:       content, all (default)
              ssh:        publicKey, privateKey, comment, fingerprint, keyType,
                          approvalPolicy, boundHosts, all (default)
              otp:        (not applicable)

            Examples:
              authsia get password GitHub                   Get all fields
              authsia get password GitHub --field username   Username only
              authsia get password DB_PASSWORD --folder Team/API
              authsia get api-key Stripe --field key
              authsia get cert TLS_CERT --folder Team/API
              authsia get cert MyCert --field privateKey     Private key only
              authsia get note Runbook --folder Team/Ops
              authsia get otp GitHub --copy                  TOTP code to clipboard
              authsia get note "API Keys" --format table     Table format
              authsia get ssh DeployKey --folder Infra/SSH
              authsia get ssh WorkKey --field fingerprint    SSH fingerprint only
            """
    )

    enum ItemType: String, ExpressibleByArgument, CaseIterable {
        case password
        case apiKey = "api-key"
        case cert
        case note
        case ssh
        case otp

        static var allValueStrings: [String] { allCases.map(\.rawValue) }
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
        case keyType
        case approvalPolicy
        case boundHosts
        case all

        static var allValueStrings: [String] { allCases.map(\.rawValue) }
    }

    @Argument(help: "Item type: password, api-key, cert, note, ssh, otp")
    var type: ItemType

    @Argument(help: "Item name or ID to match", completion: .custom(ShellCompletionMetadata.completeItems))
    var query: String

    @Option(
        name: .shortAndLong,
        help: "Restrict password/api-key/cert/note/ssh lookup to an exact folder",
        completion: .custom(ShellCompletionMetadata.completeFolders)
    )
    var folder: String?

    @Option(name: .long, help: "Environment tag used to disambiguate the item")
    var environment: String?

    @Option(
        name: .long,
        help: "Return a specific field (see above)",
        completion: .custom(ShellCompletionMetadata.completeGetFields)
    )
    var field: Field?

    @Flag(name: .long, help: "Copy the result to clipboard")
    var copy = false

    @Option(name: .long, help: "Clear clipboard after N seconds (0 to disable, default: 30)")
    var clipboardTimeout: Int = 30

    @Option(name: .long, help: "Output format: json (default), table")
    var format: OutputFormat = .json

    @Flag(name: .customLong("json"), help: .hidden)
    var json = false

    @Flag(name: .customLong("chrome-native-host"), help: .hidden)
    var chromeNativeHost = false

    func run() throws {
        if clipboardTimeout < 0 {
            throw ValidationError("--clipboard-timeout must be 0 or greater. Use 0 to clear immediately after copy.")
        }
        try validateChromeNativeHostMarker()
        if type == .otp, environment != nil {
            throw ValidationError("--environment is not supported for OTP items.")
        }

        let outputFormat = try resolveOutputFormat(format: format, jsonFlag: json, command: "authsia get")
        let client = AuthsiaBridgeClient.shared
        let requestedCommand: String
        if chromeNativeHost {
            requestedCommand = BridgeContext.chromeNativeHostRequestedCommand
        } else {
            requestedCommand = CapabilityCommand.get.rawValue
        }
        try client.withRequestedCommand(requestedCommand, includeAutomationCredential: !chromeNativeHost) {
            let normalizedFolder = normalizeFolderPath(folder)
            let needsPayload = type != .otp || normalizedFolder != nil ||
                ProcessInfo.processInfo.environment[AutomationAccessResolver.environmentKey] != nil
            let payload = try needsPayload ? client.list() : nil
            let bridgeQuery = try Self.resolveBridgeQuery(
                type: type,
                query: query,
                folder: normalizedFolder,
                environment: environment,
                payload: payload,
                currentMachineId: MachineIdentity.load().machineId
            )

            if ProcessInfo.processInfo.environment[AutomationAccessResolver.environmentKey] != nil {
                try Self.authorizeAutomationAccess(type: type, query: query, folder: normalizedFolder, payload: payload!)
            }

            switch type {
            case .password:
                let result = try client.getPassword(query: bridgeQuery, field: field?.rawValue)
                let output = try Self.formatPassword(result: result, field: field, format: outputFormat)
                if copy, let value = Self.copyValue(for: result, field: field) { try ClipboardClient.system.copy(value, clipboardTimeout) }
                print(output)

            case .apiKey:
                let result = try client.getAPIKey(query: bridgeQuery, field: field?.rawValue)
                let output = try Self.formatAPIKey(result: result, field: field, format: outputFormat)
                if copy, let value = Self.copyValue(for: result, field: field) { try ClipboardClient.system.copy(value, clipboardTimeout) }
                print(output)

            case .cert:
                let result = try client.getCertificate(query: bridgeQuery, field: field?.rawValue)
                let includeKey = field == .privateKey || field == .all
                let output = try Self.formatCertificate(
                    result: result,
                    field: field,
                    includePrivateKey: includeKey,
                    format: outputFormat
                )
                if copy, let value = Self.copyValue(for: result, field: field) { try ClipboardClient.system.copy(value, clipboardTimeout) }
                print(output)

            case .note:
                let result = try client.getNote(query: bridgeQuery)
                let output = try Self.formatNote(result: result, field: field, format: outputFormat)
                if copy, let value = Self.copyValue(for: result, field: field) { try ClipboardClient.system.copy(value, clipboardTimeout) }
                print(output)

            case .ssh:
                let result = try client.getSSH(query: bridgeQuery, field: field?.rawValue)
                let output = try Self.formatSSH(result: result, field: field, format: outputFormat)
                if copy, let value = Self.copyValue(for: result, field: field) { try ClipboardClient.system.copy(value, clipboardTimeout) }
                print(output)

            case .otp:
                let result = try client.getOTP(query: bridgeQuery)
                let output = try Self.formatOTP(result: result, format: outputFormat)
                // For OTP, default copy is the code
                if copy { try ClipboardClient.system.copy(result.code, clipboardTimeout) }
                print(output)
            }
        }
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

    static func formatOTP(result: OTPResult, format: OutputFormat) throws -> String {
        try OutputFormatter.formatOTPResult(result, format: format)
    }

    static func authorizeAutomationAccess(
        type: ItemType,
        query: String,
        folder: String? = nil,
        payload: BridgeListPayload,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        store: AccessCredentialStore = AccessCredentialStore(),
        now: Date = Date(),
        currentMachineId: String = MachineIdentity.load().machineId
    ) throws {
        guard let credential = try AutomationAccessResolver.resolveActiveCredential(
            environment: environment,
            store: store,
            now: now
        ) else {
            return
        }

        try AutomationAccessResolver.authorizeCommand(.get, credential: credential)
        try AutomationAccessResolver.authorizeGetType(type)

        let loadType: Load.ItemType
        switch type {
        case .password: loadType = .password
        case .apiKey: loadType = .apiKey
        case .cert: loadType = .cert
        case .note: loadType = .note
        case .ssh: loadType = .ssh
        case .otp:
            return
        }

        let filteredPayload = AutomationAccessResolver.filterPayload(payload, allowedScope: credential.scope, environmentScope: credential.environmentScope)
        let scope: Load.ScopeSelection = if let folder {
            .itemInFolder(query: query, folderPath: folder)
        } else {
            .single(query)
        }
        _ = try Load.selectReferences(
            type: loadType,
            scope: scope,
            payload: filteredPayload,
            allMachines: true,
            currentMachineId: currentMachineId
        )
    }

    static func resolveBridgeQuery(
        type: ItemType,
        query: String,
        folder: String?,
        environment: String? = nil,
        payload: BridgeListPayload?,
        currentMachineId: String = MachineIdentity.load().machineId,
        currentMachineName: String? = MachineIdentity.load().displayName
    ) throws -> String {
        if type == .otp {
            guard folder == nil else {
                throw CLIError.unsupported(
                    message: "--folder is not supported for OTP items. Run `authsia list otp --format table`, " +
                        "then retry with `authsia get otp <name-or-id>`."
                ).asValidationError
            }
            return query
        }

        guard let payload else {
            throw CLIError.unsupported(
                message: "Item lookup requires list metadata. Run `authsia list \(listScope(for: type)) " +
                    "--format table`, then retry with an item ID."
            ).asValidationError
        }

        if folder == nil || environment != nil {
            return try VaultItemQueryResolver.resolve(
                type: vaultQueryType(for: type),
                query: query,
                environment: environment,
                folder: folder,
                payload: payload
            ).uuidString
        }

        guard let folder else { return query }

        let loadType: Load.ItemType
        switch type {
        case .password:
            loadType = .password
        case .apiKey:
            loadType = .apiKey
        case .cert:
            loadType = .cert
        case .note:
            loadType = .note
        case .ssh:
            loadType = .ssh
        case .otp:
            throw CLIError.unsupported(
                message: "--folder is not supported for OTP items. Run `authsia list otp --format table`, " +
                    "then retry with `authsia get otp <name-or-id>`."
            ).asValidationError
        }

        let reference: Load.ItemReference
        do {
            reference = try Load.selectExactFolderReference(
                type: loadType,
                query: query,
                folderPath: folder,
                payload: payload,
                allMachines: true,
                currentMachineId: currentMachineId,
                currentMachineName: currentMachineName
            )
        } catch CLIError.multipleMatches(let kind, let query, let matches) {
            throw CLIError.multipleMatches(
                kind: kind,
                query: query,
                matches: matches.map {
                    CLIError.MatchDescriptor(
                        name: $0.name,
                        id: $0.id,
                        context: $0.context,
                        commandHint: getCommandHint(type: type, id: $0.id, folder: folder)
                    )
                }
            )
        }
        return reference.id
    }

    private static func vaultQueryType(for type: ItemType) -> VaultItemQueryType {
        switch type {
        case .password: return .password
        case .apiKey: return .apiKey
        case .cert: return .certificate
        case .note: return .note
        case .ssh: return .ssh
        case .otp: preconditionFailure("OTP is not a vault environment item")
        }
    }

    private static func getCommandHint(type: ItemType, id: String, folder: String?) -> String {
        var command = "authsia get \(type.rawValue) \(id)"
        if let folder {
            command += " --folder \(Load.shellQuote(folder))"
        }
        return command
    }

    private static func listScope(for type: ItemType) -> String {
        switch type {
        case .password: return "passwords"
        case .apiKey: return "api-keys"
        case .cert: return "certs"
        case .note: return "notes"
        case .ssh: return "ssh"
        case .otp: return "otp"
        }
    }

    static func formatPassword(result: PasswordResult, field: Field?, format: OutputFormat) throws -> String {
        switch field {
        case .username:
            return result.username
        case .password:
            return result.password
        case .all, .none:
            return try OutputFormatter.formatPasswordResult(result, format: format)
        default:
            throw CLIError.unsupported(
                message: "Field '\(field?.rawValue ?? "")' is not supported for password. " +
                    "Use --field username, --field password, or omit --field for JSON output."
            ).asValidationError
        }
    }

    static func formatAPIKey(result: APIKeyResult, field: Field?, format: OutputFormat) throws -> String {
        switch field {
        case .key:
            return result.key
        case .all, .none:
            return try OutputFormatter.formatAPIKeyResult(result, format: format)
        default:
            throw CLIError.unsupported(
                message: "Field '\(field?.rawValue ?? "")' is not supported for api-key. " +
                    "Use --field key, or omit --field for JSON output."
            ).asValidationError
        }
    }

    static func formatCertificate(
        result: CertificateResult,
        field: Field?,
        includePrivateKey: Bool,
        format: OutputFormat
    ) throws -> String {
        switch field {
        case .certificate:
            return result.certificate
        case .privateKey:
            guard let key = result.privateKey else {
                throw CLIError.unsupported(
                    message: "Certificate has no private key stored."
                ).asValidationError
            }
            return key
        case .all, .none:
            return try OutputFormatter.formatCertificateResult(result, includePrivateKey: includePrivateKey, format: format)
        default:
            throw CLIError.unsupported(
                message: "Field '\(field?.rawValue ?? "")' is not supported for certificate. " +
                    "Use --field certificate, --field privateKey, or omit --field for JSON output."
            ).asValidationError
        }
    }

    static func formatNote(result: NoteResult, field: Field?, format: OutputFormat) throws -> String {
        switch field {
        case .content:
            return result.content
        case .all, .none:
            return try OutputFormatter.formatNoteResult(result, format: format)
        default:
            throw CLIError.unsupported(
                message: "Field '\(field?.rawValue ?? "")' is not supported for note. " +
                    "Use --field content, or omit --field for JSON output."
            ).asValidationError
        }
    }

    static func formatSSH(result: SSHKeyResult, field: Field?, format: OutputFormat) throws -> String {
        switch field {
        case .publicKey:
            return result.publicKey
        case .privateKey:
            return result.privateKey
        case .comment:
            return result.comment
        case .fingerprint:
            return result.fingerprint
        case .keyType:
            return result.keyType.rawValue
        case .approvalPolicy:
            return result.approvalPolicy.rawValue
        case .boundHosts:
            return result.boundHosts.joined(separator: ",")
        case .all, .none:
            return try OutputFormatter.formatSSHKeyResult(result, format: format)
        default:
            throw CLIError.unsupported(
                message: "Field '\(field?.rawValue ?? "")' is not supported for SSH. " +
                    "Use --field publicKey, privateKey, comment, fingerprint, keyType, approvalPolicy, or boundHosts."
            ).asValidationError
        }
    }

    private static func copyValue(for result: PasswordResult, field: Field?) -> String? {
        switch field {
        case .username:
            return result.username
        case .password, .all, .none:
            return result.password
        default:
            return nil
        }
    }

    private static func copyValue(for result: APIKeyResult, field: Field?) -> String? {
        switch field {
        case .key, .all, .none:
            return result.key
        default:
            return nil
        }
    }

    private static func copyValue(for result: CertificateResult, field: Field?) -> String? {
        switch field {
        case .privateKey:
            return result.privateKey
        case .certificate, .all, .none:
            return result.certificate
        default:
            return nil
        }
    }

    private static func copyValue(for result: NoteResult, field: Field?) -> String? {
        switch field {
        case .content, .all, .none:
            return result.content
        default:
            return nil
        }
    }

    private static func copyValue(for result: SSHKeyResult, field: Field?) -> String? {
        switch field {
        case .publicKey:
            return result.publicKey
        case .privateKey, .all, .none:
            return result.privateKey
        case .comment:
            return result.comment
        case .fingerprint:
            return result.fingerprint
        case .keyType:
            return result.keyType.rawValue
        case .approvalPolicy:
            return result.approvalPolicy.rawValue
        case .boundHosts:
            return result.boundHosts.joined(separator: ",")
        default:
            return nil
        }
    }
}
