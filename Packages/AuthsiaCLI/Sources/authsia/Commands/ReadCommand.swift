import ArgumentParser
import Foundation
import Darwin
import AuthenticatorBridge

struct ReadCmd: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "read",
        abstract: "Resolve a secret reference URI and print its value",
        discussion: """
            Reads a single secret via an authsia:// URI and outputs the raw value.
            Use this to compose secrets in shell scripts without storing them on disk.

            URI format: authsia://<type>/<item>[/<field>][?folder=<path>]
              type:   password, api-key, cert, note, ssh, otp
              item:   item name or ID
              field:  specific field (defaults: password/key/certificate/content/privateKey/code)

            Examples:
              authsia read "authsia://password/GitHub/password"
              authsia read "authsia://api-key/Stripe/key"
              authsia read "authsia://cert/TLS/privateKey" --out-file key.pem
              authsia read "authsia://otp/GitHub/code" --copy
              export API_KEY=$(authsia read "authsia://api-key/Stripe/key")
              authsia read "authsia://ssh/deploy/publicKey" >> ~/.ssh/authorized_keys
            """
    )

    @Argument(help: "Secret reference URI (authsia://type/item[/field][?folder=path])")
    var uri: String

    @Option(name: .long, help: "Write value to file instead of stdout (sets 0600 permissions)")
    var outFile: String?

    @Flag(name: .long, help: "Copy the value to clipboard instead of stdout")
    var copy = false

    @Option(name: .long, help: "Clear clipboard after N seconds (0 to disable, default: 30)")
    var clipboardTimeout: Int = 30

    func run() throws {
        if clipboardTimeout < 0 {
            throw ValidationError("--clipboard-timeout must be 0 or greater. Use 0 to clear immediately after copy.")
        }

        let ref = try Self.parseAndValidate(uri)
        try AuthsiaBridgeClient.shared.withRequestedCommand(.read) {
            if ProcessInfo.processInfo.environment[AutomationAccessResolver.environmentKey] != nil {
                let payload = try AuthsiaBridgeClient.shared.list()
                try Self.authorizeAutomationAccess(ref: ref, payload: payload)
            }
            let resolver = SecretReferenceResolver(client: AuthsiaBridgeClient.shared)
            let value = try resolver.resolve(ref)

            if copy {
                try ClipboardClient.system.copy(value, clipboardTimeout)
                return
            }

            if let outFile {
                try Self.writeToFile(value: value, path: outFile)
                return
            }

            // Raw value to stdout — no newline added, no JSON wrapping
            FileHandle.standardOutput.write(Data(value.utf8))
        }
    }

    // MARK: - Testable helpers

    static func parseAndValidate(_ uri: String) throws -> SecretReference {
        guard SecretReference.isSecretReference(uri) else {
            throw CLIError.unsupported(
                message: "Invalid secret reference '\(uri)'. Expected authsia://<type>/<item>[/<field>].\n" +
                    "  Example: authsia://password/GitHub/password"
            ).asValidationError
        }
        return try SecretReference.parse(uri)
    }

    static func authorizeAutomationAccess(
        ref: SecretReference,
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

        try AutomationAccessResolver.authorizeCommand(.read, credential: credential)

        let loadType: Load.ItemType
        switch ref.type {
        case .otp:
            throw ValidationError(
                "Automation credentials do not permit OTP access. Use an interactive terminal for OTP, " +
                    "or create a non-OTP scoped credential with `authsia access create`."
            )
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
        }
        let filteredPayload = AutomationAccessResolver.filterPayload(payload, allowedScope: credential.scope, environmentScope: credential.environmentScope)
        if let folderPath = normalizeFolderPath(ref.folder) {
            _ = try Load.selectExactFolderReference(
                type: loadType,
                query: ref.item,
                folderPath: folderPath,
                payload: filteredPayload,
                allMachines: true,
                currentMachineId: currentMachineId
            )
        } else {
            _ = try Load.selectReferences(
                type: loadType,
                scope: .single(ref.item),
                payload: filteredPayload,
                allMachines: true,
                currentMachineId: currentMachineId
            )
        }
    }

    static func writeToFile(value: String, path: String) throws {
        let url = URL(fileURLWithPath: path)
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        var statBuffer = Darwin.stat()
        if Darwin.lstat(path, &statBuffer) == 0, (statBuffer.st_mode & S_IFMT) == S_IFLNK {
            throw CLIError.unsupported(
                message: "Refusing to write secret to symlink path '\(path)'."
            )
        }

        // Use open(2) with O_CREAT|O_WRONLY|O_TRUNC and mode 0600 so the file is
        // never world-readable, even briefly. The two-step write+chmod approach has
        // a TOCTOU window between creation (umask perms) and the chmod call.
        let fd = Darwin.open(path, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else {
            throw CLIError.unsupported(
                message: "Cannot create file at '\(path)': \(String(cString: strerror(errno)))"
            )
        }
        defer { Darwin.close(fd) }

        guard Darwin.fchmod(fd, 0o600) == 0 else {
            throw CLIError.unsupported(
                message: "Cannot set permissions on '\(path)': \(String(cString: strerror(errno)))"
            )
        }

        let data = Data(value.utf8)
        try data.withUnsafeBytes { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            var offset = 0
            while offset < buffer.count {
                let written = Darwin.write(fd, baseAddress.advanced(by: offset), buffer.count - offset)
                if written < 0 {
                    if errno == EINTR { continue }
                    throw CLIError.unsupported(
                        message: "Failed to write to '\(path)': \(String(cString: strerror(errno)))"
                    )
                }
                guard written > 0 else {
                    throw CLIError.unsupported(
                        message: "Failed to write to '\(path)': write returned 0 bytes."
                    )
                }
                offset += written
            }
        }
    }
}
