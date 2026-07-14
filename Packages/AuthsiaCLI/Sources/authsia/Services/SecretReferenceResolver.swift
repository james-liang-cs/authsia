import Foundation
import AuthenticatorBridge

// MARK: - Error

enum SecretReferenceError: Error, LocalizedError {
    case invalidScheme(String)
    case missingType(String)
    case unknownType(String)
    case missingItem(String)
    case invalidURI(String)
    case unsupportedField(type: SecretReference.ItemType, field: String, supported: [String])

    var errorDescription: String? {
        switch self {
        case .invalidScheme(let uri):
            return "Invalid scheme in '\(uri)'. Expected 'authsia://'. Example: authsia://password/GitHub/password"
        case .missingType(let uri):
            return "Missing item type in '\(uri)'. Expected authsia://<type>/<item>[/<field>]. Example: authsia://password/GitHub/password"
        case .unknownType(let type):
            return "Unknown item type '\(type)'. Valid types: password, api-key, cert, note, ssh, otp. Example: authsia://api-key/Stripe/key"
        case .missingItem(let uri):
            return "Missing item name in '\(uri)'. Expected authsia://<type>/<item>[/<field>]. Example: authsia://password/GitHub/password"
        case .invalidURI(let uri):
            return "Invalid secret reference: '\(uri)'. Expected authsia://<type>/<item>[/<field>]. Example: authsia://password/GitHub/password"
        case .unsupportedField(let type, let field, let supported):
            return "Field '\(field)' is not supported for \(type.rawValue). Supported: \(supported.joined(separator: ", ")). " +
                "Update the URI field segment or omit it to use the default field."
        }
    }
}

// MARK: - Model

struct SecretReference: Equatable {
    enum ItemType: String, CaseIterable {
        case password
        case apiKey = "api-key"
        case cert
        case note
        case ssh
        case otp
    }

    let type: ItemType
    let item: String
    let field: String?
    let folder: String?
    let isFolderScoped: Bool

    init(type: ItemType, item: String, field: String?, folder: String?, isFolderScoped: Bool? = nil) {
        self.type = type
        self.item = item
        self.field = field
        self.folder = folder
        self.isFolderScoped = isFolderScoped ?? (folder != nil)
    }

    /// Default field for each type when field is omitted from the URI.
    var defaultField: String {
        switch type {
        case .password: return "password"
        case .apiKey: return "key"
        case .cert: return "certificate"
        case .note: return "content"
        case .ssh: return "privateKey"
        case .otp: return "code"
        }
    }

    /// The field to resolve — explicit field or type default.
    var resolvedField: String {
        field ?? defaultField
    }

    var supportedFields: [String] {
        switch type {
        case .password:
            return ["username", "password"]
        case .apiKey:
            return ["key"]
        case .cert:
            return ["certificate", "privateKey"]
        case .note:
            return ["content"]
        case .ssh:
            return ["publicKey", "privateKey", "comment", "fingerprint"]
        case .otp:
            return ["code"]
        }
    }

    var displayName: String {
        switch type {
        case .password:
            return "password"
        case .apiKey:
            return "api-key"
        case .cert:
            return "certificate"
        case .note:
            return "note"
        case .ssh:
            return "ssh"
        case .otp:
            return "otp"
        }
    }

    func validateResolvedField() throws {
        let field = resolvedField
        guard supportedFields.contains(field) else {
            throw SecretReferenceError.unsupportedField(type: type, field: field, supported: supportedFields)
        }
    }

    // MARK: - Parsing

    static let schemePrefix = "authsia://"

    static func isSecretReference(_ value: String) -> Bool {
        let lowered = value.lowercased()
        return lowered.hasPrefix(schemePrefix) && value.count > schemePrefix.count
    }

    /// Parse an `authsia://type/item[/field][?folder=path]` URI.
    static func parse(_ uri: String) throws -> SecretReference {
        guard !uri.isEmpty else {
            throw SecretReferenceError.invalidURI(uri)
        }

        let lowered = uri.lowercased()
        guard lowered.hasPrefix(schemePrefix) else {
            throw SecretReferenceError.invalidScheme(uri)
        }

        let afterScheme = String(uri.dropFirst(schemePrefix.count))
        guard !afterScheme.isEmpty else {
            throw SecretReferenceError.invalidURI(uri)
        }

        // Split off query string
        let parts = afterScheme.split(separator: "?", maxSplits: 1)
        let pathPart = String(parts[0])
        let queryPart = parts.count > 1 ? String(parts[1]) : nil

        let folder = parseQueryParam(queryPart, key: "folder")
        let isFolderScoped = hasQueryParam(queryPart, key: "folder")

        // Split path: type / item / field (maxSplits:2 so field can contain slashes)
        let segments = pathPart.split(separator: "/", maxSplits: 2, omittingEmptySubsequences: false)
            .map { percentDecode(String($0)) }

        guard !segments.isEmpty, !segments[0].isEmpty else {
            throw SecretReferenceError.missingType(uri)
        }

        guard let itemType = ItemType(rawValue: segments[0].lowercased()) else {
            throw SecretReferenceError.unknownType(segments[0])
        }

        guard segments.count >= 2, !segments[1].isEmpty else {
            throw SecretReferenceError.missingItem(uri)
        }

        let item = segments[1]
        let field: String? = segments.count >= 3 && !segments[2].isEmpty ? segments[2] : nil

        return SecretReference(
            type: itemType,
            item: item,
            field: field,
            folder: folder,
            isFolderScoped: isFolderScoped
        )
    }

    // MARK: - Helpers

    private static func percentDecode(_ string: String) -> String {
        string.removingPercentEncoding ?? string
    }

    private static func parseQueryParam(_ query: String?, key: String) -> String? {
        guard let query else { return nil }
        for pair in query.split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1)
            if kv.count == 2, String(kv[0]) == key {
                return percentDecode(String(kv[1]))
            }
        }
        return nil
    }

    private static func hasQueryParam(_ query: String?, key: String) -> Bool {
        guard let query else { return false }
        for pair in query.split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1)
            if let name = kv.first, String(name) == key {
                return true
            }
        }
        return false
    }
}

// MARK: - Resolver Client Protocol

protocol SecretResolverClient {
    func resolveSecret(
        type: SecretReference.ItemType,
        query: String,
        field: String,
        folder: String?,
        isFolderScoped: Bool
    ) throws -> String
}

// MARK: - Batch Resolution Error

struct SecretResolutionErrors: Error, LocalizedError {
    struct Entry {
        let envKey: String
        let uri: String
        let error: Error
    }

    let errors: [Entry]

    var errorDescription: String? {
        let details = errors.map { "  \($0.envKey)=\($0.uri) → \($0.error.localizedDescription)" }
            .joined(separator: "\n")
        return "Failed to resolve \(errors.count) secret reference(s):\n\(details)"
    }
}

// MARK: - Resolver

struct SecretReferenceResolver {
    let client: SecretResolverClient

    /// Extract metadata for JIT preflight without resolving plaintext secrets.
    static func preflightReferences(environment: [String: String]) throws -> [AgentJITPreflightReference] {
        var references: [AgentJITPreflightReference] = []

        for value in environment.values {
            guard SecretReference.isSecretReference(value) else { continue }
            let ref = try SecretReference.parse(value)
            try ref.validateResolvedField()
            guard ref.type == .password || ref.type == .apiKey || ref.type == .cert || ref.type == .note else { continue }
            references.append(
                AgentJITPreflightReference(
                    type: ref.type.rawValue,
                    query: ref.item,
                    folderPath: normalizeFolderPath(ref.folder),
                    isFolderScoped: ref.isFolderScoped
                )
            )
        }

        return references.sorted {
            if $0.type != $1.type { return $0.type < $1.type }
            let lhsFolder = $0.folderPath ?? ""
            let rhsFolder = $1.folderPath ?? ""
            if lhsFolder != rhsFolder { return lhsFolder < rhsFolder }
            return $0.query < $1.query
        }
    }

    static func unsupportedAgentJITReferences(environment: [String: String]) throws -> [SecretReference] {
        var references: [SecretReference] = []

        for value in environment.values {
            guard SecretReference.isSecretReference(value) else { continue }
            let ref = try SecretReference.parse(value)
            try ref.validateResolvedField()
            if ref.type == .ssh || ref.type == .otp {
                references.append(ref)
            }
        }

        return references.sorted {
            if $0.type.rawValue != $1.type.rawValue {
                return $0.type.rawValue < $1.type.rawValue
            }
            return $0.item < $1.item
        }
    }

    /// Resolve a single secret reference to its plaintext value.
    func resolve(_ ref: SecretReference) throws -> String {
        try ref.validateResolvedField()
        return try client.resolveSecret(
            type: ref.type,
            query: ref.item,
            field: ref.resolvedField,
            folder: ref.folder,
            isFolderScoped: ref.isFolderScoped
        )
    }

    /// Scan an env dict for `authsia://` values, resolve them all.
    /// Returns (resolved dict, list of secret values for masking).
    /// Collects ALL errors before failing — never stops at first error.
    func resolveEnvironment(
        _ env: [String: String]
    ) throws -> (resolved: [String: String], secrets: [String]) {
        var resolved = env
        var secrets: [String] = []
        var errors: [SecretResolutionErrors.Entry] = []

        for (key, value) in env {
            guard SecretReference.isSecretReference(value) else { continue }
            do {
                let ref = try SecretReference.parse(value)
                let secret = try resolve(ref)
                resolved[key] = secret
                secrets.append(secret)
            } catch {
                errors.append(.init(envKey: key, uri: value, error: error))
            }
        }

        guard errors.isEmpty else {
            throw SecretResolutionErrors(errors: errors.sorted { $0.envKey < $1.envKey })
        }

        return (resolved, secrets)
    }
}

// MARK: - Bridge Client Conformance

extension AuthsiaBridgeClient: SecretResolverClient {
    func resolveSecret(
        type: SecretReference.ItemType,
        query: String,
        field: String,
        folder: String?,
        isFolderScoped: Bool
    ) throws -> String {
        try SecretReference(
            type: type,
            item: query,
            field: field,
            folder: folder,
            isFolderScoped: isFolderScoped
        ).validateResolvedField()
        if let folder = normalizeFolderPath(folder) {
            return try resolveFolderScopedSecret(type: type, query: query, field: field, folder: folder)
        }
        if isFolderScoped {
            return try resolveRootScopedSecret(type: type, query: query, field: field)
        }
        return try resolveUnscopedSecret(type: type, query: query, field: field)
    }

    private func resolveUnscopedSecret(type: SecretReference.ItemType, query: String, field: String) throws -> String {
        switch type {
        case .password:
            let result = try getPassword(query: query, field: field)
            return field == "username" ? result.username : result.password
        case .apiKey:
            return try getAPIKey(query: query, field: field).key
        case .cert:
            let result = try getCertificate(query: query, field: field)
            return field == "privateKey" ? (result.privateKey ?? "") : result.certificate
        case .note:
            return try getNote(query: query).content
        case .ssh:
            let result = try getSSH(query: query, field: field)
            switch field {
            case "publicKey": return result.publicKey
            case "comment": return result.comment
            case "fingerprint": return result.fingerprint
            default: return result.privateKey
            }
        case .otp:
            return try getOTP(query: query).code
        }
    }

    private func resolveFolderScopedSecret(
        type: SecretReference.ItemType,
        query: String,
        field: String,
        folder: String
    ) throws -> String {
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
                message: "Folder scoping is not supported for OTP references. Remove the folder query and use authsia://otp/<name>."
            ).asValidationError
        }

        let match = try Load.selectExactFolderReference(
            type: loadType,
            query: query,
            folderPath: folder,
            payload: list(),
            allMachines: true
        )

        return try resolveUnscopedSecret(type: type, query: match.id, field: field)
    }

    private func resolveRootScopedSecret(
        type: SecretReference.ItemType,
        query: String,
        field: String
    ) throws -> String {
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
                message: "Folder scoping is not supported for OTP references. Remove the folder query and use authsia://otp/<name>."
            ).asValidationError
        }

        let references = try Load.selectReferences(
            type: loadType,
            scope: .global,
            payload: list(),
            allMachines: true
        ).filter {
            normalizeFolderPath($0.folderPath) == nil
        }
        let match = try MatchHelper.findSingle(
            query: query,
            items: references,
            kind: "\(loadType.rawValue) item",
            id: { $0.id },
            searchable: { [$0.name] },
            display: { CLIError.MatchDescriptor(name: $0.name, id: $0.id, context: "folder: (root)") }
        )

        return try resolveUnscopedSecret(type: type, query: match.id, field: field)
    }
}
