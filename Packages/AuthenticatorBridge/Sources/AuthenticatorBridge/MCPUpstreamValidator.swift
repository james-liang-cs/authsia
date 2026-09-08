import Foundation

public enum MCPUpstreamValidationError: Error, Equatable, Sendable {
    case missingCommand(String)
    case invalidCommand(String)
    case invalidArguments(String)
    case invalidEnvironment(String)
    case invalidTools(String)
    case invalidCatalog(String)
    case invalidEndpoint(String)
    case invalidCredentialHeader(String)
}

public enum MCPUpstreamSecretReferenceClassification: Equatable, Sendable {
    case notReference
    case permitted
    case invalidOrUnsupported
}

/// Shared validation for workspace-owned MCP declarations.
public enum MCPUpstreamValidator {
    private static let namePattern = try! NSRegularExpression(
        pattern: "^[A-Za-z][A-Za-z0-9_-]{0,31}$"
    )
    private static let secretEnvironmentNamePattern = try! NSRegularExpression(
        pattern: #"(?i)(TOKEN|SECRET|PASSWORD|PASSWD|PASS\b|AUTHORIZATION|BEARER|_KEY$)"#
    )
    private static let catalogJSONLimit = 64 * 1_024
    private static let maximumArgumentCount = 64
    private static let maximumArgumentBytes = 32 * 1_024
    private static let maximumToolNameLength = 128

    public static func isValidName(_ name: String) -> Bool {
        let range = NSRange(name.startIndex..<name.endIndex, in: name)
        return namePattern.firstMatch(in: name, options: [], range: range) != nil
    }

    public static func validate(
        _ upstream: MCPUpstreamConfig,
        classifySecretReference: (String) -> MCPUpstreamSecretReferenceClassification = { _ in
            .notReference
        }
    ) throws {
        if upstream.requiresStdioPolicy {
            let command = upstream.command?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !command.isEmpty else {
                throw MCPUpstreamValidationError.missingCommand(upstream.name)
            }
            try validateStdioCommand(command, arguments: upstream.args)
            try validateArguments(upstream.args)
        } else if upstream.transport == .http || upstream.transport == .streamableHTTP {
            guard let rawURL = upstream.url else {
                throw MCPUpstreamValidationError.invalidEndpoint(upstream.name)
            }
            do {
                _ = try MCPLocalHTTPEndpointValidator.validate(rawURL)
            } catch {
                throw MCPUpstreamValidationError.invalidEndpoint(upstream.name)
            }
        }
        try validateTools(upstream.tools)
        try validateEnvironment(
            upstream.env,
            classifySecretReference: classifySecretReference
        )
        try validateCatalog(upstream.catalog)
        try validateCredentialHeaders(
            upstream.credentialHeaders,
            classifySecretReference: classifySecretReference
        )
    }

    public static func validateCatalogBounds(_ upstreams: [MCPUpstreamConfig]) throws {
        for upstream in upstreams {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let data = try encoder.encode(upstream.catalog)
            guard data.count <= catalogJSONLimit else {
                throw MCPUpstreamValidationError.invalidCatalog("exceeds 64 KiB")
            }
        }
    }

    private static func validateStdioCommand(_ command: String, arguments: [String]) throws {
        guard let launch = MCPUpstreamCommandRules.launch(command: command, arguments: arguments),
              launch.command == command, launch.arguments == arguments else {
            throw MCPUpstreamValidationError.invalidCommand("joined command line; put the executable in command and arguments in args")
        }
        if command.hasPrefix("/") {
            throw MCPUpstreamValidationError.invalidCommand(command)
        }
        if command.contains("/") {
            guard isCommitSafeRelativePath(command) else {
                throw MCPUpstreamValidationError.invalidCommand(command)
            }
        } else if command.contains(where: \.isWhitespace)
            || command.contains("\0")
            || command == "."
            || command == ".."
            || !command.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) {
            throw MCPUpstreamValidationError.invalidCommand(command)
        }
        if MCPUpstreamCommandRules.containsShellCommandString([command] + arguments) {
            throw MCPUpstreamValidationError.invalidCommand(command)
        }
    }

    private static func validateArguments(_ arguments: [String]) throws {
        guard arguments.count <= maximumArgumentCount else {
            throw MCPUpstreamValidationError.invalidArguments(
                "at most \(maximumArgumentCount) entries"
            )
        }
        for argument in arguments {
            guard argument.utf8.count <= maximumArgumentBytes else {
                throw MCPUpstreamValidationError.invalidArguments("each entry must be at most 32 KiB")
            }
            guard argument.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
                throw MCPUpstreamValidationError.invalidArguments("must not contain control characters")
            }
            guard !argument.lowercased().contains("authsia://") else {
                throw MCPUpstreamValidationError.invalidArguments("authsia:// references belong in env")
            }
        }
    }

    private static func validateEnvironment(
        _ environment: [String: String],
        classifySecretReference: (String) -> MCPUpstreamSecretReferenceClassification
    ) throws {
        for (name, value) in environment {
            guard isValidEnvironmentName(name),
                  value.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
                throw MCPUpstreamValidationError.invalidEnvironment(name)
            }
            switch classifySecretReference(value) {
            case .permitted:
                continue
            case .invalidOrUnsupported:
                    throw MCPUpstreamValidationError.invalidEnvironment(name)
            case .notReference:
                if environmentNameRequiresSecretReference(name) {
                    throw MCPUpstreamValidationError.invalidEnvironment(name)
                }
            }
        }
    }

    private static func validateTools(_ tools: MCPUpstreamToolPolicy) throws {
        var seen = Set<String>()
        for name in tools.allow + tools.approve + tools.deny {
            guard !name.isEmpty,
                  name.count <= maximumToolNameLength,
                  name.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }),
                  seen.insert(name).inserted else {
                throw MCPUpstreamValidationError.invalidTools(name)
            }
        }
    }

    private static func validateCredentialHeaders(
        _ headers: [MCPUpstreamCredentialHeader],
        classifySecretReference: (String) -> MCPUpstreamSecretReferenceClassification
    ) throws {
        let forbidden = Set([
            "connection", "content-length", "cookie", "host",
            "mcp-protocol-version", "mcp-session-id", "proxy-authorization",
            "te", "trailer", "transfer-encoding", "upgrade",
        ])
        var seen = Set<String>()
        for header in headers {
            let canonical = header.headerName.lowercased()
            guard isValidHeaderName(header.headerName),
                  !forbidden.contains(canonical),
                  (canonical != "authorization" || header.format == .bearer),
                  ["api-key", "password", "note"].contains(URLComponents(string: header.reference)?.host ?? ""),
                  seen.insert(canonical).inserted,
                  classifySecretReference(header.reference) == .permitted else {
                throw MCPUpstreamValidationError.invalidCredentialHeader(header.headerName)
            }
        }
    }

    private static func isValidHeaderName(_ value: String) -> Bool {
        let allowed = CharacterSet(charactersIn: "!#$%&'*+-.^_`|~")
            .union(.alphanumerics)
        return !value.isEmpty && value.unicodeScalars.allSatisfy { allowed.contains($0) }
    }

    private static func validateCatalog(_ catalog: [MCPUpstreamToolDescriptor]) throws {
        for entry in catalog {
            guard case .object(let object) = entry.inputSchema else {
                throw MCPUpstreamValidationError.invalidCatalog("inputSchema must be a JSON object")
            }
            guard case .string("object") = object["type"] else {
                throw MCPUpstreamValidationError.invalidCatalog("inputSchema type must be object")
            }
            if containsForbiddenSchemaContent(entry.inputSchema) {
                throw MCPUpstreamValidationError.invalidCatalog(
                    "inputSchema must not contain $ref, $schema, or URI-shaped values"
                )
            }
        }
    }

    private static func containsForbiddenSchemaContent(_ value: MCPJSONValue) -> Bool {
        switch value {
        case .object(let object):
            if object.keys.contains("$ref") || object.keys.contains("$schema") {
                return true
            }
            return object.values.contains(where: containsForbiddenSchemaContent)
        case .array(let array):
            return array.contains(where: containsForbiddenSchemaContent)
        case .string(let string):
            let lowered = string.lowercased()
            return lowered.hasPrefix("http:")
                || lowered.hasPrefix("https:")
                || lowered.hasPrefix("file:")
        case .number, .bool, .null:
            return false
        }
    }

    private static func environmentNameRequiresSecretReference(_ name: String) -> Bool {
        let range = NSRange(name.startIndex..<name.endIndex, in: name)
        return secretEnvironmentNamePattern.firstMatch(in: name, options: [], range: range) != nil
    }

    private static func isValidEnvironmentName(_ name: String) -> Bool {
        guard let first = name.unicodeScalars.first,
              first == "_" || CharacterSet.letters.contains(first) else {
            return false
        }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "_"))
        return name.unicodeScalars.dropFirst().allSatisfy { allowed.contains($0) }
    }

    private static func isCommitSafeRelativePath(_ path: String) -> Bool {
        guard !path.isEmpty, !path.hasPrefix("/"), !path.contains("\0") else {
            return false
        }
        let components = path.split(separator: "/", omittingEmptySubsequences: false)
        return !components.contains(where: { $0 == ".." || $0.isEmpty })
    }
}
