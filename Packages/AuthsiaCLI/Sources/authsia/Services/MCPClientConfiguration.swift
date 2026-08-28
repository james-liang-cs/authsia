import ArgumentParser
import AuthenticatorBridge
import Foundation

enum MCPClient: String, CaseIterable, Sendable {
    case codex
    case claude
    case cursor
    case devin
    case vscode
}

extension MCPClient: ExpressibleByArgument {
    init?(argument: String) {
        switch argument.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "codex":
            self = .codex
        case "claude":
            self = .claude
        case "cursor":
            self = .cursor
        case "devin", "devin-desktop", "windsurf":
            self = .devin
        case "vscode":
            self = .vscode
        default:
            return nil
        }
    }

    static var allValueStrings: [String] {
        ["codex", "claude", "cursor", "devin", "vscode"]
    }
}

enum MCPClientConfigurationError: LocalizedError, Equatable {
    case unsupportedClient
    case unsafeValue

    var errorDescription: String? {
        switch self {
        case .unsupportedClient:
            return "Supported MCP clients are codex, claude, cursor, devin, and vscode."
        case .unsafeValue:
            return "MCP configuration values must be absolute paths without control characters."
        }
    }
}

enum MCPClientConfiguration {
    static func scanReport(_ findings: [MCPClientServerFinding]) -> String? {
        guard !findings.isEmpty else { return nil }
        let rows = findings.map { finding in
            let state: String
            switch finding.status {
            case .admittedWrapped:
                state = "wrapped and admitted"
            case .directBypass:
                state = "declared, but launches directly and bypasses admission"
            case .unadmitted:
                state = "not on the current workspace allowlist"
            }
            return "- \(finding.source.displayName) / \(finding.serverName) "
                + "(\(finding.commandLabel)): \(state)"
        }
        return ([
            "Read-only local MCP configuration scan:",
        ] + rows + [
            "Detection is visibility only for direct client launches; Authsia does not edit client files or block them.",
        ]).joined(separator: "\n")
    }

    static func render(
        clientName: String,
        executableURL: URL,
        upstreamNames: [String] = []
    ) throws -> String {
        guard isSafe(clientName), let client = MCPClient(argument: clientName) else {
            throw isSafe(clientName)
                ? MCPClientConfigurationError.unsupportedClient
                : MCPClientConfigurationError.unsafeValue
        }
        return try render(
            client: client,
            executableURL: executableURL,
            upstreamNames: upstreamNames
        )
    }

    static func render(
        client: MCPClient,
        executableURL: URL,
        upstreamNames: [String] = []
    ) throws -> String {
        let binaryPath = executableURL.resolvingSymlinksInPath().path
        guard binaryPath.hasPrefix("/"), isSafe(binaryPath),
              upstreamNames.allSatisfy(isSafeServerName) else {
            throw MCPClientConfigurationError.unsafeValue
        }

        var seen = Set<String>()
        let upstreams = upstreamNames.filter { seen.insert($0).inserted }
        let servers = [ServerConfiguration(name: "authsia", arguments: ["mcp", "serve"])]
            + upstreams.map {
                ServerConfiguration(
                    name: $0,
                    arguments: MCPProxyClientLaunch.arguments,
                    environment: MCPProxyClientLaunch.environment(upstreamName: $0)
                )
            }

        let warning = "Machine-specific absolute path for user-global configuration; do not commit or share it. " +
            "The server can start from any directory and accepts an optional workspaceRoot tool argument from " +
            "IDE clients, with safe launch context as fallback; workspace tools remain unavailable until an " +
            "initialized Authsia workspace is selected."
        let hint = upstreams.isEmpty
            ? "\n\nProxy blocks appear here when mcpUpstreams are declared in a managed workspace."
            : ""
        switch client {
        case .codex:
            let direct = servers.map { server in
                "codex mcp add \(server.name)\(envFlags(server.environment)) -- \(shellQuoted(binaryPath)) \(server.arguments.joined(separator: " "))"
            }.joined(separator: "\n")
            let manual = servers.map { server in
                var table = """
                [mcp_servers.\(server.name)]
                command = "\(tomlEscaped(binaryPath))"
                args = \(tomlStringArray(server.arguments))
                """
                table += "\nenv_vars = [\(MCPInheritedEnvironment.codexEnvVarsLiteral)]"
                if !server.environment.isEmpty {
                    table += "\n\n[mcp_servers.\(server.name).env]\n"
                    table += server.environment.keys.sorted().map { key in
                        "\(key) = \"\(tomlEscaped(server.environment[key] ?? ""))\""
                    }.joined(separator: "\n")
                }
                return table
            }.joined(separator: "\n\n")
            return """
            Configure directly:
            \(direct)

            For a custom TLS CA, use the manual configuration below.

            Or add to user-global ~/.codex/config.toml:
            \(manual)

            \(warning)\(hint)
            """
        case .claude:
            let configuration = try jsonConfiguration(
                heading: "Or merge into user-global ~/.claude.json:",
                rootKey: "mcpServers",
                binaryPath: binaryPath,
                includeType: false,
                servers: servers,
                warning: warning + hint
            )
            let direct = servers.map { server in
                // `-e, --env <env...>` is variadic, so the server name must
                // precede it or `claude mcp add` reads the name as a KEY=value.
                "claude mcp add --scope user \(server.name)\(envFlags(server.environment)) -- \(shellQuoted(binaryPath)) " +
                    server.arguments.joined(separator: " ")
            }.joined(separator: "\n")
            return """
            Configure directly:
            \(direct)

            Claude Code refuses a name that already exists. To replace a server
            you launch directly today, run `claude mcp remove --scope user <name>`
            first.

            \(configuration)
            """
        case .cursor:
            return try jsonConfiguration(
                heading: "Place in user-global ~/.cursor/mcp.json:",
                rootKey: "mcpServers",
                binaryPath: binaryPath,
                includeType: false,
                servers: servers,
                warning: warning + hint
            )
        case .devin:
            return try jsonConfiguration(
                heading: "Place in user-global ~/.config/devin/mcp_config.json:",
                rootKey: "mcpServers",
                binaryPath: binaryPath,
                includeType: false,
                servers: servers,
                warning: warning + hint
            )
        case .vscode:
            let configuration = try jsonConfiguration(
                heading: "Or in VS Code, run `MCP: Open User Configuration` and merge:",
                rootKey: "servers",
                binaryPath: binaryPath,
                includeType: true,
                servers: servers,
                warning: warning + hint
            )
            let direct = try servers.map { server in
                var object: [String: Any] = [
                    "args": server.arguments,
                    "command": binaryPath,
                    "name": server.name,
                ]
                if !server.environment.isEmpty {
                    object["env"] = server.environment
                }
                if server.name != "authsia" { object["type"] = "stdio" }
                let data = try JSONSerialization.data(
                    withJSONObject: object,
                    options: [.sortedKeys, .withoutEscapingSlashes]
                )
                return "code --add-mcp \(shellQuoted(String(decoding: data, as: UTF8.self)))"
            }.joined(separator: "\n")
            return """
            Configure directly:
            \(direct)

            \(configuration)
            """
        }
    }

    private static func jsonConfiguration(
        heading: String,
        rootKey: String,
        binaryPath: String,
        includeType: Bool,
        servers: [ServerConfiguration],
        warning: String
    ) throws -> String {
        var renderedServers: [String: Any] = [:]
        for configuration in servers {
            var server: [String: Any] = [
                "args": configuration.arguments,
                "command": binaryPath,
            ]
            if includeType { server["type"] = "stdio" }
            if !configuration.environment.isEmpty {
                server["env"] = configuration.environment
            }
            renderedServers[configuration.name] = server
        }
        let object: [String: Any] = [rootKey: renderedServers]
        let data = try JSONSerialization.data(
            withJSONObject: object,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        )
        return "\(heading)\n\(String(decoding: data, as: UTF8.self))\n\n\(warning)"
    }

    private static func tomlEscaped(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }

    private static func tomlStringArray(_ values: [String]) -> String {
        "[" + values.map { "\"\(tomlEscaped($0))\"" }.joined(separator: ", ") + "]"
    }

    private static func envFlags(_ environment: [String: String]) -> String {
        environment.keys.sorted().map { key in
            " --env \(key)=\(environment[key] ?? "")"
        }.joined()
    }

    private static func shellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func isSafe(_ value: String) -> Bool {
        !value.isEmpty && value.unicodeScalars.allSatisfy {
            !CharacterSet.controlCharacters.contains($0)
        }
    }

    private static func isSafeServerName(_ value: String) -> Bool {
        value.range(
            of: #"^[A-Za-z][A-Za-z0-9_-]{0,31}$"#,
            options: .regularExpression
        ) != nil
    }
}

private struct ServerConfiguration {
    let name: String
    let arguments: [String]
    var environment: [String: String] = [:]
}
