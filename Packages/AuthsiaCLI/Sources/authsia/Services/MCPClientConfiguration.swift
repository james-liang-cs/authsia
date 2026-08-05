import ArgumentParser
import Foundation

enum MCPClient: String, CaseIterable, ExpressibleByArgument, Sendable {
    case codex
    case claude
    case cursor
    case windsurf
    case vscode
}

enum MCPClientConfigurationError: LocalizedError, Equatable {
    case unsupportedClient
    case unsafeValue

    var errorDescription: String? {
        switch self {
        case .unsupportedClient:
            return "Supported MCP clients are codex, claude, cursor, windsurf, and vscode."
        case .unsafeValue:
            return "MCP configuration values must be absolute paths without control characters."
        }
    }
}

enum MCPClientConfiguration {
    static func render(
        clientName: String,
        executableURL: URL
    ) throws -> String {
        guard isSafe(clientName), let client = MCPClient(rawValue: clientName) else {
            throw isSafe(clientName)
                ? MCPClientConfigurationError.unsupportedClient
                : MCPClientConfigurationError.unsafeValue
        }
        return try render(
            client: client,
            executableURL: executableURL
        )
    }

    static func render(
        client: MCPClient,
        executableURL: URL
    ) throws -> String {
        let binaryPath = executableURL.resolvingSymlinksInPath().path
        guard binaryPath.hasPrefix("/"), isSafe(binaryPath) else {
            throw MCPClientConfigurationError.unsafeValue
        }

        let warning = "Machine-specific absolute path for user-global configuration; do not commit or share it. " +
            "The server can start from any directory and accepts an optional workspaceRoot tool argument from " +
            "IDE clients, with safe launch context as fallback; workspace tools remain unavailable until an " +
            "initialized Authsia workspace is selected."
        switch client {
        case .codex:
            return """
            Configure directly:
            codex mcp add authsia -- \(shellQuoted(binaryPath)) mcp serve

            Or add to user-global ~/.codex/config.toml:
            [mcp_servers.authsia]
            command = "\(tomlEscaped(binaryPath))"
            args = ["mcp", "serve"]

            \(warning)
            """
        case .claude:
            let configuration = try jsonConfiguration(
                heading: "Or merge into user-global ~/.claude.json:",
                rootKey: "mcpServers",
                binaryPath: binaryPath,
                includeType: false,
                warning: warning
            )
            return """
            Configure directly:
            claude mcp add --scope user authsia -- \(shellQuoted(binaryPath)) mcp serve

            \(configuration)
            """
        case .cursor:
            return try jsonConfiguration(
                heading: "Place in user-global ~/.cursor/mcp.json:",
                rootKey: "mcpServers",
                binaryPath: binaryPath,
                includeType: false,
                warning: warning
            )
        case .windsurf:
            return try jsonConfiguration(
                heading: "Place in user-global ~/.codeium/windsurf/mcp_config.json:",
                rootKey: "mcpServers",
                binaryPath: binaryPath,
                includeType: false,
                warning: warning
            )
        case .vscode:
            let configuration = try jsonConfiguration(
                heading: "Or in VS Code, run `MCP: Open User Configuration` and merge:",
                rootKey: "servers",
                binaryPath: binaryPath,
                includeType: true,
                warning: warning
            )
            let directConfiguration: [String: Any] = [
                "args": ["mcp", "serve"],
                "command": binaryPath,
                "name": "authsia",
            ]
            let directData = try JSONSerialization.data(
                withJSONObject: directConfiguration,
                options: [.sortedKeys, .withoutEscapingSlashes]
            )
            return """
            Configure directly:
            code --add-mcp \(shellQuoted(String(decoding: directData, as: UTF8.self)))

            \(configuration)
            """
        }
    }

    private static func jsonConfiguration(
        heading: String,
        rootKey: String,
        binaryPath: String,
        includeType: Bool,
        arguments: [String] = ["mcp", "serve"],
        warning: String
    ) throws -> String {
        var server: [String: Any] = [
            "args": arguments,
            "command": binaryPath,
        ]
        if includeType { server["type"] = "stdio" }
        let object: [String: Any] = [rootKey: ["authsia": server]]
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

    private static func shellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func isSafe(_ value: String) -> Bool {
        !value.isEmpty && value.unicodeScalars.allSatisfy {
            !CharacterSet.controlCharacters.contains($0)
        }
    }
}
