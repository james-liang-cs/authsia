import ArgumentParser
import Foundation

enum MCPClient: String, CaseIterable, ExpressibleByArgument, Sendable {
    case codex
    case claude
    case cursor
    case vscode
}

enum MCPClientConfigurationError: LocalizedError, Equatable {
    case unsupportedClient
    case unsafeValue
    case workspaceUnavailable

    var errorDescription: String? {
        switch self {
        case .unsupportedClient:
            return "Supported MCP clients are codex, claude, cursor, and vscode."
        case .unsafeValue:
            return "MCP configuration values must be absolute paths without control characters."
        case .workspaceUnavailable:
            return "Run this command from an initialized Authsia workspace."
        }
    }
}

enum MCPClientConfiguration {
    static func render(
        clientName: String,
        executableURL: URL,
        startingDirectory: URL,
        fileManager: FileManager = .default
    ) throws -> String {
        guard isSafe(clientName), let client = MCPClient(rawValue: clientName) else {
            throw isSafe(clientName)
                ? MCPClientConfigurationError.unsupportedClient
                : MCPClientConfigurationError.unsafeValue
        }
        return try render(
            client: client,
            executableURL: executableURL,
            startingDirectory: startingDirectory,
            fileManager: fileManager
        )
    }

    static func render(
        client: MCPClient,
        executableURL: URL,
        startingDirectory: URL,
        fileManager: FileManager = .default
    ) throws -> String {
        guard let discoveredRoot = WorkspaceRootResolver.findWorkspaceRoot(
            startingAt: startingDirectory,
            fileManager: fileManager
        ) else {
            throw MCPClientConfigurationError.workspaceUnavailable
        }
        let binaryPath = executableURL.resolvingSymlinksInPath().path
        let workspacePath = discoveredRoot.resolvingSymlinksInPath().path
        guard binaryPath.hasPrefix("/"), workspacePath.hasPrefix("/"),
              isSafe(binaryPath), isSafe(workspacePath) else {
            throw MCPClientConfigurationError.unsafeValue
        }

        let warning = "Machine-specific absolute path: review before sharing or committing this configuration."
        switch client {
        case .codex:
            return """
            Add to Codex config.toml:
            [mcp_servers.authsia]
            command = "\(tomlEscaped(binaryPath))"
            args = ["mcp", "serve"]
            cwd = "\(tomlEscaped(workspacePath))"

            \(warning)
            """
        case .claude:
            return try jsonConfiguration(
                heading: "Place in \(workspacePath)/.mcp.json:",
                rootKey: "mcpServers",
                binaryPath: binaryPath,
                workspacePath: nil,
                includeType: false,
                warning: warning
            )
        case .cursor:
            return try jsonConfiguration(
                heading: "Place in \(workspacePath)/.cursor/mcp.json:",
                rootKey: "mcpServers",
                binaryPath: binaryPath,
                workspacePath: nil,
                includeType: false,
                warning: warning
            )
        case .vscode:
            return try jsonConfiguration(
                heading: "Place in \(workspacePath)/.vscode/mcp.json:",
                rootKey: "servers",
                binaryPath: binaryPath,
                workspacePath: workspacePath,
                includeType: true,
                warning: warning
            )
        }
    }

    private static func jsonConfiguration(
        heading: String,
        rootKey: String,
        binaryPath: String,
        workspacePath: String?,
        includeType: Bool,
        warning: String
    ) throws -> String {
        var server: [String: Any] = [
            "args": ["mcp", "serve"],
            "command": binaryPath,
        ]
        if includeType { server["type"] = "stdio" }
        if let workspacePath { server["cwd"] = workspacePath }
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

    private static func isSafe(_ value: String) -> Bool {
        !value.isEmpty && value.unicodeScalars.allSatisfy {
            !CharacterSet.controlCharacters.contains($0)
        }
    }
}
