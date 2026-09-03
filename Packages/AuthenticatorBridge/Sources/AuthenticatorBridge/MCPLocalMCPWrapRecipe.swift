import Foundation

public enum MCPLocalMCPWrapRecipe {
    public static func clipboardText(
        for finding: MCPClientServerFinding,
        authsiaCommand: String
    ) -> String? {
        clipboardText(
            for: finding,
            authsiaCommand: authsiaCommand,
            includeWorkspacePolicy: finding.status == .unadmitted
        )
    }

    public static func clipboardText(
        for finding: MCPClientServerFinding,
        authsiaCommand: String,
        includeWorkspacePolicy: Bool
    ) -> String? {
        guard finding.isWrapEligible,
              let command = finding.wrapCommand,
              let authsia = sanitizedCommand(authsiaCommand),
              let replacement = clientReplacement(for: finding, authsiaCommand: authsia) else {
            return nil
        }

        var sections: [String] = [
            clientLaunchInstruction(for: finding),
            "",
            replacement,
        ]
        if includeWorkspacePolicy {
            sections.append(contentsOf: [
                "",
                "Workspace policy is already written if you used Declare in workspace. Otherwise add this object to mcpUpstreams in .authsia/workspace.json:",
                policyObject(
                    name: finding.serverName,
                    command: command,
                    arguments: finding.wrapArguments
                ),
            ])
        }
        sections.append(contentsOf: [
            "",
            "Authsia writes the scanned client file only after you confirm Write wrap. Next: authsia mcp catalog --server \(finding.serverName) --write records what that server advertises, then the first permitted tool call requests local MCP admission.",
        ])
        return sections.joined(separator: "\n")
    }

    public static func clientLaunchInstruction(for finding: MCPClientServerFinding) -> String {
        "Replace the \(finding.source.displayName) \(finding.serverName) entry in \(finding.configPathLabel)."
    }

    public static func wrapWriteCommand(for finding: MCPClientServerFinding) -> String {
        "authsia mcp wrap --write --server \(finding.serverName)"
    }

    /// What to paste when an upstream is wrapped but advertises nothing. Its
    /// declared env forbids the probe, so the tool names have to come from the
    /// server's own documentation; only the shape can be supplied here.
    public static func toolPolicyText(for finding: MCPClientServerFinding) -> String? {
        guard finding.needsToolPolicy,
              let name = MCPProxyClientLaunch.validUpstreamName(
                finding.declaredUpstreamName ?? finding.serverName
              ) else {
            return nil
        }
        return """
            The \(name) upstream declares environment values, so Authsia will not \
            start it to read its tool list. Name the tools yourself in the \(name) \
            entry under mcpUpstreams in .authsia/workspace.json:

            "tools": {
              "allow": ["tool-that-may-run"],
              "approve": ["tool-that-should-prompt"]
            }

            allow runs under the admission grant; approve asks every call. Until \
            one of them names a tool, the client sees no tools and the agent \
            falls back to the unproxied CLI.
            """
    }

    private static func clientReplacement(
        for finding: MCPClientServerFinding,
        authsiaCommand: String
    ) -> String? {
        guard MCPProxyClientLaunch.validUpstreamName(finding.serverName) != nil else {
            return nil
        }
        let name = finding.serverName
        let env = MCPProxyClientLaunch.environment(
            upstreamName: name,
            workspacePath: MCPLocalMCPClientWrap.wrapWorkspacePath(for: finding)
        )
        switch finding.source {
        case .codex:
            return """
            Open \(finding.configPathLabel) and replace the existing [mcp_servers.\(name)] table.

            Configure directly:
            \(codexAddCommand(name: name, authsiaCommand: authsiaCommand, environment: env))

            Or paste this table:
            \(codexTable(name: name, authsiaCommand: authsiaCommand, environment: env))
            """
        case .claude:
            if finding.configScope == .project {
                return """
                Open \(finding.configPathLabel). Find "\(name)" under "mcpServers" and replace that object with:

                \(jsonServerObject(authsiaCommand: authsiaCommand, environment: env, includeType: false))
                """
            }
            return """
            Open \(finding.configPathLabel). Find "\(name)" under "mcpServers" and replace that object.

            Configure directly:
            \(claudeAddCommand(name: name, authsiaCommand: authsiaCommand, environment: env))

            Or paste this object:
            \(jsonServerObject(authsiaCommand: authsiaCommand, environment: env, includeType: false))
            """
        case .claudeDesktop:
            // Claude Desktop has no repository of its own, so the workspace it
            // binds to is pinned in the entry rather than inferred from a cwd.
            return """
            Open \(finding.configPathLabel). Find "\(name)" under "mcpServers" and replace that object.

            \(jsonServerObject(authsiaCommand: authsiaCommand, environment: env, includeType: false))

            Quit and reopen Claude Desktop afterwards.
            """
        case .cursor:
            return """
            Open \(finding.configPathLabel). Find "\(name)" under "mcpServers" and replace that object.

            Configure directly:
            \(wrapWriteCommand(for: finding))

            Or paste this object:
            \(jsonServerObject(authsiaCommand: authsiaCommand, environment: env, includeType: false))
            """
        case .devin:
            return """
            Open \(finding.configPathLabel). Find "\(name)" under "mcpServers" and replace that object.

            Configure directly:
            \(wrapWriteCommand(for: finding))

            Or paste this object:
            \(jsonServerObject(authsiaCommand: authsiaCommand, environment: env, includeType: false))
            """
        case .vscode:
            if finding.configScope == .project {
                return """
                Open \(finding.configPathLabel). Find "\(name)" under "servers" and replace that object with:

                \(jsonServerObject(authsiaCommand: authsiaCommand, environment: env, includeType: true))
                """
            }
            return """
            In VS Code, run MCP: Open User Configuration (\(finding.configPathLabel)). Find "\(name)" under "servers" and replace that object.

            Configure directly:
            \(vscodeAddCommand(name: name, authsiaCommand: authsiaCommand, environment: env))

            Or paste this object:
            \(jsonServerObject(authsiaCommand: authsiaCommand, environment: env, includeType: true))
            """
        }
    }

    private static func policyObject(name: String, command: String, arguments: [String]) -> String {
        var object: [String: Any] = [
            "name": name,
            "command": command,
            "env": [:] as [String: String],
        ]
        if !arguments.isEmpty {
            object["args"] = arguments
        }
        return jsonObject(object)
    }

    static func jsonServerObject(
        authsiaCommand: String,
        environment: [String: String],
        includeType: Bool
    ) -> String {
        var object: [String: Any] = [
            "command": authsiaCommand,
            "args": MCPProxyClientLaunch.arguments,
            "env": environment,
        ]
        if includeType {
            object["type"] = "stdio"
        }
        return jsonObject(object)
    }

    private static func jsonObject(_ object: [String: Any]) -> String {
        let data = try? JSONSerialization.data(
            withJSONObject: object,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        )
        return data.flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
    }

    static func codexTable(
        name: String,
        authsiaCommand: String,
        environment: [String: String],
        preservedLines: [String] = []
    ) -> String {
        var table = """
        [mcp_servers.\(name)]
        command = "\(tomlEscaped(authsiaCommand))"
        args = \(tomlStringArray(MCPProxyClientLaunch.arguments))
        env_vars = [\(MCPProxyClientLaunch.tlsTrustEnvironmentNames.map { "\"\($0)\"" }.joined(separator: ", "))]
        """
        // Settings the human put on this launch that Authsia does not manage,
        // such as a raised startup timeout, still apply to the proxy process.
        // Dropping them would change how the launch behaves without saying so.
        for line in preservedLines {
            table += "\n" + line
        }
        if !environment.isEmpty {
            table += "\n\n[mcp_servers.\(name).env]\n"
            table += environment.keys.sorted().map { key in
                "\(key) = \"\(tomlEscaped(environment[key] ?? ""))\""
            }.joined(separator: "\n")
        }
        return table
    }

    private static func codexAddCommand(
        name: String,
        authsiaCommand: String,
        environment: [String: String]
    ) -> String {
        "codex mcp add \(name)\(envFlags(environment)) -- \(shellQuoted(authsiaCommand)) "
            + MCPProxyClientLaunch.arguments.joined(separator: " ")
    }

    private static func claudeAddCommand(
        name: String,
        authsiaCommand: String,
        environment: [String: String]
    ) -> String {
        // This recipe always replaces an entry the scan just found, and
        // `claude mcp add` refuses a name that already exists, so the remove
        // comes first. `claude mcp add` also declares `-e, --env <env...>` as
        // variadic, so the server name has to precede it or the parser collects
        // the name as another KEY=value.
        "claude mcp remove --scope user \(name)\n"
            + "claude mcp add --scope user \(name)\(envFlags(environment)) -- \(shellQuoted(authsiaCommand)) "
            + MCPProxyClientLaunch.arguments.joined(separator: " ")
    }

    private static func vscodeAddCommand(
        name: String,
        authsiaCommand: String,
        environment: [String: String]
    ) -> String {
        let object: [String: Any] = [
            "args": MCPProxyClientLaunch.arguments,
            "command": authsiaCommand,
            "env": environment,
            "name": name,
            "type": "stdio",
        ]
        let data = (try? JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )).flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
        return "code --add-mcp \(shellQuoted(data))"
    }

    private static func envFlags(_ environment: [String: String]) -> String {
        environment.keys.sorted().map { key in
            " --env \(key)=\(environment[key] ?? "")"
        }.joined()
    }

    static func tomlEscaped(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }

    static func tomlStringArray(_ values: [String]) -> String {
        "[" + values.map { "\"\(tomlEscaped($0))\"" }.joined(separator: ", ") + "]"
    }

    private static func shellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    static func sanitizedCommand(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              trimmed.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            return nil
        }
        return trimmed
    }
}
