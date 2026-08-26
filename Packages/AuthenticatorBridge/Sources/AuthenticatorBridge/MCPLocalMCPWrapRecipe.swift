import Foundation

public enum MCPLocalMCPWrapRecipe {
    public static func clipboardText(
        for finding: MCPClientServerFinding,
        authsiaCommand: String
    ) -> String? {
        guard finding.isWrapEligible,
              let command = finding.wrapCommand,
              let authsia = sanitizedCommand(authsiaCommand) else {
            return nil
        }
        let argsJSON = jsonArray(finding.wrapArguments)
        return """
        Route \(finding.source.displayName) \(finding.serverName) through Authsia.

        1. Add this object to mcpUpstreams in .authsia/workspace.json:
        {
          "name": \(jsonString(finding.serverName)),
          "command": \(jsonString(command)),
          "args": \(argsJSON),
          "env": {}
        }

        2. Replace the client launch with:
        command: \(authsia)
        args: ["mcp", "proxy"]
        env: { \(jsonString(MCPProxyClientLaunch.environmentKey)): \(jsonString(finding.serverName)) }

        Authsia does not edit the client file. The first permitted tool call requests local MCP admission.
        """
    }

    private static func sanitizedCommand(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              trimmed.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            return nil
        }
        return trimmed
    }

    private static func jsonString(_ value: String) -> String {
        jsonArray([value]).dropFirst().dropLast().trimmingCharacters(in: .whitespaces)
    }

    private static func jsonArray(_ values: [String]) -> String {
        let data = try? JSONSerialization.data(withJSONObject: values)
        return data.flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
    }
}
