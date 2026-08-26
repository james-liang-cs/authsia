import Foundation

/// Client-facing launch for `authsia mcp proxy`.
///
/// Company MCP allowlists match command plus argv. Putting `--upstream <name>`
/// in that argv would force the company to enumerate every local tool. Client
/// configuration therefore uses a stable argv and names the workspace upstream
/// with `AUTHSIA_MCP_UPSTREAM`. `--upstream` remains a CLI convenience for
/// terminal launches and is still recognized in existing client files.
public enum MCPProxyClientLaunch: Sendable {
    public static let arguments = ["mcp", "proxy"]
    public static let environmentKey = "AUTHSIA_MCP_UPSTREAM"
    public static let legacyUpstreamFlag = "--upstream"

    public static func environment(upstreamName: String) -> [String: String] {
        [environmentKey: upstreamName]
    }

    public static func wrappedUpstreamName(
        arguments: [String],
        environmentName: String?
    ) -> String? {
        if arguments.count == 4,
           Array(arguments.prefix(3)) == ["mcp", "proxy", legacyUpstreamFlag] {
            return validUpstreamName(arguments[3])
        }
        if arguments == Self.arguments {
            return validUpstreamName(environmentName)
        }
        return nil
    }

    public static func isProxyLaunch(arguments: [String]) -> Bool {
        arguments == Self.arguments
            || (arguments.count == 4
                && Array(arguments.prefix(3)) == ["mcp", "proxy", legacyUpstreamFlag])
    }

    public static func validUpstreamName(_ value: String?) -> String? {
        guard let value, value.range(
            of: #"^[A-Za-z][A-Za-z0-9_-]{0,31}$"#,
            options: .regularExpression
        ) != nil else {
            return nil
        }
        return value
    }
}
