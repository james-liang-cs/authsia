import AuthenticatorBridge
import Foundation

enum MCPInheritedEnvironment {
    static let names: Set<String> = Set([
        "HOME",
        "LANG",
        "LOGNAME",
        "PATH",
        "SHELL",
        "TERM",
        "TMPDIR",
        "USER",
        "__CF_USER_TEXT_ENCODING",
    ]).union(MCPProxyClientLaunch.tlsTrustEnvironmentNames)

    static func filtered(_ environment: [String: String]) -> [String: String] {
        environment.filter { names.contains($0.key) || $0.key.hasPrefix("LC_") }
    }

    static var codexEnvVarsLiteral: String {
        MCPProxyClientLaunch.tlsTrustEnvironmentNames.map { "\"\($0)\"" }.joined(separator: ", ")
    }
}
