import AuthenticatorBridge
import Foundation

enum MCPInheritedEnvironment {
    static let names: Set<String> = Set([
        "HOME",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "LANG",
        "LOGNAME",
        "NO_PROXY",
        "PATH",
        "SHELL",
        "TERM",
        "TMPDIR",
        "USER",
        "__CF_USER_TEXT_ENCODING",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    ]).union(MCPProxyClientLaunch.tlsTrustEnvironmentNames)

    static func filtered(_ environment: [String: String]) -> [String: String] {
        environment.filter { names.contains($0.key) || $0.key.hasPrefix("LC_") }
    }
}
