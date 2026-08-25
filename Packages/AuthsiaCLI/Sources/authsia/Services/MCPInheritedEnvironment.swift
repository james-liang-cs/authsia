import Foundation

enum MCPInheritedEnvironment {
    static let names: Set<String> = [
        "HOME",
        "LANG",
        "LOGNAME",
        "PATH",
        "REQUESTS_CA_BUNDLE",
        "SHELL",
        "SSL_CERT_FILE",
        "TERM",
        "TMPDIR",
        "USER",
        "__CF_USER_TEXT_ENCODING",
    ]

    static func filtered(_ environment: [String: String]) -> [String: String] {
        environment.filter { names.contains($0.key) || $0.key.hasPrefix("LC_") }
    }
}
