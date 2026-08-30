import Foundation

/// Directories searched after the process PATH when resolving a declared MCP
/// upstream basename. GUI-launched clients often have a PATH that omits
/// Homebrew.
public enum MCPProxyPathOverlay: Sendable {
    public static func directories(homeDirectory: URL) -> [String] {
        [
            homeDirectory.appendingPathComponent(".local/bin").path,
            "/opt/homebrew/bin",
            "/usr/local/bin",
        ]
    }

    public static func searchPath(
        path: String,
        homeDirectory: URL
    ) -> String {
        var seen = Set<String>()
        var entries: [String] = []
        for directory in path.split(separator: ":").map(String.init) + directories(homeDirectory: homeDirectory)
        where !directory.isEmpty && seen.insert(directory).inserted {
            entries.append(directory)
        }
        return entries.joined(separator: ":")
    }
}
