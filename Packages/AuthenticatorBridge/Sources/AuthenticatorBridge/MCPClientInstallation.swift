import Foundation

/// Whether a coding client is installed on this Mac well enough to offer
/// Protect and client-filter actions. VS Code and Devin are presence-gated;
/// Codex, Claude Code, Cursor, and Claude Desktop stay offered.
public enum MCPClientInstallation: Sendable {
    public struct Probe: Sendable {
        public var bundleInstalled: @Sendable (String) -> Bool
        public var appExists: @Sendable (String) -> Bool

        public init(
            bundleInstalled: @escaping @Sendable (String) -> Bool,
            appExists: @escaping @Sendable (String) -> Bool
        ) {
            self.bundleInstalled = bundleInstalled
            self.appExists = appExists
        }

        /// Filesystem check of `/Applications` and `~/Applications`.
        public static var live: Probe {
            Probe(
                bundleInstalled: { _ in false },
                appExists: { name in
                    let home = FileManager.default.homeDirectoryForCurrentUser
                    let directories = [
                        URL(fileURLWithPath: "/Applications", isDirectory: true),
                        home.appendingPathComponent("Applications", isDirectory: true),
                    ]
                    return directories.contains {
                        FileManager.default.fileExists(atPath: $0.appendingPathComponent(name).path)
                    }
                }
            )
        }
    }

    public static let filterOrder: [MCPClientConfigSource] = [
        .codex, .claude, .cursor, .vscode, .devin, .claudeDesktop,
    ]

    public static func isInstalled(
        _ source: MCPClientConfigSource,
        probe: Probe = .live
    ) -> Bool {
        guard source.requiresAppPresence else { return true }
        switch source {
        case .vscode:
            return ["com.microsoft.VSCode", "com.microsoft.VSCodeInsiders"].contains(where: probe.bundleInstalled)
                || ["Visual Studio Code.app", "Visual Studio Code - Insiders.app"].contains(where: probe.appExists)
        case .devin:
            return probe.bundleInstalled("com.cognition.devin")
                || ["Devin.app", "Devin Desktop.app"].contains(where: probe.appExists)
        default:
            return true
        }
    }

    public static func protectableSources(probe: Probe = .live) -> [MCPClientConfigSource] {
        filterOrder.filter { isInstalled($0, probe: probe) }
    }
}
