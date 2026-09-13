import Darwin
import Foundation

/// Canonical identity for workspace paths used as exact client-config keys.
///
/// Foundation's lexical URL normalization does not cross macOS firmlinks such
/// as `/var` to `/private/var`. Claude Code resolves those paths before looking
/// up `projects[<root>]`, so Authsia must use the same filesystem identity.
enum MCPWorkspacePathIdentity {
    static func canonicalPath(_ path: String) -> String {
        let standardized = URL(fileURLWithPath: path, isDirectory: true)
            .standardizedFileURL.path
        if let resolved = standardized.withCString({ realpath($0, nil) }) {
            defer { free(resolved) }
            return String(cString: resolved)
        }
        return URL(fileURLWithPath: standardized, isDirectory: true)
            .resolvingSymlinksInPath().standardizedFileURL.path
    }

    static func equivalentProjectKeys(
        in projects: [String: Any],
        workspacePath: String
    ) -> [String] {
        let canonical = canonicalPath(workspacePath)
        return projects.keys
            .filter { canonicalPath($0) == canonical }
            .sorted { lhs, rhs in
                if lhs == canonical { return true }
                if rhs == canonical { return false }
                return lhs < rhs
            }
    }
}
