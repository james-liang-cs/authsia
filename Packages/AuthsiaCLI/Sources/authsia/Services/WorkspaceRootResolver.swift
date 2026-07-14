import Foundation

enum WorkspaceRootResolver {
    static func findWorkspaceRoot(
        startingAt startURL: URL,
        fileManager: FileManager = .default
    ) -> URL? {
        firstAncestor(startingAt: startURL, fileManager: fileManager) { candidate in
            fileManager.fileExists(
                atPath: candidate.appendingPathComponent(WorkspaceConfigStore.relativeConfigPath).path
            )
        }
    }

    static func resolveInitRoot(
        startingAt startURL: URL,
        fileManager: FileManager = .default
    ) -> URL {
        findGitRoot(startingAt: startURL, fileManager: fileManager) ?? normalizedDirectory(startURL)
    }

    /// Returns the root of an existing workspace config that `init` would not
    /// write to, i.e. when init resolves to the git root but a workspace already
    /// exists at a nearer ancestor. Returns nil when no existing config is found
    /// or it sits at the same root init will use.
    static func conflictingExistingWorkspaceRoot(
        startingAt startURL: URL,
        initRoot: URL,
        fileManager: FileManager = .default
    ) -> URL? {
        guard let existing = findWorkspaceRoot(startingAt: startURL, fileManager: fileManager) else {
            return nil
        }
        return existing.standardizedFileURL.path == initRoot.standardizedFileURL.path ? nil : existing
    }

    private static func findGitRoot(
        startingAt startURL: URL,
        fileManager: FileManager
    ) -> URL? {
        firstAncestor(startingAt: startURL, fileManager: fileManager) { candidate in
            fileManager.fileExists(atPath: candidate.appendingPathComponent(".git").path)
        }
    }

    private static func firstAncestor(
        startingAt startURL: URL,
        fileManager: FileManager,
        matching predicate: (URL) -> Bool
    ) -> URL? {
        var isDirectory: ObjCBool = false
        let startPath = startURL.standardizedFileURL.path
        let start: URL
        if fileManager.fileExists(atPath: startPath, isDirectory: &isDirectory), !isDirectory.boolValue {
            start = startURL.deletingLastPathComponent()
        } else {
            start = normalizedDirectory(startURL)
        }

        var candidate = start
        while true {
            if predicate(candidate) {
                return candidate
            }
            let parent = candidate.deletingLastPathComponent()
            if parent.path == candidate.path {
                return nil
            }
            candidate = parent
        }
    }

    private static func normalizedDirectory(_ url: URL) -> URL {
        URL(fileURLWithPath: url.standardizedFileURL.path, isDirectory: true)
    }
}

