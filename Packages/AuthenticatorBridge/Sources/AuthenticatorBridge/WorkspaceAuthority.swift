import Foundation

public enum WorkspaceAuthority {
    private static let workspaceConfigRelativePath = ".authsia/workspace.json"

    public static func validatedRootPath(
        _ rootPath: String?,
        containing workingDirectory: String?,
        fileManager: FileManager = .default
    ) -> String? {
        guard let rootPath,
              let workingDirectory,
              rootPath.hasPrefix("/"),
              workingDirectory.hasPrefix("/") else {
            return nil
        }

        let root = canonicalPath(rootPath)
        let directory = canonicalPath(workingDirectory)
        var isDirectory: ObjCBool = false
        guard root != "/",
              root != canonicalPath(NSHomeDirectory()),
              fileManager.fileExists(atPath: root, isDirectory: &isDirectory),
              isDirectory.boolValue,
              fileManager.fileExists(atPath: directory, isDirectory: &isDirectory),
              isDirectory.boolValue,
              directory == root || directory.hasPrefix(root + "/") else {
            return nil
        }

        #if os(macOS)
        let volumeRoots = fileManager.mountedVolumeURLs(
            includingResourceValuesForKeys: nil,
            options: []
        ) ?? []
        guard !volumeRoots.contains(where: { canonicalPath($0.path) == root }) else {
            return nil
        }
        #endif

        return root
    }

    /// The directory a terminal pairing records for its prompt and audit trail:
    /// the managed workspace when one contains the cwd, and the exact current
    /// directory otherwise — `$HOME`, `/`, a volume root, or an authority path
    /// that does not exist or does not contain the cwd. It does not scope the
    /// pairing, which binds the terminal and survives a `cd`.
    public static func pairingRootPath(
        workingDirectory: String?,
        authorityPath: String?,
        fileManager: FileManager = .default
    ) -> String? {
        guard let workingDirectory else { return nil }
        if let validated = validatedRootPath(
            authorityPath ?? workingDirectory,
            containing: workingDirectory,
            fileManager: fileManager
        ) {
            return validated
        }
        return exactExistingDirectory(workingDirectory, fileManager: fileManager)
    }

    public static func matchesWorkingDirectory(
        _ workingDirectory: String?,
        authorityPath: String?,
        fileManager: FileManager = .default
    ) -> Bool {
        guard let workingDirectory, let authorityPath else { return false }
        let directory = canonicalPath(workingDirectory)
        let authority = canonicalPath(authorityPath)
        if directory == authority {
            return true
        }
        guard fileManager.fileExists(
            atPath: URL(fileURLWithPath: authority, isDirectory: true)
                .appendingPathComponent(workspaceConfigRelativePath)
                .path
        ) else {
            return false
        }
        return validatedRootPath(
            authority,
            containing: directory,
            fileManager: fileManager
        ) != nil
    }

    private static func exactExistingDirectory(_ path: String, fileManager: FileManager) -> String? {
        guard path.hasPrefix("/") else { return nil }
        let directory = canonicalPath(path)
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: directory, isDirectory: &isDirectory),
              isDirectory.boolValue else {
            return nil
        }
        return directory
    }

    private static func canonicalPath(_ path: String) -> String {
        URL(fileURLWithPath: path, isDirectory: true)
            .resolvingSymlinksInPath()
            .standardizedFileURL
            .path
    }
}
