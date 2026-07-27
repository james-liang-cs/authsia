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
              root != canonicalPath(fileManager.homeDirectoryForCurrentUser.path),
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

    private static func canonicalPath(_ path: String) -> String {
        URL(fileURLWithPath: path, isDirectory: true)
            .resolvingSymlinksInPath()
            .standardizedFileURL
            .path
    }
}
