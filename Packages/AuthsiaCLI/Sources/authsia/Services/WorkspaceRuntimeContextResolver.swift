import AuthenticatorBridge
import Foundation

enum WorkspaceRuntimeContextResolver {
    struct Resolution {
        let context: WorkspaceRuntimeContext
        let authorityPath: String?
    }

    static func resolve(
        currentDirectoryPath: String = FileManager.default.currentDirectoryPath,
        fileManager: FileManager = .default
    ) -> WorkspaceRuntimeContext? {
        resolveWithAuthority(
            currentDirectoryPath: currentDirectoryPath,
            fileManager: fileManager
        )?.context
    }

    static func resolveWithAuthority(
        currentDirectoryPath: String = FileManager.default.currentDirectoryPath,
        fileManager: FileManager = .default
    ) -> Resolution? {
        let currentDirectory = URL(fileURLWithPath: currentDirectoryPath, isDirectory: true)
        guard let root = WorkspaceRootResolver.findWorkspaceRoot(startingAt: currentDirectory, fileManager: fileManager),
              let config = try? WorkspaceConfigStore.read(fromWorkspaceRoot: root, fileManager: fileManager) else {
            return nil
        }
        let authorityPath = WorkspaceAuthority.validatedRootPath(
            root.path,
            containing: currentDirectoryPath,
            fileManager: fileManager
        )
        return Resolution(
            context: WorkspaceRuntimeContext(
                name: config.workspace.name,
                rootLabel: root.lastPathComponent,
                authsiaFolder: config.workspace.authsiaFolder
            ),
            authorityPath: authorityPath
        )
    }
}
