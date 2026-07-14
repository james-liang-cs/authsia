import AuthenticatorBridge
import Foundation

enum WorkspaceRuntimeContextResolver {
    static func resolve(
        currentDirectoryPath: String = FileManager.default.currentDirectoryPath,
        fileManager: FileManager = .default
    ) -> WorkspaceRuntimeContext? {
        let currentDirectory = URL(fileURLWithPath: currentDirectoryPath, isDirectory: true)
        guard let root = WorkspaceRootResolver.findWorkspaceRoot(startingAt: currentDirectory, fileManager: fileManager),
              let config = try? WorkspaceConfigStore.read(fromWorkspaceRoot: root, fileManager: fileManager) else {
            return nil
        }
        return WorkspaceRuntimeContext(
            name: config.workspace.name,
            rootLabel: root.lastPathComponent,
            authsiaFolder: config.workspace.authsiaFolder
        )
    }
}
