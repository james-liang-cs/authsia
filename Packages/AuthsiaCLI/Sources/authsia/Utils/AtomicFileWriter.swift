import Foundation

enum AtomicFileWriter {
    static func writeString(
        _ content: String,
        toFile path: String,
        defaultPermissions: Int? = nil,
        fileManager: FileManager = .default
    ) throws {
        let targetURL = URL(fileURLWithPath: path)
        let directoryURL = targetURL.deletingLastPathComponent()
        let temporaryURL = directoryURL.appendingPathComponent(".\(targetURL.lastPathComponent).authsia-\(UUID().uuidString).tmp")
        let existingMode = (try? fileManager.attributesOfItem(atPath: path))?[.posixPermissions] as? Int
        let targetMode = existingMode ?? defaultPermissions

        do {
            try content.write(to: temporaryURL, atomically: false, encoding: .utf8)
            if let targetMode {
                try fileManager.setAttributes([.posixPermissions: targetMode], ofItemAtPath: temporaryURL.path)
            }

            if fileManager.fileExists(atPath: path) {
                _ = try fileManager.replaceItemAt(
                    targetURL,
                    withItemAt: temporaryURL,
                    backupItemName: nil,
                    options: []
                )
            } else {
                try fileManager.moveItem(at: temporaryURL, to: targetURL)
            }

            if let targetMode {
                try fileManager.setAttributes([.posixPermissions: targetMode], ofItemAtPath: path)
            }
        } catch {
            try? fileManager.removeItem(at: temporaryURL)
            throw error
        }
    }
}
