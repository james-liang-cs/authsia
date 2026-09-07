#if os(macOS)
import Foundation

public struct MCPPreparedFileChange: Sendable {
    public let fileURL: URL
    public let original: Data?
    public let replacement: Data
    private static let writeLock = NSLock()
    public init(fileURL: URL, original: Data?, replacement: Data) {
        self.fileURL = fileURL.deletingLastPathComponent().resolvingSymlinksInPath().appendingPathComponent(fileURL.lastPathComponent)
        self.original = original; self.replacement = replacement
    }
    public func validate() throws {
        guard fileURL.resolvingSymlinksInPath().standardizedFileURL == fileURL.standardizedFileURL else { throw MCPManagementError.invalidRequest }
        let current = FileManager.default.fileExists(atPath: fileURL.path) ? try MCPWorkspaceStore.readBytes(fileURL) : nil
        guard current == original else { throw MCPManagementError.stale }
    }
    public func apply() throws {
        try Self.writeLock.withLock {
            try validate()
            let manager = FileManager.default
            try manager.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            let temporary = fileURL.deletingLastPathComponent().appendingPathComponent(".authsia-\(UUID()).tmp")
            guard manager.createFile(atPath: temporary.path, contents: replacement, attributes: [.posixPermissions: 0o600]) else { throw MCPManagementError.unavailable }
            defer { try? manager.removeItem(at: temporary) }
            try validate()
            if original != nil { _ = try manager.replaceItemAt(fileURL, withItemAt: temporary) }
            else { try manager.moveItem(at: temporary, to: fileURL) }
            guard try MCPWorkspaceStore.readBytes(fileURL) == replacement else { throw MCPManagementError.unavailable }
        }
    }
    public func rollback() throws {
        try Self.writeLock.withLock {
            guard try MCPWorkspaceStore.readBytes(fileURL) == replacement else { throw MCPManagementError.stale }
            if let original { try original.write(to: fileURL, options: .atomic) }
            else { try FileManager.default.removeItem(at: fileURL) }
        }
    }
}
#endif
