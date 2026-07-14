import Foundation

enum WorkspaceFolderPath {
    static let rootFolder = "Workspaces"

    static func normalize(_ folderPath: String?) -> String? {
        guard let folderPath else { return nil }
        let segments = normalizedSegments(folderPath)
        guard !segments.isEmpty else { return nil }
        if segments.first == rootFolder {
            return segments.count > 1 ? segments.joined(separator: "/") : nil
        }
        return ([rootFolder] + segments).joined(separator: "/")
    }

    static func normalize(_ folderPath: String?, defaultName: String) -> String {
        if let normalized = normalize(folderPath) {
            return normalized
        }
        let fallback = normalizedSegments(defaultName).joined(separator: "/")
        return "\(rootFolder)/\(fallback.isEmpty ? "Workspace" : fallback)"
    }

    private static func normalizedSegments(_ value: String) -> [String] {
        value
            .split(separator: "/")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }
}
