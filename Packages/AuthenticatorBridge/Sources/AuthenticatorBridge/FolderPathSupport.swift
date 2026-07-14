import Foundation

/// Normalizes a folder path by splitting on `/`, trimming whitespace from each segment,
/// and rejoining with `/`. Returns nil if the path is nil or empty after normalization.
public func normalizeFolderPath(_ folderPath: String?) -> String? {
    guard let folderPath else { return nil }
    let segments = folderPath
        .split(separator: "/")
        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { !$0.isEmpty }
    guard !segments.isEmpty else { return nil }
    return segments.joined(separator: "/")
}

/// Returns true when the item's folder is equal to or nested under the filter folder.
/// A nil filter matches everything. A nil item folder matches nothing (unless filter is also nil).
public func folderMatches(itemFolderPath: String?, filterFolderPath: String?) -> Bool {
    guard let filter = normalizeFolderPath(filterFolderPath) else { return true }
    guard let item = normalizeFolderPath(itemFolderPath) else { return false }
    return item == filter || item.hasPrefix("\(filter)/")
}
