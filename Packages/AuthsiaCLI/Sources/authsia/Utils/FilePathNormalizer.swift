import Foundation

enum FilePathNormalizer {
    static func absoluteStandardizedPath(
        _ path: String,
        currentDirectoryPath: String = FileManager.default.currentDirectoryPath
    ) -> String {
        let expandedPath = NSString(string: path).expandingTildeInPath
        let absolutePath: String
        if expandedPath.hasPrefix("/") {
            absolutePath = expandedPath
        } else {
            absolutePath = (currentDirectoryPath as NSString).appendingPathComponent(expandedPath)
        }
        return (absolutePath as NSString).standardizingPath
    }
}
