import Foundation

public enum ChromeNativeHostLocation {
    public static func executableURL(
        appBundle: URL = Bundle.main.bundleURL
    ) -> URL? {
        let executableURL = appBundle.appendingPathComponent(
            "Contents/Helpers/AuthsiaNativeHost",
            isDirectory: false
        )
        guard FileManager.default.fileExists(atPath: executableURL.path) else {
            return nil
        }
        return executableURL
    }
}
