import Foundation
import XCTest
@testable import AuthenticatorBridge

final class ChromeNativeHostLocationTests: XCTestCase {
    func testExecutableURLResolvesBundledHelper() throws {
        let temporaryDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: temporaryDirectory) }

        let appBundle = temporaryDirectory.appendingPathComponent("Authsia.app", isDirectory: true)
        let helper = appBundle.appendingPathComponent(
            "Contents/Helpers/AuthsiaNativeHost",
            isDirectory: false
        )
        try FileManager.default.createDirectory(
            at: helper.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data().write(to: helper)

        XCTAssertEqual(
            ChromeNativeHostLocation.executableURL(appBundle: appBundle),
            helper
        )
    }

    func testExecutableURLRejectsBundleWithoutHelper() throws {
        let temporaryDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: temporaryDirectory) }

        let appBundle = temporaryDirectory.appendingPathComponent("Authsia.app", isDirectory: true)
        try FileManager.default.createDirectory(
            at: appBundle,
            withIntermediateDirectories: true
        )

        XCTAssertNil(ChromeNativeHostLocation.executableURL(appBundle: appBundle))
    }
}
