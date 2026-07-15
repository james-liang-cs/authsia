import Foundation
import XCTest

final class PackageDependencyPinTests: XCTestCase {
    func testArgumentParserRemainsPinnedToBehaviorBaseline() throws {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let manifest = try String(
            contentsOf: packageRoot.appendingPathComponent("Package.swift"),
            encoding: .utf8
        )
        let resolvedData = try Data(
            contentsOf: packageRoot.appendingPathComponent("Package.resolved")
        )
        let resolved = try XCTUnwrap(
            JSONSerialization.jsonObject(with: resolvedData) as? [String: Any]
        )
        let pins = try XCTUnwrap(resolved["pins"] as? [[String: Any]])
        let argumentParser = try XCTUnwrap(
            pins.first { $0["identity"] as? String == "swift-argument-parser" }
        )
        let state = try XCTUnwrap(argumentParser["state"] as? [String: Any])

        XCTAssertTrue(manifest.contains("exact: \"1.7.0\""))
        XCTAssertEqual(state["version"] as? String, "1.7.0")
        XCTAssertEqual(
            state["revision"] as? String,
            "c5d11a805e765f52ba34ec7284bd4fcd6ba68615"
        )
    }
}
