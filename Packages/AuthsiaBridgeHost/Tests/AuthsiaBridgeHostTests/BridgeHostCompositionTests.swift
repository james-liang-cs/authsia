import XCTest

final class BridgeHostCompositionTests: XCTestCase {
    func testRequestHandlerInitializerRequiresExplicitApprover() throws {
        let testFileURL = URL(fileURLWithPath: #filePath)
        let sourceURL = testFileURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources/AuthsiaBridgeHost/XPCRequestHandler.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)

        XCTAssertTrue(source.contains("approver: BridgeApprover,"))
        XCTAssertFalse(source.contains("approver: BridgeApprover ="))
    }

    func testListenerValidatesConnectionBeforeExportingHandler() throws {
        let testFileURL = URL(fileURLWithPath: #filePath)
        let sourceURL = testFileURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources/AuthsiaBridgeHost/XPCListenerManager.swift")
        let source = try String(contentsOf: sourceURL, encoding: .utf8)

        let validation = try XCTUnwrap(source.range(of: "guard validateConnection(newConnection) else"))
        let export = try XCTUnwrap(source.range(of: "newConnection.exportedObject = handler"))
        XCTAssertLessThan(validation.lowerBound, export.lowerBound)
    }
}
