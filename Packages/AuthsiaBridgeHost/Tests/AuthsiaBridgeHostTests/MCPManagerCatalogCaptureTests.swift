import AuthenticatorBridge
import Foundation
import XCTest
@testable import AuthsiaBridgeHost

final class MCPManagerCatalogCaptureTests: XCTestCase {
    func testMissingExecutableAndClientEnvironmentExplainRequiredSetup() {
        let upstream = MCPUpstreamConfig(name: "fixture", command: "authsia-test-nonexistent-mcp-8e77")
        XCTAssertEqual(MCPManagerCatalogCapture.blockReason(upstream: upstream, workspaceRoot: URL(fileURLWithPath: "/tmp"), observedEnvironmentCount: 15), .catalogEnvironmentRequired)
        XCTAssertEqual(MCPManagerCatalogCapture.blockReason(upstream: upstream, workspaceRoot: URL(fileURLWithPath: "/tmp"), observedEnvironmentCount: 0, path: ""), .catalogExecutableMissing)
    }
    func testRealHelperFailureIsActionableAndDoesNotReflectDiagnostics() throws {
        let root = try fixture("#!/bin/sh\nprintf 'synthetic-private-output\\n' >&2\nexit 1\n")
        defer { try? FileManager.default.removeItem(at: root) }
        XCTAssertThrowsError(try MCPManagerCatalogCapture.run(cli: root.appendingPathComponent("helper"), serverName: "fixture", workspace: root)) {
            XCTAssertEqual($0 as? MCPManagementError, .catalogStartupFailed)
            XCTAssertFalse($0.localizedDescription.contains("synthetic-private-output"))
        }
    }
    func testHelperSuccessAndNoisyTimeoutAreBounded() throws {
        let success = try fixture("#!/bin/sh\nexit 0\n")
        defer { try? FileManager.default.removeItem(at: success) }
        XCTAssertNoThrow(try MCPManagerCatalogCapture.run(cli: success.appendingPathComponent("helper"), serverName: "fixture", workspace: success))
        let noisy = try fixture("#!/bin/sh\nwhile :; do printf 'synthetic diagnostic line\\n' >&2; done\n")
        defer { try? FileManager.default.removeItem(at: noisy) }
        XCTAssertThrowsError(try MCPManagerCatalogCapture.run(cli: noisy.appendingPathComponent("helper"), serverName: "fixture", workspace: noisy, timeout: 0.05)) {
            XCTAssertEqual($0 as? MCPManagementError, .catalogTimedOut)
        }
    }
    func testGUILaunchIncludesExistingMCPPathOverlayForRuntimeDependencies() throws {
        let root = try fixture("#!/bin/sh\ncommand -v fixture-runtime >/dev/null || exit 1\n")
        defer { try? FileManager.default.removeItem(at: root) }
        let bin = root.appendingPathComponent(".local/bin")
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        let runtime = bin.appendingPathComponent("fixture-runtime")
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: runtime)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: runtime.path)
        XCTAssertNoThrow(try MCPManagerCatalogCapture.run(cli: root.appendingPathComponent("helper"), serverName: "fixture",
            workspace: root, environment: ["PATH": "/usr/bin:/bin"], home: root))
    }
    private func fixture(_ script: String) throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let helper = root.appendingPathComponent("helper")
        try Data(script.utf8).write(to: helper)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: helper.path)
        return root
    }
}
