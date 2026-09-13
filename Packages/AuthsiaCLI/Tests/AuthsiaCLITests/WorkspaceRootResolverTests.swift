import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
@testable import authsia

@Suite("Workspace root resolver")
struct WorkspaceRootResolverTests {
    @Test("deleted current directory does not hang workspace or git discovery")
    func deletedCurrentDirectoryDoesNotHangDiscovery() throws {
        // Isolate chdir from concurrently running tests, and bound the child so
        // a regression reports a failure instead of hanging the test runner.
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/authsia/Services/WorkspaceRootResolver.swift")
        let main = root.appendingPathComponent("main.swift")
        try """
        import Foundation
        enum WorkspaceConfigStore {
            static let relativeConfigPath = ".authsia/workspace.json"
        }
        let manager = FileManager.default
        let workspace = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try manager.createDirectory(at: workspace, withIntermediateDirectories: true)
        precondition(manager.changeCurrentDirectoryPath(workspace.path))
        try manager.removeItem(at: workspace)
        precondition(manager.currentDirectoryPath.isEmpty)
        let start = URL(fileURLWithPath: manager.currentDirectoryPath, isDirectory: true)
        precondition(WorkspaceRootResolver.findWorkspaceRoot(startingAt: start) == nil)
        _ = WorkspaceRootResolver.resolveInitRoot(startingAt: start)
        """.write(to: main, atomically: true, encoding: .utf8)
        let executable = root.appendingPathComponent("resolver-probe")
        let compiler = Process()
        compiler.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        compiler.arguments = ["swiftc", source.path, main.path, "-o", executable.path]
        try compiler.run()
        compiler.waitUntilExit()
        try #require(compiler.terminationStatus == 0)

        let process = Process()
        process.executableURL = executable
        process.arguments = [root.appendingPathComponent("workspace").path]
        try process.run()
        let deadline = Date().addingTimeInterval(5)
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        let timedOut = process.isRunning
        if timedOut { process.terminate() }
        process.waitUntilExit()
        #expect(!timedOut, "Workspace discovery must terminate after its working directory is deleted")
        #expect(process.terminationStatus == 0)
    }

    @Test("finds workspace config in ancestor")
    func findsWorkspaceConfigInAncestor() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        try "{}".write(
            to: root.appendingPathComponent(".authsia/workspace.json"),
            atomically: true,
            encoding: .utf8
        )
        let nested = root.appendingPathComponent("Sources/App", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)

        let resolved = WorkspaceRootResolver.findWorkspaceRoot(startingAt: nested)

        #expect(resolved == root)
    }

    @Test("init root falls back to git root")
    func initRootFallsBackToGitRoot() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".git"),
            withIntermediateDirectories: true
        )
        let nested = root.appendingPathComponent("Sources/App", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)

        let resolved = WorkspaceRootResolver.resolveInitRoot(startingAt: nested)

        #expect(resolved == root)
    }

    @Test("flags existing nested workspace when init targets a different root")
    func flagsExistingNestedWorkspaceWhenInitTargetsDifferentRoot() throws {
        let gitRoot = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: gitRoot) }
        let nested = gitRoot.appendingPathComponent("packages/api", isDirectory: true)
        try FileManager.default.createDirectory(
            at: nested.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        try "{}".write(
            to: nested.appendingPathComponent(".authsia/workspace.json"),
            atomically: true,
            encoding: .utf8
        )

        let conflict = WorkspaceRootResolver.conflictingExistingWorkspaceRoot(
            startingAt: nested,
            initRoot: gitRoot
        )

        #expect(conflict?.standardizedFileURL == nested.standardizedFileURL)
    }

    @Test("existing workspace conflict guidance names dry run and explicit env file yes retry")
    func existingWorkspaceConflictGuidanceNamesDryRunAndExplicitEnvFileYesRetry() {
        let existingRoot = URL(fileURLWithPath: "/tmp/app/packages/api", isDirectory: true)
        let initRoot = URL(fileURLWithPath: "/tmp/app", isDirectory: true)

        let message = Workspace.Init.existingWorkspaceConflictMessage(
            existingRoot: existingRoot,
            initRoot: initRoot
        )

        #expect(message.contains("An Authsia workspace already exists at /tmp/app/packages/api"))
        #expect(message.contains("Re-run from /tmp/app/packages/api to update it"))
        #expect(message.contains("authsia workspace init --dry-run"))
        #expect(message.contains("authsia workspace init --yes --env-file <path>"))
        #expect(!message.contains("pass --yes to create a separate workspace"))
    }

    @Test("no conflict when existing workspace is at the init root")
    func noConflictWhenExistingWorkspaceIsAtInitRoot() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".authsia"),
            withIntermediateDirectories: true
        )
        try "{}".write(
            to: root.appendingPathComponent(".authsia/workspace.json"),
            atomically: true,
            encoding: .utf8
        )

        let conflict = WorkspaceRootResolver.conflictingExistingWorkspaceRoot(
            startingAt: root,
            initRoot: root
        )

        #expect(conflict == nil)
    }

    @Test("no conflict when no existing workspace is present")
    func noConflictWhenNoExistingWorkspaceIsPresent() throws {
        let root = try makeWorkspaceRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let nested = root.appendingPathComponent("Sources/App", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)

        let conflict = WorkspaceRootResolver.conflictingExistingWorkspaceRoot(
            startingAt: nested,
            initRoot: root
        )

        #expect(conflict == nil)
    }
}
