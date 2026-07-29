import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
import AuthenticatorCore
import AuthenticatorData
@testable import authsia

@Suite("Workspace root resolver")
struct WorkspaceRootResolverTests {
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
