import Foundation
import XCTest
@testable import AuthenticatorBridge

final class WorkspaceAuthorityTests: XCTestCase {
    func testRejectsFilesystemRootAndHomeDirectory() {
        XCTAssertNil(WorkspaceAuthority.validatedRootPath(
            "/",
            containing: FileManager.default.temporaryDirectory.path
        ))
        XCTAssertNil(WorkspaceAuthority.validatedRootPath(
            FileManager.default.homeDirectoryForCurrentUser.path,
            containing: FileManager.default.homeDirectoryForCurrentUser.path
        ))
    }

    func testPairingRootFallsBackToExactHomeOrFilesystemRoot() {
        let home = FileManager.default.homeDirectoryForCurrentUser
            .resolvingSymlinksInPath()
            .standardizedFileURL
            .path
        XCTAssertEqual(
            WorkspaceAuthority.pairingRootPath(workingDirectory: home, authorityPath: nil),
            home
        )
        XCTAssertEqual(
            WorkspaceAuthority.pairingRootPath(workingDirectory: "/", authorityPath: nil),
            "/"
        )
        XCTAssertNil(
            WorkspaceAuthority.validatedRootPath(home, containing: home)
        )
        XCTAssertNil(
            WorkspaceAuthority.validatedRootPath("/", containing: "/")
        )
    }

    func testPairingRootAtHomeDoesNotCoverADescendant() {
        let home = FileManager.default.homeDirectoryForCurrentUser
            .resolvingSymlinksInPath()
            .standardizedFileURL
        let nested = home.appendingPathComponent("Library", isDirectory: true)
            .resolvingSymlinksInPath()
            .standardizedFileURL
            .path

        XCTAssertEqual(
            WorkspaceAuthority.pairingRootPath(
                workingDirectory: nested,
                authorityPath: home.path
            ),
            nested
        )
        XCTAssertNotEqual(nested, home.path)
    }

    func testPairingRootPrefersManagedRootOverTheExactSubdirectory() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-pairing-managed-\(UUID().uuidString)", isDirectory: true)
            .resolvingSymlinksInPath()
            .standardizedFileURL
        let nested = root.appendingPathComponent("service/envs/prod", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)

        XCTAssertEqual(
            WorkspaceAuthority.pairingRootPath(
                workingDirectory: nested.path,
                authorityPath: root.path
            ),
            root.path
        )
    }

    func testRejectsDirectoryOutsideProposedWorkspaceRoot() throws {
        let container = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-workspace-authority-\(UUID().uuidString)", isDirectory: true)
        let root = container.appendingPathComponent("workspace", isDirectory: true)
        let sibling = container.appendingPathComponent("sibling", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: container) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: sibling, withIntermediateDirectories: true)

        XCTAssertNil(WorkspaceAuthority.validatedRootPath(
            root.path,
            containing: sibling.path
        ))
    }

    func testMatchesManagedWorkspaceDescendantButNotSibling() throws {
        let container = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-workspace-match-\(UUID().uuidString)", isDirectory: true)
        let root = container.appendingPathComponent("workspace", isDirectory: true)
        let nested = root.appendingPathComponent("service/envs/prod", isDirectory: true)
        let sibling = container.appendingPathComponent("sibling", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: container) }
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".authsia", isDirectory: true),
            withIntermediateDirectories: true
        )
        try Data("{}".utf8).write(to: root.appendingPathComponent(".authsia/workspace.json"))
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: sibling, withIntermediateDirectories: true)

        XCTAssertTrue(WorkspaceAuthority.matchesWorkingDirectory(
            nested.path,
            authorityPath: root.path
        ))
        XCTAssertFalse(WorkspaceAuthority.matchesWorkingDirectory(
            sibling.path,
            authorityPath: root.path
        ))
    }

    func testNonWorkspaceAuthorityStillRequiresExactDirectory() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-exact-match-\(UUID().uuidString)", isDirectory: true)
        let nested = root.appendingPathComponent("nested", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)

        XCTAssertTrue(WorkspaceAuthority.matchesWorkingDirectory(
            root.path,
            authorityPath: root.path
        ))
        XCTAssertFalse(WorkspaceAuthority.matchesWorkingDirectory(
            nested.path,
            authorityPath: root.path
        ))
    }
}
