import Foundation
import Testing
@testable import authsia

@Suite("Workspace environment selection store")
struct WorkspaceEnvironmentSelectionStoreTests {
    @Test("selections are isolated, normalized, and clear independently")
    func selectionsAreIsolatedAndClearIndependently() throws {
        let fixture = try Fixture()
        defer { fixture.cleanup() }

        try fixture.store.setActiveEnvironment(" Production ", for: fixture.firstRoot)
        try fixture.store.setActiveEnvironment("Development", for: fixture.secondRoot)

        #expect(try fixture.store.activeEnvironment(for: fixture.firstRoot) == "Production")
        #expect(try fixture.store.activeEnvironment(for: fixture.secondRoot) == "Development")
        #expect(try fixture.store.clearActiveEnvironment(for: fixture.firstRoot))
        #expect(try fixture.store.activeEnvironment(for: fixture.firstRoot) == nil)
        #expect(try fixture.store.activeEnvironment(for: fixture.secondRoot) == "Development")
    }

    @Test("symlink and target share one selection")
    func symlinkAndTargetShareOneSelection() throws {
        let fixture = try Fixture()
        defer { fixture.cleanup() }
        let symlink = fixture.root.appendingPathComponent("workspace-link")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: fixture.firstRoot)

        try fixture.store.setActiveEnvironment("Production", for: symlink)

        #expect(try fixture.store.activeEnvironment(for: fixture.firstRoot) == "Production")
    }

    @Test("state directory and file use private permissions")
    func stateUsesPrivatePermissions() throws {
        let fixture = try Fixture()
        defer { fixture.cleanup() }

        try fixture.store.setActiveEnvironment("Production", for: fixture.firstRoot)

        let directoryAttributes = try FileManager.default.attributesOfItem(
            atPath: fixture.fileURL.deletingLastPathComponent().path
        )
        let fileAttributes = try FileManager.default.attributesOfItem(atPath: fixture.fileURL.path)
        #expect((directoryAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o700)
        #expect((fileAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
    }

    private final class Fixture {
        let root: URL
        let firstRoot: URL
        let secondRoot: URL
        let fileURL: URL
        let store: WorkspaceEnvironmentSelectionStore

        init() throws {
            root = FileManager.default.temporaryDirectory
                .appendingPathComponent("workspace-environment-store-\(UUID().uuidString)", isDirectory: true)
            firstRoot = root.appendingPathComponent("first", isDirectory: true)
            secondRoot = root.appendingPathComponent("second", isDirectory: true)
            fileURL = root.appendingPathComponent("state/workspace-environments.json")
            try FileManager.default.createDirectory(at: firstRoot, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: secondRoot, withIntermediateDirectories: true)
            store = WorkspaceEnvironmentSelectionStore(fileURL: fileURL)
        }

        func cleanup() {
            try? FileManager.default.removeItem(at: root)
        }
    }
}
