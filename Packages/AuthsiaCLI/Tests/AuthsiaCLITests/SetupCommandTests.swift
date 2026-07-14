import Testing
import Foundation
@testable import authsia

@Suite("Setup command")
struct SetupCommandTests {
    @Test("status output shows the native setup checklist")
    func statusOutputShowsNativeSetupChecklist() {
        let status = SetupStatus(
            cliInstalled: true,
            shellIntegrationInstalled: false,
            bridgeReachable: true,
            sshAgentSocketExists: false,
            doctorIssueCount: 1
        )

        let output = SetupStatusRenderer.render(status)

        #expect(output.contains("Install CLI"))
        #expect(output.contains("Install shell integration"))
        #expect(output.contains("Register bridge"))
        #expect(output.contains("Enable SSH agent"))
        #expect(output.contains("Run doctor"))
        #expect(output.contains("Needs attention"))
    }

    @Test("repair writes managed shell integration for zsh and bash")
    func repairWritesManagedShellIntegration() throws {
        let root = try makeHome()
        defer { try? FileManager.default.removeItem(at: root) }
        try "# custom\n".write(to: root.appendingPathComponent(".zshrc"), atomically: true, encoding: .utf8)

        let result = try SetupRepairService.repairShellIntegration(
            homeDirectory: root,
            shells: [.zsh, .bash]
        )

        let zshrc = try read(".zshrc", in: root)
        let bashrc = try read(".bashrc", in: root)

        #expect(result.updatedFiles == [".zshrc", ".bashrc"])
        #expect(zshrc.contains("# custom"))
        #expect(zshrc.contains("eval \"$(authsia init zsh)\""))
        #expect(zshrc.contains("eval \"$(authsia completion zsh)\""))
        #expect(bashrc.contains("eval \"$(authsia init bash)\""))
        #expect(bashrc.contains("eval \"$(authsia completion bash)\""))
    }

    @Test("repair removes legacy shell eval lines before adding managed block")
    func repairRemovesLegacyShellEvalLines() throws {
        let root = try makeHome()
        defer { try? FileManager.default.removeItem(at: root) }
        let existing = """
        # custom
        eval "$(authsia init zsh)"
        eval "$(authsia completion zsh)"
        """
        try existing.write(to: root.appendingPathComponent(".zshrc"), atomically: true, encoding: .utf8)

        _ = try SetupRepairService.repairShellIntegration(homeDirectory: root, shells: [.zsh])

        let zshrc = try read(".zshrc", in: root)
        #expect(zshrc.components(separatedBy: "authsia init zsh").count - 1 == 1)
        #expect(zshrc.components(separatedBy: "authsia completion zsh").count - 1 == 1)
        #expect(zshrc.contains(SetupRepairService.shellIntegrationStartMarker))
    }

    @Test("uninstall clean removes only managed shell integration")
    func uninstallCleanRemovesManagedShellIntegration() throws {
        let root = try makeHome()
        defer { try? FileManager.default.removeItem(at: root) }
        let existing = """
        # custom

        \(SetupRepairService.shellIntegrationStartMarker)
        if command -v authsia >/dev/null 2>&1; then
            eval "$(authsia init zsh)"
            eval "$(authsia completion zsh)"
        fi
        \(SetupRepairService.shellIntegrationEndMarker)
        """
        try existing.write(to: root.appendingPathComponent(".zshrc"), atomically: true, encoding: .utf8)

        let result = try SetupRepairService.uninstallClean(homeDirectory: root, shells: [.zsh])

        #expect(result.updatedFiles == [".zshrc"])
        #expect(try read(".zshrc", in: root) == "# custom\n")
    }

    @Test("uninstall clean removes legacy shell eval lines")
    func uninstallCleanRemovesLegacyShellEvalLines() throws {
        let root = try makeHome()
        defer { try? FileManager.default.removeItem(at: root) }
        let existing = """
        # custom
        eval "$(authsia init zsh)"
        eval "$(authsia completion zsh)"
        """
        try existing.write(to: root.appendingPathComponent(".zshrc"), atomically: true, encoding: .utf8)

        let result = try SetupRepairService.uninstallClean(homeDirectory: root, shells: [.zsh])

        #expect(result.updatedFiles == [".zshrc"])
        #expect(try read(".zshrc", in: root) == "# custom\n")
    }

    @Test("uninstall clean removes managed user symlink")
    func uninstallCleanRemovesManagedUserSymlink() throws {
        let root = try makeHome()
        defer { try? FileManager.default.removeItem(at: root) }
        let bin = root.appendingPathComponent(".local/bin", isDirectory: true)
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        let link = bin.appendingPathComponent("authsia")
        try FileManager.default.createSymbolicLink(
            atPath: link.path,
            withDestinationPath: "/Applications/Authsia.app/Contents/Helpers/authsia"
        )

        let result = try SetupRepairService.uninstallClean(homeDirectory: root, shells: [])

        #expect(result.removedFiles == [".local/bin/authsia"])
        #expect(!FileManager.default.fileExists(atPath: link.path))
    }

    private func makeHome() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-setup-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    private func read(_ path: String, in root: URL) throws -> String {
        try String(contentsOf: root.appendingPathComponent(path), encoding: .utf8)
    }
}
