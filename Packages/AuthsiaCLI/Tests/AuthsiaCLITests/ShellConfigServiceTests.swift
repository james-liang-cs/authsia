import Testing
import Foundation
@testable import authsia

@Suite("Shell config migration")
struct ShellConfigServiceTests {
    @Test("shell config migration uses load silent and adds shell integration")
    func shellConfigMigrationUsesLoadSilentAndAddsShellIntegration() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let zshrcURL = tempDir.appendingPathComponent(".zshrc")
        try "export API_KEY=super-secret\n".write(to: zshrcURL, atomically: true, encoding: .utf8)

        let secret = DetectedSecret(
            filePath: zshrcURL.path,
            lineNumber: 1,
            originalLine: "export API_KEY=super-secret",
            key: "API_KEY",
            value: "super-secret",
            rawContent: nil,
            confidence: .high,
            type: .password,
            entropy: 5.0,
            description: "API key",
            sshMetadata: nil
        )

        let service = ShellConfigService()
        _ = try await service.applyChanges([secret])

        let updated = try String(contentsOf: zshrcURL, encoding: .utf8)
        #expect(updated.contains("# Migrated to Authsia - Original: API_KEY"))
        #expect(updated.contains("authsia load password API_KEY --silent"))
        #expect(updated.contains("# >>> Authsia shell integration >>>"))
        #expect(updated.contains("eval \"$(authsia init zsh)\""))
        #expect(updated.contains("# <<< Authsia shell integration <<<"))

        let blockIndex = try #require(updated.range(of: "# >>> Authsia shell integration >>>")?.lowerBound)
        let loadIndex = try #require(updated.range(of: "authsia load password API_KEY --silent")?.lowerBound)
        #expect(blockIndex < loadIndex)
    }

    @Test("shell config migration includes folder when configured")
    func shellConfigMigrationIncludesFolderWhenConfigured() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let zshrcURL = tempDir.appendingPathComponent(".zshrc")
        try "export API_KEY=super-secret\n".write(to: zshrcURL, atomically: true, encoding: .utf8)

        let secret = DetectedSecret(
            filePath: zshrcURL.path,
            lineNumber: 1,
            originalLine: "export API_KEY=super-secret",
            key: "API_KEY",
            value: "super-secret",
            rawContent: nil,
            confidence: .high,
            type: .password,
            entropy: 5.0,
            description: "API key",
            sshMetadata: nil
        )

        let service = ShellConfigService()
        let diff = await service.generateDiff(for: [secret], folderPath: "Team/API")
        #expect(diff.first?.changes.first?.replacementLine.contains("--folder Team/API") == true)

        _ = try await service.applyChanges([secret], folderPath: "Team/API")

        let updated = try String(contentsOf: zshrcURL, encoding: .utf8)
        #expect(updated.contains("authsia load password API_KEY --folder Team/API --silent"))
    }

    @Test("shell config migration throws when target line changed after scan")
    func shellConfigMigrationThrowsWhenTargetLineChangedAfterScan() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let zshrcURL = tempDir.appendingPathComponent(".zshrc")
        let currentContent = "export API_KEY=changed\n"
        try currentContent.write(to: zshrcURL, atomically: true, encoding: .utf8)

        let secret = DetectedSecret(
            filePath: zshrcURL.path,
            lineNumber: 1,
            originalLine: "export API_KEY=old-secret",
            key: "API_KEY",
            value: "old-secret",
            rawContent: nil,
            confidence: .high,
            type: .password,
            entropy: 5.0,
            description: "API key",
            sshMetadata: nil
        )

        await #expect(throws: (any Error).self) {
            _ = try await ShellConfigService().applyChanges([secret])
        }
        #expect(try String(contentsOf: zshrcURL, encoding: .utf8) == currentContent)
    }

    @Test("ensureShellIntegration adds managed block to empty zshrc")
    func ensureShellIntegrationAddsBlock() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        try "export PATH=/usr/bin\n".write(
            to: tempDir.appendingPathComponent(".zshrc"), atomically: true, encoding: .utf8
        )

        let outcome = await ShellConfigService().ensureShellIntegration(
            shellPath: "/bin/zsh", homeDirectory: tempDir.path
        )

        let rcPath = tempDir.appendingPathComponent(".zshrc").path
        #expect(outcome == .added(rcPath))
        let updated = try String(contentsOfFile: rcPath, encoding: .utf8)
        #expect(updated.contains("eval \"$(authsia init zsh)\""))
        #expect(updated.contains("export PATH=/usr/bin"))
    }

    @Test("ensureShellIntegration is idempotent when block present")
    func ensureShellIntegrationIdempotent() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let rcPath = tempDir.appendingPathComponent(".zshrc").path

        let service = ShellConfigService()
        _ = await service.ensureShellIntegration(shellPath: "/bin/zsh", homeDirectory: tempDir.path)
        let first = try String(contentsOfFile: rcPath, encoding: .utf8)

        let outcome = await service.ensureShellIntegration(shellPath: "/bin/zsh", homeDirectory: tempDir.path)
        #expect(outcome == .alreadyPresent)
        #expect(try String(contentsOfFile: rcPath, encoding: .utf8) == first)
    }

    @Test("ensureShellIntegration treats manual eval line as present")
    func ensureShellIntegrationDetectsManualEval() async throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let rcPath = tempDir.appendingPathComponent(".zshrc").path
        try "eval \"$(authsia init zsh)\"\n".write(toFile: rcPath, atomically: true, encoding: .utf8)

        let outcome = await ShellConfigService().ensureShellIntegration(
            shellPath: "/bin/zsh", homeDirectory: tempDir.path
        )
        #expect(outcome == .alreadyPresent)
    }

    @Test("ensureShellIntegration unsupported for unknown shell")
    func ensureShellIntegrationUnsupportedShell() async throws {
        let outcome = await ShellConfigService().ensureShellIntegration(
            shellPath: "/usr/bin/fish", homeDirectory: NSHomeDirectory()
        )
        #expect(outcome == .unsupported)
    }
}
