import Darwin
import Foundation
import Testing
@testable import authsia

@Suite("CodeExamples", .serialized)
struct CodeExamplesTests {
    @Test("migration examples redact original secret lines")
    func migrationExamplesRedactOriginalSecretLines() throws {
        let rawSecret = "sk_live_super_secret_value"
        let secret = DetectedSecret(
            filePath: "/tmp/.env",
            lineNumber: 1,
            originalLine: "API_KEY=\(rawSecret)",
            key: "API_KEY",
            value: rawSecret,
            rawContent: nil,
            confidence: .high,
            type: .apiKey,
            entropy: 4.7,
            description: "api key",
            sshMetadata: nil
        )

        let output = try captureStandardOutput {
            CodeExamples.showMigrationExamples(for: [secret], folderPath: "Team/API")
        }

        #expect(!output.contains(rawSecret))
        #expect(output.contains("Before: API_KEY=<concealed by authsia>"))
        #expect(output.contains("- API_KEY=<concealed by authsia>"))
    }

    @Test("migration examples omit JavaScript and Python sections")
    func migrationExamplesOmitJavaScriptAndPythonSections() throws {
        let secret = DetectedSecret(
            filePath: "/tmp/.env",
            lineNumber: 1,
            originalLine: "API_KEY=sk_live_super_secret_value",
            key: "API_KEY",
            value: "sk_live_super_secret_value",
            rawContent: nil,
            confidence: .high,
            type: .apiKey,
            entropy: 4.7,
            description: "api key",
            sshMetadata: nil
        )

        let output = try captureStandardOutput {
            CodeExamples.showMigrationExamples(for: [secret], folderPath: "Team/API")
        }

        #expect(output.contains("Shell / .env"))
        #expect(output.contains("authsia exec -- <your-command>"))
        #expect(!output.contains("JavaScript/Node.js"))
        #expect(!output.contains("Python"))
        #expect(!output.contains("execFileSync"))
        #expect(!output.contains("subprocess.check_output"))
    }

    private func captureStandardOutput(_ body: () throws -> Void) throws -> String {
        let pipe = Pipe()
        let originalStdout = dup(STDOUT_FILENO)
        fflush(stdout)
        dup2(pipe.fileHandleForWriting.fileDescriptor, STDOUT_FILENO)

        do {
            try body()
            fflush(stdout)
            dup2(originalStdout, STDOUT_FILENO)
            close(originalStdout)
            pipe.fileHandleForWriting.closeFile()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            pipe.fileHandleForReading.closeFile()
            return String(data: data, encoding: .utf8) ?? ""
        } catch {
            fflush(stdout)
            dup2(originalStdout, STDOUT_FILENO)
            close(originalStdout)
            pipe.fileHandleForWriting.closeFile()
            pipe.fileHandleForReading.closeFile()
            throw error
        }
    }
}
