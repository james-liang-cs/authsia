import Testing
import Foundation
@testable import authsia

// MARK: - Shared helper

private func makeEnvSecret(
    key: String,
    value: String = "secretvalue",
    line: String? = nil,
    lineNumber: Int = 1,
    filePath: String = "/tmp/.env",
    type: SecretType = .apiKey,
    rawContent: String? = nil
) -> DetectedSecret {
    DetectedSecret(
        filePath: filePath,
        lineNumber: lineNumber,
        originalLine: line ?? "\(key)=\(value)",
        key: key,
        value: value,
        rawContent: rawContent,
        confidence: .high,
        type: type,
        entropy: 4.0,
        description: "test",
        sshMetadata: nil
    )
}

// MARK: - Diff generation tests

@Suite("EnvFileRewriteService — diff generation")
struct EnvFileRewriteServiceDiffTests {

    @Test("generates one change per secret")
    func diffChangeCount() {
        let secrets = [
            makeEnvSecret(key: "API_KEY", value: "secret1", lineNumber: 2),
            makeEnvSecret(key: "DB_PASS", value: "secret2", lineNumber: 4),
        ]
        let diffs = EnvFileRewriteService.generateDiff(for: secrets)
        #expect(diffs.count == 1)
        #expect(diffs[0].changes.count == 2)
    }

    @Test("replacement line uses secretReferenceURI")
    func replacementLineFormat() {
        let secret = makeEnvSecret(key: "API_KEY", value: "secret1")
        let diffs = EnvFileRewriteService.generateDiff(for: [secret])
        #expect(diffs[0].changes[0].replacementLine == "API_KEY=authsia://api-key/API_KEY/key")
    }

    @Test("folder-scoped replacement line pins URI to target folder")
    func folderScopedReplacementLineFormat() {
        let secret = makeEnvSecret(key: "API_KEY", value: "secret1")
        let diffs = EnvFileRewriteService.generateDiff(for: [secret], folderPath: "Team/API")
        #expect(
            diffs[0].changes[0].replacementLine ==
                "API_KEY=authsia://api-key/API_KEY/key?folder=Team%2FAPI"
        )
    }

    @Test("original line is preserved verbatim")
    func originalLinePreserved() {
        let line = "  API_KEY = secret123  "
        let secret = makeEnvSecret(key: "API_KEY", value: "secret123", line: line)
        let diffs = EnvFileRewriteService.generateDiff(for: [secret])
        #expect(diffs[0].changes[0].originalLine == line)
    }

    @Test("groups secrets by file path")
    func groupsByFile() {
        let secrets = [
            makeEnvSecret(key: "A", filePath: "/tmp/.env"),
            makeEnvSecret(key: "B", filePath: "/tmp/.env.local"),
        ]
        let diffs = EnvFileRewriteService.generateDiff(for: secrets)
        #expect(diffs.count == 2)
    }

    @Test("additions equal deletions — one-for-one replacement")
    func additionsEqualDeletions() {
        let secrets = [
            makeEnvSecret(key: "K1", lineNumber: 1),
            makeEnvSecret(key: "K2", lineNumber: 3),
        ]
        let diffs = EnvFileRewriteService.generateDiff(for: secrets)
        #expect(diffs[0].additions == diffs[0].deletions)
        #expect(diffs[0].additions == 2)
    }

    @Test("changes are sorted by ascending line number")
    func sortedByLineNumber() {
        let secrets = [
            makeEnvSecret(key: "SECOND", lineNumber: 5),
            makeEnvSecret(key: "FIRST", lineNumber: 2),
        ]
        let diffs = EnvFileRewriteService.generateDiff(for: secrets)
        #expect(diffs[0].changes[0].lineNumber == 2)
        #expect(diffs[0].changes[1].lineNumber == 5)
    }

    @Test("SSH key type produces ssh URI")
    func sshKeyReplacement() {
        let secret = makeEnvSecret(key: "DEPLOY_KEY", type: .sshKey)
        let diffs = EnvFileRewriteService.generateDiff(for: [secret])
        #expect(diffs[0].changes[0].replacementLine == "DEPLOY_KEY=authsia://ssh/DEPLOY_KEY/privateKey")
    }

    @Test("certificate file content produces cert URI")
    func certificateReplacement() {
        let secret = makeEnvSecret(
            key: "TLS_CERT",
            value: "server.pem",
            type: .certificate,
            rawContent: """
            -----BEGIN CERTIFICATE-----
            MIIB
            -----END CERTIFICATE-----
            """
        )
        let diffs = EnvFileRewriteService.generateDiff(for: [secret])
        #expect(diffs[0].changes[0].replacementLine == "TLS_CERT=authsia://cert/TLS_CERT/certificate")
    }

    @Test("empty secrets list returns empty diffs")
    func emptyInput() {
        let diffs = EnvFileRewriteService.generateDiff(for: [])
        #expect(diffs.isEmpty)
    }
}

// MARK: - File rewrite tests

@Suite("EnvFileRewriteService — file rewrite")
struct EnvFileRewriteServiceRewriteTests {

    private func writeTempEnv(_ content: String, name: String = ".env") throws -> String {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("rewrite-test-\(UUID().uuidString)\(name)").path
        try content.write(toFile: path, atomically: true, encoding: .utf8)
        return path
    }

    @Test("replaces target line with URI reference")
    func replacesLine() throws {
        let content = "HOST=localhost\nAPI_KEY=sk-abc123\nPORT=3000\n"
        let path = try writeTempEnv(content)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let secret = makeEnvSecret(
            key: "API_KEY", value: "sk-abc123",
            line: "API_KEY=sk-abc123", lineNumber: 2, filePath: path
        )
        try EnvFileRewriteService.rewrite(secrets: [secret])

        let result = try String(contentsOfFile: path, encoding: .utf8)
        #expect(result.contains("API_KEY=authsia://api-key/API_KEY/key"))
        #expect(!result.contains("sk-abc123"))
        #expect(result.contains("HOST=localhost"))
        #expect(result.contains("PORT=3000"))
    }

    @Test("adds migration comment above replaced line")
    func addsMigrationComment() throws {
        let content = "API_KEY=sk-abc123\n"
        let path = try writeTempEnv(content)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let secret = makeEnvSecret(
            key: "API_KEY", value: "sk-abc123",
            line: "API_KEY=sk-abc123", lineNumber: 1, filePath: path
        )
        try EnvFileRewriteService.rewrite(secrets: [secret])

        let result = try String(contentsOfFile: path, encoding: .utf8)
        #expect(result.contains("# Migrated to Authsia"))
    }

    @Test("handles multiple secrets in one file")
    func multipleSecrets() throws {
        let content = "A=secret1\nB=secret2\n"
        let path = try writeTempEnv(content)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let secrets = [
            makeEnvSecret(key: "A", value: "secret1", line: "A=secret1", lineNumber: 1, filePath: path),
            makeEnvSecret(key: "B", value: "secret2", line: "B=secret2", lineNumber: 2, filePath: path),
        ]
        try EnvFileRewriteService.rewrite(secrets: secrets)

        let result = try String(contentsOfFile: path, encoding: .utf8)
        #expect(result.contains("A=authsia://api-key/A/key"))
        #expect(result.contains("B=authsia://api-key/B/key"))
        #expect(!result.contains("secret1"))
        #expect(!result.contains("secret2"))
    }

    @Test("throws when file cannot be read")
    func throwsOnMissingFile() {
        let secret = makeEnvSecret(
            key: "KEY", value: "val",
            line: "KEY=val", lineNumber: 1,
            filePath: "/nonexistent/path/.env"
        )
        #expect(throws: (any Error).self) {
            try EnvFileRewriteService.rewrite(secrets: [secret])
        }
    }

    @Test("secret on line 3 is replaced correctly")
    func lineNumberMatching() throws {
        let content = "LINE1=a\nLINE2=b\nSECRET=val\nLINE4=d\n"
        let path = try writeTempEnv(content)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let secret = makeEnvSecret(
            key: "SECRET", value: "val",
            line: "SECRET=val", lineNumber: 3, filePath: path
        )
        try EnvFileRewriteService.rewrite(secrets: [secret])

        let result = try String(contentsOfFile: path, encoding: .utf8)
        #expect(result.contains("SECRET=authsia://api-key/SECRET/key"))
        #expect(result.contains("LINE1=a"))
        #expect(result.contains("LINE4=d"))
        #expect(!result.contains("SECRET=val\n"))
    }

    @Test("throws and leaves file unchanged when target line changed after scan")
    func throwsWhenTargetLineChangedAfterScan() throws {
        let content = "API_KEY=changed\n"
        let path = try writeTempEnv(content)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let secret = makeEnvSecret(
            key: "API_KEY",
            value: "old-secret",
            line: "API_KEY=old-secret",
            lineNumber: 1,
            filePath: path
        )

        #expect(throws: (any Error).self) {
            try EnvFileRewriteService.rewrite(secrets: [secret])
        }
        #expect(try String(contentsOfFile: path, encoding: .utf8) == content)
    }

    @Test("multiple secrets processed in descending line order to preserve indices")
    func descendingOrderPreservesIndices() throws {
        let content = "A=s1\nB=s2\nC=s3\n"
        let path = try writeTempEnv(content)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let secrets = [
            makeEnvSecret(key: "A", value: "s1", line: "A=s1", lineNumber: 1, filePath: path),
            makeEnvSecret(key: "C", value: "s3", line: "C=s3", lineNumber: 3, filePath: path),
        ]
        try EnvFileRewriteService.rewrite(secrets: secrets)

        let result = try String(contentsOfFile: path, encoding: .utf8)
        #expect(result.contains("A=authsia://api-key/A/key"))
        #expect(result.contains("C=authsia://api-key/C/key"))
        #expect(result.contains("B=s2"))
    }

    @Test("folder-scoped rewrite pins URI to target folder")
    func folderScopedRewrite() throws {
        let content = "API_KEY=sk-abc123\n"
        let path = try writeTempEnv(content)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let secret = makeEnvSecret(
            key: "API_KEY", value: "sk-abc123",
            line: "API_KEY=sk-abc123", lineNumber: 1, filePath: path
        )
        try EnvFileRewriteService.rewrite(secrets: [secret], folderPath: "Team/API")

        let result = try String(contentsOfFile: path, encoding: .utf8)
        #expect(result.contains("API_KEY=authsia://api-key/API_KEY/key?folder=Team%2FAPI"))
        #expect(!result.contains("sk-abc123"))
    }
}
