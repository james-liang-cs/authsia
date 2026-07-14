import Testing
import Foundation
@testable import authsia

@Suite("FileScannerService — already-migrated reference skipping")
struct FileScannerServiceReferenceSkipTests {

    private func writeTempEnv(_ content: String) throws -> String {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("scanner-test-\(UUID().uuidString).env").path
        try content.write(toFile: path, atomically: true, encoding: .utf8)
        return path
    }

    private func makeTempDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("scanner-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// Regression guard: a .env already rewritten with authsia:// URI references
    /// must NOT be re-detected as raw secrets on a subsequent scrape run.
    @Test("authsia:// URI references are skipped")
    func skipsUriReferences() async throws {
        let path = try writeTempEnv("""
        API_KEY=authsia://password/API_KEY/password
        DB_PASSWORD=authsia://password/DB_PASSWORD/password
        """)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(path, detectionService: SecretDetectionService())

        #expect(secrets.isEmpty)
    }

    @Test("findAuthsiaReferences includes authsia URI references with folders")
    func findsURIReferencesWithFolders() async throws {
        let path = try writeTempEnv("""
        API_KEY=authsia://password/API_KEY/password?folder=Team%2FAPI
        RUNBOOK=authsia://note/Runbook/content?folder=Team%2FOps
        """)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let references = await scanner.findAuthsiaReferences(in: [path])

        #expect(references.contains(.init(itemType: .password, query: "API_KEY", folderPath: "Team/API")))
        #expect(references.contains(.init(itemType: .note, query: "Runbook", folderPath: "Team/Ops")))
    }

    @Test("findShellAuthsiaReferences detects legacy shell substitutions separately")
    func findsShellAuthsiaReferencesSeparately() async throws {
        let path = try writeTempEnv("""
        API_KEY=$(authsia get password API_KEY --field password)
        URI_KEY=authsia://password/URI_KEY/password
        """)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let shellReferences = await scanner.findShellAuthsiaReferences(in: [path])

        #expect(shellReferences == [.init(itemType: .password, query: "API_KEY")])
    }

    @Test("folder rewrite updates existing authsia URI references")
    func folderRewriteUpdatesExistingURIReferences() async throws {
        let path = try writeTempEnv("""
        API_KEY=authsia://password/API_KEY/password
        RUNBOOK="authsia://note/Runbook/content?folder=Old%2FTeam"
        """)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let modified = try AuthsiaReferenceRewriteService.applyFolder(
            to: [path],
            folderPath: "Team/API"
        )

        let updated = try String(contentsOfFile: path, encoding: .utf8)
        #expect(modified == [path])
        #expect(updated.contains("API_KEY=authsia://password/API_KEY/password?folder=Team%2FAPI"))
        #expect(updated.contains(#"RUNBOOK="authsia://note/Runbook/content?folder=Team%2FAPI""#))
    }

    @Test("folder rewrite candidates are shallow by default")
    func folderRewriteCandidatesAreShallowByDefault() throws {
        let root = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let topLevelPath = root.appendingPathComponent(".env")
        let nestedDirectory = root.appendingPathComponent("nested", isDirectory: true)
        try FileManager.default.createDirectory(at: nestedDirectory, withIntermediateDirectories: true)
        let nestedPath = nestedDirectory.appendingPathComponent(".env")
        try "API_KEY=authsia://password/API_KEY/password\n".write(to: topLevelPath, atomically: true, encoding: .utf8)
        try "NESTED_KEY=authsia://password/NESTED_KEY/password\n".write(to: nestedPath, atomically: true, encoding: .utf8)

        let candidates = try AuthsiaReferenceRewriteService.filesNeedingFolderRewrite(
            in: [root.path],
            folderPath: "Team/API"
        )

        #expect(candidates == [topLevelPath.path])
    }

    @Test("folder rewrite candidates include nested files when recursive")
    func folderRewriteCandidatesIncludeNestedFilesWhenRecursive() throws {
        let root = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let topLevelPath = root.appendingPathComponent(".env")
        let nestedDirectory = root.appendingPathComponent("nested", isDirectory: true)
        try FileManager.default.createDirectory(at: nestedDirectory, withIntermediateDirectories: true)
        let nestedPath = nestedDirectory.appendingPathComponent(".env")
        try "API_KEY=authsia://password/API_KEY/password\n".write(to: topLevelPath, atomically: true, encoding: .utf8)
        try "NESTED_KEY=authsia://password/NESTED_KEY/password\n".write(to: nestedPath, atomically: true, encoding: .utf8)

        let candidates = try AuthsiaReferenceRewriteService.filesNeedingFolderRewrite(
            in: [root.path],
            folderPath: "Team/API",
            recursive: true
        )

        #expect(candidates == [topLevelPath.path, nestedPath.path].sorted())
    }

    /// Quoted URI references must also be skipped.
    @Test("quoted authsia:// URI references are skipped")
    func skipsQuotedUriReferences() async throws {
        let path = try writeTempEnv(#"API_KEY="authsia://password/API_KEY/password""#)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(path, detectionService: SecretDetectionService())

        #expect(secrets.isEmpty)
    }

    /// The legacy shell-substitution reference format stays skipped.
    @Test("legacy $(authsia get ...) references are skipped")
    func skipsLegacyShellReferences() async throws {
        let path = try writeTempEnv("export API_KEY=$(authsia get password API_KEY --field password)")
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(path, detectionService: SecretDetectionService())

        #expect(secrets.isEmpty)
    }

    @Test("lowercase shell password exports are detected even when short")
    func detectsLowercaseShortShellPasswordExport() async throws {
        let root = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent(".zshrc")
        try "export password=abcd".write(to: path, atomically: true, encoding: .utf8)

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(path.path, detectionService: SecretDetectionService())

        let secret = try #require(secrets.first)
        #expect(secret.key == "password")
        #expect(secret.value == "abcd")
        #expect(secret.type == .password)
    }

    @Test("selected env files detect generic key suffixes")
    func detectsGenericKeySuffixEnvValues() async throws {
        let path = try writeTempEnv("""
        HF_KEY=abcd1234
        HF_TOKEN=qwerasdv
        """)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(path, detectionService: SecretDetectionService())
        let keys = Set(secrets.map(\.key))

        #expect(keys.contains("HF_KEY"))
        #expect(keys.contains("HF_TOKEN"))
        #expect(secrets.first { $0.key == "HF_KEY" }?.type == .apiKey)
    }

    @Test("public key env values are not detected as secret keys")
    func doesNotDetectPublicKeyEnvValuesAsSecrets() async throws {
        let path = try writeTempEnv("""
        PUBLIC_KEY=ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCdemo
        """)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(path, detectionService: SecretDetectionService())

        #expect(!secrets.contains { $0.key == "PUBLIC_KEY" })
    }

    @Test("standalone PEM certificate file is detected")
    func detectsStandaloneCertificateFile() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("server-\(UUID().uuidString).pem").path
        try """
        -----BEGIN CERTIFICATE-----
        MIIB
        -----END CERTIFICATE-----
        """.write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(path, detectionService: SecretDetectionService())

        #expect(secrets.count == 1)
        #expect(secrets.first?.type == .certificate)
        #expect(secrets.first?.rawContent?.contains("BEGIN CERTIFICATE") == true)
    }

    @Test("ordinary JSON config file is not detected as JSON credential")
    func ordinaryJSONConfigFileIsNotDetectedAsJSONCredential() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("package-\(UUID().uuidString).json").path
        try """
        {
          "name": "demo",
          "version": "1.0.0",
          "scripts": {
            "test": "swift test"
          }
        }
        """.write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(path, detectionService: SecretDetectionService())

        #expect(secrets.isEmpty)
    }

    @Test("ordinary JSON file is not line-scanned as password secrets")
    func ordinaryJSONFileIsNotLineScannedAsPasswordSecrets() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("fixture-\(UUID().uuidString).json").path
        try """
        {
          "items": [
            {
              "account": "demo@example.com",
              "issuer": "Demo",
              "secret": "AUTHSIA_FIXTURE_SECRET_abcdefghijklmnopqrstuvwxyz123456"
            }
          ]
        }
        """.write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(path, detectionService: SecretDetectionService())

        #expect(secrets.isEmpty)
    }

    @Test("service account JSON file is detected as JSON credential")
    func serviceAccountJSONFileIsDetectedAsJSONCredential() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("service-account-\(UUID().uuidString).json").path
        try """
        {
          "type": "service_account",
          "project_id": "demo-project",
          "private_key_id": "abc123",
          "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----\\n",
          "client_email": "svc@demo-project.iam.gserviceaccount.com",
          "client_id": "1234567890",
          "token_uri": "https://oauth2.googleapis.com/token"
        }
        """.write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(path, detectionService: SecretDetectionService())

        #expect(secrets.count == 1)
        #expect(secrets.first?.type == .jsonCredential)
    }

    @Test("build metadata JSON keys are not detected as secrets")
    func buildMetadataJSONKeysAreNotDetectedAsSecrets() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("build-request-\(UUID().uuidString).json").path
        try """
        {
          "id": "8C992573-EC01-4A08-9E6B-F86B31882764",
          "guid": "0A63E48D-A54F-44D2-8B63-63DE5A371BF9",
          "cwd": "/Users/dev/Projects/ExampleApp",
          "diagnostics": "/tmp/DerivedData/Authenticator/Build/Diagnostics/arm64/compile.dia",
          "pch": "/tmp/DerivedData/Authenticator/Build/PrecompiledHeaders/Authenticator-Bridging.pch",
          "dependencies": "/tmp/DerivedData/Authenticator/Build/Objects-normal/arm64/source.d",
          "object": "/tmp/DerivedData/Authenticator/Build/Objects-normal/arm64/source.o",
          "swiftmodule": "/tmp/DerivedData/Authenticator/Build/Products/Debug/Authenticator.swiftmodule"
        }
        """.write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(path, detectionService: SecretDetectionService())

        #expect(secrets.isEmpty)
    }

    @Test("package lock integrity hashes are not detected as secrets")
    func packageLockIntegrityHashesAreNotDetectedAsSecrets() async throws {
        let root = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("package-lock.json")
        try """
        {
          "name": "demo",
          "lockfileVersion": 3,
          "packages": {
            "node_modules/demo": {
              "version": "1.0.0",
              "resolved": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
              "integrity": "sha512-ABCDEFabcdef0123456789ABCDEFabcdef0123456789ABCDEFabcdef0123456789ABCDEFabcdef0123456789"
            },
            "node_modules/other": {
              "version": "2.0.0",
              "integrity": "sha512-1234567890abcdefABCDEF1234567890abcdefABCDEF1234567890abcdefABCDEF1234567890abcdef"
            }
          }
        }
        """.write(to: path, atomically: true, encoding: .utf8)

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(path.path, detectionService: SecretDetectionService())

        #expect(secrets.isEmpty)
    }

    @Test("graph metadata keys are not detected as secrets")
    func graphMetadataKeysAreNotDetectedAsSecrets() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("graph-\(UUID().uuidString).json").path
        try """
        {
          "nodes": [
            {
              "source_file": "/Users/dev/Projects/Authsia/Sources/App/LongNamedView.swift",
              "label": "AuthenticatorBuildGraphNode"
            }
          ]
        }
        """.write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(path, detectionService: SecretDetectionService())

        #expect(secrets.isEmpty)
    }

    @Test("generated SDK metadata files are not detected as secrets")
    func generatedSDKMetadataFilesAreNotDetectedAsSecrets() async throws {
        let root = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let files = [
            (
                "resources-1.js",
                """
                {
                  "operation": "ListThings",
                  "shape": "LongGeneratedResourceShapeName"
                }
                """
            ),
            (
                "paginators-1.js",
                """
                {
                  "pagination": {
                    "ListThings": {
                      "input_token": "NextToken",
                      "output_token": "NextToken"
                    }
                  }
                }
                """
            ),
            (
                "examples-1.json",
                """
                {
                  "examples": [
                    {
                      "input": {
                        "Content": "Example payload content",
                        "data": "Example response data",
                        "GrantToken": "GrantToken",
                        "CodeSha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                        "Id": "1234567890abcdef1234567890abcdef",
                        "NextMarker": "next-marker",
                        "NextContinuationToken": "next-continuation-token",
                        "VersionId": "version-1"
                      }
                    }
                  ]
                }
                """
            ),
        ]

        let scanner = FileScannerService()
        for (fileName, content) in files {
            let path = root.appendingPathComponent(fileName)
            try content.write(to: path, atomically: true, encoding: .utf8)
            let secrets = await scanner.scanFile(path.path, detectionService: SecretDetectionService())
            #expect(secrets.isEmpty)
        }
    }

    @Test("generic input token env values are still detected")
    func genericInputTokenEnvValuesAreStillDetected() async throws {
        let path = try writeTempEnv("INPUT_TOKEN=AUTHSIA_FIXTURE_SECRET_abcdefghijklmnopqrstuvwxyz123456")
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(path, detectionService: SecretDetectionService())

        let secret = try #require(secrets.first)
        #expect(secret.key == "INPUT_TOKEN")
        #expect(secret.type == .token)
    }

    @Test("combined PEM certificate and private key file is detected")
    func detectsCombinedCertificateAndPrivateKeyFile() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("combined-\(UUID().uuidString).pem").path
        try """
        -----BEGIN CERTIFICATE-----
        MIIB
        -----END CERTIFICATE-----
        -----BEGIN PRIVATE KEY-----
        MIIE
        -----END PRIVATE KEY-----
        """.write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(path, detectionService: SecretDetectionService())

        #expect(secrets.count == 1)
        #expect(secrets.first?.type == .certificate)
        #expect(secrets.first?.rawContent?.contains("BEGIN CERTIFICATE") == true)
        #expect(secrets.first?.rawContent?.contains("BEGIN PRIVATE KEY") == true)
    }

    @Test(".env with inline PEM does not short-circuit line scanning")
    func envWithInlinePEMDoesNotShortCircuitLineScanning() async throws {
        let path = try writeTempEnv("""
        API_KEY=AUTHSIA_FIXTURE_SECRET_1234567890abcdef
        TLS_CERT=-----BEGIN CERTIFICATE-----
        MIIB
        -----END CERTIFICATE-----
        """)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(path, detectionService: SecretDetectionService())

        #expect(secrets.contains { $0.key == "API_KEY" })
        #expect(!secrets.contains { $0.lineNumber == 0 && $0.type == .certificate })
    }

    @Test("relative certificate path resolves from scanned file directory")
    func relativeCertificatePathResolvesFromScannedFileDirectory() async throws {
        let root = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let envPath = root.appendingPathComponent(".env")
        let certPath = root.appendingPathComponent("server.pem")
        try """
        -----BEGIN CERTIFICATE-----
        MIIB
        -----END CERTIFICATE-----
        """.write(to: certPath, atomically: true, encoding: .utf8)
        try "TLS_CERT_PATH=./server.pem".write(to: envPath, atomically: true, encoding: .utf8)

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(envPath.path, detectionService: SecretDetectionService())
        let secret = try #require(secrets.first { $0.key == "TLS_CERT_PATH" })

        #expect(secret.type == .certificate)
        #expect(secret.rawContent?.contains("BEGIN CERTIFICATE") == true)
        #expect(secret.secretReferenceURI == "authsia://cert/TLS_CERT_PATH/certificate")
    }

    @Test("relative CER certificate path resolves from scanned file directory")
    func relativeCERCertificatePathResolvesFromScannedFileDirectory() async throws {
        let root = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let envPath = root.appendingPathComponent(".env")
        let certPath = root.appendingPathComponent("server.cer")
        try """
        -----BEGIN CERTIFICATE-----
        MIIB
        -----END CERTIFICATE-----
        """.write(to: certPath, atomically: true, encoding: .utf8)
        try "TLS_CERT_PATH=./server.cer".write(to: envPath, atomically: true, encoding: .utf8)

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(envPath.path, detectionService: SecretDetectionService())
        let secret = try #require(secrets.first { $0.key == "TLS_CERT_PATH" })

        #expect(secret.type == .certificate)
        #expect(secret.rawContent?.contains("BEGIN CERTIFICATE") == true)
        #expect(secret.secretReferenceURI == "authsia://cert/TLS_CERT_PATH/certificate")
    }

    @Test("PKCS12 paths are not classified as certificate scrape targets")
    func pkcs12PathsAreNotClassifiedAsCertificateScrapeTargets() async throws {
        let path = try writeTempEnv("TLS_CERT_PATH=./client.p12")
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(path, detectionService: SecretDetectionService())

        #expect(!secrets.contains { $0.type == .certificate })
    }

    @Test("legacy SSH PEM private key without public key is not imported as certificate")
    func legacySSHPEMPrivateKeyWithoutPublicKeyIsNotImportedAsCertificate() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("id_rsa-\(UUID().uuidString).key").path
        try """
        -----BEGIN RSA PRIVATE KEY-----
        MIIE
        -----END RSA PRIVATE KEY-----
        """.write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let secrets = await scanner.scanFile(path, detectionService: SecretDetectionService())

        #expect(!secrets.contains { $0.type == .certificate })
    }

    @Test("explicit legacy RSA private key PEM path is imported as certificate private key")
    func explicitLegacyRSAPrivateKeyPEMPathIsImportedAsCertificatePrivateKey() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("server-\(UUID().uuidString).key").path
        try """
        -----BEGIN RSA PRIVATE KEY-----
        MIIE
        -----END RSA PRIVATE KEY-----
        """.write(toFile: path, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let scanner = FileScannerService()
        let secrets = await scanner.scanPaths([path], detectionService: SecretDetectionService())
        let secret = try #require(secrets.first)

        #expect(secrets.count == 1)
        #expect(secret.type == .certificate)
        #expect(secret.resolvedCertificateContent?.certificate == nil)
        #expect(secret.resolvedCertificateContent?.privateKey?.contains("BEGIN RSA PRIVATE KEY") == true)
        #expect(secret.secretReferenceURI == "authsia://cert/\(secret.authsiaKey)/privateKey")
    }

    @Test("directory certificate scan uses relative names for duplicate basenames")
    func directoryCertificateScanUsesRelativeNamesForDuplicateBasenames() async throws {
        let root = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let prod = root.appendingPathComponent("prod", isDirectory: true)
        let old = root.appendingPathComponent("old", isDirectory: true)
        try FileManager.default.createDirectory(at: prod, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: old, withIntermediateDirectories: true)
        try """
        -----BEGIN CERTIFICATE-----
        PROD
        -----END CERTIFICATE-----
        """.write(to: prod.appendingPathComponent("server.crt"), atomically: true, encoding: .utf8)
        try """
        -----BEGIN PRIVATE KEY-----
        PRODKEY
        -----END PRIVATE KEY-----
        """.write(to: prod.appendingPathComponent("server.key"), atomically: true, encoding: .utf8)
        try """
        -----BEGIN CERTIFICATE-----
        OLD
        -----END CERTIFICATE-----
        """.write(to: old.appendingPathComponent("server.crt"), atomically: true, encoding: .utf8)

        let scanner = FileScannerService()
        let secrets = await scanner.scanDirectory(
            root.path,
            detectionService: SecretDetectionService(),
            recursive: true
        )
        let keysByRelativePath = Dictionary(
            uniqueKeysWithValues: secrets
                .filter { $0.type == .certificate }
                .map { secret in
                    (
                        String(secret.filePath.dropFirst(root.path.count + 1)),
                        secret.authsiaKey
                    )
                }
        )

        #expect(keysByRelativePath["prod/server.crt"] == "prod_server")
        #expect(keysByRelativePath["prod/server.key"] == "prod_server")
        #expect(keysByRelativePath["old/server.crt"] == "old_server")
    }

    @Test("directory certificate scan pairs certificate with legacy RSA private key")
    func directoryCertificateScanPairsCertificateWithLegacyRSAPrivateKey() async throws {
        let root = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        try """
        -----BEGIN CERTIFICATE-----
        MIIB
        -----END CERTIFICATE-----
        """.write(to: root.appendingPathComponent("server.crt"), atomically: true, encoding: .utf8)
        try """
        -----BEGIN RSA PRIVATE KEY-----
        MIIE
        -----END RSA PRIVATE KEY-----
        """.write(to: root.appendingPathComponent("server.key"), atomically: true, encoding: .utf8)

        let scanner = FileScannerService()
        let secrets = await scanner.scanDirectory(root.path, detectionService: SecretDetectionService())
        let privateKeySecret = try #require(secrets.first { $0.filePath.hasSuffix("server.key") })

        #expect(privateKeySecret.type == .certificate)
        #expect(privateKeySecret.authsiaKey == "server")
        #expect(privateKeySecret.rawContent?.contains("BEGIN RSA PRIVATE KEY") == true)
    }

    @Test("directory certificate scan skips unpaired private key PEM files")
    func directoryCertificateScanSkipsUnpairedPrivateKeyPEMFiles() async throws {
        let root = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        try """
        -----BEGIN PRIVATE KEY-----
        LONELY
        -----END PRIVATE KEY-----
        """.write(to: root.appendingPathComponent("lonely.key"), atomically: true, encoding: .utf8)

        let scanner = FileScannerService()
        let secrets = await scanner.scanDirectory(root.path, detectionService: SecretDetectionService())

        #expect(secrets.filter { $0.type == .certificate }.isEmpty)
    }

    @Test("directory scan is shallow by default")
    func directoryScanIsShallowByDefault() async throws {
        let root = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        try "ROOT_API_KEY=AUTHSIA_FIXTURE_SECRET_ROOT_1234567890abcdef\n"
            .write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        let nested = root.appendingPathComponent("nested", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        try "NESTED_API_KEY=AUTHSIA_FIXTURE_SECRET_NESTED_1234567890abcdef\n"
            .write(to: nested.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        let scanner = FileScannerService()
        let progressRecorder = ScanProgressRecorder()
        let secrets = await scanner.scanDirectory(
            root.path,
            detectionService: SecretDetectionService(),
            progress: progressRecorder.record
        )
        let scannedPaths = Set(secrets.map(\.filePath))

        #expect(scannedPaths.contains(root.appendingPathComponent(".env").path))
        #expect(!scannedPaths.contains(nested.appendingPathComponent(".env").path))
        #expect(progressRecorder.messages == [
            "Scanning \(root.lastPathComponent), 1/1",
        ])
    }

    @Test("recursive directory scan includes nested files and reports progress")
    func recursiveDirectoryScanIncludesNestedFilesAndReportsProgress() async throws {
        let root = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        try "ROOT_API_KEY=AUTHSIA_FIXTURE_SECRET_ROOT_1234567890abcdef\n"
            .write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        let nested = root.appendingPathComponent("nested", isDirectory: true)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        try "NESTED_API_KEY=AUTHSIA_FIXTURE_SECRET_NESTED_1234567890abcdef\n"
            .write(to: nested.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        let progressRecorder = ScanProgressRecorder()
        let scanner = FileScannerService()
        let secrets = await scanner.scanDirectory(
            root.path,
            detectionService: SecretDetectionService(),
            recursive: true,
            progress: progressRecorder.record
        )
        let scannedPaths = Set(secrets.map(\.filePath))

        #expect(scannedPaths.contains(root.appendingPathComponent(".env").path))
        #expect(scannedPaths.contains(nested.appendingPathComponent(".env").path))
        #expect(progressRecorder.messages == [
            "Scanning \(root.lastPathComponent), 1/2",
            "Scanning \(root.lastPathComponent), 2/2",
        ])
    }

    @Test("directory scan prunes generated dependency and cache folders")
    func directoryScanPrunesGeneratedDependencyAndCacheFolders() async throws {
        let root = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        try "ROOT_API_KEY=AUTHSIA_FIXTURE_SECRET_ROOT_1234567890abcdef\n"
            .write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        let skippedDirectoryNames = [
            "node_modules",
            ".git",
            ".build",
            "DerivedData",
            "Library",
            "venv",
            ".venv",
            "__pycache__",
            "graphify-out",
            ".worktrees",
            "build",
            ".qoder",
            ".terraform",
        ]
        for (index, directoryName) in skippedDirectoryNames.enumerated() {
            let directoryURL = root.appendingPathComponent(directoryName, isDirectory: true)
            try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
            try "SKIPPED_\(index)_API_KEY=AUTHSIA_FIXTURE_SECRET_IGNORED_1234567890abcdef\n"
                .write(to: directoryURL.appendingPathComponent(".env"), atomically: true, encoding: .utf8)
        }

        let scanner = FileScannerService()
        let secrets = await scanner.scanDirectory(
            root.path,
            detectionService: SecretDetectionService(),
            recursive: true
        )
        let scannedPaths = Set(secrets.map(\.filePath))

        #expect(scannedPaths.contains(root.appendingPathComponent(".env").path))
        for directoryName in skippedDirectoryNames {
            let skippedPath = root
                .appendingPathComponent(directoryName, isDirectory: true)
                .appendingPathComponent(".env")
                .path
            #expect(!scannedPaths.contains(skippedPath))
        }
    }

    @Test("directory scan skips generated dependency lockfiles")
    func directoryScanSkipsGeneratedDependencyLockfiles() async throws {
        let root = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        try "ROOT_API_KEY=AUTHSIA_FIXTURE_SECRET_ROOT_1234567890abcdef\n"
            .write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)
        try """
        {
          "packages": {
            "node_modules/demo": {
              "API_KEY": "AUTHSIA_FIXTURE_SECRET_LOCKFILE_1234567890abcdef"
            }
          }
        }
        """.write(to: root.appendingPathComponent("package-lock.json"), atomically: true, encoding: .utf8)

        let scanner = FileScannerService()
        let secrets = await scanner.scanDirectory(
            root.path,
            detectionService: SecretDetectionService(),
            recursive: true
        )
        let scannedPaths = Set(secrets.map(\.filePath))

        #expect(scannedPaths.contains(root.appendingPathComponent(".env").path))
        #expect(!scannedPaths.contains(root.appendingPathComponent("package-lock.json").path))
    }

    @Test("directory scan prunes Xcode asset catalog metadata")
    func directoryScanPrunesXcodeAssetCatalogMetadata() async throws {
        let root = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        try "ROOT_API_KEY=AUTHSIA_FIXTURE_SECRET_ROOT_1234567890abcdef\n"
            .write(to: root.appendingPathComponent(".env"), atomically: true, encoding: .utf8)

        let assetCatalog = root
            .appendingPathComponent("Assets.xcassets", isDirectory: true)
            .appendingPathComponent("AppIcon.appiconset", isDirectory: true)
        try FileManager.default.createDirectory(at: assetCatalog, withIntermediateDirectories: true)
        try """
        {
          "images": [
            {
              "filename": "AppIcon.png",
              "idiom": "universal",
              "scale": "2x"
            }
          ]
        }
        """.write(to: assetCatalog.appendingPathComponent("Contents.json"), atomically: true, encoding: .utf8)

        let progressRecorder = ScanProgressRecorder()
        let scanner = FileScannerService()
        let secrets = await scanner.scanDirectory(
            root.path,
            detectionService: SecretDetectionService(),
            recursive: true,
            progress: progressRecorder.record
        )
        let scannedPaths = Set(secrets.map(\.filePath))

        #expect(scannedPaths.contains(root.appendingPathComponent(".env").path))
        #expect(!scannedPaths.contains(assetCatalog.appendingPathComponent("Contents.json").path))
        #expect(progressRecorder.messages == [
            "Scanning \(root.lastPathComponent), 1/1",
        ])
    }
}

private final class ScanProgressRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [FileScannerService.ScanProgress] = []

    var messages: [String] {
        lock.lock()
        defer { lock.unlock() }
        return events.map(\.displayMessage)
    }

    func record(_ progress: FileScannerService.ScanProgress) {
        lock.lock()
        defer { lock.unlock() }
        events.append(progress)
    }
}
