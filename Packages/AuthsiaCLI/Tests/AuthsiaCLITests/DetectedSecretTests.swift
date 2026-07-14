import Testing
import Foundation
@testable import authsia

@Suite("DetectedSecret secretReferenceURI")
struct DetectedSecretTests {

    private func makeSecret(
        key: String,
        type: SecretType,
        rawContent: String? = nil
    ) -> DetectedSecret {
        DetectedSecret(
            filePath: "/tmp/.env",
            lineNumber: 1,
            originalLine: "\(key)=value",
            key: key,
            value: "value",
            rawContent: rawContent,
            confidence: .high,
            type: type,
            entropy: 3.5,
            description: "test",
            sshMetadata: nil
        )
    }

    @Test("api key type produces api-key URI")
    func apiKeyURI() {
        let secret = makeSecret(key: "API_KEY", type: .apiKey)
        #expect(secret.secretReferenceURI == "authsia://api-key/API_KEY/key")
    }

    @Test("key with spaces uses underscore-normalised authsiaKey")
    func spacesInKey() {
        let secret = makeSecret(key: "MY API KEY", type: .apiKey)
        #expect(secret.secretReferenceURI == "authsia://api-key/MY_API_KEY/key")
    }

    @Test("key with hyphens uses underscore-normalised authsiaKey")
    func hyphensInKey() {
        let secret = makeSecret(key: "db-password", type: .apiKey)
        #expect(secret.secretReferenceURI == "authsia://api-key/db_password/key")
    }

    @Test("SSH key type produces ssh URI")
    func sshKeyURI() {
        let secret = makeSecret(key: "DEPLOY_KEY", type: .sshKey)
        #expect(secret.secretReferenceURI == "authsia://ssh/DEPLOY_KEY/privateKey")
    }

    @Test("certificate type without rawContent produces password URI")
    func certNoRawContent() {
        let secret = makeSecret(key: "TLS_CERT", type: .certificate, rawContent: nil)
        #expect(secret.secretReferenceURI == "authsia://password/TLS_CERT/password")
    }

    @Test("certificate type with rawContent produces note URI")
    func certWithRawContent() {
        let secret = makeSecret(key: "TLS_CERT", type: .certificate, rawContent: "-----BEGIN CERT-----")
        #expect(secret.secretReferenceURI == "authsia://note/TLS_CERT/content")
    }

    @Test("jsonCredential type produces password URI")
    func jsonCredentialURI() {
        let secret = makeSecret(key: "GCP_CREDS", type: .jsonCredential)
        #expect(secret.secretReferenceURI == "authsia://password/GCP_CREDS/password")
    }

    @Test("unknown type falls through to password URI")
    func unknownTypeURI() {
        let secret = makeSecret(key: "SOME_SECRET", type: .unknown)
        #expect(secret.secretReferenceURI == "authsia://password/SOME_SECRET/password")
    }

    @Test("redactedOriginalLine conceals raw secret value")
    func redactedOriginalLineConcealsSecret() {
        let secret = DetectedSecret(
            filePath: "/tmp/.env",
            lineNumber: 1,
            originalLine: "export API_KEY=sk-live-super-secret",
            key: "API_KEY",
            value: "sk-live-super-secret",
            rawContent: nil,
            confidence: .high,
            type: .apiKey,
            entropy: 4.0,
            description: "test",
            sshMetadata: nil
        )

        #expect(!secret.redactedOriginalLine.contains("sk-live-super-secret"))
        #expect(secret.redactedOriginalLine.contains("<concealed by authsia>"))
    }

    @Test("redactedOriginalLine falls back to concealed assignment")
    func redactedOriginalLineFallback() {
        let secret = DetectedSecret(
            filePath: "/tmp/id_ed25519",
            lineNumber: 1,
            originalLine: "-----BEGIN OPENSSH PRIVATE KEY-----",
            key: "deploy",
            value: "",
            rawContent: "-----BEGIN OPENSSH PRIVATE KEY-----",
            confidence: .high,
            type: .sshKey,
            entropy: 6.0,
            description: "ssh",
            sshMetadata: nil
        )

        #expect(secret.redactedOriginalLine == "deploy=<concealed by authsia>")
    }
}
