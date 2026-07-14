import Testing
import Foundation
@testable import authsia

// MARK: - Mock Client

struct MockResolverClient: SecretResolverClient {
    var passwords: [String: (username: String, password: String)] = [:]
    var apiKeys: [String: String] = [:]
    var certificates: [String: (certificate: String, privateKey: String?)] = [:]
    var notes: [String: String] = [:]
    var sshKeys: [String: (publicKey: String, privateKey: String, comment: String, fingerprint: String)] = [:]
    var otpCodes: [String: String] = [:]
    var shouldFail: [String: Error] = [:]
    var expectedFolder: String?
    var expectedFolderScoped: Bool?

    func resolveSecret(
        type: SecretReference.ItemType,
        query: String,
        field: String,
        folder: String?,
        isFolderScoped: Bool
    ) throws -> String {
        if let expectedFolder {
            #expect(folder == expectedFolder)
        }
        if let expectedFolderScoped {
            #expect(isFolderScoped == expectedFolderScoped)
        }
        if let error = shouldFail[query] { throw error }
        switch type {
        case .password:
            guard let pw = passwords[query] else {
                throw BridgeClientError.bridgeError(code: "notFound", message: "not found", query: query)
            }
            return field == "username" ? pw.username : pw.password
        case .apiKey:
            guard let key = apiKeys[query] else {
                throw BridgeClientError.bridgeError(code: "notFound", message: "not found", query: query)
            }
            return key
        case .cert:
            guard let cert = certificates[query] else {
                throw BridgeClientError.bridgeError(code: "notFound", message: "not found", query: query)
            }
            return field == "privateKey" ? (cert.privateKey ?? "") : cert.certificate
        case .note:
            guard let content = notes[query] else {
                throw BridgeClientError.bridgeError(code: "notFound", message: "not found", query: query)
            }
            return content
        case .ssh:
            guard let key = sshKeys[query] else {
                throw BridgeClientError.bridgeError(code: "notFound", message: "not found", query: query)
            }
            switch field {
            case "publicKey": return key.publicKey
            case "privateKey": return key.privateKey
            case "comment": return key.comment
            case "fingerprint": return key.fingerprint
            default: return key.privateKey
            }
        case .otp:
            guard let code = otpCodes[query] else {
                throw BridgeClientError.bridgeError(code: "notFound", message: "not found", query: query)
            }
            return code
        }
    }
}

@Suite("SecretReferenceResolver")
struct SecretReferenceResolverTests {

    @Test("resolves a single password reference")
    func resolveSinglePassword() throws {
        var mock = MockResolverClient()
        mock.passwords["GitHub"] = (username: "octocat", password: "gh-secret-123")
        let resolver = SecretReferenceResolver(client: mock)
        let ref = try SecretReference.parse("authsia://password/GitHub/password")
        #expect(try resolver.resolve(ref) == "gh-secret-123")
    }

    @Test("resolves username field")
    func resolveUsernameField() throws {
        var mock = MockResolverClient()
        mock.passwords["GitHub"] = (username: "octocat", password: "gh-secret-123")
        let resolver = SecretReferenceResolver(client: mock)
        let ref = try SecretReference.parse("authsia://password/GitHub/username")
        #expect(try resolver.resolve(ref) == "octocat")
    }

    @Test("resolves OTP code")
    func resolveOTP() throws {
        var mock = MockResolverClient()
        mock.otpCodes["GitHub"] = "482901"
        let resolver = SecretReferenceResolver(client: mock)
        let ref = try SecretReference.parse("authsia://otp/GitHub/code")
        #expect(try resolver.resolve(ref) == "482901")
    }

    @Test("resolves default field when field omitted")
    func resolveDefaultField() throws {
        var mock = MockResolverClient()
        mock.passwords["GitHub"] = (username: "octocat", password: "gh-secret-123")
        let resolver = SecretReferenceResolver(client: mock)
        let ref = try SecretReference.parse("authsia://password/GitHub")
        #expect(try resolver.resolve(ref) == "gh-secret-123")
    }

    @Test("rejects unsupported password field before resolving")
    func rejectsUnsupportedPasswordField() throws {
        var mock = MockResolverClient()
        mock.passwords["GitHub"] = (username: "octocat", password: "gh-secret-123")
        let resolver = SecretReferenceResolver(client: mock)
        let ref = try SecretReference.parse("authsia://password/GitHub/passwrod")

        #expect(throws: SecretReferenceError.self) {
            try resolver.resolve(ref)
        }
    }

    @Test("rejects unsupported ssh field before resolving")
    func rejectsUnsupportedSSHField() throws {
        var mock = MockResolverClient()
        mock.sshKeys["deploy"] = (
            publicKey: "ssh-ed25519 AAAA",
            privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----",
            comment: "deploy",
            fingerprint: "SHA256:abc"
        )
        let resolver = SecretReferenceResolver(client: mock)
        let ref = try SecretReference.parse("authsia://ssh/deploy/private")

        #expect(throws: SecretReferenceError.self) {
            try resolver.resolve(ref)
        }
    }

    @Test("passes folder scope to resolver client")
    func resolvePassesFolderScope() throws {
        var mock = MockResolverClient()
        mock.passwords["GitHub"] = (username: "octocat", password: "prod-secret")
        mock.expectedFolder = "Team/API"
        mock.expectedFolderScoped = true
        let resolver = SecretReferenceResolver(client: mock)
        let ref = try SecretReference.parse("authsia://password/GitHub/password?folder=Team%2FAPI")

        #expect(try resolver.resolve(ref) == "prod-secret")
    }

    @Test("explicit root folder remains scoped during resolution")
    func resolveExplicitRootRemainsScoped() throws {
        var mock = MockResolverClient()
        mock.passwords["GitHub"] = (username: "octocat", password: "root-secret")
        mock.expectedFolder = nil
        mock.expectedFolderScoped = true
        let resolver = SecretReferenceResolver(client: mock)
        let ref = try SecretReference.parse("authsia://password/GitHub/password?folder=%2F")

        #expect(try resolver.resolve(ref) == "root-secret")
    }

    @Test("folderless references remain unscoped during resolution")
    func resolveFolderlessRemainsUnscoped() throws {
        var mock = MockResolverClient()
        mock.passwords["GitHub"] = (username: "octocat", password: "global-secret")
        mock.expectedFolder = nil
        mock.expectedFolderScoped = false
        let resolver = SecretReferenceResolver(client: mock)
        let ref = try SecretReference.parse("authsia://password/GitHub/password")

        #expect(try resolver.resolve(ref) == "global-secret")
    }

    @Test("resolveEnvironment resolves all authsia:// values")
    func resolveEnvBatch() throws {
        var mock = MockResolverClient()
        mock.passwords["GitHub"] = (username: "octocat", password: "gh-secret")
        mock.passwords["AWS"] = (username: "admin", password: "aws-secret")
        let resolver = SecretReferenceResolver(client: mock)
        let env: [String: String] = [
            "API_KEY": "authsia://password/GitHub/password",
            "AWS_KEY": "authsia://password/AWS/password",
            "PORT": "8080",
        ]
        let result = try resolver.resolveEnvironment(env)
        #expect(result.resolved["API_KEY"] == "gh-secret")
        #expect(result.resolved["AWS_KEY"] == "aws-secret")
        #expect(result.resolved["PORT"] == "8080")
        #expect(result.secrets.contains("gh-secret"))
        #expect(result.secrets.contains("aws-secret"))
        #expect(!result.secrets.contains("8080"))
    }

    @Test("resolveEnvironment collects all errors before failing")
    func resolveEnvCollectsErrors() throws {
        let mock = MockResolverClient()
        let resolver = SecretReferenceResolver(client: mock)
        let env: [String: String] = [
            "A": "authsia://password/Missing1/password",
            "B": "authsia://password/Missing2/password",
            "C": "plain-value",
        ]
        #expect(throws: SecretResolutionErrors.self) {
            try resolver.resolveEnvironment(env)
        }
    }

    @Test("resolveEnvironment passes through non-reference values unchanged")
    func resolveEnvPassthrough() throws {
        let mock = MockResolverClient()
        let resolver = SecretReferenceResolver(client: mock)
        let env = ["PORT": "8080", "HOST": "localhost"]
        let result = try resolver.resolveEnvironment(env)
        #expect(result.resolved == env)
        #expect(result.secrets.isEmpty)
    }
}

@Suite("SecretReference URI parsing")
struct SecretReferenceParsingTests {

    // MARK: - Valid URIs

    @Test("parses full URI with type, item, and field")
    func parseFullURI() throws {
        let ref = try SecretReference.parse("authsia://password/GitHub/username")
        #expect(ref.type == .password)
        #expect(ref.item == "GitHub")
        #expect(ref.field == "username")
        #expect(ref.folder == nil)
    }

    @Test("parses URI with folder query param")
    func parseWithFolder() throws {
        let ref = try SecretReference.parse("authsia://password/GitHub/password?folder=Team/API")
        #expect(ref.type == .password)
        #expect(ref.item == "GitHub")
        #expect(ref.field == "password")
        #expect(ref.folder == "Team/API")
    }

    @Test("parses URI without field — uses nil (resolver applies default)")
    func parseWithoutField() throws {
        let ref = try SecretReference.parse("authsia://password/GitHub")
        #expect(ref.type == .password)
        #expect(ref.item == "GitHub")
        #expect(ref.field == nil)
        #expect(ref.folder == nil)
    }

    @Test("parses all item types")
    func parseAllTypes() throws {
        let cases: [(String, SecretReference.ItemType)] = [
            ("authsia://password/X/password", .password),
            ("authsia://cert/X/certificate", .cert),
            ("authsia://note/X/content", .note),
            ("authsia://ssh/X/publicKey", .ssh),
            ("authsia://otp/X/code", .otp),
        ]
        for (uri, expectedType) in cases {
            let ref = try SecretReference.parse(uri)
            #expect(ref.type == expectedType)
        }
    }

    @Test("decodes percent-encoded item name")
    func parsePercentEncoded() throws {
        let ref = try SecretReference.parse("authsia://password/My%20API%20Key/password")
        #expect(ref.item == "My API Key")
    }

    @Test("accepts unencoded spaces in item name")
    func parseUnencoded() throws {
        let ref = try SecretReference.parse("authsia://password/My API Key/password")
        #expect(ref.item == "My API Key")
    }

    @Test("decodes percent-encoded folder path")
    func parseFolderEncoded() throws {
        let ref = try SecretReference.parse("authsia://password/Key/password?folder=Team%2FInfra/Prod")
        #expect(ref.folder == "Team/Infra/Prod")
    }

    // MARK: - Invalid URIs

    @Test("rejects wrong scheme")
    func rejectWrongScheme() {
        #expect(throws: SecretReferenceError.self) {
            try SecretReference.parse("op://password/GitHub/password")
        }
    }

    @Test("rejects missing type")
    func rejectMissingType() {
        #expect(throws: SecretReferenceError.self) {
            try SecretReference.parse("authsia:///GitHub/password")
        }
    }

    @Test("rejects unknown type")
    func rejectUnknownType() {
        #expect(throws: SecretReferenceError.self) {
            try SecretReference.parse("authsia://database/MySQL/password")
        }
    }

    @Test("rejects missing item")
    func rejectMissingItem() {
        #expect(throws: SecretReferenceError.self) {
            try SecretReference.parse("authsia://password")
        }
    }

    @Test("rejects empty string")
    func rejectEmpty() {
        #expect(throws: SecretReferenceError.self) {
            try SecretReference.parse("")
        }
    }

    @Test("rejects non-URI string")
    func rejectPlainString() {
        #expect(throws: SecretReferenceError.self) {
            try SecretReference.parse("just-a-string")
        }
    }

    // MARK: - isSecretReference detection

    @Test("detects authsia:// prefix")
    func detectsReference() {
        #expect(SecretReference.isSecretReference("authsia://password/X/y") == true)
        #expect(SecretReference.isSecretReference("AUTHSIA://password/X/y") == true)
        #expect(SecretReference.isSecretReference("not-a-ref") == false)
        #expect(SecretReference.isSecretReference("") == false)
        #expect(SecretReference.isSecretReference("authsia://") == false)
    }
}
