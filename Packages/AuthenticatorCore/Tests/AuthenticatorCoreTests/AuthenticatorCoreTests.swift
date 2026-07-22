import XCTest
@testable import AuthenticatorCore

final class AuthenticatorCoreTests: XCTestCase {
    
    // MARK: - Base32 Tests
    
    func testBase32Decoding() throws {
        // RFC 4648 Test Vectors
        XCTAssertEqual(try Base32.decode(""), Data())
        XCTAssertEqual(try Base32.decode("MY======"), Data("f".utf8))
        XCTAssertEqual(try Base32.decode("MZXQ===="), Data("fo".utf8))
        XCTAssertEqual(try Base32.decode("MZXW6==="), Data("foo".utf8))
        XCTAssertEqual(try Base32.decode("MZXW6YQ="), Data("foob".utf8))
        XCTAssertEqual(try Base32.decode("MZXW6YTB"), Data("fooba".utf8))
        XCTAssertEqual(try Base32.decode("MZXW6YTBOI======"), Data("foobar".utf8))
    }
    
    func testBase32Hardening() throws {
        // "MZXW6YTB" -> "fooba"
        // Lowercase
        XCTAssertEqual(try Base32.decode("mzxw6ytb"), Data("fooba".utf8))
        // Spaces/Hyphens
        XCTAssertEqual(try Base32.decode("MZXW-6YTB"), Data("fooba".utf8))
        XCTAssertEqual(try Base32.decode("MZXW 6YTB"), Data("fooba".utf8))
        // No padding
        XCTAssertEqual(try Base32.decode("MZXW6YTB"), Data("fooba".utf8))
    }
    
    func testBase32Invalid() {
        XCTAssertThrowsError(try Base32.decode("MZXW6YTB!")) { error in
            guard case Base32Error.invalidCharacter(let char) = error else {
                XCTFail("Unexpected error: \(error)")
                return
            }
            XCTAssertEqual(char, "!")
        }
    }
    
    // MARK: - RFC 4226 (HOTP) Tests
    
    func testRFC4226() {
        // Seed: "12345678901234567890" (20 bytes)
        let secret = Data("12345678901234567890".utf8)
        
        // Count 0
        XCTAssertEqual(OTPGenerator.hotp(secret: secret, counter: 0, digits: 6), "755224")
        // Count 1
        XCTAssertEqual(OTPGenerator.hotp(secret: secret, counter: 1, digits: 6), "287082")
        // Count 2
        XCTAssertEqual(OTPGenerator.hotp(secret: secret, counter: 2, digits: 6), "359152")
        // Count 3
        XCTAssertEqual(OTPGenerator.hotp(secret: secret, counter: 3, digits: 6), "969429")
        // Count 4
        XCTAssertEqual(OTPGenerator.hotp(secret: secret, counter: 4, digits: 6), "338314")
        // Count 5
        XCTAssertEqual(OTPGenerator.hotp(secret: secret, counter: 5, digits: 6), "254676")
        // Count 6
        XCTAssertEqual(OTPGenerator.hotp(secret: secret, counter: 6, digits: 6), "287922")
        // Count 7
        XCTAssertEqual(OTPGenerator.hotp(secret: secret, counter: 7, digits: 6), "162583")
        // Count 8
        XCTAssertEqual(OTPGenerator.hotp(secret: secret, counter: 8, digits: 6), "399871")
        // Count 9
        XCTAssertEqual(OTPGenerator.hotp(secret: secret, counter: 9, digits: 6), "520489")
    }
    
    // MARK: - RFC 6238 (TOTP) Tests
    
    func testRFC6238_SHA1() {
         // Seed: "12345678901234567890" (20 bytes)
        let secret = Data("12345678901234567890".utf8)
        
        // T0 -> 59s (Count 1)
        let time1 = Date(timeIntervalSince1970: 59)
        XCTAssertEqual(OTPGenerator.totp(secret: secret, time: time1, period: 30, digits: 8, algorithm: .sha1), "94287082")
        
        // T2 -> 1111111109 (Count 37037036)
        let time2 = Date(timeIntervalSince1970: 1111111109)
        XCTAssertEqual(OTPGenerator.totp(secret: secret, time: time2, period: 30, digits: 8, algorithm: .sha1), "07081804")
        
        // T3 -> 1234567890 (Count 41152263)
        let time3 = Date(timeIntervalSince1970: 1234567890)
        XCTAssertEqual(OTPGenerator.totp(secret: secret, time: time3, period: 30, digits: 8, algorithm: .sha1), "89005924")
    }
    
    func testRFC6238_SHA256() {
        // Seed = 32 bytes
        // 12345678901234567890123456789012
        let secret = Data("12345678901234567890123456789012".utf8)
        
        // T1 -> 59s
        let time1 = Date(timeIntervalSince1970: 59)
        XCTAssertEqual(OTPGenerator.totp(secret: secret, time: time1, period: 30, digits: 8, algorithm: .sha256), "46119246")
        
         // T2 -> 1111111109
        let time2 = Date(timeIntervalSince1970: 1111111109)
        XCTAssertEqual(OTPGenerator.totp(secret: secret, time: time2, period: 30, digits: 8, algorithm: .sha256), "68084774")
    }
    
    func testRFC6238_SHA512() {
        // Seed = 64 bytes
        // 1234567890123456789012345678901234567890123456789012345678901234
        let secret = Data("1234567890123456789012345678901234567890123456789012345678901234".utf8)
        
        // T1 -> 59s
        let time1 = Date(timeIntervalSince1970: 59)
        XCTAssertEqual(OTPGenerator.totp(secret: secret, time: time1, period: 30, digits: 8, algorithm: .sha512), "90693936")
        
        // T2 -> 1111111109
        let time2 = Date(timeIntervalSince1970: 1111111109)
        XCTAssertEqual(OTPGenerator.totp(secret: secret, time: time2, period: 30, digits: 8, algorithm: .sha512), "25091201")
    }

    // MARK: - SSH Key Tests

    func testSSHKeyItemCodableRoundTrip() throws {
        let item = SSHKeyItem(
            name: "Work Key",
            publicKey: Data("ssh-ed25519 AAAA...".utf8),
            privateKey: Data("-----BEGIN OPENSSH PRIVATE KEY-----\n...".utf8),
            comment: "laptop",
            fingerprint: "SHA256:abc",
            isScraped: true
        )
        let data = try JSONEncoder().encode(item)
        let decoded = try JSONDecoder().decode(SSHKeyItem.self, from: data)
        XCTAssertEqual(decoded, item)
    }

    func testAPIKeyItemCodableRoundTrip() throws {
        XCTAssertEqual(VaultItemType.apiKey.displayName, "API Keys")

        let item = APIKeyItem(
            name: "Stripe",
            key: Data("sk_test_123".utf8),
            website: "https://dashboard.stripe.com",
            notes: "Billing automation",
            folderPath: "Team/API",
            isCliEnabled: true,
            expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
            autoDestroyOnExpiry: true
        )

        let data = try JSONEncoder().encode(item)
        let decoded = try JSONDecoder().decode(APIKeyItem.self, from: data)

        XCTAssertEqual(decoded, item)
    }

    func testPasswordItemCodableRoundTripPreservesExpiryPolicy() throws {
        let item = PasswordItem(
            name: "GitHub",
            username: "octo",
            password: Data("secret".utf8),
            expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
            autoDestroyOnExpiry: false
        )

        let data = try JSONEncoder().encode(item)
        let decoded = try JSONDecoder().decode(PasswordItem.self, from: data)

        XCTAssertEqual(decoded, item)
        XCTAssertFalse(decoded.autoDestroyOnExpiry)
    }

    // MARK: - Vault Environment Tests

    func testEnvironmentTagsNormalizeAndMatchCaseInsensitively() {
        let tags = VaultEnvironmentTags.normalize([
            " Production ", "development", "PRODUCTION", "", " Development ", "   "
        ])

        XCTAssertEqual(tags, ["development", "Production"])
        XCTAssertTrue(VaultEnvironmentTags.contains("production", in: tags))
        XCTAssertFalse(VaultEnvironmentTags.contains("staging", in: tags))
    }

    func testVaultItemsNormalizeAndRoundTripEnvironmentTags() throws {
        let environments = [" Production ", "development", "PRODUCTION"]
        let expected = ["development", "Production"]
        let password = PasswordItem(
            name: "Database",
            username: "service",
            password: Data("value".utf8),
            environments: environments
        )
        let apiKey = APIKeyItem(name: "API", key: Data("value".utf8), environments: environments)
        let certificate = CertificateItem(
            name: "TLS",
            certificateData: Data("certificate".utf8),
            environments: environments
        )
        let note = SecureNoteItem(title: "Runbook", content: Data("content".utf8), environments: environments)
        let sshKey = SSHKeyItem(
            name: "Deploy",
            publicKey: Data("public".utf8),
            privateKey: Data("private".utf8),
            comment: "deploy",
            fingerprint: "SHA256:test",
            environments: environments
        )

        XCTAssertEqual(password.environments, expected)
        XCTAssertEqual(apiKey.environments, expected)
        XCTAssertEqual(certificate.environments, expected)
        XCTAssertEqual(note.environments, expected)
        XCTAssertEqual(sshKey.environments, expected)
        XCTAssertEqual(try roundTrip(password), password)
        XCTAssertEqual(try roundTrip(apiKey), apiKey)
        XCTAssertEqual(try roundTrip(certificate), certificate)
        XCTAssertEqual(try roundTrip(note), note)
        XCTAssertEqual(try roundTrip(sshKey), sshKey)
    }

    func testVaultItemsDecodeMissingEnvironmentsAsDefault() throws {
        let password = PasswordItem(name: "Database", username: "service", password: Data("value".utf8))
        let apiKey = APIKeyItem(name: "API", key: Data("value".utf8))
        let certificate = CertificateItem(name: "TLS", certificateData: Data("certificate".utf8))
        let note = SecureNoteItem(title: "Runbook", content: Data("content".utf8))
        let sshKey = SSHKeyItem(
            name: "Deploy",
            publicKey: Data("public".utf8),
            privateKey: Data("private".utf8),
            comment: "deploy",
            fingerprint: "SHA256:test"
        )

        XCTAssertEqual(try decodeLegacy(password).environments, [])
        XCTAssertEqual(try decodeLegacy(apiKey).environments, [])
        XCTAssertEqual(try decodeLegacy(certificate).environments, [])
        XCTAssertEqual(try decodeLegacy(note).environments, [])
        XCTAssertEqual(try decodeLegacy(sshKey).environments, [])
    }

    private func roundTrip<Item: Codable>(_ item: Item) throws -> Item {
        let data = try JSONEncoder().encode(item)
        return try JSONDecoder().decode(Item.self, from: data)
    }

    private func decodeLegacy<Item: Codable>(_ item: Item) throws -> Item {
        let encoded = try JSONEncoder().encode(item)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        object.removeValue(forKey: "environments")
        let legacyData = try JSONSerialization.data(withJSONObject: object)
        return try JSONDecoder().decode(Item.self, from: legacyData)
    }
}
