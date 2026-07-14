import XCTest
@testable import AuthenticatorData

final class ExportEncryptorTests: XCTestCase {
    func testEncryptDecryptRoundTrip() throws {
        let plaintext = Data("Hello, World! This is secret export data.".utf8)
        let password = "test-password-123"

        let encrypted = try ExportEncryptor.encrypt(data: plaintext, password: password)
        let decrypted = try ExportEncryptor.decrypt(data: encrypted, password: password)

        XCTAssertEqual(decrypted, plaintext)
    }

    func testWrongPasswordFails() throws {
        let plaintext = Data("Secret data".utf8)
        let encrypted = try ExportEncryptor.encrypt(data: plaintext, password: "correct-password")

        XCTAssertThrowsError(try ExportEncryptor.decrypt(data: encrypted, password: "wrong-password")) { error in
            XCTAssertTrue(error is ExportEncryptionError)
            if case ExportEncryptionError.decryptionFailed = error {
                // Expected
            } else {
                XCTFail("Expected decryptionFailed, got \(error)")
            }
        }
    }

    func testEnvelopeFormat() throws {
        let plaintext = Data("Test payload".utf8)
        let encrypted = try ExportEncryptor.encrypt(data: plaintext, password: "testpass")

        let envelope = try JSONDecoder().decode(EncryptedExportEnvelope.self, from: encrypted)
        XCTAssertEqual(envelope.version, 1)
        XCTAssertEqual(envelope.format, "authsia-encrypted-export")
        XCTAssertEqual(envelope.kdf, "pbkdf2-sha256")
        XCTAssertEqual(envelope.kdfIterations, 600_000)
        XCTAssertFalse(envelope.salt.isEmpty)
        XCTAssertFalse(envelope.iv.isEmpty)
        XCTAssertFalse(envelope.ciphertext.isEmpty)
        XCTAssertFalse(envelope.tag.isEmpty)
    }

    func testIsEncryptedExportDetection() throws {
        let plaintext = Data("Test".utf8)
        let encrypted = try ExportEncryptor.encrypt(data: plaintext, password: "pass")
        let plainJSON = Data(#"{"items":[]}"#.utf8)
        let notJSON = Data("not json at all".utf8)

        XCTAssertTrue(ExportEncryptor.isEncryptedExport(data: encrypted))
        XCTAssertFalse(ExportEncryptor.isEncryptedExport(data: plainJSON))
        XCTAssertFalse(ExportEncryptor.isEncryptedExport(data: notJSON))
    }

    func testLargeDataRoundTrip() throws {
        // Simulate a real export of ~100 accounts (~50KB of JSON)
        let plaintext = Data(repeating: 0x42, count: 50_000)
        let password = "long-password-with-special-chars-!@#$%^&*()"

        let encrypted = try ExportEncryptor.encrypt(data: plaintext, password: password)
        let decrypted = try ExportEncryptor.decrypt(data: encrypted, password: password)

        XCTAssertEqual(decrypted, plaintext)
    }

    func testEmptyDataRoundTrip() throws {
        let plaintext = Data()
        let encrypted = try ExportEncryptor.encrypt(data: plaintext, password: "pass")
        let decrypted = try ExportEncryptor.decrypt(data: encrypted, password: "pass")
        XCTAssertEqual(decrypted, plaintext)
    }

    func testUnicodePasswordRoundTrip() throws {
        let plaintext = Data("secret".utf8)
        let password = "pässwörд🔑"

        let encrypted = try ExportEncryptor.encrypt(data: plaintext, password: password)
        let decrypted = try ExportEncryptor.decrypt(data: encrypted, password: password)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testEachEncryptionProducesDifferentOutput() throws {
        let plaintext = Data("same input".utf8)
        let password = "same-password"

        let encrypted1 = try ExportEncryptor.encrypt(data: plaintext, password: password)
        let encrypted2 = try ExportEncryptor.encrypt(data: plaintext, password: password)

        // Different salts and IVs each time
        XCTAssertNotEqual(encrypted1, encrypted2)

        // But both decrypt correctly
        XCTAssertEqual(try ExportEncryptor.decrypt(data: encrypted1, password: password), plaintext)
        XCTAssertEqual(try ExportEncryptor.decrypt(data: encrypted2, password: password), plaintext)
    }
}
