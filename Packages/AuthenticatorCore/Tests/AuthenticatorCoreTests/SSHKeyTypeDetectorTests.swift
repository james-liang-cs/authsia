import Testing
import Foundation
@testable import AuthenticatorCore

@Suite("SSHKeyTypeDetector")
struct SSHKeyTypeDetectorTests {

    @Test("detects ed25519 from public key string")
    func detectEd25519() {
        let pubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey user@host"
        #expect(SSHKeyTypeDetector.detect(publicKey: pubKey) == .ed25519)
    }

    @Test("detects RSA from public key string")
    func detectRSA() {
        // Use a long enough blob to be detected as 4096
        let longBlob = String(repeating: "A", count: 700)
        let pubKey = "ssh-rsa \(longBlob) user@host"
        #expect(SSHKeyTypeDetector.detect(publicKey: pubKey) == .rsa4096)
    }

    @Test("detects RSA 2048 from key data length")
    func detectRSA2048() {
        let shortBlob = String(repeating: "A", count: 372)
        let pubKey = "ssh-rsa \(shortBlob) user@host"
        let result = SSHKeyTypeDetector.detect(publicKey: pubKey)
        #expect(result == .rsa2048)
    }

    @Test("returns ed25519 for unrecognized format")
    func fallbackEd25519() {
        #expect(SSHKeyTypeDetector.detect(publicKey: "garbage") == .ed25519)
    }

    @Test("detects type from Data public key")
    func detectFromData() {
        let pubKey = Data("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey user@host".utf8)
        #expect(SSHKeyTypeDetector.detect(publicKeyData: pubKey) == .ed25519)
    }
}
