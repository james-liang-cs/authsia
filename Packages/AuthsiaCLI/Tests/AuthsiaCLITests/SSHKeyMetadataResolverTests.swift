import Testing
import Foundation
import AuthenticatorCore
@testable import authsia

@Suite("SSHKeyMetadataResolver")
struct SSHKeyMetadataResolverTests {
    private static let fakeKeyData = "AAAAC3NzaC1lZDI1NTE5AAAAIAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    @Test("parses public key metadata and fingerprint")
    func parsesPublicKeyMetadata() throws {
        let metadata = try SSHKeyMetadataResolver.parsePublicKeyLine(
            "ssh-ed25519 \(Self.fakeKeyData) james@mac",
            fallbackComment: "id_ed25519"
        )

        #expect(metadata.publicKey == "ssh-ed25519 \(Self.fakeKeyData) james@mac")
        #expect(metadata.comment == "james@mac")
        #expect(metadata.fingerprint.hasPrefix("SHA256:"))
        #expect(metadata.keyType == .ed25519)
    }

    @Test("uses filename as fallback comment")
    func usesFallbackComment() throws {
        let metadata = try SSHKeyMetadataResolver.parsePublicKeyLine(
            "ssh-rsa \(Self.fakeKeyData)",
            fallbackComment: "id_rsa"
        )

        #expect(metadata.comment == "id_rsa")
        #expect(metadata.publicKey == "ssh-rsa \(Self.fakeKeyData)")
        #expect(metadata.keyType == .rsa2048)
    }
}
