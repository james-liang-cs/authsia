import Testing
import Foundation
@testable import AuthenticatorData
@testable import AuthenticatorCore

@Suite("SSHKeyMetadata new fields")
struct SSHKeyMetadataFieldsTests {

    @Test("SSHKeyMetadata copies keyType from SSHKeyItem")
    func keyTypeFromItem() {
        let item = SSHKeyItem(
            name: "rsa",
            publicKey: Data("pub".utf8),
            privateKey: Data("priv".utf8),
            comment: "rsa",
            fingerprint: "SHA256:abc",
            keyType: .rsa4096
        )
        let metadata = SSHKeyMetadata(from: item)
        #expect(metadata.keyType == .rsa4096)
    }

    @Test("SSHKeyMetadata copies approvalPolicy from SSHKeyItem")
    func approvalPolicyFromItem() {
        let item = SSHKeyItem(
            name: "locked",
            publicKey: Data("pub".utf8),
            privateKey: Data("priv".utf8),
            comment: "locked",
            fingerprint: "SHA256:abc",
            approvalPolicy: .alwaysPrompt
        )
        let metadata = SSHKeyMetadata(from: item)
        #expect(metadata.approvalPolicy == .alwaysPrompt)
    }

    @Test("SSHKeyMetadata copies boundHosts from SSHKeyItem")
    func boundHostsFromItem() {
        let item = SSHKeyItem(
            name: "deploy",
            publicKey: Data("pub".utf8),
            privateKey: Data("priv".utf8),
            comment: "deploy",
            fingerprint: "SHA256:abc",
            boundHosts: ["github.com"]
        )
        let metadata = SSHKeyMetadata(from: item)
        #expect(metadata.boundHosts == ["github.com"])
    }

    @Test("SSHKeyMetadata JSON backward compat with missing new fields")
    func backwardCompat() throws {
        let json = """
        {
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "old",
            "publicKey": "ssh-ed25519 AAAA",
            "comment": "old",
            "fingerprint": "SHA256:old",
            "createdAt": 0,
            "modifiedAt": 0
        }
        """.data(using: .utf8)!
        let metadata = try JSONDecoder().decode(SSHKeyMetadata.self, from: json)
        #expect(metadata.keyType == .ed25519)
        #expect(metadata.approvalPolicy == .sessionBased)
        #expect(metadata.boundHosts.isEmpty)
    }
}
