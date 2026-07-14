import Testing
import Foundation
@testable import AuthenticatorCore

@Suite("SSHKeyType")
struct SSHKeyTypeTests {

    @Test("SSHKeyType raw values match expected strings")
    func rawValues() {
        #expect(SSHKeyType.ed25519.rawValue == "ed25519")
        #expect(SSHKeyType.rsa2048.rawValue == "rsa2048")
        #expect(SSHKeyType.rsa3072.rawValue == "rsa3072")
        #expect(SSHKeyType.rsa4096.rawValue == "rsa4096")
    }

    @Test("SSHKeyType round-trips through JSON")
    func jsonRoundTrip() throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        for keyType in SSHKeyType.allCases {
            let data = try encoder.encode(keyType)
            let decoded = try decoder.decode(SSHKeyType.self, from: data)
            #expect(decoded == keyType)
        }
    }

    @Test("SSHKeyItem defaults keyType to ed25519")
    func defaultKeyType() {
        let item = SSHKeyItem(
            name: "test",
            publicKey: Data("ssh-ed25519 AAAA".utf8),
            privateKey: Data("private".utf8),
            comment: "test",
            fingerprint: "SHA256:abc"
        )
        #expect(item.keyType == .ed25519)
    }

    @Test("SSHKeyItem with keyType survives JSON round-trip")
    func itemRoundTrip() throws {
        let item = SSHKeyItem(
            name: "rsa-key",
            publicKey: Data("ssh-rsa AAAA".utf8),
            privateKey: Data("private".utf8),
            comment: "rsa",
            fingerprint: "SHA256:def",
            keyType: .rsa4096
        )
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        let data = try encoder.encode(item)
        let decoded = try decoder.decode(SSHKeyItem.self, from: data)
        #expect(decoded.keyType == .rsa4096)
    }

    @Test("SSHKeyItem decodes missing keyType as ed25519 for backward compat")
    func backwardCompat() throws {
        let json = """
        {
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "old-key",
            "publicKey": "c3NoLWVkMjU1MTkgQUFBQQ==",
            "privateKey": "cHJpdmF0ZQ==",
            "comment": "old",
            "fingerprint": "SHA256:old",
            "createdAt": 0,
            "modifiedAt": 0
        }
        """.data(using: .utf8)!
        let decoder = JSONDecoder()
        let item = try decoder.decode(SSHKeyItem.self, from: json)
        #expect(item.keyType == .ed25519)
    }
}
