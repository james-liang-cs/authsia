import Testing
import Foundation
@testable import AuthenticatorCore

@Suite("SSHKeyItem boundHosts")
struct SSHKeyBoundHostsTests {

    @Test("boundHosts defaults to empty array")
    func defaultEmpty() {
        let item = SSHKeyItem(
            name: "test",
            publicKey: Data("pub".utf8),
            privateKey: Data("priv".utf8),
            comment: "test",
            fingerprint: "SHA256:abc"
        )
        #expect(item.boundHosts.isEmpty)
    }

    @Test("boundHosts round-trips through JSON")
    func roundTrip() throws {
        let item = SSHKeyItem(
            name: "deploy",
            publicKey: Data("pub".utf8),
            privateKey: Data("priv".utf8),
            comment: "deploy",
            fingerprint: "SHA256:def",
            boundHosts: ["github.com", "*.internal.corp"]
        )
        let data = try JSONEncoder().encode(item)
        let decoded = try JSONDecoder().decode(SSHKeyItem.self, from: data)
        #expect(decoded.boundHosts == ["github.com", "*.internal.corp"])
    }

    @Test("missing boundHosts decodes as empty array for backward compat")
    func backwardCompat() throws {
        let json = """
        {
            "id": "00000000-0000-0000-0000-000000000003",
            "name": "old",
            "publicKey": "cHVi",
            "privateKey": "cHJpdg==",
            "comment": "old",
            "fingerprint": "SHA256:old",
            "createdAt": 0,
            "modifiedAt": 0
        }
        """.data(using: .utf8)!
        let item = try JSONDecoder().decode(SSHKeyItem.self, from: json)
        #expect(item.boundHosts.isEmpty)
    }
}
