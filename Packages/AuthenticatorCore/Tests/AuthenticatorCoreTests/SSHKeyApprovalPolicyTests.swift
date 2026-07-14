import Testing
import Foundation
@testable import AuthenticatorCore

@Suite("SSHKeyApprovalPolicy")
struct SSHKeyApprovalPolicyTests {

    @Test("SSHKeyApprovalPolicy raw values")
    func rawValues() {
        #expect(SSHKeyApprovalPolicy.alwaysPrompt.rawValue == "alwaysPrompt")
        #expect(SSHKeyApprovalPolicy.sessionBased.rawValue == "sessionBased")
        #expect(SSHKeyApprovalPolicy.autoApprove.rawValue == "autoApprove")
    }

    @Test("SSHKeyItem defaults approvalPolicy to sessionBased")
    func defaultPolicy() {
        let item = SSHKeyItem(
            name: "test",
            publicKey: Data("pub".utf8),
            privateKey: Data("priv".utf8),
            comment: "test",
            fingerprint: "SHA256:abc"
        )
        #expect(item.approvalPolicy == .sessionBased)
    }

    @Test("SSHKeyItem with approvalPolicy round-trips through JSON")
    func roundTrip() throws {
        let item = SSHKeyItem(
            name: "locked",
            publicKey: Data("pub".utf8),
            privateKey: Data("priv".utf8),
            comment: "locked",
            fingerprint: "SHA256:def",
            approvalPolicy: .alwaysPrompt
        )
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        let data = try encoder.encode(item)
        let decoded = try decoder.decode(SSHKeyItem.self, from: data)
        #expect(decoded.approvalPolicy == .alwaysPrompt)
    }

    @Test("SSHKeyItem decodes missing approvalPolicy as sessionBased")
    func backwardCompat() throws {
        let json = """
        {
            "id": "00000000-0000-0000-0000-000000000002",
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
        #expect(item.approvalPolicy == .sessionBased)
    }
}
