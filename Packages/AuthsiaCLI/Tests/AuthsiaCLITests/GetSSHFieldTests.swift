import Testing
import Foundation
import AuthenticatorCore
@testable import authsia

@Suite("Get SSH fields")
struct GetSSHFieldTests {
    @Test("parses ssh metadata fields")
    func parsesSSHMetadataFields() throws {
        for field in ["keyType", "approvalPolicy", "boundHosts"] {
            let command = try Get.parse(["ssh", "deploy", "--field", field])
            #expect(command.field?.rawValue == field)
        }
    }

    @Test("formats ssh metadata fields")
    func formatsSSHMetadataFields() throws {
        let result = SSHKeyResult(
            id: UUID().uuidString,
            name: "deploy",
            publicKey: "ssh-rsa AAAA deploy",
            privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----",
            comment: "deploy",
            fingerprint: "SHA256:abc",
            passphrase: nil,
            keyType: .rsa4096,
            approvalPolicy: .alwaysPrompt,
            boundHosts: ["github.com", "*.corp.internal"],
            createdAt: Date(timeIntervalSince1970: 0),
            modifiedAt: Date(timeIntervalSince1970: 1),
            isFavorite: false
        )

        #expect(try Get.formatSSH(result: result, field: .keyType, format: .json) == "rsa4096")
        #expect(try Get.formatSSH(result: result, field: .approvalPolicy, format: .json) == "alwaysPrompt")
        #expect(try Get.formatSSH(result: result, field: .boundHosts, format: .json) == "github.com,*.corp.internal")
    }
}
