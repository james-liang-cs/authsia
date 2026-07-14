import Testing
import Foundation
@testable import authsia

@Suite("EditSSH --approval flag")
struct EditSSHApprovalTests {

    @Test("EditSSH accepts --approval option")
    func acceptsApprovalOption() throws {
        let cmd = try EditSSH.parse(["mykey", "--approval", "always"])
        #expect(cmd.approval == "always")
    }

    @Test("EditSSH approval defaults to nil")
    func defaultNil() throws {
        let cmd = try EditSSH.parse(["mykey"])
        #expect(cmd.approval == nil)
    }

    @Test("EditSSH accepts valid approval values")
    func validValues() throws {
        for value in ["always", "session", "auto"] {
            let cmd = try EditSSH.parse(["mykey", "--approval", value])
            #expect(cmd.approval == value)
        }
    }
}
