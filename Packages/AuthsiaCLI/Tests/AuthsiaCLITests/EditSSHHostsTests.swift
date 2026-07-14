import Testing
import Foundation
@testable import authsia

@Suite("EditSSH --hosts flag")
struct EditSSHHostsTests {

    @Test("EditSSH accepts --hosts option")
    func acceptsHostsOption() throws {
        let cmd = try EditSSH.parse(["mykey", "--hosts", "github.com,gitlab.com"])
        #expect(cmd.hosts == "github.com,gitlab.com")
    }

    @Test("EditSSH hosts defaults to nil")
    func defaultNil() throws {
        let cmd = try EditSSH.parse(["mykey"])
        #expect(cmd.hosts == nil)
    }

    @Test("empty string clears hosts")
    func emptyClears() throws {
        let cmd = try EditSSH.parse(["mykey", "--hosts", ""])
        #expect(cmd.hosts == "")
    }
}
