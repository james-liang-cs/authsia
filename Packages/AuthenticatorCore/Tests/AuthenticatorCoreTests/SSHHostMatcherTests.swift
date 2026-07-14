import Testing
import Foundation
@testable import AuthenticatorCore

@Suite("SSHHostMatcher")
struct SSHHostMatcherTests {

    @Test("exact match")
    func exactMatch() {
        #expect(SSHHostMatcher.matches(host: "github.com", pattern: "github.com"))
    }

    @Test("exact match is case-insensitive")
    func caseInsensitive() {
        #expect(SSHHostMatcher.matches(host: "GitHub.COM", pattern: "github.com"))
    }

    @Test("wildcard prefix match")
    func wildcardPrefix() {
        #expect(SSHHostMatcher.matches(host: "git.internal.corp", pattern: "*.internal.corp"))
    }

    @Test("wildcard does not match the base domain itself")
    func wildcardNoBase() {
        #expect(!SSHHostMatcher.matches(host: "internal.corp", pattern: "*.internal.corp"))
    }

    @Test("no match for different host")
    func noMatch() {
        #expect(!SSHHostMatcher.matches(host: "gitlab.com", pattern: "github.com"))
    }

    @Test("empty boundHosts matches any host")
    func emptyBoundHostsMatchesAll() {
        #expect(SSHHostMatcher.keyMatchesHost(boundHosts: [], targetHost: "anything.com"))
    }

    @Test("boundHosts filters correctly")
    func boundHostsFilter() {
        let hosts = ["github.com", "*.corp.internal"]
        #expect(SSHHostMatcher.keyMatchesHost(boundHosts: hosts, targetHost: "github.com"))
        #expect(SSHHostMatcher.keyMatchesHost(boundHosts: hosts, targetHost: "git.corp.internal"))
        #expect(!SSHHostMatcher.keyMatchesHost(boundHosts: hosts, targetHost: "gitlab.com"))
    }
}
