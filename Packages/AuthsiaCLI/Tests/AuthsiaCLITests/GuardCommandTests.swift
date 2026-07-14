import ArgumentParser
import Testing
@testable import authsia

@Suite("Top-level guard command")
struct GuardCommandTests {
    @Test("guard is registered as a top-level command")
    func guardIsRegistered() throws {
        _ = try Authsia.parseAsRoot(["guard"])
    }

    @Test("guard fails with shell integration guidance when invoked directly")
    func guardFailsWithShellIntegrationGuidance() {
        do {
            try Guard().run()
            Issue.record("Expected direct guard invocation to fail")
        } catch let error as ValidationError {
            #expect(error.message.contains("authsia setup --repair"))
            #expect(error.message.contains("authsia guard"))
        } catch {
            Issue.record("Expected ValidationError, got \(error)")
        }
    }

    @Test("unguard is registered as a top-level command")
    func unguardIsRegistered() throws {
        _ = try Authsia.parseAsRoot(["unguard"])
    }

    @Test("unguard fails with shell integration guidance when invoked directly")
    func unguardFailsWithShellIntegrationGuidance() {
        do {
            try Unguard().run()
            Issue.record("Expected direct unguard invocation to fail")
        } catch let error as ValidationError {
            #expect(error.message.contains("authsia setup --repair"))
            #expect(error.message.contains("authsia unguard"))
        } catch {
            Issue.record("Expected ValidationError, got \(error)")
        }
    }
}
