import Testing
@testable import authsia

@Suite("ClipboardClient auto-clear timeout")
struct ClipboardTimeoutTests {
    @Test("copy with timeout=0 does not launch background process")
    func noTimeoutNoBackground() throws {
        nonisolated(unsafe) var called = false
        let client = ClipboardClient { value, clearAfterSeconds in
            called = true
            #expect(clearAfterSeconds == 0)
        }
        try client.copy("secret", 0)
        #expect(called)
    }

    @Test("copy with timeout>0 passes seconds through")
    func timeoutPassedThrough() throws {
        nonisolated(unsafe) var receivedSeconds = -1
        let client = ClipboardClient { value, clearAfterSeconds in
            receivedSeconds = clearAfterSeconds
        }
        try client.copy("secret", 30)
        #expect(receivedSeconds == 30)
    }

    @Test("copy passes value correctly")
    func valuePassedCorrectly() throws {
        nonisolated(unsafe) var receivedValue = ""
        let client = ClipboardClient { value, clearAfterSeconds in
            receivedValue = value
        }
        try client.copy("my-secret-value", 0)
        #expect(receivedValue == "my-secret-value")
    }
}
