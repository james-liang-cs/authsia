import Foundation
import Testing
@testable import AuthenticatorBridge
#if os(macOS)
import Darwin
#endif

@Suite("Terminal session scope")
struct TerminalSessionScopeTests {
    @Test("identity includes terminal and process session")
    func identityIncludesTerminalAndProcessSession() {
        let scope = TerminalSessionScope.identity(
            terminalIdentifier: "/dev/ttys001",
            processSessionIdentifier: 1001
        )

        #expect(scope == "tty:/dev/ttys001:sid:1001")
    }

    @Test("components parse terminal and process session")
    func componentsParseTerminalAndProcessSession() throws {
        let components = try #require(TerminalSessionScope.components(from: "tty:/dev/ttys001:sid:1001"))

        #expect(components.terminalIdentifier == "/dev/ttys001")
        #expect(components.processSessionIdentifier == 1001)
    }

    @Test("liveness uses process session when present")
    func livenessUsesProcessSessionWhenPresent() {
        let active = TerminalSessionScope.liveness(
            for: "tty:/dev/ttys001:sid:1001",
            isProcessRunning: { $0 == 1001 }
        )
        let closed = TerminalSessionScope.liveness(
            for: "tty:/dev/ttys001:sid:1001",
            isProcessRunning: { _ in false }
        )
        let unknown = TerminalSessionScope.liveness(
            for: "tty:/dev/ttys001",
            isProcessRunning: { _ in true }
        )

        #expect(active == .active)
        #expect(closed == .closed)
        #expect(unknown == .unknown)
    }

    @Test("liveness uses agent host process when present")
    func livenessUsesAgentHostProcessWhenPresent() {
        let active = TerminalSessionScope.liveness(
            for: "agent:cursor:pid:1001",
            isProcessRunning: { $0 == 1001 }
        )
        let closed = TerminalSessionScope.liveness(
            for: "agent:cursor:pid:1001",
            isProcessRunning: { _ in false }
        )

        #expect(active == .active)
        #expect(closed == .closed)
    }

    @Test("current process scope requires terminal-backed standard I/O")
    func currentProcessScopeRequiresTerminalBackedStandardIO() {
        let current = TerminalSessionScope.currentProcess()
        let byPID = TerminalSessionScope.process(pid: getpid())
        let hasTerminalIO = [STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO].contains {
            isatty($0) != 0
        }

        if hasTerminalIO {
            #expect(current == byPID)
        } else {
            #expect(current == nil)
        }
    }

    #if os(macOS)
    @Test("current terminal identifier prefers concrete controlling terminal over /dev/tty")
    func currentTerminalIdentifierPrefersConcreteControllingTerminal() {
        let identifier = TerminalSessionScope.currentTerminalIdentifier(
            isTerminal: { $0 == STDIN_FILENO },
            terminalName: { _ in "/dev/tty" },
            controllingTerminalPath: { "/dev/ttys003" }
        )

        #expect(identifier == "/dev/ttys003")
    }

    @Test("current terminal identifier falls back to ttyname")
    func currentTerminalIdentifierFallsBackToTTYName() {
        let identifier = TerminalSessionScope.currentTerminalIdentifier(
            isTerminal: { $0 == STDIN_FILENO },
            terminalName: { _ in "/dev/tty" },
            controllingTerminalPath: { nil }
        )

        #expect(identifier == "/dev/tty")
    }
    #endif

    @Test("ancestral scope returns first ancestor with a terminal scope")
    func ancestralScopeReturnsFirstAncestorWithTerminalScope() {
        let parents: [Int32: Int32] = [100: 200, 200: 300, 300: 1]
        let scopes: [Int32: String] = [300: "tty:/dev/ttys004:sid:94228"]

        let scope = TerminalSessionScope.ancestralScope(
            startingAt: 100,
            parentProcessIdentifier: { parents[$0] },
            scopeForProcess: { scopes[$0] }
        )

        #expect(scope == "tty:/dev/ttys004:sid:94228")
    }

    @Test("ancestral scope prefers the starting process scope")
    func ancestralScopePrefersStartingProcessScope() {
        let parents: [Int32: Int32] = [100: 200]
        let scopes: [Int32: String] = [
            100: "tty:/dev/ttys001:sid:100",
            200: "tty:/dev/ttys002:sid:200",
        ]

        let scope = TerminalSessionScope.ancestralScope(
            startingAt: 100,
            parentProcessIdentifier: { parents[$0] },
            scopeForProcess: { scopes[$0] }
        )

        #expect(scope == "tty:/dev/ttys001:sid:100")
    }

    @Test("ancestral scope returns nil when no ancestor has a terminal")
    func ancestralScopeReturnsNilWithoutTerminalAncestor() {
        let parents: [Int32: Int32] = [100: 200, 200: 1]

        let scope = TerminalSessionScope.ancestralScope(
            startingAt: 100,
            parentProcessIdentifier: { parents[$0] },
            scopeForProcess: { _ in nil }
        )

        #expect(scope == nil)
    }

    @Test("ancestral scope stops on parent cycles and hop limit")
    func ancestralScopeStopsOnCyclesAndHopLimit() {
        let cyclic = TerminalSessionScope.ancestralScope(
            startingAt: 100,
            parentProcessIdentifier: { _ in 100 },
            scopeForProcess: { _ in nil }
        )
        #expect(cyclic == nil)

        var visited = 0
        let limited = TerminalSessionScope.ancestralScope(
            startingAt: 2,
            maxHops: 4,
            parentProcessIdentifier: { $0 + 1 },
            scopeForProcess: { _ in
                visited += 1
                return nil
            }
        )
        #expect(limited == nil)
        #expect(visited == 4)
    }
}
