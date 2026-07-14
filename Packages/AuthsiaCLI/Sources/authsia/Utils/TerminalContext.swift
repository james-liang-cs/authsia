import Darwin

enum TerminalContext {
    static var stdinIsTTY: Bool {
        isatty(STDIN_FILENO) != 0
    }

    static var stdoutIsTTY: Bool {
        isatty(STDOUT_FILENO) != 0
    }

    static var isInteractiveSession: Bool {
        stdinIsTTY && stdoutIsTTY
    }
}
