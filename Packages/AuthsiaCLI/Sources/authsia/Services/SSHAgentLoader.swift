import Darwin
import Foundation

/// Loads SSH private keys into the running ssh-agent via `ssh-add -`.
enum SSHAgentLoader {

    enum AgentError: LocalizedError {
        case noAgent
        case addFailed(String)

        var errorDescription: String? {
            switch self {
            case .noAgent:
                return "No ssh-agent found. Start one with: eval $(ssh-agent)"
            case .addFailed(let output):
                return "ssh-add failed: \(output)"
            }
        }
    }

    /// Returns true when `SSH_AUTH_SOCK` is set in the environment.
    static func isAgentRunning(
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> Bool {
        environment["SSH_AUTH_SOCK"] != nil
    }

    static func isUsingAuthsiaBuiltInAgent(
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) -> Bool {
        guard let socket = environment["SSH_AUTH_SOCK"] else { return false }
        return (socket as NSString).standardizingPath.hasSuffix("/.authsia/agent.sock")
    }

    /// Adds a private key to the running ssh-agent.
    static func add(privateKey: String, passphrase: String?, keyName: String, ttlSeconds: Int) throws -> String {
        guard isAgentRunning() else {
            throw AgentError.noAgent
        }

        var env = ProcessInfo.processInfo.environment

        var helperPath: String?
        var readFD: Int32?
        if let passphrase {
            let (path, fd) = try createAskPassPipe(passphrase: passphrase)
            helperPath = path
            readFD = fd
            env["SSH_ASKPASS"] = path
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env["DISPLAY"] = env["DISPLAY"] ?? ":0"
        }

        defer {
            if let fd = readFD { close(fd) }
            if let path = helperPath {
                try? FileManager.default.removeItem(atPath: path)
            }
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-add")
        process.arguments = ["-t", String(ttlSeconds), "-"]
        process.environment = env

        let inputPipe = Pipe()
        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardInput = inputPipe
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        try process.run()
        inputPipe.fileHandleForWriting.write(Data(privateKey.utf8))
        inputPipe.fileHandleForWriting.closeFile()
        process.waitUntilExit()

        let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
        let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
        let combined = String(data: outputData + errorData, encoding: .utf8) ?? ""

        guard process.terminationStatus == 0 else {
            throw AgentError.addFailed(combined.trimmingCharacters(in: .whitespacesAndNewlines))
        }

        return formatAddResult(
            output: combined.trimmingCharacters(in: .whitespacesAndNewlines),
            keyName: keyName
        )
    }

    // MARK: - Internal helpers (internal for testing)

    /// Legacy script builder — kept for backward-compatible tests.
    /// No longer used in production; `buildAskPassScript(fd:)` is used instead.
    @available(*, deprecated, message: "Use buildAskPassScript(fd:) instead — this variant embeds the passphrase on disk")
    static func buildAskPassScript(passphrase: String) -> String {
        let escaped = passphrase.replacingOccurrences(of: "'", with: "'\\''")
        return "#!/bin/sh\nprintf '%s' '\(escaped)'\n"
    }

    /// Generates an SSH_ASKPASS helper script that reads the passphrase from an
    /// inherited file descriptor rather than embedding it in the script body.
    static func buildAskPassScript(fd: Int32) -> String {
        return "#!/bin/sh\nread -r passphrase <&\(fd)\nprintf '%s' \"$passphrase\"\n"
    }

    /// Creates a socketpair, writes the passphrase to the write-end, and returns
    /// the helper-script path plus the read-end file descriptor.
    ///
    /// The helper script on disk contains **no passphrase** — only a `read <&N`
    /// instruction. The passphrase travels exclusively through the socketpair fd,
    /// which the child process inherits.
    static func createAskPassPipe(passphrase: String) throws -> (helperPath: String, readFD: Int32) {
        var fds: [Int32] = [0, 0]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else {
            throw AgentError.addFailed("Failed to create socketpair: \(String(cString: strerror(errno)))")
        }
        let readFD = fds[0]
        let writeFD = fds[1]

        // Write the passphrase to the write-end, then close it so the reader
        // gets EOF after the passphrase.
        let data = Array(passphrase.utf8)
        let written = data.withUnsafeBufferPointer { buffer -> Int in
            guard let base = buffer.baseAddress else { return 0 }
            return Darwin.write(writeFD, base, buffer.count)
        }
        close(writeFD)

        guard written == data.count else {
            close(readFD)
            throw AgentError.addFailed("Failed to write passphrase to pipe")
        }

        // Build a helper script that reads from the inherited fd — no passphrase on disk.
        let script = buildAskPassScript(fd: readFD)
        let tmp = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("authsia-askpass-\(UUID().uuidString).sh")
        try script.write(toFile: tmp, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: tmp)

        return (helperPath: tmp, readFD: readFD)
    }

    static func formatAddResult(output: String, keyName: String) -> String {
        if output.lowercased().contains("already") {
            return "Already loaded: \(keyName) (skipped)"
        }
        if output.hasPrefix("Identity added:") {
            return "Added identity: \(keyName)"
        }
        return output.isEmpty ? "Added identity: \(keyName)" : output
    }
}
