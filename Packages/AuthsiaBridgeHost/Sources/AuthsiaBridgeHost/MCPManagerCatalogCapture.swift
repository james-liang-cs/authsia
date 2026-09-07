#if os(macOS)
import AuthenticatorBridge
import Darwin
import Foundation

/// Invokes the existing admission-gated CLI. Output is bounded in memory and
/// classified into fixed messages; child diagnostics never reach the browser.
public enum MCPManagerCatalogCapture {
    public static func blockReason(upstream: MCPUpstreamConfig, workspaceRoot: URL,
                                   observedEnvironmentCount: Int,
                                   path: String = ProcessInfo.processInfo.environment["PATH"] ?? "",
                                   home: URL = FileManager.default.homeDirectoryForCurrentUser) -> MCPManagementError? {
        guard upstream.requiresStdioPolicy else {
            guard let endpoint = upstream.url, (try? MCPLocalHTTPEndpointValidator.validate(endpoint)) != nil else {
                return .invalidRequest
            }
            return nil
        }
        guard upstream.env.isEmpty, observedEnvironmentCount == 0 else { return .catalogEnvironmentRequired }
        guard let command = upstream.command, !command.isEmpty else { return .catalogExecutableMissing }
        let candidates: [URL]
        if command.contains("/") {
            let root = workspaceRoot.resolvingSymlinksInPath().standardizedFileURL
            let candidate = root.appendingPathComponent(command).resolvingSymlinksInPath().standardizedFileURL
            guard candidate.path.hasPrefix(root.path + "/") else { return .catalogExecutableMissing }
            candidates = [candidate]
        } else {
            candidates = MCPProxyPathOverlay.searchPath(path: path, homeDirectory: home).split(separator: ":")
                .map { URL(fileURLWithPath: String($0)).appendingPathComponent(command) }
        }
        let available = candidates.contains { candidate in
            var directory: ObjCBool = false
            return FileManager.default.fileExists(atPath: candidate.path, isDirectory: &directory)
                && !directory.boolValue && FileManager.default.isExecutableFile(atPath: candidate.path)
        }
        return available ? nil : .catalogExecutableMissing
    }

    public static func run(cli: URL, serverName: String, workspace: URL, timeout: TimeInterval = 180,
                           environment: [String: String] = ProcessInfo.processInfo.environment,
                           home: URL = FileManager.default.homeDirectoryForCurrentUser) throws {
        let process = Process(), errors = Pipe()
        process.executableURL = cli
        process.arguments = ["mcp", "catalog", "--server", serverName, "--workspace", workspace.path, "--write"]
        process.currentDirectoryURL = workspace
        var helperEnvironment = environment
        helperEnvironment["PATH"] = MCPProxyPathOverlay.searchPath(
            path: environment["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin", homeDirectory: home)
        process.environment = helperEnvironment
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errors
        let fd = errors.fileHandleForReading.fileDescriptor
        defer { try? errors.fileHandleForReading.close(); try? errors.fileHandleForWriting.close() }
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw MCPManagementError.catalogHelperUnavailable }
        do { try process.run() } catch { throw MCPManagementError.catalogHelperUnavailable }
        var diagnostics = Data(), buffer = [UInt8](repeating: 0, count: 4096)
        func drain() {
            // Bound each drain as well as retention so a noisy child cannot
            // starve the timeout check. Never persist these bytes.
            for _ in 0..<16 {
                let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!, $0.count) }
                guard count > 0 else { break }
                diagnostics.append(contentsOf: buffer.prefix(count))
                if diagnostics.count > 65_536 { diagnostics.removeFirst(diagnostics.count - 65_536) }
            }
        }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        var terminated = false
        while process.isRunning {
            drain()
            let now = ProcessInfo.processInfo.systemUptime
            if now >= deadline, !terminated { terminated = true; process.terminate() }
            if now >= deadline + 2, process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
            Thread.sleep(forTimeInterval: 0.02)
        }
        process.waitUntilExit(); drain()
        if terminated { throw MCPManagementError.catalogTimedOut }
        guard process.terminationStatus == 0 else { throw failure(diagnostics) }
    }

    public static func failure(_ diagnostics: Data) -> MCPManagementError {
        let text = String(decoding: diagnostics.suffix(65_536), as: UTF8.self).lowercased()
        if text.contains("mcp integrations is off") { return .catalogAccessDisabled }
        if text.contains("declares environment values") { return .catalogEnvironmentRequired }
        if text.contains("advertised no tools") { return .catalogEmpty }
        // Unknown output also maps to this fixed, actionable message. Never
        // reflect arbitrary upstream output or its last line into the portal.
        return .catalogStartupFailed
    }
}
#endif
