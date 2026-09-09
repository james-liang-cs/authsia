import Darwin
import Foundation

/// Enrolls only Authsia's exact generated hooks using hashes reported by Codex.
/// Project trust, disabled hooks, and unrelated hook trust remain user controlled.
enum CodexHookTrustInstaller {
    enum Failure: Error { case unavailable, unsupportedAPI, invalidResponse, incompleteHooks, verificationFailed }
    typealias Request = (String, [String: Any]) throws -> [String: Any]

    static func install(projectRoot: URL) throws {
        let environment = ProcessInfo.processInfo.environment
        let paths = (environment["PATH"] ?? "").split(separator: ":").map(String.init) +
            [FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin").path,
             "/opt/homebrew/bin", "/usr/local/bin"]
        var visited = Set<String>()
        let binaries = paths.map { URL(fileURLWithPath: $0).appendingPathComponent("codex").resolvingSymlinksInPath() }
            .filter { FileManager.default.isExecutableFile(atPath: $0.path) && visited.insert($0.path).inserted }
        try install(using: binaries) { binary in
            let client = try Client(projectRoot: projectRoot, binary: binary)
            defer { client.close() }
            try install(projectRoot: projectRoot, request: client.request)
        }
    }

    static func install(using binaries: [URL], attempt: (URL) throws -> Void) throws {
        for binary in binaries {
            do {
                try attempt(binary)
                return
            } catch Failure.unavailable {
                continue
            } catch Failure.unsupportedAPI {
                continue
            }
        }
        throw Failure.unavailable
    }

    static func install(projectRoot: URL, request: Request) throws {
        let root = projectRoot.standardizedFileURL.path
        func hooks() throws -> [[String: Any]] {
            let response = try request("hooks/list", ["cwds": [root]])
            guard let entries = response["data"] as? [[String: Any]],
                  let entry = entries.first(where: { $0["cwd"] as? String == root }),
                  let errors = entry["errors"] as? [Any], errors.isEmpty,
                  let all = entry["hooks"] as? [[String: Any]] else { throw Failure.invalidResponse }
            // Older Codex versions omit execution-mode metadata. Ask a newer
            // installed CLI instead of trusting a definition we cannot fully check.
            if all.contains(where: {
                ["\(root)/.codex/hooks.json", "\(root)/.codex/config.toml"].contains($0["sourcePath"] as? String ?? "") &&
                    $0["async"] == nil
            }) { throw Failure.unsupportedAPI }
            let matching = all.filter { isAuthsiaHook($0, root: root) }
            let preMatchers = matching.filter { $0["eventName"] as? String == "preToolUse" }
                .compactMap { $0["matcher"] as? String }
            guard matching.count == 4,
                  Set(preMatchers) == Set(["^Bash$", AgentRuleInstaller.mcpAttributionMatcher]),
                  Set(matching.compactMap { $0["eventName"] as? String }) ==
                    Set(["preToolUse", "subagentStart", "subagentStop"]) else { throw Failure.incompleteHooks }
            return matching
        }
        let before = try hooks()
        let edits = try before.filter { $0["trustStatus"] as? String != "trusted" }.map { hook -> [String: Any] in
            guard let key = hook["key"] as? String,
                  let hash = hook["currentHash"] as? String,
                  hash.range(of: "^sha256:[a-f0-9]{64}$", options: .regularExpression) != nil else {
                throw Failure.invalidResponse
            }
            // JSON string quoting is also valid for a TOML basic-string key segment.
            let quotedKey = String(decoding: try JSONSerialization.data(withJSONObject: key, options: [.fragmentsAllowed, .withoutEscapingSlashes]), as: UTF8.self)
            return ["keyPath": "hooks.state.\(quotedKey).trusted_hash", "value": hash, "mergeStrategy": "replace"]
        }
        guard !edits.isEmpty else { return }
        _ = try request("config/batchWrite", ["edits": edits])
        let after = try hooks()
        guard after.allSatisfy({ hook in
            hook["trustStatus"] as? String == "trusted" && before.contains {
                $0["key"] as? String == hook["key"] as? String &&
                $0["currentHash"] as? String == hook["currentHash"] as? String
            }
        }) else { throw Failure.verificationFailed }
    }

    private static func isAuthsiaHook(_ hook: [String: Any], root: String) -> Bool {
        guard let source = hook["sourcePath"] as? String,
              ["\(root)/.codex/hooks.json", "\(root)/.codex/config.toml"].contains(source),
              let key = hook["key"] as? String, key.hasPrefix(source + ":"),
              hook["source"] as? String == "project",
              hook["handlerType"] as? String == "command",
              hook["enabled"] as? Bool == true,
              hook["isManaged"] as? Bool == false,
              hook["async"] as? Bool == false,
              hook["timeoutSec"] as? Int == 5,
              hook["pluginId"] == nil || hook["pluginId"] is NSNull,
              hook["statusMessage"] == nil || hook["statusMessage"] is NSNull,
              hook["additionalContextLimit"] == nil || hook["additionalContextLimit"] is NSNull else { return false }
        switch hook["eventName"] as? String {
        case "preToolUse":
            return hook["command"] as? String == "authsia agent record-command --platform codex --source hook" &&
                ["^Bash$", AgentRuleInstaller.mcpAttributionMatcher].contains(hook["matcher"] as? String ?? "")
        case "subagentStart", "subagentStop":
            return hook["command"] as? String == "authsia agent record-lineage --platform codex" &&
                (hook["matcher"] == nil || hook["matcher"] is NSNull)
        default: return false
        }
    }

    /// A short-lived stdio connection: no threads, model requests, or tool execution.
    private final class Client {
        let process = Process()
        let input = Pipe()
        let output = Pipe()
        var buffer = Data()
        var nextID = 0
        let deadline = ProcessInfo.processInfo.systemUptime + 20

        init(projectRoot: URL, binary: URL) throws {
            process.executableURL = binary
            process.arguments = ["app-server"]
            process.currentDirectoryURL = projectRoot
            process.standardInput = input
            process.standardOutput = output
            process.standardError = FileHandle.nullDevice
            do {
                try process.run()
                _ = try request("initialize", [
                    "clientInfo": ["name": "authsia_hook_setup", "version": "1"],
                    "capabilities": ["experimentalApi": true]
                ])
            } catch {
                close()
                throw Failure.unavailable
            }
        }

        func close() {
            try? input.fileHandleForWriting.close()
            if process.isRunning { process.terminate() }
            try? output.fileHandleForReading.close()
        }

        func request(_ method: String, _ params: [String: Any]) throws -> [String: Any] {
            nextID += 1
            var data = try JSONSerialization.data(withJSONObject: ["id": nextID, "method": method, "params": params])
            data.append(10)
            try input.fileHandleForWriting.write(contentsOf: data)
            var totalBytes = 0
            while ProcessInfo.processInfo.systemUptime < deadline {
                while let newline = buffer.firstIndex(of: 10) {
                    let line = buffer.prefix(upTo: newline)
                    buffer.removeSubrange(...newline)
                    guard let response = try JSONSerialization.jsonObject(with: line) as? [String: Any] else {
                        throw Failure.invalidResponse
                    }
                    guard response["id"] as? Int == nextID else { continue }
                    if let error = response["error"] as? [String: Any], error["code"] as? Int == -32601 {
                        throw Failure.unsupportedAPI
                    }
                    guard response["error"] == nil, let result = response["result"] as? [String: Any] else {
                        throw Failure.invalidResponse
                    }
                    return result
                }
                var fd = pollfd(fd: output.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
                let ready = Darwin.poll(&fd, 1, 100)
                if ready < 0 { if errno == EINTR { continue }; throw Failure.unavailable }
                guard ready > 0 else { continue }
                var bytes = [UInt8](repeating: 0, count: 8192)
                let count = Darwin.read(fd.fd, &bytes, bytes.count)
                guard count > 0 else { throw Failure.unavailable }
                totalBytes += count
                guard totalBytes <= 4 * 1024 * 1024 else { throw Failure.invalidResponse }
                buffer.append(contentsOf: bytes.prefix(count))
            }
            throw Failure.unavailable
        }
    }
}
