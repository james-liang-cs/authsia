import Foundation
import Testing
@testable import authsia

@Suite("Codex hook trust")
struct CodexHookTrustInstallerTests {
    private let root = URL(fileURLWithPath: "/tmp/authsia-synthetic-project")

    @Test("An older CLI without the hooks API falls back to another installed CLI")
    func unsupportedCLIFallback() throws {
        let candidates = [root.appendingPathComponent("old-codex"), root.appendingPathComponent("current-codex")]
        var attempts: [URL] = []
        try CodexHookTrustInstaller.install(using: candidates) { binary in
            attempts.append(binary)
            if binary == candidates[0] { throw CodexHookTrustInstaller.Failure.unsupportedAPI }
        }
        #expect(attempts == candidates)
        attempts = []
        #expect(throws: CodexHookTrustInstaller.Failure.incompleteHooks) {
            try CodexHookTrustInstaller.install(using: candidates) { binary in
                attempts.append(binary)
                throw CodexHookTrustInstaller.Failure.incompleteHooks
            }
        }
        #expect(attempts == [candidates[0]])
    }

    private func hooks(trusted: Bool = false) -> [[String: Any]] {
        ["preToolUse", "subagentStart", "subagentStop"].map { event in
            var hook: [String: Any] = [
                "key": root.path + "/.codex/hooks.json:" + event + ":0:0",
                "sourcePath": root.path + "/.codex/hooks.json", "source": "project",
                "eventName": event, "handlerType": "command", "enabled": true,
                "isManaged": false, "async": false, "timeoutSec": 5,
                "command": event == "preToolUse"
                    ? "authsia agent record-command --platform codex --source hook"
                    : "authsia agent record-lineage --platform codex",
                "currentHash": "sha256:" + String(repeating: "a", count: 64),
                "trustStatus": trusted ? "trusted" : "untrusted"
            ]
            if event == "preToolUse" { hook["matcher"] = "^Bash$" }
            return hook
        }
    }

    private func response(_ hooks: [[String: Any]]) -> [String: Any] {
        ["data": [["cwd": root.path, "errors": [], "hooks": hooks]]]
    }

    @Test("Trust writes only exact Authsia entries and verifies current hashes")
    func targetedTrust() throws {
        var methods: [String] = []
        var unrelated = hooks()[0]
        unrelated["command"] = "echo unrelated"
        unrelated["key"] = "unrelated"
        try CodexHookTrustInstaller.install(projectRoot: root) { method, params in
            methods.append(method)
            if method == "config/batchWrite" {
                let edits = try #require(params["edits"] as? [[String: Any]])
                #expect(edits.count == 3)
                for edit in edits {
                    let key = try #require(edit["keyPath"] as? String)
                    #expect(key.hasPrefix("hooks.state.\"/tmp/authsia-synthetic-project/.codex/hooks.json:"))
                    #expect(key.hasSuffix("\".trusted_hash"))
                    #expect(edit["value"] as? String == "sha256:" + String(repeating: "a", count: 64))
                    #expect(edit["mergeStrategy"] as? String == "replace")
                }
                return [:]
            }
            return response(hooks(trusted: methods.count == 3) + [unrelated])
        }
        #expect(methods == ["hooks/list", "config/batchWrite", "hooks/list"])
    }

    @Test("Already trusted hooks do not rewrite configuration")
    func idempotent() throws {
        try CodexHookTrustInstaller.install(projectRoot: root) { method, _ in
            #expect(method == "hooks/list")
            return response(hooks(trusted: true))
        }
    }

    @Test("Older hook metadata triggers compatibility fallback without writing trust")
    func olderMetadata() throws {
        var values = hooks()
        values[0].removeValue(forKey: "async")
        #expect(throws: CodexHookTrustInstaller.Failure.unsupportedAPI) {
            try CodexHookTrustInstaller.install(projectRoot: root) { method, _ in
                #expect(method == "hooks/list")
                return response(values)
            }
        }
    }

    @Test("Modified, disabled, managed, foreign, duplicate, or missing hooks are not enrolled",
          arguments: ["command", "matcher", "enabled", "isManaged", "sourcePath", "async", "timeoutSec", "duplicate", "missing", "hash"])
    func rejectsUnsafeOrIncompleteHooks(change: String) throws {
        var values = hooks()
        switch change {
        case "command": values[0][change] = "authsia agent record-command --platform codex --source hook; echo unexpected"
        case "matcher": values[0][change] = ".*"
        case "enabled": values[0][change] = false
        case "isManaged", "async": values[0][change] = true
        case "sourcePath": values[0][change] = "/tmp/other/.codex/hooks.json"
        case "timeoutSec": values[0][change] = 60
        case "duplicate": values.append(values[0])
        case "missing": values.removeLast()
        default: values[0]["currentHash"] = "invalid"
        }
        #expect(throws: (any Error).self) {
            try CodexHookTrustInstaller.install(projectRoot: root) { method, _ in
                #expect(method == "hooks/list")
                return response(values)
            }
        }
    }

    @Test("A changed hook after write is not reported as verified")
    func rejectsChangedHash() throws {
        var calls = 0
        #expect(throws: CodexHookTrustInstaller.Failure.verificationFailed) {
            try CodexHookTrustInstaller.install(projectRoot: root) { method, _ in
                calls += 1
                if method == "config/batchWrite" { return [:] }
                var values = hooks(trusted: calls == 3)
                if calls == 3 { values[0]["currentHash"] = "sha256:" + String(repeating: "b", count: 64) }
                return response(values)
            }
        }
    }

    @Test("Rule installation installs hooks before trust and skips trust in dry runs")
    func installIntegration() throws {
        let project = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: project, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: project) }
        var calls = 0
        let trust: (URL) throws -> Void = { url in
            calls += 1
            #expect(FileManager.default.fileExists(atPath: url.appendingPathComponent("AGENTS.md").path))
            #expect(FileManager.default.fileExists(atPath: url.appendingPathComponent(".codex/hooks.json").path))
        }
        _ = try AgentRuleInstaller.install(projectRoot: project, agents: [.codex], dryRun: true, trustCodexHooks: trust)
        #expect(calls == 0)
        let result = try AgentRuleInstaller.install(projectRoot: project, agents: [.codex], trustCodexHooks: trust)
        #expect(calls == 1)
        #expect(AgentRuleInstaller.renderResult(result).contains("installed and trusted"))
        let failed = try AgentRuleInstaller.install(projectRoot: project, agents: [.codex], trustCodexHooks: { _ in
            throw CodexHookTrustInstaller.Failure.unavailable
        })
        #expect(AgentRuleInstaller.renderResult(failed).contains("could not be verified"))
    }
}
