import Foundation
import Testing
@testable import AuthenticatorBridge
@testable import authsia

@Suite("AgentRuntimeContextResolver")
struct AgentRuntimeContextResolverTests {
    @Test("resolver returns newest unexpired cwd-matching authsia hook record")
    func resolverReturnsNewestMatchingRecord() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeEvents([
            record(
                id: "11111111-1111-1111-1111-111111111111",
                platform: "codex",
                agentType: "older",
                workingDirectory: "/repo",
                command: "authsia list",
                recordedAt: now.addingTimeInterval(-10),
                expiresAt: now.addingTimeInterval(20)
            ),
            record(
                id: "22222222-2222-2222-2222-222222222222",
                platform: "codex",
                agentType: "reviewer",
                workingDirectory: "/repo",
                command: "authsia exec password API_KEY -- printenv API_KEY",
                recordedAt: now.addingTimeInterval(-2),
                expiresAt: now.addingTimeInterval(20)
            ),
        ])

        let context = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo",
            processAncestry: codexAncestry,
            eventsURL: eventsURL
        )

        #expect(context?.platform == "codex")
        #expect(context?.agentType == "reviewer")
    }

    @Test("resolver ignores expired records")
    func resolverIgnoresExpiredRecords() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeEvents([
            record(
                id: "11111111-1111-1111-1111-111111111111",
                platform: "codex",
                agentType: "expired",
                workingDirectory: "/repo",
                command: "authsia list",
                recordedAt: now.addingTimeInterval(-60),
                expiresAt: now.addingTimeInterval(-1)
            ),
        ])

        let context = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo",
            processAncestry: codexAncestry,
            eventsURL: eventsURL
        )

        #expect(context == nil)
    }

    @Test("resolver ignores records for another cwd")
    func resolverIgnoresAnotherWorkingDirectory() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeEvents([
            record(
                id: "11111111-1111-1111-1111-111111111111",
                platform: "codex",
                agentType: "reviewer",
                workingDirectory: "/other",
                command: "authsia list",
                recordedAt: now.addingTimeInterval(-1),
                expiresAt: now.addingTimeInterval(20)
            ),
        ])

        let context = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo",
            processAncestry: codexAncestry,
            eventsURL: eventsURL
        )

        #expect(context == nil)
    }

    @Test("resolver ignores records without authsia command")
    func resolverIgnoresNonAuthsiaCommands() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeEvents([
            record(
                id: "11111111-1111-1111-1111-111111111111",
                platform: "codex",
                agentType: "reviewer",
                workingDirectory: "/repo",
                command: "npm test",
                recordedAt: now.addingTimeInterval(-1),
                expiresAt: now.addingTimeInterval(20)
            ),
        ])

        let context = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo",
            processAncestry: codexAncestry,
            eventsURL: eventsURL
        )

        #expect(context == nil)
    }

    @Test("resolver matches long authsia commands")
    func resolverMatchesLongAuthsiaCommands() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let longPrefix = String(repeating: "SAFE_", count: 40)
        let eventsURL = try writeEvents([
            record(
                id: "11111111-1111-1111-1111-111111111111",
                platform: "codex",
                agentType: "reviewer",
                workingDirectory: "/repo",
                command: "\(longPrefix) authsia list passwords",
                recordedAt: now.addingTimeInterval(-1),
                expiresAt: now.addingTimeInterval(20)
            ),
        ])

        let context = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo",
            processAncestry: codexAncestry,
            eventsURL: eventsURL
        )

        #expect(context?.agentType == "reviewer")
    }

    @Test("resolver prefers platform-compatible records")
    func resolverPrefersPlatformCompatibleRecords() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeEvents([
            record(
                id: "11111111-1111-1111-1111-111111111111",
                platform: "claude-code",
                agentType: "claude-agent",
                workingDirectory: "/repo",
                command: "authsia list",
                recordedAt: now.addingTimeInterval(-1),
                expiresAt: now.addingTimeInterval(20)
            ),
            record(
                id: "22222222-2222-2222-2222-222222222222",
                platform: "codex",
                agentType: "codex-agent",
                workingDirectory: "/repo",
                command: "authsia list",
                recordedAt: now.addingTimeInterval(-5),
                expiresAt: now.addingTimeInterval(20)
            ),
        ])

        let context = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo",
            processAncestry: codexAncestry,
            eventsURL: eventsURL
        )

        #expect(context?.platform == "codex")
        #expect(context?.agentType == "codex-agent")
    }

    @Test("resolver ignores hook records when ancestry is not agentic")
    func resolverIgnoresRecordsWithoutAgenticAncestry() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeEvents([
            record(
                id: "11111111-1111-1111-1111-111111111111",
                platform: "codex",
                agentType: "reviewer",
                workingDirectory: "/repo",
                command: "authsia list",
                recordedAt: now.addingTimeInterval(-1),
                expiresAt: now.addingTimeInterval(20)
            ),
        ])

        let context = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo",
            processAncestry: [
                AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
                AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
                AgenticProcessReference(processName: "Terminal", bundleIdentifier: "com.apple.Terminal"),
            ],
            eventsURL: eventsURL
        )

        #expect(context == nil)
    }

    @Test("resolver ignores records for another detected agent platform")
    func resolverIgnoresMismatchedAgentPlatform() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeEvents([
            record(
                id: "11111111-1111-1111-1111-111111111111",
                platform: "claude-code",
                agentType: "claude-agent",
                workingDirectory: "/repo",
                command: "authsia list",
                recordedAt: now.addingTimeInterval(-1),
                expiresAt: now.addingTimeInterval(20)
            ),
        ])

        let context = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo",
            processAncestry: codexAncestry,
            eventsURL: eventsURL
        )

        #expect(context == nil)
    }

    @Test("resolver accepts privacy-preserving authsia invocation markers")
    func resolverAcceptsAuthsiaInvocationMarkers() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeEvents([
            record(
                id: "11111111-1111-1111-1111-111111111111",
                platform: "codex",
                agentType: "reviewer",
                workingDirectory: "/repo",
                command: nil,
                invokesAuthsia: true,
                recordedAt: now.addingTimeInterval(-1),
                expiresAt: now.addingTimeInterval(20)
            ),
        ])

        let context = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo",
            processAncestry: codexAncestry,
            eventsURL: eventsURL
        )

        #expect(context?.platform == "codex")
        #expect(context?.agentType == "reviewer")
    }

    @Test("resolver accepts explicit agent environment marker without an event record")
    func resolverAcceptsExplicitAgentEnvironmentMarker() throws {
        let context = AgentRuntimeContextResolver.resolve(
            now: Date(timeIntervalSince1970: 1_000),
            currentDirectoryPath: "/repo",
            processAncestry: humanTerminalAncestry,
            eventsURL: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString),
            environment: [
                AgentRuntimeContextResolver.environmentPlatformKey: "copilot",
                AgentRuntimeContextResolver.environmentInvokesAuthsiaKey: "1",
                AgentRuntimeContextResolver.environmentAgentTypeKey: "default-chat",
                AgentRuntimeContextResolver.environmentToolUseIDKey: "tool-1",
            ]
        )

        #expect(context?.platform == "copilot")
        #expect(context?.agentType == "default-chat")
        #expect(context?.toolUseID == "tool-1")
    }

    @Test("resolver ignores explicit agent environment marker without invocation opt in")
    func resolverIgnoresExplicitAgentEnvironmentMarkerWithoutInvocationOptIn() throws {
        let context = AgentRuntimeContextResolver.resolve(
            now: Date(timeIntervalSince1970: 1_000),
            currentDirectoryPath: "/repo",
            processAncestry: humanTerminalAncestry,
            eventsURL: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString),
            environment: [
                AgentRuntimeContextResolver.environmentPlatformKey: "copilot",
            ]
        )

        #expect(context == nil)
    }

    @Test("resolver accepts VS Code runtime context when ancestry matches VS Code")
    func resolverAcceptsVSCodeRuntimeContext() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeEvents([
            record(
                id: "11111111-1111-1111-1111-111111111111",
                platform: "vscode",
                agentType: "chat",
                workingDirectory: "/repo",
                command: nil,
                invokesAuthsia: true,
                recordedAt: now.addingTimeInterval(-1),
                expiresAt: now.addingTimeInterval(20)
            ),
        ])

        let context = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo",
            processAncestry: vscodeAncestry,
            eventsURL: eventsURL
        )

        #expect(context?.platform == "vscode")
        #expect(context?.agentType == "chat")
    }

    @Test("resolver accepts Copilot runtime context when ancestry matches VS Code")
    func resolverAcceptsCopilotRuntimeContextThroughVSCode() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeEvents([
            record(
                id: "11111111-1111-1111-1111-111111111111",
                platform: "copilot",
                agentType: "default-chat",
                workingDirectory: "/repo",
                command: nil,
                invokesAuthsia: true,
                recordedAt: now.addingTimeInterval(-1),
                expiresAt: now.addingTimeInterval(20)
            ),
        ])

        let context = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo",
            processAncestry: vscodeAncestry,
            eventsURL: eventsURL
        )

        #expect(context?.platform == "copilot")
        #expect(context?.agentType == "default-chat")
    }

    @Test("resolver sanitizes unsafe fields")
    func resolverSanitizesUnsafeFields() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeEvents([
            record(
                id: "11111111-1111-1111-1111-111111111111",
                platform: "codex",
                sessionID: "session-1\\nspoof",
                agentType: " reviewer ",
                workingDirectory: "/repo",
                command: "authsia list",
                recordedAt: now.addingTimeInterval(-1),
                expiresAt: now.addingTimeInterval(20)
            ),
        ])

        let context = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo",
            processAncestry: codexAncestry,
            eventsURL: eventsURL
        )

        #expect(context?.platform == "codex")
        #expect(context?.sessionID == nil)
        #expect(context?.agentType == "reviewer")
    }

    private var codexAncestry: [AgenticProcessReference] {
        [
            AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
            AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
            AgenticProcessReference(processName: "codex", bundleIdentifier: nil),
        ]
    }

    private var humanTerminalAncestry: [AgenticProcessReference] {
        [
            AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
            AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
            AgenticProcessReference(processName: "Terminal", bundleIdentifier: "com.apple.Terminal"),
        ]
    }

    private var vscodeAncestry: [AgenticProcessReference] {
        [
            AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
            AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
            AgenticProcessReference(
                processName: "Code Helper",
                bundleIdentifier: "com.microsoft.VSCode",
                arguments: [
                    "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper",
                    "--type=extensionHost",
                ]
            ),
        ]
    }

    private func writeEvents(_ events: [String]) throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-agent-context-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("events.jsonl")
        try events.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
        return url
    }

    private func record(
        id: String,
        platform: String,
        sessionID: String = "session-1",
        agentType: String,
        workingDirectory: String,
        command: String? = "authsia list",
        invokesAuthsia: Bool? = nil,
        recordedAt: Date,
        expiresAt: Date
    ) -> String {
        let formatter = ISO8601DateFormatter()
        var fields = [
            "\"id\":\"\(id)\"",
            "\"platform\":\"\(platform)\"",
            "\"sessionID\":\"\(sessionID)\"",
            "\"turnID\":\"turn-1\"",
            "\"agentID\":\"agent-1\"",
            "\"agentType\":\"\(agentType)\"",
            "\"toolUseID\":\"tool-1\"",
            "\"workingDirectory\":\"\(workingDirectory)\"",
            "\"recordedAt\":\"\(formatter.string(from: recordedAt))\"",
            "\"expiresAt\":\"\(formatter.string(from: expiresAt))\"",
        ]
        if let command {
            fields.append("\"command\":\"\(command)\"")
        }
        if let invokesAuthsia {
            fields.append("\"invokesAuthsia\":\(invokesAuthsia)")
        }
        return "{\(fields.joined(separator: ","))}"
    }
}
