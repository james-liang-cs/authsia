import Foundation
import Testing
@testable import AuthenticatorBridge
@testable import authsia

@Suite("AgentRuntimeContextResolver")
struct AgentRuntimeContextResolverTests {
    @Test("loadRecords reuses cached records while file attributes are unchanged")
    func loadRecordsReusesCachedRecordsWhileAttributesUnchanged() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeEvents([
            record(
                id: "11111111-1111-1111-1111-111111111111",
                platform: "codex",
                agentType: "cached",
                workingDirectory: "/repo",
                command: "authsia list",
                recordedAt: now.addingTimeInterval(-2),
                expiresAt: now.addingTimeInterval(20)
            ),
        ])
        let attributes = try FileManager.default.attributesOfItem(atPath: eventsURL.path)
        let modificationDate = try #require(attributes[.modificationDate] as? Date)
        let originalData = try Data(contentsOf: eventsURL)

        let first = AgentRuntimeContextResolver.loadRecords(from: eventsURL)
        #expect(first.first?.agentType == "cached")

        // Overwrite with undecodable bytes of the same length and restore mtime.
        // A cache miss would re-read and return [], so equal non-empty results prove a hit.
        try Data(repeating: UInt8(ascii: "a"), count: originalData.count).write(to: eventsURL)
        try FileManager.default.setAttributes(
            [.modificationDate: modificationDate],
            ofItemAtPath: eventsURL.path
        )

        let second = AgentRuntimeContextResolver.loadRecords(from: eventsURL)
        #expect(second.first?.agentType == "cached")
        #expect(second == first)
    }

    @Test("loadRecords invalidates cache when the event file changes")
    func loadRecordsInvalidatesCacheWhenFileChanges() throws {
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
        ])

        #expect(AgentRuntimeContextResolver.loadRecords(from: eventsURL).count == 1)

        try writeEvents(
            [
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
                    agentType: "newer",
                    workingDirectory: "/repo",
                    command: "authsia list",
                    recordedAt: now.addingTimeInterval(-1),
                    expiresAt: now.addingTimeInterval(20)
                ),
            ],
            to: eventsURL
        )
        // Ensure mtime advances on fast filesystems.
        try FileManager.default.setAttributes(
            [.modificationDate: Date(timeIntervalSince1970: 2_000)],
            ofItemAtPath: eventsURL.path
        )

        let reloaded = AgentRuntimeContextResolver.loadRecords(from: eventsURL)
        #expect(reloaded.count == 2)
        #expect(reloaded.map(\.agentType) == ["older", "newer"])
    }

    @Test("loadRecords parses only records appended to a cached history file")
    func loadRecordsReadsAppendedTail() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let firstLine = record(
            id: "11111111-1111-1111-1111-111111111111",
            platform: "codex",
            agentType: "older",
            workingDirectory: "/repo",
            recordedAt: now.addingTimeInterval(-10),
            expiresAt: now.addingTimeInterval(20)
        )
        let secondLine = record(
            id: "22222222-2222-2222-2222-222222222222",
            platform: "codex",
            agentType: "newer",
            workingDirectory: "/repo",
            recordedAt: now.addingTimeInterval(-1),
            expiresAt: now.addingTimeInterval(20)
        )
        let eventsURL = try writeEvents([firstLine])

        #expect(AgentRuntimeContextResolver.loadRecords(from: eventsURL).count == 1)

        let handle = try FileHandle(forUpdating: eventsURL)
        defer { try? handle.close() }
        _ = try handle.seekToEnd()
        try handle.write(contentsOf: Data("\n\(secondLine)".utf8))
        try handle.seek(toOffset: 0)
        try handle.write(contentsOf: Data(repeating: UInt8(ascii: "a"), count: firstLine.utf8.count))

        let loaded = AgentRuntimeContextResolver.loadRecords(from: eventsURL)
        #expect(loaded.count == 2)
        #expect(loaded.map(\.agentType) == ["older", "newer"])
    }

    @Test("loadRecords parses byte newlines without requiring String splits")
    func loadRecordsParsesByteNewlines() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let line = record(
            id: "11111111-1111-1111-1111-111111111111",
            platform: "codex",
            agentType: "reviewer",
            workingDirectory: "/repo",
            command: "authsia list",
            recordedAt: now.addingTimeInterval(-1),
            expiresAt: now.addingTimeInterval(20)
        )
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-agent-context-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("events.jsonl")
        var data = Data(line.utf8)
        data.append(0x0A)
        data.append(contentsOf: line.utf8)
        data.append(0x0A)
        try data.write(to: url)

        let records = AgentRuntimeContextResolver.loadRecords(from: url)
        #expect(records.count == 2)
    }

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
        try writeEvents(events, to: url)
        return url
    }

    private func writeEvents(_ events: [String], to url: URL) throws {
        try events.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
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
