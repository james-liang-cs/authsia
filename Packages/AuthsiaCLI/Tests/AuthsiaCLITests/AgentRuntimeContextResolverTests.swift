import Foundation
import Testing
@testable import AuthenticatorBridge
@testable import authsia

@Suite("AgentRuntimeContextResolver")
struct AgentRuntimeContextResolverTests {
    @Test("platform-only markers preserve a matching hook sub-agent")
    func platformMarkerPreservesSubagent() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeEvents([record(
            id: "11111111-1111-1111-1111-111111111111", platform: "codex",
            agentType: "reviewer", workingDirectory: "/repo", invokesAuthsia: true,
            recordedAt: now.addingTimeInterval(-1), expiresAt: now.addingTimeInterval(20)
        )])
        defer { try? FileManager.default.removeItem(at: eventsURL.deletingLastPathComponent()) }
        let context = AgentRuntimeContextResolver.resolve(
            now: now, currentDirectoryPath: "/repo", processAncestry: codexAncestry,
            eventsURL: eventsURL,
            environment: ["AUTHSIA_AGENT_PLATFORM": "codex", "AUTHSIA_AGENT_INVOKES_AUTHSIA": "1"]
        )
        #expect(context?.agentID == "agent-1")
        #expect(context?.agentType == "reviewer")
    }

    @Test("explicit identity and mismatched platform markers do not claim another hook",
          arguments: [false, true])
    func explicitIdentityAndPlatformIsolation(hasIdentity: Bool) throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeEvents([record(
            id: "11111111-1111-1111-1111-111111111111", platform: "codex",
            agentType: "reviewer", workingDirectory: "/repo", invokesAuthsia: true,
            recordedAt: now.addingTimeInterval(-1), expiresAt: now.addingTimeInterval(20)
        )])
        defer { try? FileManager.default.removeItem(at: eventsURL.deletingLastPathComponent()) }
        var environment = ["AUTHSIA_AGENT_PLATFORM": hasIdentity ? "codex" : "claude-code",
                           "AUTHSIA_AGENT_INVOKES_AUTHSIA": "1"]
        if hasIdentity { environment["AUTHSIA_AGENT_ID"] = "explicit-agent" }
        let context = AgentRuntimeContextResolver.resolve(
            now: now, currentDirectoryPath: "/repo", processAncestry: codexAncestry,
            eventsURL: eventsURL, environment: environment
        )
        #expect(context?.agentID == (hasIdentity ? "explicit-agent" : nil))
        #expect(context?.agentType == nil)
        #expect(context?.platform == environment["AUTHSIA_AGENT_PLATFORM"])
    }

    @Test("process observations and post hooks do not compete with the calling pre hook")
    func onlyPreHookAttributesCaller() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("history.jsonl")
        let store = AgentCommandHistoryStore(fileURL: url)
        let now = Date()
        try store.record(AgentCommandEvent(
            recordedAt: now, agentPlatform: "codex", captureSource: .process,
            workingDirectory: "/repo", command: "authsia list"
        ))
        let command = try Agent.RecordCommand.parse(["--platform", "codex", "--source", "hook"])
        for phase in ["PreToolUse", "PostToolUse"] {
            let data = try JSONSerialization.data(withJSONObject: [
                "hook_event_name": phase, "tool_name": "Bash", "cwd": "/repo",
                "session_id": "session-1", "agent_id": "agent-1", "agent_type": "reviewer",
                "tool_use_id": "tool-1", "tool_input": ["command": "authsia list"],
            ])
            try command.run(store: store, stdinData: data)
        }
        let records = AgentRuntimeContextResolver.loadRecords(from: url)
        #expect(records.count == 1)
        let context = AgentRuntimeContextResolver.resolve(
            now: Date(), currentDirectoryPath: "/repo", processAncestry: codexAncestry,
            eventsURL: url,
            environment: ["AUTHSIA_AGENT_PLATFORM": "codex", "AUTHSIA_AGENT_INVOKES_AUTHSIA": "1"]
        )
        #expect(context?.agentID == "agent-1")
        #expect(context?.attributionConfidence == .high)
    }

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

    @Test("resolver claims sequential records once each")
    func resolverClaimsSequentialRecordsOnceEach() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let first = record(
            id: "11111111-1111-1111-1111-111111111111",
            platform: "codex",
            agentType: "older",
            workingDirectory: "/repo",
            command: "authsia list",
            recordedAt: now.addingTimeInterval(-10),
            expiresAt: now.addingTimeInterval(20)
        )
        let second = record(
            id: "22222222-2222-2222-2222-222222222222",
            platform: "codex",
            agentType: "reviewer",
            workingDirectory: "/repo",
            command: "authsia exec password API_KEY -- printenv API_KEY",
            recordedAt: now.addingTimeInterval(-2),
            expiresAt: now.addingTimeInterval(20)
        )
        let eventsURL = try writeEvents([first])

        let firstContext = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo",
            processAncestry: codexAncestry,
            eventsURL: eventsURL,
            claimOwner: 100
        )
        try writeEvents([first, second], to: eventsURL)
        let secondContext = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo",
            processAncestry: codexAncestry,
            eventsURL: eventsURL,
            claimOwner: 200
        )

        #expect(firstContext?.agentType == "older")
        #expect(firstContext?.attributionConfidence == .high)
        #expect(secondContext?.agentType == "reviewer")
        #expect(secondContext?.attributionConfidence == .high)
    }

    @Test("resolver marks concurrent records ambiguous")
    func resolverMarksConcurrentRecordsAmbiguous() throws {
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
            record(
                id: "33333333-3333-3333-3333-333333333333",
                platform: "codex",
                agentType: "plan",
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
            eventsURL: eventsURL,
            claimOwner: 100
        )

        #expect(context?.platform == "codex")
        #expect(context?.agentType == nil)
        #expect(context?.attributionConfidence == .ambiguous)
        let claimsURL = eventsURL.deletingPathExtension().appendingPathExtension("claimed.json")
        #expect(!FileManager.default.fileExists(atPath: claimsURL.path))
    }

    @Test("resolver reuses a claim for the same process")
    func resolverReusesClaimForSameProcess() throws {
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

        let first = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo",
            processAncestry: codexAncestry,
            eventsURL: eventsURL,
            claimOwner: 100
        )
        let second = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo",
            processAncestry: codexAncestry,
            eventsURL: eventsURL,
            claimOwner: 100
        )

        #expect(first?.agentType == "reviewer")
        #expect(second?.agentType == "reviewer")
        #expect(first == second)
    }

    @Test("resolver ignores records outside the attribution TTL")
    func resolverIgnoresRecordsOutsideAttributionTTL() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeEvents([
            record(
                id: "11111111-1111-1111-1111-111111111111",
                platform: "codex",
                agentType: "expired",
                workingDirectory: "/repo",
                command: "authsia list",
                recordedAt: now.addingTimeInterval(-6 * 60),
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

    @Test("resolver reads AUTHSIA_HOOK_CONTEXT_PATH as a fallback source")
    func resolverReadsHookContextPathOverride() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let primary = try writeEvents([])
        let hookURL = try writeEvents([
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
            eventsURL: primary,
            environment: [AgentRuntimeContextResolver.environmentHookContextPathKey: hookURL.path],
            claimOwner: 100
        )

        #expect(context?.agentType == "reviewer")
    }

    @Test("resolver claims a contested record for exactly one process")
    func resolverClaimsContestedRecordOnce() throws {
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
        let ancestry = codexAncestry
        let exact = Locked(0)

        DispatchQueue.concurrentPerform(iterations: 16) { index in
            let context = AgentRuntimeContextResolver.resolve(
                now: now,
                currentDirectoryPath: "/repo",
                processAncestry: ancestry,
                eventsURL: eventsURL,
                environment: [:],
                claimOwner: pid_t(100 + index)
            )
            if context?.attributionConfidence == .high {
                exact.increment()
            }
        }

        #expect(exact.value == 1)
    }

    @Test("resolver keeps a claim another workspace's process holds")
    func resolverKeepsClaimFromAnotherWorkspace() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeEvents([
            record(
                id: "11111111-1111-1111-1111-111111111111",
                platform: "codex",
                agentType: "reviewer",
                workingDirectory: "/repo-a",
                command: "authsia list",
                recordedAt: now.addingTimeInterval(-1),
                expiresAt: now.addingTimeInterval(20)
            ),
            record(
                id: "22222222-2222-2222-2222-222222222222",
                platform: "codex",
                agentType: "planner",
                workingDirectory: "/repo-b",
                command: "authsia list",
                recordedAt: now.addingTimeInterval(-1),
                expiresAt: now.addingTimeInterval(20)
            ),
        ])

        let owner = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo-a",
            processAncestry: codexAncestry,
            eventsURL: eventsURL,
            environment: [:],
            claimOwner: 100
        )
        // A process in another workspace filters /repo-a out of its candidates. Pruning claims
        // against that filtered set would release the claim pid 100 still holds.
        let neighbour = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo-b",
            processAncestry: codexAncestry,
            eventsURL: eventsURL,
            environment: [:],
            claimOwner: 200
        )
        let latecomer = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo-a",
            processAncestry: codexAncestry,
            eventsURL: eventsURL,
            environment: [:],
            claimOwner: 300
        )

        #expect(owner?.agentType == "reviewer")
        #expect(neighbour?.agentType == "planner")
        #expect(latecomer == nil)
    }

    @Test("resolver will not claim a record older than the claim freshness window")
    func resolverDoesNotClaimStaleRecord() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeEvents([
            record(
                id: "11111111-1111-1111-1111-111111111111",
                platform: "codex",
                agentType: "reviewer",
                workingDirectory: "/repo",
                command: "authsia list",
                recordedAt: now.addingTimeInterval(-90),
                expiresAt: now.addingTimeInterval(20)
            ),
        ])

        let context = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo",
            processAncestry: codexAncestry,
            eventsURL: eventsURL,
            environment: [:],
            claimOwner: 100
        )

        #expect(context?.platform == "codex")
        #expect(context?.agentType == nil)
        #expect(context?.attributionConfidence == .ambiguous)
    }

    @Test("resolver hides the platform when unclaimed records disagree")
    func resolverHidesPlatformWhenAmbiguousAcrossPlatforms() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeEvents([
            record(
                id: "11111111-1111-1111-1111-111111111111",
                platform: "vscode",
                agentType: "editor",
                workingDirectory: "/repo",
                command: "authsia list",
                recordedAt: now.addingTimeInterval(-2),
                expiresAt: now.addingTimeInterval(20)
            ),
            record(
                id: "22222222-2222-2222-2222-222222222222",
                platform: "copilot",
                agentType: "agent",
                workingDirectory: "/repo",
                command: "authsia list",
                recordedAt: now.addingTimeInterval(-1),
                expiresAt: now.addingTimeInterval(20)
            ),
        ])

        let context = AgentRuntimeContextResolver.resolve(
            now: now,
            currentDirectoryPath: "/repo",
            processAncestry: vscodeAncestry,
            eventsURL: eventsURL,
            environment: [:],
            claimOwner: 100
        )

        #expect(context?.attributionConfidence == .ambiguous)
        #expect(context?.platform == nil)
    }

    private final class Locked: @unchecked Sendable {
        private let lock = NSLock()
        private var count: Int

        init(_ count: Int) {
            self.count = count
        }

        var value: Int {
            lock.withLock { count }
        }

        func increment() {
            lock.withLock { count += 1 }
        }
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
