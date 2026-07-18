import Testing
import Foundation
@testable import AuthenticatorBridge
@testable import authsia

@Suite("BridgeContext")
struct BridgeContextTests {

    @Test("legacy JSON (no requestedCommand or workingDirectory) decodes as nil")
    func legacyDecodeTreatsFieldAsNil() throws {
        let legacyJSON = """
        {
          "isTTY": true,
          "isPiped": false,
          "isSSH": false,
          "isCI": false,
          "timestamp": "2026-04-01T00:00:00Z",
          "automationCredentialID": null,
          "automationScope": null
        }
        """
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let ctx = try decoder.decode(BridgeContext.self, from: Data(legacyJSON.utf8))
        #expect(ctx.requestedCommand == nil)
        #expect(ctx.fullCommand == nil)
        #expect(ctx.sessionScope == nil)
        #expect(ctx.workingDirectory == nil)
        #expect(ctx.agentRuntimeContext == nil)
        #expect(ctx.workspaceContext == nil)
    }

    @Test("legacy JSON without agent runtime context decodes nil")
    func legacyDecodeTreatsAgentRuntimeContextAsNil() throws {
        let legacyJSON = """
        {
          "isTTY": true,
          "isPiped": false,
          "isSSH": false,
          "isCI": false,
          "timestamp": "2026-04-01T00:00:00Z",
          "automationCredentialID": null,
          "automationScope": null,
          "requestedCommand": "exec",
          "sessionScope": "tty:/dev/ttys001:sid:1001",
          "workingDirectory": "/repo"
        }
        """
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let ctx = try decoder.decode(BridgeContext.self, from: Data(legacyJSON.utf8))
        #expect(ctx.agentRuntimeContext == nil)
        #expect(ctx.fullCommand == nil)
        #expect(ctx.workspaceContext == nil)
    }

    @Test("explicit requestedCommand, sessionScope, and workingDirectory round-trip")
    func requestedCommandSessionScopeAndWorkingDirectoryRoundTrip() throws {
        let original = BridgeContext(
            isTTY: true,
            isPiped: false,
            isSSH: false,
            isCI: false,
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            automationCredentialID: nil,
            automationScope: nil,
            requestedCommand: "exec",
            fullCommand: "authsia exec password SERVICE_ENDPOINT -- npm start",
            sessionScope: "tty:/dev/ttys001",
            workingDirectory: "/Users/example/project",
            agentRuntimeContext: AgentRuntimeContext(
                platform: "codex",
                sessionID: "session-1",
                turnID: "turn-1",
                agentID: "agent-1",
                agentType: "reviewer",
                toolUseID: "tool-1"
            )
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(original)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(BridgeContext.self, from: data)
        #expect(decoded.requestedCommand == "exec")
        #expect(decoded.fullCommand == "authsia exec password SERVICE_ENDPOINT -- npm start")
        #expect(decoded.sessionScope == "tty:/dev/ttys001")
        #expect(decoded.workingDirectory == "/Users/example/project")
        #expect(decoded.agentRuntimeContext?.platform == "codex")
        #expect(decoded.agentRuntimeContext?.agentType == "reviewer")
        #expect(decoded.agentRuntimeContext?.toolUseID == "tool-1")
    }

    @Test("CLI context carries terminal session scope")
    func cliContextCarriesTerminalSessionScope() {
        let ctx = AutomationAccessResolver.bridgeContext(
            requestedCommand: "read",
            fullCommand: "authsia read password GitHub",
            environment: [:],
            terminalIdentifier: "/dev/ttys001",
            processSessionIdentifier: 1001
        )

        #expect(ctx.sessionScope == "tty:/dev/ttys001:sid:1001")
        #expect(ctx.fullCommand == "authsia read password GitHub")
    }

    @Test("CLI context resolves hook agent runtime context")
    func cliContextResolvesHookAgentRuntimeContext() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let eventsURL = try writeAgentContextEvents([
            agentContextRecord(
                platform: "codex",
                agentType: "reviewer",
                workingDirectory: "/repo",
                recordedAt: now.addingTimeInterval(-1),
                expiresAt: now.addingTimeInterval(20)
            ),
        ])

        let ctx = AutomationAccessResolver.bridgeContext(
            requestedCommand: "exec",
            environment: [:],
            now: now,
            terminalIdentifier: nil,
            processSessionIdentifier: nil,
            ancestralScope: { nil },
            currentDirectoryPath: "/repo",
            processAncestry: [
                AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
                AgenticProcessReference(processName: "codex", bundleIdentifier: nil),
            ],
            agentRuntimeContextEventsURL: eventsURL
        )

        #expect(ctx.agentRuntimeContext?.platform == "codex")
        #expect(ctx.agentRuntimeContext?.agentType == "reviewer")
    }

    @Test("CLI context carries workspace display context from current directory")
    func cliContextCarriesWorkspaceDisplayContextFromCurrentDirectory() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-workspace-context-\(UUID().uuidString)", isDirectory: true)
        let nested = root.appendingPathComponent("Sources/App", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        try WorkspaceConfigStore.write(
            WorkspaceConfig(
                workspace: WorkspaceConfig.Workspace(name: "selected-api", authsiaFolder: "Workspaces/selected-api"),
                managedEnvFiles: [".env"],
                agents: nil
            ),
            toWorkspaceRoot: root
        )

        let ctx = AutomationAccessResolver.bridgeContext(
            requestedCommand: "exec",
            environment: [:],
            terminalIdentifier: nil,
            processSessionIdentifier: nil,
            ancestralScope: { nil },
            currentDirectoryPath: nested.path,
            processAncestry: [
                AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
            ],
            agentRuntimeContextEventsURL: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        )

        #expect(ctx.workspaceContext?.name == "selected-api")
        #expect(ctx.workspaceContext?.rootLabel == root.lastPathComponent)
        #expect(ctx.workspaceContext?.authsiaFolder == "Workspaces/selected-api")
        #expect(ctx.workspaceContext?.displayName == "selected-api (\(root.lastPathComponent))")
        #expect(ctx.workspaceContext?.displayName.contains(root.path) == false)
    }

    @Test("CLI context resolves explicit agent environment marker")
    func cliContextResolvesExplicitAgentEnvironmentMarker() {
        let ctx = AutomationAccessResolver.bridgeContext(
            requestedCommand: "get",
            environment: [
                AgentRuntimeContextResolver.environmentPlatformKey: "copilot",
                AgentRuntimeContextResolver.environmentInvokesAuthsiaKey: "true",
                AgentRuntimeContextResolver.environmentAgentTypeKey: "default-chat",
            ],
            terminalIdentifier: nil,
            processSessionIdentifier: nil,
            ancestralScope: { nil },
            currentDirectoryPath: "/repo",
            processAncestry: [
                AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
                AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
                AgenticProcessReference(processName: "Code Helper", bundleIdentifier: nil),
            ],
            agentRuntimeContextEventsURL: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        )

        #expect(ctx.agentRuntimeContext?.platform == "copilot")
        #expect(ctx.agentRuntimeContext?.agentType == "default-chat")
    }

    @Test("explicit non-terminal agent context carries process-session scope")
    func explicitNonTerminalAgentContextCarriesProcessSessionScope() {
        let ctx = AutomationAccessResolver.bridgeContext(
            requestedCommand: "list",
            environment: [
                AgentRuntimeContextResolver.environmentPlatformKey: "codex",
                AgentRuntimeContextResolver.environmentInvokesAuthsiaKey: "1",
            ],
            terminalIdentifier: nil,
            processSessionIdentifier: 4242,
            ancestralScope: { nil },
            currentDirectoryPath: "/repo",
            processAncestry: [
                AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
                AgenticProcessReference(processName: "Codex", bundleIdentifier: nil),
            ],
            agentRuntimeContextEventsURL: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        )

        #expect(ctx.sessionScope == "agent:codex:sid:4242")
    }

    @Test("explicit agent marker does not scope automation credential")
    func explicitAgentMarkerDoesNotScopeAutomationCredential() {
        let ctx = AutomationAccessResolver.bridgeContext(
            requestedCommand: "list",
            environment: [
                AgentRuntimeContextResolver.environmentPlatformKey: "codex",
                AgentRuntimeContextResolver.environmentInvokesAuthsiaKey: "1",
                AutomationCredentialEnvironment.generalCredentialKey: UUID().uuidString,
            ],
            terminalIdentifier: nil,
            processSessionIdentifier: 4242,
            ancestralScope: { nil }
        )

        #expect(ctx.sessionScope == nil)
    }

    @Test("CLI context falls back to ancestor terminal scope")
    func cliContextFallsBackToAncestorTerminalScope() {
        let ctx = AutomationAccessResolver.bridgeContext(
            requestedCommand: "exec",
            environment: [:],
            terminalIdentifier: nil,
            processSessionIdentifier: nil,
            ancestralScope: { "tty:/dev/ttys004:sid:94228" }
        )

        #expect(ctx.sessionScope == "tty:/dev/ttys004:sid:94228")
    }

    @Test("automation context does not inherit ancestor terminal scope")
    func automationContextDoesNotInheritAncestorTerminalScope() {
        let ctx = AutomationAccessResolver.bridgeContext(
            requestedCommand: "exec",
            environment: [
                AutomationCredentialEnvironment.generalCredentialKey: UUID().uuidString,
            ],
            terminalIdentifier: nil,
            processSessionIdentifier: nil,
            ancestralScope: { "tty:/dev/ttys004:sid:94228" }
        )

        #expect(ctx.sessionScope == nil)
    }

    private func writeAgentContextEvents(_ events: [String]) throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-bridge-context-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("events.jsonl")
        try events.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
        return url
    }

    private func agentContextRecord(
        platform: String,
        agentType: String,
        workingDirectory: String,
        recordedAt: Date,
        expiresAt: Date
    ) -> String {
        let formatter = ISO8601DateFormatter()
        return """
        {"id":"11111111-1111-1111-1111-111111111111","platform":"\(platform)","sessionID":"session-1","turnID":"turn-1","agentID":"agent-1","agentType":"\(agentType)","toolUseID":"tool-1","workingDirectory":"\(workingDirectory)","command":"authsia list","recordedAt":"\(formatter.string(from: recordedAt))","expiresAt":"\(formatter.string(from: expiresAt))"}
        """
    }
}
