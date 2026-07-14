import Testing
import Foundation
import AuthenticatorBridge
@testable import authsia

@Suite("Audit command")
struct AuditCommandTests {

    @Test("loadEvents deduplicates and sorts newest first")
    func loadEventsDeduplicatesAndSortsNewestFirst() throws {
        let older = makeEvent(
            command: .getPassword,
            itemId: "item-1",
            itemName: "Old Secret",
            approvedBy: "biometric",
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            entryHash: "hash-older",
            previousHash: nil
        )
        let newer = makeEvent(
            command: .exportAccounts,
            itemId: "all-accounts",
            itemName: "All Accounts",
            approvedBy: "session",
            timestamp: Date(timeIntervalSince1970: 1_700_000_060),
            entryHash: "hash-newer",
            previousHash: "hash-older"
        )

        let firstLog = try writeAuditLog([older, newer])
        let secondLog = try writeAuditLog([newer])
        defer {
            try? FileManager.default.removeItem(at: firstLog)
            try? FileManager.default.removeItem(at: secondLog)
        }

        let events = try Audit.loadEvents(from: [firstLog, secondLog])

        #expect(events.count == 2)
        #expect(events.first?.entryHash == "hash-newer")
        #expect(events.last?.entryHash == "hash-older")
    }

    @Test("loadEvents skips unreadable fallback when another log is valid")
    func loadEventsSkipsUnreadableFallback() throws {
        let valid = makeEvent(
            command: .getPassword,
            itemId: "item-1",
            itemName: "Primary Secret",
            approvedBy: "biometric",
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            entryHash: "hash-valid",
            previousHash: nil
        )

        let validLog = try writeAuditLog([valid])
        let directoryURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("audit-dir-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: validLog)
            try? FileManager.default.removeItem(at: directoryURL)
        }

        let events = try Audit.loadEvents(from: [validLog, directoryURL])

        #expect(events.count == 1)
        #expect(events.first?.entryHash == "hash-valid")
    }

    @Test("loadEvents throws when a log contains malformed entries")
    func loadEventsThrowsOnMalformedEntry() throws {
        let valid = makeEvent(
            command: .getPassword,
            itemId: "item-1",
            itemName: "Primary Secret",
            approvedBy: "biometric",
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            entryHash: "hash-valid",
            previousHash: nil
        )

        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("audit-corrupt-\(UUID().uuidString).log")
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let validData = try encoder.encode(valid)
        let corruptData = Data("not-json".utf8)
        let payload = [validData, corruptData].joined(with: Data([0x0A]))
        try payload.write(to: url, options: .atomic)
        defer { try? FileManager.default.removeItem(at: url) }

        #expect(throws: (any Error).self) {
            try Audit.loadEvents(from: [url])
        }
    }

    @Test("renderList json returns structured events")
    func renderListJSONReturnsStructuredEvents() throws {
        let events = sampleEvents()

        let output = try AuditFormatter.formatList(events, format: .json)
        let decoded = try auditDecoder().decode([AuditEvent].self, from: Data(output.utf8))

        #expect(decoded.count == 2)
        #expect(decoded.first?.entryHash == "hash-newer")
        #expect(decoded.last?.entryHash == "hash-older")
    }

    @Test("renderList table includes useful headers and values")
    func renderListTableIncludesHeadersAndValues() throws {
        let events = sampleEvents()

        let output = try AuditFormatter.formatList(events, format: .table)

        #expect(output.contains("Timestamp"))
        #expect(output.contains("Command"))
        #expect(output.contains("Item"))
        #expect(output.contains("getPassword"))
        #expect(output.contains("All Accounts"))
    }

    @Test("renderList table shows newest event at bottom")
    func renderListTableShowsNewestEventAtBottom() throws {
        let output = try Audit.renderList(events: sampleEvents(), format: .table)

        let olderRange = try #require(output.range(of: "Old Secret"))
        let newerRange = try #require(output.range(of: "All Accounts"))
        #expect(olderRange.lowerBound < newerRange.lowerBound)
    }

    @Test("renderList JSON shows newest event last")
    func renderListJSONShowsNewestEventLast() throws {
        let output = try Audit.renderList(events: sampleEvents(), format: .json)
        let decoded = try auditDecoder().decode([AuditEvent].self, from: Data(output.utf8))

        #expect(decoded.first?.entryHash == "hash-older")
        #expect(decoded.last?.entryHash == "hash-newer")
    }

    @Test("renderList table shows requested CLI command")
    func renderListTableShowsRequestedCLICommand() throws {
        let event = makeEvent(
            command: .getPassword,
            itemId: "item-1",
            itemName: "API Key",
            approvedBy: "session",
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            entryHash: "hash-exec",
            previousHash: nil,
            requestedCommand: "exec"
        )

        let output = try AuditFormatter.formatList([event], format: .table)

        #expect(output.contains("exec"))
    }

    @Test("renderList table shows vault automation approval")
    func renderListTableShowsVaultAutomationApproval() throws {
        let event = makeEvent(
            command: .getPassword,
            itemId: "item-1",
            itemName: "API Key",
            approvedBy: "automation",
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            entryHash: "hash-automation",
            previousHash: nil,
            requestedCommand: "exec"
        )

        let output = try AuditFormatter.formatList([event], format: .table)

        #expect(output.contains("exec"))
        #expect(output.contains("API Key"))
        #expect(output.contains("automation"))
    }

    @Test("renderList table shows agent attribution")
    func renderListTableShowsAgentAttribution() throws {
        let event = makeEvent(
            command: .getPassword,
            itemId: "item-1",
            itemName: "API Key",
            approvedBy: "jit",
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            entryHash: "hash-agent",
            previousHash: nil,
            requestedCommand: "exec",
            agentRuntimeContext: AgentRuntimeContext(
                platform: "codex",
                sessionID: "session-1",
                turnID: "turn-1",
                agentID: "agent-1",
                agentType: "reviewer",
                toolUseID: "tool-1"
            )
        )

        let output = try AuditFormatter.formatList([event], format: .table)

        #expect(output.contains("Codex / reviewer"))
    }

    @Test("renderList table shows workspace attribution without root path")
    func renderListTableShowsWorkspaceAttributionWithoutRootPath() throws {
        let event = makeEvent(
            command: .getPassword,
            itemId: "item-1",
            itemName: "API Key",
            approvedBy: "jit",
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            entryHash: "hash-workspace",
            previousHash: nil,
            requestedCommand: "exec",
            workspaceContext: WorkspaceRuntimeContext(
                name: "selected-api",
                rootLabel: "api",
                authsiaFolder: "Workspaces/selected-api"
            )
        )

        let output = try AuditFormatter.formatList([event], format: .table)

        #expect(output.contains("Workspace"))
        #expect(output.contains("selected-api (api)"))
        #expect(!output.contains("/Users/example/project/api"))
    }

    @Test("renderList JSON preserves workspace attribution")
    func renderListJSONPreservesWorkspaceAttribution() throws {
        let event = makeEvent(
            command: .getPassword,
            itemId: "item-1",
            itemName: "API Key",
            approvedBy: "jit",
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            entryHash: "hash-workspace",
            previousHash: nil,
            requestedCommand: "exec",
            workspaceContext: WorkspaceRuntimeContext(
                name: "selected-api",
                rootLabel: "api",
                authsiaFolder: "Workspaces/selected-api"
            )
        )

        let output = try AuditFormatter.formatList([event], format: .json)
        let decoded = try auditDecoder().decode([AuditEvent].self, from: Data(output.utf8))

        #expect(decoded.first?.record.workspaceContext?.name == "selected-api")
        #expect(decoded.first?.record.workspaceContext?.rootLabel == "api")
        #expect(decoded.first?.record.workspaceContext?.authsiaFolder == "Workspaces/selected-api")
    }

    @Test("renderList table shows environment scope")
    func renderListTableShowsEnvironmentScope() throws {
        let event = makeEvent(
            command: .getPassword,
            itemId: "item-1",
            itemName: "API Key",
            approvedBy: "jit",
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            entryHash: "hash-environment",
            previousHash: nil,
            requestedCommand: "exec",
            environmentScope: .named("Production")
        )

        let output = try AuditFormatter.formatList([event], format: .table)

        #expect(output.contains("Environment"))
        #expect(output.contains("Production"))
    }

    @Test("renderList table shows Copilot agent attribution")
    func renderListTableShowsCopilotAgentAttribution() throws {
        let event = makeEvent(
            command: .getPassword,
            itemId: "item-1",
            itemName: "API Key",
            approvedBy: "jit",
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            entryHash: "hash-agent",
            previousHash: nil,
            requestedCommand: "exec",
            agentRuntimeContext: AgentRuntimeContext(
                platform: "copilot",
                sessionID: "session-1",
                turnID: "turn-1",
                agentID: "agent-1",
                agentType: "default-chat",
                toolUseID: "tool-1"
            )
        )

        let output = try AuditFormatter.formatList([event], format: .table)

        #expect(output.contains("GitHub Copilot / default-chat"))
    }

    @Test("renderList filters by type and limit")
    func renderListFiltersByTypeAndLimit() throws {
        let events = sampleEvents()

        let output = try Audit.renderList(events: events, format: .json, limit: 1, typeFilters: ["getPassword"])
        let decoded = try auditDecoder().decode([AuditEvent].self, from: Data(output.utf8))

        #expect(decoded.count == 1)
        #expect(decoded.first?.record.command == .getPassword)
    }

    @Test("renderList filters by requested CLI command")
    func renderListFiltersByRequestedCLICommand() throws {
        let events = [
            makeEvent(
                command: .getPassword,
                itemId: "item-1",
                itemName: "API Key",
                approvedBy: "session",
                timestamp: Date(timeIntervalSince1970: 1_700_000_000),
                entryHash: "hash-exec",
                previousHash: nil,
                requestedCommand: "exec"
            ),
            makeEvent(
                command: .getPassword,
                itemId: "item-2",
                itemName: "Manual Key",
                approvedBy: "session",
                timestamp: Date(timeIntervalSince1970: 1_700_000_001),
                entryHash: "hash-get",
                previousHash: "hash-exec",
                requestedCommand: "get"
            ),
        ]

        let output = try Audit.renderList(events: events, format: .json, typeFilters: ["exec"])
        let decoded = try auditDecoder().decode([AuditEvent].self, from: Data(output.utf8))

        #expect(decoded.count == 1)
        #expect(decoded.first?.record.requestedCommand == "exec")
    }

    @Test("writeExport writes JSON array to file")
    func writeExportWritesJSONArrayToFile() throws {
        let events = sampleEvents()
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("audit-export-\(UUID().uuidString).json").path
        defer { try? FileManager.default.removeItem(atPath: path) }

        try Audit.writeExport(events: events, format: .json, outFile: path)

        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let decoded = try auditDecoder().decode([AuditEvent].self, from: data)
        #expect(decoded.count == 2)
        #expect(decoded.first?.entryHash == "hash-newer")
    }

    @Test("writeExport writes NDJSON to file")
    func writeExportWritesNDJSONToFile() throws {
        let events = sampleEvents()
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("audit-export-\(UUID().uuidString).ndjson").path
        defer { try? FileManager.default.removeItem(atPath: path) }

        try Audit.writeExport(events: events, format: .ndjson, outFile: path)

        let content = try String(contentsOfFile: path, encoding: .utf8)
        let lines = content.split(separator: "\n")
        #expect(lines.count == 2)
        let decoded = try lines.map { line in
            try auditDecoder().decode(AuditEvent.self, from: Data(line.utf8))
        }
        #expect(decoded.first?.entryHash == "hash-newer")
        #expect(decoded.last?.entryHash == "hash-older")
    }

    private func sampleEvents() -> [AuditEvent] {
        let older = makeEvent(
            command: .getPassword,
            itemId: "item-1",
            itemName: "Old Secret",
            approvedBy: "biometric",
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            entryHash: "hash-older",
            previousHash: nil
        )
        let newer = makeEvent(
            command: .exportAccounts,
            itemId: "all-accounts",
            itemName: "All Accounts",
            approvedBy: "session",
            timestamp: Date(timeIntervalSince1970: 1_700_000_060),
            entryHash: "hash-newer",
            previousHash: "hash-older"
        )
        return [newer, older]
    }

    private func makeEvent(
        command: BridgeRequestType,
        itemId: String,
        itemName: String?,
        approvedBy: String,
        timestamp: Date,
        entryHash: String,
        previousHash: String?,
        requestedCommand: String? = nil,
        agentRuntimeContext: AgentRuntimeContext? = nil,
        workspaceContext: WorkspaceRuntimeContext? = nil,
        environmentScope: EnvironmentAccessScope? = nil
    ) -> AuditEvent {
        AuditEvent(
            version: 4,
            record: BridgeAuditRecord(
                command: command,
                itemId: itemId,
                itemName: itemName,
                approvedBy: approvedBy,
                timestamp: timestamp,
                caller: nil,
                requestedCommand: requestedCommand,
                agentRuntimeContext: agentRuntimeContext,
                workspaceContext: workspaceContext,
                environmentScope: environmentScope
            ),
            previousHash: previousHash,
            entryHash: entryHash
        )
    }

    private func writeAuditLog(_ events: [AuditEvent]) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("audit-log-\(UUID().uuidString).log")
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try events.map { try encoder.encode($0) }.joined(with: Data([0x0A]))
        try data.write(to: url, options: Data.WritingOptions.atomic)
        return url
    }

    private func auditDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}

private extension Array where Element == Data {
    func joined(with separator: Data) -> Data {
        guard let first = first else { return Data() }
        var result = first
        for element in dropFirst() {
            result.append(separator)
            result.append(element)
        }
        return result
    }
}
