import ArgumentParser
import AuthenticatorBridge
import Foundation

struct Audit: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Audit log management",
        subcommands: [Verify.self, List.self, Export.self]
    )

    enum ExportFormat: String, ExpressibleByArgument, CaseIterable {
        case json
        case ndjson

        static var allValueStrings: [String] { allCases.map(\.rawValue) }
    }

    private enum LoadError: LocalizedError {
        case malformedEntry(file: String, line: Int)

        var errorDescription: String? {
            switch self {
            case .malformedEntry(let file, let line):
                return "Malformed audit entry in \(file) at line \(line)."
            }
        }
    }

    struct Verify: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Verify audit log integrity",
            discussion: """
                Checks the HMAC-SHA256 hash chain of the audit log to detect
                tampering, modifications, or deletions. Each entry is verified
                against the previous entry's hash using a Keychain-stored key.

                Examples:
                  authsia audit verify
                """
        )

        func run() throws {
            let isValid = try AuthsiaBridgeClient.shared.auditVerify()
            if isValid {
                print("Audit log integrity: OK")
                print("All entries verified against HMAC chain.")
            } else {
                print("Audit log integrity: FAILED")
                print("The audit log has been tampered with or corrupted.")
                throw ExitCode.failure
            }
        }
    }

    struct List: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "list",
            abstract: "List audit log entries",
            discussion: """
                Reads audit entries from the local Authsia audit log and shows selected entries
                oldest-to-newest so the newest entry appears at the bottom.

                Examples:
                  authsia audit list
                  authsia audit list --format json
                  authsia audit list --type getPassword --type getOTP
                  authsia audit list --limit 20
                """
        )

        @Option(name: .long, help: "Output format: table (default), json")
        var format: OutputFormat = .table

        @Option(name: .long, help: "Maximum number of entries to show")
        var limit: Int?

        @Option(name: .shortAndLong, help: "Filter by bridge command raw value (repeatable)")
        var type: [String] = []

        mutating func validate() throws {
            if let limit, limit <= 0 {
                throw ValidationError("--limit must be greater than 0. Example: authsia audit list --limit 20")
            }
        }

        func run() throws {
            let events = try Audit.loadEvents()
            let output = try Audit.renderList(
                events: events,
                format: format,
                limit: limit,
                typeFilters: type
            )
            print(output)
        }
    }

    struct Export: ParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "export",
            abstract: "Export audit log entries to a file",
            discussion: """
                Writes audit entries from the local Authsia audit log to a file.

                Examples:
                  authsia audit export --out-file audit.json
                  authsia audit export --format ndjson --out-file audit.ndjson
                """
        )

        @Option(name: .shortAndLong, help: "Output file path")
        var outFile: String

        @Option(name: .long, help: "Output format: json (default), ndjson")
        var format: ExportFormat = .json

        func run() throws {
            let events = try Audit.loadEvents()
            try Audit.writeExport(events: events, format: format, outFile: outFile)
            print("Exported \(events.count) audit events to \(outFile)")
        }
    }

    static func loadEvents(from fileURLs: [URL]? = nil) throws -> [AuditEvent] {
        let urls = uniqueLogURLs(fileURLs ?? auditLogCandidateURLs())
        var eventsByHash: [String: AuditEvent] = [:]
        var firstError: Error?

        for url in urls {
            do {
                for event in try readEvents(from: url) {
                    if eventsByHash[event.entryHash] == nil {
                        eventsByHash[event.entryHash] = event
                    }
                }
            } catch {
                firstError = firstError ?? error
            }
        }

        if eventsByHash.isEmpty, let firstError {
            throw firstError
        }

        return eventsByHash.values.sorted { lhs, rhs in
            if lhs.record.timestamp != rhs.record.timestamp {
                return lhs.record.timestamp > rhs.record.timestamp
            }
            return lhs.entryHash < rhs.entryHash
        }
    }

    static func renderList(
        events: [AuditEvent],
        format: OutputFormat,
        limit: Int? = nil,
        typeFilters: [String] = []
    ) throws -> String {
        let filtered = filter(events: events, typeFilters: typeFilters, limit: limit)
        return try AuditFormatter.formatList(Array(filtered.reversed()), format: format)
    }

    static func writeExport(events: [AuditEvent], format: ExportFormat, outFile: String) throws {
        let output = try AuditFormatter.formatExport(events, format: format)
        try ReadCmd.writeToFile(value: output, path: outFile)
    }

    private static func filter(events: [AuditEvent], typeFilters: [String], limit: Int?) -> [AuditEvent] {
        let normalizedTypes = Set(typeFilters.map { $0.lowercased() })
        let filtered = events.filter { event in
            guard !normalizedTypes.isEmpty else { return true }
            return normalizedTypes.contains(event.record.command.rawValue.lowercased()) ||
                event.record.requestedCommand.map { normalizedTypes.contains($0.lowercased()) } == true
        }

        guard let limit else {
            return filtered
        }
        return Array(filtered.prefix(limit))
    }

    private static func auditLogCandidateURLs(fileManager: FileManager = .default) -> [URL] {
        var urls: [URL] = []

        let containerBase = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? fileManager.temporaryDirectory
        urls.append(containerBase.appendingPathComponent("Authsia/bridge_audit.log"))

        let homeBase = fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Authsia/bridge_audit.log")
        urls.append(homeBase)

        return uniqueLogURLs(urls)
    }

    private static func uniqueLogURLs(_ urls: [URL]) -> [URL] {
        var seen = Set<String>()
        var unique: [URL] = []
        for url in urls {
            let path = url.standardizedFileURL.path
            guard seen.insert(path).inserted else { continue }
            unique.append(url)
        }
        return unique
    }

    private static func readEvents(from url: URL) throws -> [AuditEvent] {
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }

        let data = try Data(contentsOf: url)
        guard !data.isEmpty else { return [] }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        return try data.split(separator: 0x0A).enumerated().map { index, rawLine in
            do {
                return try decoder.decode(AuditEvent.self, from: Data(rawLine))
            } catch {
                throw LoadError.malformedEntry(file: url.lastPathComponent, line: index + 1)
            }
        }
    }
}
