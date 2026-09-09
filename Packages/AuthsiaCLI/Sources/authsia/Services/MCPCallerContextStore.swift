import AuthenticatorBridge
import Foundation
import Darwin

/// Short-lived, display-only hook metadata. Tool inputs and responses are never stored.
struct MCPCallerContextStore: Sendable {
    let fileURL: URL

    static let live = MCPCallerContextStore(fileURL: AgentRuntimeContextResolver.defaultEventsURL
        .deletingLastPathComponent().appendingPathComponent("AgentRuntimeContext/mcp-callers.json"))

    struct Record: Codable {
        let tool: String
        let cwd: String
        let recordedAt: Date
        let context: AgentRuntimeContext
    }

    static func toolName(_ name: String?) -> String? {
        guard let name, name.hasPrefix("mcp__"),
              let separator = name.range(of: "__", options: .backwards) else { return nil }
        let tool = String(name[separator.upperBound...])
        return ["authsia_list", "authsia_exec", "authsia_access_revoke"].contains(tool) ? tool : nil
    }

    func record(tool: String, cwd: String, context: AgentRuntimeContext, now: Date = Date()) throws {
        try transaction(now: now) { records in
            // A duplicate hook must not create a second claim for one tool use.
            if let id = context.toolUseID {
                records.removeAll { $0.context.sessionID == context.sessionID && $0.context.toolUseID == id }
            }
            records.append(Record(tool: tool, cwd: canonical(cwd), recordedAt: now, context: context))
        }
    }

    func consume(tool: String, cwd: String, platform: String, now: Date = Date()) -> AgentCallerIdentity {
        let unknown = AgentCallerIdentity(context: AgentRuntimeContext(attributionConfidence: .ambiguous))
        return (try? transaction(now: now) { records in
            let matches = records.filter {
                $0.tool == tool && $0.cwd == canonical(cwd)
                    && normalized($0.context.platform) == normalized(platform)
            }
            // Retire every competing candidate; never reuse it on a later invocation.
            records.removeAll {
                $0.tool == tool && $0.cwd == canonical(cwd)
                    && normalized($0.context.platform) == normalized(platform)
            }
            guard matches.count == 1, let match = matches.first else { return unknown }
            return AgentCallerIdentity(context: match.context)
        }) ?? unknown
    }

    private func canonical(_ path: String) -> String {
        let directory = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath()
        return (WorkspaceRootResolver.findWorkspaceRoot(startingAt: directory) ?? directory).path
    }

    private func normalized(_ platform: String?) -> String? {
        let value = platform?.lowercased()
        return value == "claude" || value == "claude code" ? "claude-code" : value
    }

    private func transaction<T>(now: Date, _ body: (inout [Record]) throws -> T) throws -> T {
        try FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let fd = open(fileURL.path + ".lock", O_CREAT | O_RDWR | O_NOFOLLOW, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { throw CocoaError(.fileWriteUnknown) }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw CocoaError(.fileWriteUnknown) }
        defer { flock(fd, LOCK_UN) }
        let data = (try? Data(contentsOf: fileURL)) ?? Data()
        var records = data.count <= 256 * 1024
            ? ((try? JSONDecoder().decode([Record].self, from: data)) ?? []) : []
        records.removeAll { now.timeIntervalSince($0.recordedAt) < 0 || now.timeIntervalSince($0.recordedAt) > 60 }
        let result = try body(&records)
        let output = try JSONEncoder().encode(Array(records.suffix(128)))
        try output.write(to: fileURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        return result
    }
}
