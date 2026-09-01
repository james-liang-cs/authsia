import CryptoKit
import Foundation

/// Confirmed replacement of a scanned client MCP launch with `authsia mcp proxy`.
///
/// Authsia still never rewrites a client file silently. `plan` is read-only.
/// `apply` writes only when the file checksum still matches the plan.
public enum MCPLocalMCPClientWrap {
    public static let maximumConfigBytes: UInt64 = 1_048_576

    public struct Plan: Equatable, Sendable {
        public let finding: MCPClientServerFinding
        public let fileURL: URL
        public let checksum: String
        public let existingSnippet: String
        public let replacementSnippet: String

        public init(
            finding: MCPClientServerFinding,
            fileURL: URL,
            checksum: String,
            existingSnippet: String,
            replacementSnippet: String
        ) {
            self.finding = finding
            self.fileURL = fileURL
            self.checksum = checksum
            self.existingSnippet = existingSnippet
            self.replacementSnippet = replacementSnippet
        }
    }

    public enum WrapError: Error, Equatable, LocalizedError {
        case notWrapEligible
        case overriddenByProject
        case missingFile
        case configTooLarge
        case malformedConfig
        case checksumMismatch
        case writeFailed

        public var errorDescription: String? {
            switch self {
            case .notWrapEligible:
                return "This local MCP server cannot be wrapped as a stdio proxy launch."
            case .overriddenByProject:
                return "This user-global entry is not the launch that wins. Wrap the project file instead."
            case .missingFile:
                return "The scanned client file is no longer present."
            case .configTooLarge:
                return "Client config is larger than 1 MiB."
            case .malformedConfig:
                return "Client config is not valid or does not contain this server."
            case .checksumMismatch:
                return "The client file changed since this wrap was planned. Scan again."
            case .writeFailed:
                return "Could not write the client file."
            }
        }
    }

    public static func fileURL(
        for finding: MCPClientServerFinding,
        homeDirectory: URL
    ) -> URL {
        let label = finding.configPathLabel
        if label == "~" {
            return homeDirectory
        }
        if label.hasPrefix("~/") {
            return homeDirectory.appendingPathComponent(String(label.dropFirst(2)))
        }
        return URL(fileURLWithPath: label)
    }

    public static func checksum(of data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    public static func plan(
        finding: MCPClientServerFinding,
        authsiaCommand: String,
        fileURL: URL? = nil,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser,
        fileManager: FileManager = .default
    ) throws -> Plan {
        try validateFinding(finding)
        let url = fileURL ?? Self.fileURL(for: finding, homeDirectory: homeDirectory)
        let data = try readConfig(at: url, fileManager: fileManager)
        let replacement = try replacementSnippet(
            for: finding,
            authsiaCommand: authsiaCommand,
            data: data
        )
        let existing = try existingSnippet(for: finding, data: data)
        return Plan(
            finding: finding,
            fileURL: url,
            checksum: checksum(of: data),
            existingSnippet: existing,
            replacementSnippet: replacement
        )
    }

    public static func apply(
        _ plan: Plan,
        authsiaCommand: String,
        fileManager: FileManager = .default
    ) throws {
        try validateFinding(plan.finding)
        let data = try readConfig(at: plan.fileURL, fileManager: fileManager)
        guard checksum(of: data) == plan.checksum else {
            throw WrapError.checksumMismatch
        }
        let encoded: Data
        switch plan.finding.source {
        case .codex:
            guard let text = String(data: data, encoding: .utf8),
                  let rewritten = rewriteCodex(
                    text,
                    serverName: plan.finding.serverName,
                    replacement: plan.replacementSnippet
                  ) else {
                throw WrapError.malformedConfig
            }
            encoded = Data(rewritten.utf8)
        case .claude, .cursor, .devin, .vscode:
            encoded = try rewriteJSON(
                data,
                source: plan.finding.source,
                serverName: plan.finding.serverName,
                authsiaCommand: authsiaCommand
            )
        }
        do {
            try encoded.write(to: plan.fileURL, options: .atomic)
        } catch {
            throw WrapError.writeFailed
        }
    }

    /// Prefer the launch that actually runs: effective project over user-global.
    public static func preferredFinding(
        named serverName: String,
        in findings: [MCPClientServerFinding]
    ) -> MCPClientServerFinding? {
        let matches = findings.filter {
            $0.serverName == serverName && $0.isWrapEligible && $0.precedence != .overridden
        }
        if let project = matches.first(where: { $0.configScope == .project }) {
            return project
        }
        return matches.first
    }

    private static func validateFinding(_ finding: MCPClientServerFinding) throws {
        guard finding.isWrapEligible, finding.precedence != .overridden else {
            throw finding.precedence == .overridden
                ? WrapError.overriddenByProject
                : WrapError.notWrapEligible
        }
        guard MCPProxyClientLaunch.validUpstreamName(finding.serverName) != nil else {
            throw WrapError.notWrapEligible
        }
    }

    private static func readConfig(at url: URL, fileManager: FileManager) throws -> Data {
        guard fileManager.fileExists(atPath: url.path) else {
            throw WrapError.missingFile
        }
        guard let attributes = try? fileManager.attributesOfItem(atPath: url.path),
              let size = (attributes[.size] as? NSNumber)?.uint64Value,
              size <= maximumConfigBytes else {
            throw WrapError.configTooLarge
        }
        guard let data = try? Data(contentsOf: url) else {
            throw WrapError.missingFile
        }
        return data
    }

    private static func replacementSnippet(
        for finding: MCPClientServerFinding,
        authsiaCommand: String,
        data: Data
    ) throws -> String {
        guard let authsia = MCPLocalMCPWrapRecipe.sanitizedCommand(authsiaCommand) else {
            throw WrapError.notWrapEligible
        }
        switch finding.source {
        case .codex:
            return MCPLocalMCPWrapRecipe.codexTable(
                name: finding.serverName,
                authsiaCommand: authsia,
                environment: MCPProxyClientLaunch.environment(upstreamName: finding.serverName),
                preservedLines: preservedCodexLines(data: data, serverName: finding.serverName)
            )
        case .claude, .cursor, .devin, .vscode:
            return prettyJSON(jsonObject(
                authsiaCommand: authsia,
                upstreamName: finding.serverName,
                includeType: finding.source == .vscode,
                preserving: preservedJSONKeys(
                    data: data,
                    source: finding.source,
                    serverName: finding.serverName
                )
            ))
        }
    }

    /// Keys the human set on the scanned entry that Authsia does not manage.
    /// The wrap replaces the launch, not the rest of the entry.
    private static func preservedJSONKeys(
        data: Data,
        source: MCPClientConfigSource,
        serverName: String
    ) -> [String: Any] {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let servers = root[jsonServersKey(for: source)] as? [String: Any],
              let existing = servers[serverName] as? [String: Any] else {
            return [:]
        }
        return existing.filter { key, _ in !managedJSONKeys.contains(key) }
    }

    private static func preservedCodexLines(data: Data, serverName: String) -> [String] {
        guard let text = String(data: data, encoding: .utf8),
              let table = extractCodexTable(text, serverName: serverName) else {
            return []
        }
        var preserved: [String] = []
        var sawTableHeader = false
        for rawLine in table.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            // Only the entry's own top-level keys are preserved. Everything
            // from the first sub-table on -- `env` above all -- is replaced by
            // the proxy's own environment and must not be carried forward.
            if line.hasPrefix("["), line.hasSuffix("]") {
                if sawTableHeader { break }
                sawTableHeader = true
                continue
            }
            guard !line.hasPrefix("#"), let equals = line.firstIndex(of: "=") else { continue }
            let key = String(line[..<equals]).trimmingCharacters(in: .whitespaces)
            guard !managedCodexKeys.contains(key),
                  !MCPClientConfigScanner.unsupportedLaunchKeys.contains(key) else {
                continue
            }
            preserved.append(line)
        }
        return preserved
    }

    private static let managedJSONKeys: Set<String> = ["command", "args", "env", "type"]
    private static let managedCodexKeys: Set<String> = ["command", "args", "env_vars"]

    private static func existingSnippet(
        for finding: MCPClientServerFinding,
        data: Data
    ) throws -> String {
        switch finding.source {
        case .codex:
            guard let text = String(data: data, encoding: .utf8),
                  let snippet = extractCodexTable(text, serverName: finding.serverName) else {
                throw WrapError.malformedConfig
            }
            return snippet
        case .claude, .cursor, .devin, .vscode:
            guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let servers = root[jsonServersKey(for: finding.source)] as? [String: Any],
                  let value = servers[finding.serverName] else {
                throw WrapError.malformedConfig
            }
            return prettyJSON(value)
        }
    }

    private static func rewriteJSON(
        _ data: Data,
        source: MCPClientConfigSource,
        serverName: String,
        authsiaCommand: String
    ) throws -> Data {
        guard let authsia = MCPLocalMCPWrapRecipe.sanitizedCommand(authsiaCommand) else {
            throw WrapError.notWrapEligible
        }
        guard var root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw WrapError.malformedConfig
        }
        let key = jsonServersKey(for: source)
        guard var servers = root[key] as? [String: Any],
              servers[serverName] != nil else {
            throw WrapError.malformedConfig
        }
        servers[serverName] = jsonObject(
            authsiaCommand: authsia,
            upstreamName: serverName,
            includeType: source == .vscode,
            preserving: preservedJSONKeys(data: data, source: source, serverName: serverName)
        )
        root[key] = servers
        guard let encoded = try? JSONSerialization.data(
            withJSONObject: root,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        ) else {
            throw WrapError.writeFailed
        }
        return encoded
    }

    private static func jsonObject(
        authsiaCommand: String,
        upstreamName: String,
        includeType: Bool,
        preserving preserved: [String: Any] = [:]
    ) -> [String: Any] {
        var object = preserved
        object["command"] = authsiaCommand
        object["args"] = MCPProxyClientLaunch.arguments
        // The child's credentials never survive the wrap: the proxy resolves
        // them from workspace policy instead of the client file.
        object["env"] = MCPProxyClientLaunch.environment(upstreamName: upstreamName)
        if includeType {
            object["type"] = "stdio"
        }
        return object
    }

    private static func jsonServersKey(for source: MCPClientConfigSource) -> String {
        source == .vscode ? "servers" : "mcpServers"
    }

    private static func prettyJSON(_ value: Any) -> String {
        guard JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(
                withJSONObject: value,
                options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
              ) else {
            return String(describing: value)
        }
        return String(data: data, encoding: .utf8) ?? "{}"
    }

    private static func extractCodexTable(_ text: String, serverName: String) -> String? {
        guard let range = tableRange(in: text, serverName: serverName) else { return nil }
        return String(text[range]).trimmingCharacters(in: .newlines)
    }

    private static func rewriteCodex(
        _ text: String,
        serverName: String,
        replacement: String
    ) -> String? {
        guard let range = tableRange(in: text, serverName: serverName) else { return nil }
        var result = text
        result.replaceSubrange(range, with: replacement.trimmingCharacters(in: .newlines) + "\n")
        return result
    }

    private static func tableRange(in text: String, serverName: String) -> Range<String.Index>? {
        var start: String.Index?
        var end = text.endIndex
        var lineStart = text.startIndex
        var index = text.startIndex

        func considerLine(lineEnd: String.Index) {
            let line = text[lineStart..<lineEnd].trimmingCharacters(in: .whitespaces)
            guard line.hasPrefix("["), line.hasSuffix("]") else { return }
            let heading = String(line.dropFirst().dropLast())
            if isCodexHeading(heading, serverName: serverName) {
                if start == nil {
                    start = lineStart
                }
            } else if start != nil {
                end = lineStart
            }
        }

        while index < text.endIndex {
            if text[index] == "\n" {
                considerLine(lineEnd: index)
                if start != nil, end != text.endIndex {
                    break
                }
                index = text.index(after: index)
                lineStart = index
                continue
            }
            index = text.index(after: index)
        }
        if lineStart < text.endIndex {
            considerLine(lineEnd: text.endIndex)
        }
        guard let start else { return nil }
        return start..<end
    }

    private static func isCodexHeading(_ heading: String, serverName: String) -> Bool {
        let unquoted = heading.replacingOccurrences(of: "\"", with: "")
        return unquoted == "mcp_servers.\(serverName)"
            || unquoted.hasPrefix("mcp_servers.\(serverName).")
    }
}
