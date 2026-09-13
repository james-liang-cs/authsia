#if os(macOS)
import Foundation

public enum MCPHTTPClientConfiguration {
    public static func prepare(binding: MCPHTTPAssociationBinding, token: String,
                               home: URL = FileManager.default.homeDirectoryForCurrentUser,
                               replacingEndpoint: String? = nil) throws -> MCPPreparedFileChange {
        let name = binding.identity.upstreamName
        guard MCPUpstreamValidator.isValidName(name), binding.serverID == MCPWorkspaceStore.serverID(binding.identity) else { throw MCPManagementError.invalidRequest }
        let workspace = URL(fileURLWithPath: binding.identity.workspacePath)
        let url: URL
        switch binding.client {
        case .codex:
            url = home.appendingPathComponent(".codex/config.toml")
            let project = workspace.appendingPathComponent(".codex/config.toml")
            if let data = try existing(project), containsTOMLServer(data, name: name) { throw MCPManagementError.stale }
        case .claude: url = home.appendingPathComponent(".claude.json")
        case .cursor:
            url = home.appendingPathComponent(".cursor/mcp.json")
            let project = workspace.appendingPathComponent(".cursor/mcp.json")
            if let data = try existing(project), try object(data)["mcpServers"].flatMap({ $0 as? [String: Any] })?[name] != nil { throw MCPManagementError.stale }
        default: throw MCPManagementError.unsupported
        }
        let original = try existing(url)
        let endpoint = "http://127.0.0.1:8788/mcp/" + binding.serverID
        let replacement: Data
        if binding.client == .codex {
            let bytes = original ?? Data()
            guard let text = String(data: bytes, encoding: .utf8) else { throw MCPManagementError.invalidRequest }
            if containsTOMLServer(bytes, name: name) {
                guard let replacingEndpoint, let range = sectionRange(text, name: name) else { throw MCPManagementError.stale }
                let section = String(text[range])
                let subtree = serverSubtree(text, name: name)
                guard !subtree.contains("headers"), !subtree.contains("bearer_token"),
                      let urlRange = section.range(of: "(?m)^\\s*url\\s*=.*$", options: .regularExpression),
                      section[urlRange].contains("\"" + replacingEndpoint + "\"") || section[urlRange].contains("'" + replacingEndpoint + "'") else { throw MCPManagementError.stale }
                var updated = section; updated.replaceSubrange(urlRange, with: "url = \"\(endpoint)\"")
                updated += "\nhttp_headers = { Authorization = \"Bearer \(token)\" }\n"
                replacement = Data(text.replacingCharacters(in: range, with: updated).utf8)
            } else {
                replacement = Data((text + "\n[mcp_servers.\(name)]\nurl = \"\(endpoint)\"\nhttp_headers = { Authorization = \"Bearer \(token)\" }\n").utf8)
            }
        } else {
            var root = try original.map(object) ?? [:]
            let entry: [String: Any] = ["type":"http", "url":endpoint, "headers":["Authorization":"Bearer " + token]]
            if binding.client == .claude {
                var projects = try map(root["projects"])
                let projectKey = MCPWorkspacePathIdentity.canonicalPath(binding.identity.workspacePath)
                let equivalentKeys = MCPWorkspacePathIdentity.equivalentProjectKeys(
                    in: projects,
                    workspacePath: binding.identity.workspacePath
                )
                let existingEntries = try equivalentKeys.compactMap { key -> Any? in
                    let project = try map(projects[key])
                    return try map(project["mcpServers"])[name]
                }
                guard existingEntries.count <= 1 else { throw MCPManagementError.stale }
                let existingEntry = existingEntries.first
                try validateReplacement(existingEntry, endpoint: replacingEndpoint)
                for key in equivalentKeys where key != projectKey {
                    var project = try map(projects[key])
                    var servers = try map(project["mcpServers"])
                    servers.removeValue(forKey: name)
                    project["mcpServers"] = servers
                    projects[key] = project
                }
                var project = try map(projects[projectKey])
                var servers = try map(project["mcpServers"])
                servers[name] = (existingEntry as? [String: Any] ?? [:]).merging(entry) { _, new in new }
                project["mcpServers"] = servers
                projects[projectKey] = project; root["projects"] = projects
            } else {
                var servers = try map(root["mcpServers"])
                try validateReplacement(servers[name], endpoint: replacingEndpoint)
                servers[name] = (servers[name] as? [String: Any] ?? [:]).merging(entry) { _, new in new }
                root["mcpServers"] = servers
            }
            replacement = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes])
        }
        return MCPPreparedFileChange(fileURL: url, original: original, replacement: replacement)
    }
    private static func existing(_ file: URL) throws -> Data? {
        guard FileManager.default.fileExists(atPath: file.path) else { return nil }
        return try MCPWorkspaceStore.readBytes(file)
    }
    private static func validateReplacement(_ raw: Any?, endpoint: String?) throws {
        guard let raw else { return }
        guard let entry = raw as? [String: Any], let endpoint, entry["url"] as? String == endpoint,
              entry["headers"] == nil, entry["headersHelper"] == nil else { throw MCPManagementError.stale }
    }
    private static func sectionRange(_ text: String, name: String) -> Range<String.Index>? {
        serverSections(text, name: name, includeChildren: false).first
    }
    /// Parent table plus dotted subtables such as `[mcp_servers.name.http_headers]`.
    private static func serverSubtree(_ text: String, name: String) -> String {
        serverSectionRanges(text, name: name).map { String(text[$0]) }.joined(separator: "\n")
    }
    private static func serverSectionRanges(_ text: String, name: String) -> [Range<String.Index>] {
        serverSections(text, name: name, includeChildren: true)
    }
    private static func serverSections(_ text: String, name: String, includeChildren: Bool) -> [Range<String.Index>] {
        let escaped = NSRegularExpression.escapedPattern(for: name)
        let children = includeChildren ? "(?:\\..+)?" : ""
        let open = includeChildren ? "\\[\\[?" : "\\["
        let close = includeChildren ? "\\]\\]?" : "\\]"
        let pattern = "^[\\t ]*" + open + "[\\t ]*(?:mcp_servers|\"mcp_servers\"|'mcp_servers')[\\t ]*\\.[\\t ]*(?:" + escaped + "|\"" + escaped + "\"|'" + escaped + "')[\\t ]*" + children + close + "[\\t ]*(?:#.*)?$"
        guard let headings = tableHeadings(text) else { return [] }
        return headings.enumerated().compactMap { index, heading in
            guard text[heading].range(of: pattern, options: .regularExpression) != nil else { return nil }
            let end = index + 1 < headings.count ? headings[index + 1].lowerBound : text.endIndex
            return heading.lowerBound..<end
        }
    }

    /// Lexical table boundaries, not a TOML decoder. Never interpret a header
    /// example inside a string/comment/array as configuration. Incomplete strings
    /// or collections fail closed; all retained bytes stay exactly as written.
    private static func tableHeadings(_ text: String) -> [Range<String.Index>]? {
        let bytes = Array(text.utf8)
        var headings: [Range<String.Index>] = []
        var i = 0, depth = 0, lineOffset = 0, lineStart = true, multiline = false
        var quote: UInt8?
        func index(_ offset: Int) -> String.Index { String.Index(text.utf8.index(text.utf8.startIndex, offsetBy: offset), within: text)! }
        while i < bytes.count {
            let c = bytes[i]
            if let delimiter = quote {
                if c == 92 && delimiter == 34 { i += min(2, bytes.count - i); continue }
                if c == delimiter {
                    var end = i + 1
                    while end < bytes.count && bytes[end] == delimiter { end += 1 }
                    if !multiline { quote = nil; i += 1; continue }
                    if end - i >= 3 { quote = nil; i = end; continue }
                }
                if !multiline && (c == 10 || c == 13) { return nil }
                i += 1; continue
            }
            if c == 10 || c == 13 { lineStart = true; i += 1; lineOffset = i; continue }
            if lineStart && (c == 32 || c == 9) { i += 1; continue }
            if c == 35 {
                while i < bytes.count && bytes[i] != 10 && bytes[i] != 13 { i += 1 }
                continue
            }
            if lineStart && depth == 0 && c == 91 {
                var end = i
                while end < bytes.count && bytes[end] != 10 && bytes[end] != 13 { end += 1 }
                let heading = index(lineOffset)..<index(end)
                guard !text[heading].contains("\\"),
                      text[heading].range(of: "^[\\t ]*\\[.+\\][\\t ]*(?:#.*)?$", options: .regularExpression) != nil else { return nil }
                // Escaped table keys need a full TOML decoder; refuse that form
                // rather than accidentally leaving part of the selected subtree.
                headings.append(heading); i = end; continue
            }
            lineStart = false
            if c == 34 || c == 39 {
                quote = c
                multiline = i + 2 < bytes.count && bytes[i + 1] == c && bytes[i + 2] == c
                i += multiline ? 3 : 1
            } else {
                if c == 91 || c == 123 { depth += 1 }
                if c == 93 || c == 125 { depth -= 1; if depth < 0 { return nil } }
                i += 1
            }
        }
        return quote == nil && depth == 0 ? headings : nil
    }
    public static func prepareRemoval(binding: MCPHTTPAssociationBinding,
                                      home: URL = FileManager.default.homeDirectoryForCurrentUser) throws -> MCPPreparedFileChange {
        let name = binding.identity.upstreamName
        let file = home.appendingPathComponent(binding.client == .codex ? ".codex/config.toml" : binding.client == .claude ? ".claude.json" : ".cursor/mcp.json")
        let original = try MCPWorkspaceStore.readBytes(file)
        let endpoint = "http://127.0.0.1:8788/mcp/" + binding.serverID
        let after: Data
        if binding.client == .codex {
            guard let text = String(data: original, encoding: .utf8), let range = sectionRange(text, name: name), text[range].contains(endpoint) else { throw MCPManagementError.stale }
            var updated = text
            for section in serverSectionRanges(text, name: name).reversed() {
                updated.removeSubrange(section)
            }
            after = Data(updated.utf8)
        } else {
            var root = try object(original)
            if binding.client == .claude {
                var projects = try map(root["projects"])
                let projectKeys = MCPWorkspacePathIdentity.equivalentProjectKeys(
                    in: projects,
                    workspacePath: binding.identity.workspacePath
                )
                var removed = false
                for key in projectKeys {
                    var project = try map(projects[key])
                    var servers = try map(project["mcpServers"])
                    guard let raw = servers[name] else { continue }
                    guard (raw as? [String: Any])?["url"] as? String == endpoint else { throw MCPManagementError.stale }
                    servers.removeValue(forKey: name); project["mcpServers"] = servers
                    projects[key] = project; removed = true
                }
                guard removed else { throw MCPManagementError.stale }
                root["projects"] = projects
            } else {
                var servers = try map(root["mcpServers"])
                guard (servers[name] as? [String: Any])?["url"] as? String == endpoint else { throw MCPManagementError.stale }
                servers.removeValue(forKey: name); root["mcpServers"] = servers
            }
            after = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
        }
        return MCPPreparedFileChange(fileURL: file, original: original, replacement: after)
    }
    private static func map(_ value: Any?) throws -> [String: Any] {
        guard let value else { return [:] }
        guard let map = value as? [String: Any] else { throw MCPManagementError.invalidRequest }
        return map
    }
    private static func object(_ data: Data) throws -> [String: Any] { try map(JSONSerialization.jsonObject(with: data)) }
    private static func containsTOMLServer(_ data: Data, name: String) -> Bool {
        guard let text = String(data: data, encoding: .utf8) else { return true }
        let escaped = NSRegularExpression.escapedPattern(for: name)
        let pattern = "(?m)^\\s*\\[\\s*mcp_servers\\s*\\.\\s*(?:" + escaped + "|\"" + escaped + "\"|'" + escaped + "')\\s*(?:\\.|\\])"
        return text.range(of: pattern, options: .regularExpression) != nil
    }
}
#endif
