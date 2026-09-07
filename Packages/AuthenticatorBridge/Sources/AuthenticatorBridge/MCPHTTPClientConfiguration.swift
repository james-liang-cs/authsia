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
                var project = try map(projects[binding.identity.workspacePath])
                var servers = try map(project["mcpServers"])
                try validateReplacement(servers[name], endpoint: replacingEndpoint)
                servers[name] = (servers[name] as? [String: Any] ?? [:]).merging(entry) { _, new in new }
                project["mcpServers"] = servers
                projects[binding.identity.workspacePath] = project; root["projects"] = projects
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
        let name = NSRegularExpression.escapedPattern(for: name)
        return text.range(of: "(?ms)^\\s*\\[mcp_servers\\.(?:" + name + "|\"" + name + "\"|'" + name + "')\\][^\\n]*\\n(?:(?!^\\[).)*", options: .regularExpression)
    }
    /// Parent table plus dotted subtables such as `[mcp_servers.name.http_headers]`.
    private static func serverSubtree(_ text: String, name: String) -> String {
        let escaped = NSRegularExpression.escapedPattern(for: name)
        let pattern = "(?ms)^\\s*\\[\\s*mcp_servers\\s*\\.\\s*(?:" + escaped + "|\"" + escaped + "\"|'" + escaped + "')(?:\\.[^\\]]*)?\\s*\\][^\\n]*\\n(?:(?!^\\[).)*"
        var collected = ""
        var search = text.startIndex
        while search < text.endIndex,
              let range = text.range(of: pattern, options: .regularExpression, range: search..<text.endIndex) {
            collected += String(text[range])
            collected += "\n"
            search = range.upperBound
        }
        return collected
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
            after = Data(text.replacingCharacters(in: range, with: "").utf8)
        } else {
            var root = try object(original)
            if binding.client == .claude {
                var projects = try map(root["projects"]), project = try map((root["projects"] as? [String: Any])?[binding.identity.workspacePath])
                var servers = try map(project["mcpServers"])
                guard (servers[name] as? [String: Any])?["url"] as? String == endpoint else { throw MCPManagementError.stale }
                servers.removeValue(forKey: name); project["mcpServers"] = servers
                projects[binding.identity.workspacePath] = project; root["projects"] = projects
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
