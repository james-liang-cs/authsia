import Foundation
import MCP

enum MCPProxyCatalog {
    static let defaultInputSchema = Value.object([
        "additionalProperties": true,
        "type": "object",
    ])

    static let maximumDiscoveredToolCount = 256
    static let maximumToolNameLength = 128
    static let maximumDescriptionLength = 1_024

    private static let schemaJSONLimit = 64 * 1_024

    static func listedTools(for upstream: MCPUpstreamConfig?) -> [Tool] {
        guard let upstream, upstream.requiresStdioPolicy else { return [] }
        return advertisedTools(from: upstream)
    }

    static func shouldDiscoverChildCatalog(_ upstream: MCPUpstreamConfig) -> Bool {
        upstream.requiresStdioPolicy
            && upstream.tools.allow.isEmpty
            && upstream.tools.approve.isEmpty
            && upstream.env.isEmpty
    }

    static func advertisedNames(in policy: MCPUpstreamToolPolicy) -> [String] {
        let denied = Set(policy.deny)
        var seen = Set<String>()
        var names: [String] = []
        for name in policy.allow + policy.approve where !denied.contains(name) {
            if seen.insert(name).inserted {
                names.append(name)
            }
        }
        return names
    }

    static func listedTools(fromChild tools: [Tool], deny: [String]) -> [Tool] {
        let denied = Set(deny)
        var seen = Set<String>()
        var advertised: [Tool] = []
        advertised.reserveCapacity(min(tools.count, maximumDiscoveredToolCount))
        for tool in tools {
            guard advertised.count < maximumDiscoveredToolCount else { break }
            guard isAdvertisableToolName(tool.name),
                  !denied.contains(tool.name),
                  seen.insert(tool.name).inserted else {
                continue
            }
            advertised.append(advertisedChildTool(tool))
        }
        return advertised
    }

    private static func advertisedChildTool(_ tool: Tool) -> Tool {
        let schema: Value
        if let data = try? JSONEncoder().encode(tool.inputSchema),
           let json = try? JSONDecoder().decode(MCPJSONValue.self, from: data) {
            schema = advertisedSchema(json)
        } else {
            schema = defaultInputSchema
        }
        return Tool(
            name: tool.name,
            description: sanitizedDescription(tool.description ?? ""),
            inputSchema: schema
        )
    }

    static func isAdvertisableToolName(_ name: String) -> Bool {
        !name.isEmpty
            && name.count <= maximumToolNameLength
            && name.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) }
    }

    static func sanitizedDescription(_ value: String) -> String {
        let stripped = String(value.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) })
        return String(stripped.prefix(maximumDescriptionLength))
    }

    static func advertisedTools(from upstream: MCPUpstreamConfig) -> [Tool] {
        let names = advertisedNames(in: upstream.tools)
        let advertised = Set(names)
        var catalogByName: [String: MCPUpstreamToolDescriptor] = [:]
        for entry in upstream.catalog where advertised.contains(entry.name) {
            if catalogByName[entry.name] == nil {
                catalogByName[entry.name] = entry
            }
        }
        return names.map { name in
            guard let entry = catalogByName[name] else {
                return Tool(name: name, description: "", inputSchema: defaultInputSchema)
            }
            return Tool(
                name: name,
                description: entry.description,
                inputSchema: advertisedSchema(entry.inputSchema)
            )
        }
    }

    static func advertisedSchema(_ schema: MCPJSONValue) -> Value {
        guard let sanitized = sanitizedSchema(schema),
              case .object(let object) = sanitized,
              case .string("object") = object["type"],
              let encoded = try? JSONEncoder().encode(sanitized),
              encoded.count <= schemaJSONLimit,
              let value = try? Value(sanitized) else {
            return defaultInputSchema
        }
        return value
    }

    private static func sanitizedSchema(_ value: MCPJSONValue) -> MCPJSONValue? {
        switch value {
        case .object(let object):
            var result: [String: MCPJSONValue] = [:]
            result.reserveCapacity(object.count)
            for (key, nested) in object {
                if key == "$ref" || key == "$schema" { continue }
                if let sanitized = sanitizedSchema(nested) {
                    result[key] = sanitized
                }
            }
            return .object(result)
        case .array(let array):
            return .array(array.compactMap(sanitizedSchema))
        case .string(let string):
            let lowered = string.lowercased()
            if lowered.hasPrefix("http:")
                || lowered.hasPrefix("https:")
                || lowered.hasPrefix("file:") {
                return nil
            }
            return .string(string)
        case .number, .bool, .null:
            return value
        }
    }
}
