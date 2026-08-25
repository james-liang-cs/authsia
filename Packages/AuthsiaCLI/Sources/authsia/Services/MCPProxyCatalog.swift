import Foundation
import MCP

enum MCPProxyCatalog {
    static let defaultInputSchema = Value.object([
        "additionalProperties": true,
        "type": "object",
    ])

    private static let schemaJSONLimit = 64 * 1_024

    static func listedTools(for upstream: MCPUpstreamConfig?) -> [Tool] {
        guard let upstream, upstream.requiresStdioPolicy else { return [] }
        return advertisedTools(from: upstream)
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
