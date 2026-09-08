import Foundation

/// Transport declared for one workspace-owned MCP upstream.
///
/// HTTP cases are decoded today so newer declarations fail closed in older
/// runtimes. Runtime support remains transport-specific.
public enum MCPUpstreamTransport: String, Codable, Equatable, Sendable {
    case stdio
    case http
    case sse
    case streamableHTTP = "streamable-http"
}

public struct MCPUpstreamToolPolicy: Codable, Equatable, Sendable {
    public var allow: [String]
    public var approve: [String]
    public var deny: [String]

    public init(allow: [String] = [], approve: [String] = [], deny: [String] = []) {
        self.allow = allow
        self.approve = approve
        self.deny = deny
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        allow = try container.decodeIfPresent([String].self, forKey: .allow) ?? []
        approve = try container.decodeIfPresent([String].self, forKey: .approve) ?? []
        deny = try container.decodeIfPresent([String].self, forKey: .deny) ?? []
    }
}

public indirect enum MCPJSONValue: Codable, Equatable, Sendable {
    case object([String: MCPJSONValue])
    case array([MCPJSONValue])
    case string(String)
    case number(Double)
    case bool(Bool)
    case null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int64.self) {
            self = .number(Double(value))
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([MCPJSONValue].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: MCPJSONValue].self) {
            self = .object(value)
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Unsupported JSON value"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .object(let value):
            try container.encode(value)
        case .array(let value):
            try container.encode(value)
        case .string(let value):
            try container.encode(value)
        case .number(let value):
            if value.rounded() == value, let integer = Int64(exactly: value) {
                try container.encode(integer)
            } else {
                try container.encode(value)
            }
        case .bool(let value):
            try container.encode(value)
        case .null:
            try container.encodeNil()
        }
    }
}

public struct MCPUpstreamToolDescriptor: Codable, Equatable, Sendable {
    public var name: String
    public var description: String
    public var inputSchema: MCPJSONValue

    public init(
        name: String,
        description: String = "",
        inputSchema: MCPJSONValue = .object([
            "additionalProperties": .bool(true),
            "type": .string("object"),
        ])
    ) {
        self.name = name
        self.description = description
        self.inputSchema = inputSchema
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        description = try container.decodeIfPresent(String.self, forKey: .description) ?? ""
        inputSchema = try container.decodeIfPresent(MCPJSONValue.self, forKey: .inputSchema)
            ?? .object([
                "additionalProperties": .bool(true),
                "type": .string("object"),
            ])
    }
}

public enum MCPUpstreamCredentialHeaderFormat: String, Codable, Equatable, Sendable {
    case bearer
    case raw
}

public struct MCPUpstreamCredentialHeader: Codable, Equatable, Sendable {
    public var headerName: String
    public var reference: String
    public var format: MCPUpstreamCredentialHeaderFormat

    public init(
        headerName: String,
        reference: String,
        format: MCPUpstreamCredentialHeaderFormat
    ) {
        self.headerName = headerName
        self.reference = reference
        self.format = format
    }
}

public struct MCPUpstreamConfig: Codable, Equatable, Sendable {
    /// Catalog capture defaults an empty policy to allow the recorded tools.
    /// Existing policy decisions are preserved for both transports.
    public func recordingCatalog(_ descriptors: [MCPUpstreamToolDescriptor], at date: Date = Date()) -> Self {
        var updated = self
        updated.catalog = descriptors
        updated.catalogCapturedAt = date
        if tools.allow.isEmpty && tools.approve.isEmpty && tools.deny.isEmpty {
            updated.tools.allow = Array(Set(descriptors.map(\.name))).sorted()
        }
        return updated
    }

    public var name: String
    public var transport: MCPUpstreamTransport
    public var url: String?
    public var command: String?
    public var args: [String]
    public var env: [String: String]
    public var tools: MCPUpstreamToolPolicy
    public var catalog: [MCPUpstreamToolDescriptor]
    public var credentialHeaders: [MCPUpstreamCredentialHeader]
    /// Observation time of the last successful catalog capture. Independent of
    /// authorization revision until launch/policy/credential invalidation is
    /// proven separately.
    public var catalogCapturedAt: Date?

    public init(
        name: String,
        transport: MCPUpstreamTransport = .stdio,
        url: String? = nil,
        command: String? = nil,
        args: [String] = [],
        env: [String: String] = [:],
        tools: MCPUpstreamToolPolicy = MCPUpstreamToolPolicy(),
        catalog: [MCPUpstreamToolDescriptor] = [],
        credentialHeaders: [MCPUpstreamCredentialHeader] = [],
        catalogCapturedAt: Date? = nil
    ) {
        self.name = name
        self.transport = transport
        self.url = url
        self.command = command
        self.args = args
        self.env = env
        self.tools = tools
        self.catalog = catalog
        self.credentialHeaders = credentialHeaders
        self.catalogCapturedAt = catalogCapturedAt
    }

    public var requiresStdioPolicy: Bool {
        transport == .stdio && url == nil
    }

    enum CodingKeys: String, CodingKey {
        case name
        case transport
        case url
        case command
        case args
        case env
        case tools
        case catalog
        case credentialHeaders
        case catalogCapturedAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        transport = try container.decodeIfPresent(MCPUpstreamTransport.self, forKey: .transport) ?? .stdio
        url = try container.decodeIfPresent(String.self, forKey: .url)
        command = try container.decodeIfPresent(String.self, forKey: .command)
        args = try container.decodeIfPresent([String].self, forKey: .args) ?? []
        env = try container.decodeIfPresent([String: String].self, forKey: .env) ?? [:]
        tools = try container.decodeIfPresent(MCPUpstreamToolPolicy.self, forKey: .tools)
            ?? MCPUpstreamToolPolicy()
        catalog = try container.decodeIfPresent([MCPUpstreamToolDescriptor].self, forKey: .catalog) ?? []
        credentialHeaders = try container.decodeIfPresent(
            [MCPUpstreamCredentialHeader].self,
            forKey: .credentialHeaders
        ) ?? []
        if let captured = try container.decodeIfPresent(String.self, forKey: .catalogCapturedAt) {
            catalogCapturedAt = ISO8601DateFormatter().date(from: captured)
        } else {
            catalogCapturedAt = nil
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(name, forKey: .name)
        try container.encode(transport, forKey: .transport)
        try container.encodeIfPresent(url, forKey: .url)
        try container.encodeIfPresent(command, forKey: .command)
        if !args.isEmpty {
            try container.encode(args, forKey: .args)
        }
        if !env.isEmpty {
            try container.encode(env, forKey: .env)
        }
        if !tools.allow.isEmpty || !tools.approve.isEmpty || !tools.deny.isEmpty {
            try container.encode(tools, forKey: .tools)
        }
        if !catalog.isEmpty {
            try container.encode(catalog, forKey: .catalog)
        }
        if !credentialHeaders.isEmpty {
            try container.encode(credentialHeaders, forKey: .credentialHeaders)
        }
        if let catalogCapturedAt {
            try container.encode(ISO8601DateFormatter().string(from: catalogCapturedAt), forKey: .catalogCapturedAt)
        }
    }
}
