import Foundation
import MCP
import Testing
@testable import authsia

@Suite("MCP proxy catalog")
struct MCPProxyCatalogTests {
    @Test("allow union approve is advertised and deny catalog names are omitted")
    func allowApproveUnionOmitsDeny() {
        let upstream = MCPUpstreamConfig(
            name: "jira",
            command: "mcp-atlassian",
            tools: MCPUpstreamToolPolicy(
                allow: ["jira_get_issue", "jira_search"],
                approve: ["jira_create_issue"],
                deny: ["jira_delete_issue"]
            ),
            catalog: [
                MCPUpstreamToolDescriptor(
                    name: "jira_get_issue",
                    description: "Get one Jira issue by key",
                    inputSchema: .object([
                        "additionalProperties": .bool(false),
                        "properties": .object([
                            "issueKey": .object(["type": .string("string")]),
                        ]),
                        "required": .array([.string("issueKey")]),
                        "type": .string("object"),
                    ])
                ),
                MCPUpstreamToolDescriptor(name: "jira_delete_issue", description: "must not leak"),
                MCPUpstreamToolDescriptor(name: "other_tool", description: "not in policy"),
            ]
        )

        let tools = MCPProxyCatalog.listedTools(for: upstream)
        #expect(tools.map(\.name) == ["jira_get_issue", "jira_search", "jira_create_issue"])
        #expect(!tools.map(\.name).contains("jira_delete_issue"))
        #expect(!tools.map(\.name).contains("other_tool"))
        #expect(tools[0].description == "Get one Jira issue by key")
        #expect(tools[0].inputSchema.objectValue?["properties"]?.objectValue?["issueKey"] != nil)
        #expect(tools[1].description == "")
        #expect(tools[1].inputSchema == MCPProxyCatalog.defaultInputSchema)
        #expect(tools[2].description == "")
        #expect(tools[2].inputSchema == MCPProxyCatalog.defaultInputSchema)
    }

    @Test("empty allow and approve advertise no tools")
    func emptyCatalogAdvertisesNothing() {
        let upstream = MCPUpstreamConfig(
            name: "jira",
            command: "mcp-atlassian",
            tools: MCPUpstreamToolPolicy(deny: ["jira_delete_issue"]),
            catalog: [MCPUpstreamToolDescriptor(name: "jira_delete_issue")]
        )
        #expect(MCPProxyCatalog.listedTools(for: upstream).isEmpty)
    }

    @Test("credential-less empty policy is eligible for child catalog discovery")
    func emptyPolicyIsEligibleForChildDiscovery() {
        let codegraph = MCPUpstreamConfig(
            name: "codegraph",
            command: "codegraph",
            args: ["serve", "--mcp"],
            tools: MCPUpstreamToolPolicy(deny: ["hidden_tool"])
        )
        #expect(MCPProxyCatalog.shouldDiscoverChildCatalog(codegraph))

        let named = MCPUpstreamConfig(
            name: "codegraph",
            command: "codegraph",
            tools: MCPUpstreamToolPolicy(allow: ["codegraph_explore"])
        )
        #expect(!MCPProxyCatalog.shouldDiscoverChildCatalog(named))

        let secret = MCPUpstreamConfig(
            name: "jira",
            command: "mcp-atlassian",
            env: ["JIRA_API_TOKEN": "authsia://api-key/Atlassian/key"],
            tools: MCPUpstreamToolPolicy()
        )
        #expect(!MCPProxyCatalog.shouldDiscoverChildCatalog(secret))

        let literalEnvironment = MCPUpstreamConfig(
            name: "codegraph",
            command: "codegraph",
            env: ["PYTHONUNBUFFERED": "1"],
            tools: MCPUpstreamToolPolicy()
        )
        #expect(!MCPProxyCatalog.shouldDiscoverChildCatalog(literalEnvironment))

        let http = MCPUpstreamConfig(
            name: "rovo",
            transport: .http,
            url: "https://example.atlassian.net/mcp"
        )
        #expect(!MCPProxyCatalog.shouldDiscoverChildCatalog(http))
    }

    @Test("discovered child tools omit deny, invalid names, and unsanitary schemas")
    func discoveredChildToolsAreBoundedAndSanitized() {
        let child: [Tool] = [
            Tool(
                name: "codegraph_explore",
                description: "Explore\u{0007} symbols",
                inputSchema: .object([
                    "type": "object",
                    "$ref": "#/defs/query",
                    "properties": .object([
                        "query": .object(["type": "string"]),
                    ]),
                ])
            ),
            Tool(
                name: "hidden_tool",
                description: "must not leak",
                inputSchema: MCPProxyCatalog.defaultInputSchema
            ),
            Tool(
                name: "bad\nname",
                description: "",
                inputSchema: MCPProxyCatalog.defaultInputSchema
            ),
            Tool(
                name: "",
                description: "",
                inputSchema: MCPProxyCatalog.defaultInputSchema
            ),
            Tool(
                name: String(repeating: "x", count: MCPProxyCatalog.maximumToolNameLength + 1),
                description: "",
                inputSchema: MCPProxyCatalog.defaultInputSchema
            ),
        ]
        let listed = MCPProxyCatalog.listedTools(fromChild: child, deny: ["hidden_tool"])
        #expect(listed.map(\.name) == ["codegraph_explore"])
        #expect(listed[0].description == "Explore symbols")
        #expect(listed[0].inputSchema.objectValue?["$ref"] == nil)
        #expect(listed[0].inputSchema.objectValue?["properties"]?.objectValue?["query"] != nil)
    }

    @Test("unbound and HTTP upstreams advertise an empty list")
    func unboundAndHTTPAdvertiseNothing() {
        #expect(MCPProxyCatalog.listedTools(for: nil).isEmpty)

        let http = MCPUpstreamConfig(
            name: "rovo",
            transport: .http,
            url: "https://example.atlassian.net/mcp",
            tools: MCPUpstreamToolPolicy(allow: ["jira_get_issue"]),
            catalog: [MCPUpstreamToolDescriptor(name: "jira_get_issue")]
        )
        #expect(MCPProxyCatalog.listedTools(for: http).isEmpty)

        let sse = MCPUpstreamConfig(
            name: "rovo",
            transport: .sse,
            url: "https://example.atlassian.net/mcp",
            tools: MCPUpstreamToolPolicy(allow: ["jira_get_issue"])
        )
        #expect(MCPProxyCatalog.listedTools(for: sse).isEmpty)

        let streamable = MCPUpstreamConfig(
            name: "rovo",
            transport: .streamableHTTP,
            url: "https://example.atlassian.net/mcp",
            tools: MCPUpstreamToolPolicy(allow: ["jira_get_issue"])
        )
        #expect(MCPProxyCatalog.listedTools(for: streamable).isEmpty)

        let urlOnly = MCPUpstreamConfig(
            name: "rovo",
            url: "https://example.atlassian.net/mcp",
            tools: MCPUpstreamToolPolicy(allow: ["jira_get_issue"])
        )
        #expect(MCPProxyCatalog.listedTools(for: urlOnly).isEmpty)
    }

    @Test("dollar-ref schema and URI-shaped values are rejected from the advertised catalog")
    func forbiddenSchemaContentIsRejected() {
        let refSchema = MCPJSONValue.object([
            "type": .string("object"),
            "$ref": .string("#/defs/issue"),
            "properties": .object([
                "url": .object([
                    "type": .string("string"),
                    "default": .string("https://example.invalid"),
                ]),
            ]),
        ])
        let advertised = MCPProxyCatalog.advertisedSchema(refSchema)
        #expect(advertised.objectValue?["$ref"] == nil)
        #expect(advertised.objectValue?["$schema"] == nil)
        let encoded = String(decoding: (try? JSONEncoder().encode(advertised)) ?? Data(), as: UTF8.self)
        #expect(!encoded.contains("$ref"))
        #expect(!encoded.lowercased().contains("https:"))

        let schemaKey = MCPJSONValue.object([
            "type": .string("object"),
            "$schema": .string("https://json-schema.org/draft/2020-12/schema"),
        ])
        #expect(MCPProxyCatalog.advertisedSchema(schemaKey).objectValue?["$schema"] == nil)
        #expect(MCPProxyCatalog.advertisedSchema(.bool(true)) == MCPProxyCatalog.defaultInputSchema)
        #expect(MCPProxyCatalog.advertisedSchema(.array([])) == MCPProxyCatalog.defaultInputSchema)
    }

    @Test("too-large catalog schemas fall back to the open object schema")
    func oversizedSchemaIsRejected() {
        let oversized = MCPJSONValue.object([
            "type": .string("object"),
            "description": .string(String(repeating: "x", count: 65_536)),
        ])
        #expect(MCPProxyCatalog.advertisedSchema(oversized) == MCPProxyCatalog.defaultInputSchema)
    }

    @Test("serve still exposes exactly six tools and inspect does not grow")
    func serveCatalogStaysFrozen() {
        #expect(MCPToolCatalog.tools.count == 6)
        #expect(!MCPToolCatalog.tools.map(\.name).contains { $0.hasPrefix("jira_") })
        let inspect = MCPToolCatalog.descriptors.first { $0.name == .workspaceInspect }
        #expect(inspect?.outputPropertyNames.contains("mcpUpstreams") == false)
        #expect(inspect?.outputPropertyNames == [
            "workspaceName", "workspaceRoot", "schemaVersion", "selectedEnvironment",
            "availableEnvironments", "managedFiles", "references", "referencesTruncated",
            "diagnostics",
        ])

        let errorCodes = MCPToolErrorCode.allCases.map(\.rawValue)
        #expect(errorCodes.contains("upstreamDenied"))
        #expect(errorCodes.contains("upstreamUnavailable"))
        #expect(errorCodes.contains("httpUpstreamUnsupported"))

        let errorEnum = MCPToolCatalog.tools[0].outputSchema?
            .objectValue?["oneOf"]?.arrayValue?.last?
            .objectValue?["properties"]?.objectValue?["code"]?
            .objectValue?["enum"]?.arrayValue?.compactMap(\.stringValue) ?? []
        #expect(Set(errorEnum) == Set(errorCodes))
        #expect(errorEnum.count == MCPToolErrorCode.allCases.count)
    }
}
