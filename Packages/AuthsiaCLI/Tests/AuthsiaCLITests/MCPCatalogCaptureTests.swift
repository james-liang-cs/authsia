import Foundation
import AuthenticatorBridge
import MCP
import Testing
@testable import authsia

@Suite("MCP catalog capture")
struct MCPCatalogCaptureTests {
    @Test("oversized metadata retains names and default allow policy")
    func oversizedMetadataKeepsNamesOnly() throws {
        let root = try makeMCPProxyWorkspace(upstreams: [.init(name: "fixture", command: "fixture")])
        defer { try? FileManager.default.removeItem(at: root) }
        let outcome = try MCPCatalogCapture.apply(
            tools: [Tool(name: "new_tool", description: String(repeating: "x", count: 70_000), inputSchema: .object([:]))],
            upstreamName: "fixture", workspaceRoot: root)
        let upstream = try #require(WorkspaceConfigStore.read(fromWorkspaceRoot: root).mcpUpstreams.first)
        #expect(!outcome.wroteDescriptors)
        #expect(upstream.catalog.map(\.name) == ["new_tool"])
        #expect(upstream.tools.allow == upstream.catalog.map(\.name))
        #expect(MCPProxyCatalog.listedTools(for: upstream).map(\.name) == ["new_tool"])
    }
    private func probedTools() -> [Tool] {
        MCPProxyCatalog.listedTools(fromChild: [
            Tool(
                name: "codegraph_explore",
                description: "Explore the graph",
                inputSchema: .object([
                    "type": .string("object"),
                    "properties": .object(["query": .object(["type": .string("string")])]),
                ])
            ),
            Tool(name: "codegraph_node", description: "Read one node", inputSchema: .object([
                "type": .string("object"),
            ])),
        ])
    }

    @Test("capture records the probed catalog so listing never starts the child")
    func captureRecordsCatalog() throws {
        let root = try makeMCPProxyWorkspace(
            upstreams: [
                MCPUpstreamConfig(name: "codegraph", command: "codegraph", args: ["serve", "--mcp"]),
            ]
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let outcome = try MCPCatalogCapture.apply(
            tools: probedTools(),
            upstreamName: "codegraph",
            workspaceRoot: root
        )
        #expect(outcome.advertised == ["codegraph_explore", "codegraph_node"])
        #expect(outcome.wroteDescriptors)

        let stored = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        let upstream = try #require(stored.mcpUpstreams.first)
        #expect(upstream.tools.allow == upstream.catalog.map(\.name))
        #expect(upstream.catalog.map(\.name) == ["codegraph_explore", "codegraph_node"])
        #expect(upstream.catalog.first?.description == "Explore the graph")
        #expect(upstream.catalogCapturedAt != nil)
        // A recorded catalog is what lets the proxy answer a client's connect
        // list from committed policy, with no child and no admission prompt.
        #expect(!MCPProxyCatalog.shouldDiscoverChildCatalog(upstream))
        #expect(
            MCPProxyCatalog.listedTools(for: upstream).map(\.name)
                == ["codegraph_explore", "codegraph_node"]
        )
    }

    @Test("re-capture refreshes names and keeps the human's deny and approve")
    func recaptureKeepsHumanPlacement() throws {
        let root = try makeMCPProxyWorkspace(
            upstreams: [
                MCPUpstreamConfig(
                    name: "codegraph",
                    command: "codegraph",
                    tools: MCPUpstreamToolPolicy(
                        allow: ["codegraph_explore", "previously_allowed"],
                        approve: ["codegraph_node"],
                        deny: ["codegraph_write"]
                    )
                ),
            ]
        )
        defer { try? FileManager.default.removeItem(at: root) }

        var tools = probedTools()
        tools.append(Tool(name: "new_destructive_tool", description: "Synthetic fixture", inputSchema: .object([:])))
        tools.append(contentsOf: MCPProxyCatalog.listedTools(fromChild: [
            Tool(name: "codegraph_write", description: "", inputSchema: .object([
                "type": .string("object"),
            ])),
        ]))
        let outcome = try MCPCatalogCapture.apply(
            tools: tools,
            upstreamName: "codegraph",
            workspaceRoot: root
        )

        let stored = try WorkspaceConfigStore.read(fromWorkspaceRoot: root)
        let upstream = try #require(stored.mcpUpstreams.first)
        #expect(upstream.tools.allow == ["codegraph_explore", "previously_allowed"])
        #expect(upstream.tools.approve == ["codegraph_node"])
        #expect(upstream.tools.deny == ["codegraph_write"])
        #expect(!outcome.advertised.contains("codegraph_write"))
    }

    @Test("capture refuses an undeclared upstream and one that declares env")
    func captureRefusesIneligibleUpstreams() throws {
        let root = try makeMCPProxyWorkspace(
            upstreams: [
                MCPUpstreamConfig(
                    name: "jira",
                    command: "mcp-atlassian",
                    env: ["JIRA_API_TOKEN": "authsia://api-key/Atlassian/key?folder=Workspaces%2Fproxy"]
                ),
            ]
        )
        defer { try? FileManager.default.removeItem(at: root) }

        #expect(throws: MCPCatalogCaptureError.unknownUpstream("codegraph")) {
            _ = try MCPCatalogCapture.apply(
                tools: probedTools(),
                upstreamName: "codegraph",
                workspaceRoot: root
            )
        }
        // Listing must never resolve or forward a credential, so an upstream
        // that declares env is not probeable and has to be listed by hand.
        #expect(throws: MCPCatalogCaptureError.notProbeable("jira")) {
            _ = try MCPCatalogCapture.apply(
                tools: probedTools(),
                upstreamName: "jira",
                workspaceRoot: root
            )
        }
    }
}
