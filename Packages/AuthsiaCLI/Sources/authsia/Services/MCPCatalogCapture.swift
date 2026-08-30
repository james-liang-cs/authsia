import Foundation
import MCP

enum MCPCatalogCaptureError: LocalizedError, Equatable {
    case unknownUpstream(String)
    case notProbeable(String)

    var errorDescription: String? {
        switch self {
        case .unknownUpstream(let name):
            return "'\(name)' is not declared in this workspace's mcpUpstreams."
        case .notProbeable(let name):
            return "'\(name)' declares environment values, so its catalog cannot be probed. " +
                "List its tools under mcpUpstreams.tools.allow in .authsia/workspace.json."
        }
    }
}

/// Records what a declared stdio child advertises into workspace policy, so the
/// proxy answers `tools/list` from the committed file instead of starting the
/// child. Capture is the human-initiated moment that pays the admission prompt;
/// opening a workspace afterwards costs none.
enum MCPCatalogCapture {
    struct Outcome: Equatable {
        let advertised: [String]
        /// False when descriptions and schemas were dropped to stay inside the
        /// committed catalog bound. The names are still recorded.
        let wroteDescriptors: Bool
    }

    static func apply(
        tools: [Tool],
        upstreamName: String,
        workspaceRoot: URL
    ) throws -> Outcome {
        let config = try WorkspaceConfigStore.read(fromWorkspaceRoot: workspaceRoot)
        guard let index = config.mcpUpstreams.firstIndex(where: { $0.name == upstreamName }) else {
            throw MCPCatalogCaptureError.unknownUpstream(upstreamName)
        }
        var upstream = config.mcpUpstreams[index]
        guard MCPProxyCatalog.canProbeChildCatalog(upstream) else {
            throw MCPCatalogCaptureError.notProbeable(upstreamName)
        }
        // A re-capture refreshes what the child offers. Where a human already
        // placed a name -- denied, or moved to approve -- that placement stands.
        let denied = Set(upstream.tools.deny)
        let approved = Set(upstream.tools.approve)
        upstream.tools.allow = tools.map(\.name).filter {
            !denied.contains($0) && !approved.contains($0)
        }
        upstream.catalog = tools.map(descriptor(for:))
        let advertised = MCPProxyCatalog.advertisedNames(in: upstream.tools)

        do {
            try write(upstream, at: index, in: config, workspaceRoot: workspaceRoot)
            return Outcome(advertised: advertised, wroteDescriptors: !upstream.catalog.isEmpty)
        } catch WorkspaceConfigError.invalidMCPUpstreamCatalog {
            // Descriptions and schemas past the committed bound are dropped
            // rather than losing the tool names they belong to.
            upstream.catalog = []
            try write(upstream, at: index, in: config, workspaceRoot: workspaceRoot)
            return Outcome(advertised: advertised, wroteDescriptors: false)
        }
    }

    private static func write(
        _ upstream: MCPUpstreamConfig,
        at index: Int,
        in config: WorkspaceConfig,
        workspaceRoot: URL
    ) throws {
        var upstreams = config.mcpUpstreams
        upstreams[index] = upstream
        let updated = WorkspaceConfig(
            schemaVersion: config.schemaVersion,
            workspace: config.workspace,
            managedEnvFiles: config.managedEnvFiles,
            agents: config.agents,
            guardSettings: config.guardSettings,
            envBindings: config.envBindings,
            mcpUpstreams: upstreams
        )
        try WorkspaceConfigStore.write(updated, toWorkspaceRoot: workspaceRoot)
    }

    private static func descriptor(for tool: Tool) -> MCPUpstreamToolDescriptor {
        guard let data = try? JSONEncoder().encode(tool.inputSchema),
              let schema = try? JSONDecoder().decode(MCPJSONValue.self, from: data) else {
            return MCPUpstreamToolDescriptor(
                name: tool.name,
                description: tool.description ?? ""
            )
        }
        return MCPUpstreamToolDescriptor(
            name: tool.name,
            description: tool.description ?? "",
            inputSchema: schema
        )
    }
}
